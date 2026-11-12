//! Módulo de deteção de varrimentos (port scans) por captura de pacotes raw.
//!
//! No Linux: usa sockets raw (AF_PACKET via pnet) para capturar pacotes SYN antes do handshake.
//! Em outros SOs (Windows / macOS): opera através do motor de armadilhas assíncrono nativo (TcpListener).

/// Classifica flags TCP para deteção de varrimentos furtivos (stealth scans).
#[allow(dead_code)]
pub fn classify_tcp_flags(flags: u8) -> Option<&'static str> {
    match flags {
        0x00 => Some("NULL Scan (T1046)"),
        0x01 => Some("FIN Scan (T1046)"),
        0x29 => Some("XMAS Scan (T1046)"),
        0x02 => Some("SYN Scan (T1046)"),
        0x14 => Some("RST-ACK Scan Response"),
        _ => None,
    }
}

#[cfg(not(target_os = "linux"))]
mod non_linux {
    use crate::models::Incident;
    use tokio::sync::mpsc::UnboundedSender;

    /// No Windows e macOS portáteis sem drivers adicionais de kernel (Npcap / WinPcap),
    /// o scanner de pacotes raw fica desativado.
    /// O Sentinela opera 100% de forma segura e nativa através do motor
    /// de armadilhas assíncrono (TcpListener) nas portas definidas, sem precisar de instalações.
    pub fn start_packet_scanner(_tx: UnboundedSender<Incident>, _trap_ports: Vec<u16>) -> bool {
        false
    }
}

#[cfg(not(target_os = "linux"))]
pub use non_linux::*;

#[cfg(target_os = "linux")]
mod linux {
    use crate::models::Incident;
    use crate::network::{inspect_ip, resolve_rdns};
    use crate::traps::classify_port;
    use chrono::Local;
    use pnet::datalink::{self, Channel};
    use pnet::packet::{
        ethernet::{EtherTypes, EthernetPacket},
        ip::IpNextHeaderProtocols,
        ipv4::Ipv4Packet,
        ipv6::Ipv6Packet,
        tcp::{TcpFlags, TcpPacket},
        Packet,
    };
    use std::{
        collections::{HashMap, HashSet},
        net::IpAddr,
        time::{Duration, Instant},
    };
    use tokio::runtime::Handle;
    use tokio::sync::mpsc::UnboundedSender;

    /// Janela de dedup por (IP, porto) — evita duplicar retransmissões do mesmo pacote.
    /// Curta o suficiente para não bloquear scans consecutivos.
    const DEDUP_WINDOW: Duration = Duration::from_secs(2);

    /// Configuração para deteção de Port Sweep.
    #[derive(Clone, Copy, Debug)]
    pub struct SweepConfig {
        pub threshold: usize,
        pub window: Duration,
    }

    impl Default for SweepConfig {
        fn default() -> Self {
            let threshold = std::env::var("SENTINELA_SWEEP_THRESHOLD")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(5);

            let window_secs = std::env::var("SENTINELA_SWEEP_WINDOW_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(5);

            SweepConfig {
                threshold,
                window: Duration::from_secs(window_secs),
            }
        }
    }

    /// Limpa periodicamente entradas antigas de todos os 3 mapas do scanner:
    pub fn cleanup_scanner_maps(
        trap_dedup: &mut HashMap<(IpAddr, u16), Instant>,
        sweep_tracker: &mut HashMap<IpAddr, Vec<(u16, Instant)>>,
        sweep_alert_dedup: &mut HashMap<IpAddr, Instant>,
        now: Instant,
        sweep_window: Duration,
    ) {
        trap_dedup.retain(|_, t| now.saturating_duration_since(*t) < Duration::from_secs(30));
        sweep_tracker.retain(|_, history| {
            history.retain(|(_, t)| now.saturating_duration_since(*t) <= sweep_window);
            !history.is_empty()
        });
        sweep_alert_dedup
            .retain(|_, t| now.saturating_duration_since(*t) < Duration::from_secs(30));
    }

    /// Tenta iniciar o scanner de pacotes raw em todas as interfaces não-loopback.
    pub fn start_packet_scanner(tx: UnboundedSender<Incident>, trap_ports: Vec<u16>) -> bool {
        let interfaces = datalink::interfaces();
        let handle = Handle::current();
        let sweep_config = SweepConfig::default();
        let mut started = false;

        for iface in interfaces {
            if iface.is_loopback() || !iface.is_up() || iface.ips.is_empty() {
                continue;
            }

            let config = datalink::Config {
                read_timeout: Some(Duration::from_millis(200)),
                ..Default::default()
            };

            if let Ok(Channel::Ethernet(_, mut rx)) = datalink::channel(&iface, config) {
                started = true;
                let tx_clone = tx.clone();
                let ports = trap_ports.clone();
                let rt = handle.clone();

                std::thread::spawn(move || {
                    let mut trap_dedup: HashMap<(IpAddr, u16), Instant> = HashMap::new();
                    let mut sweep_tracker: HashMap<IpAddr, Vec<(u16, Instant)>> = HashMap::new();
                    let mut sweep_alert_dedup: HashMap<IpAddr, Instant> = HashMap::new();
                    let mut last_cleanup = Instant::now();

                    loop {
                        if tx_clone.is_closed() {
                            break;
                        }

                        let now = Instant::now();
                        // Limpeza periódica dos mapas a cada 10 segundos
                        if now.saturating_duration_since(last_cleanup) >= Duration::from_secs(10)
                            || sweep_tracker.len() >= 10_000
                            || trap_dedup.len() >= 10_000
                        {
                            last_cleanup = now;
                            cleanup_scanner_maps(
                                &mut trap_dedup,
                                &mut sweep_tracker,
                                &mut sweep_alert_dedup,
                                now,
                                sweep_config.window,
                            );
                            if sweep_tracker.len() >= 10_000 {
                                sweep_tracker.clear();
                            }
                        }

                        match rx.next() {
                            Ok(raw) => {
                                if let Some(eth) = EthernetPacket::new(raw) {
                                    if let Some((src_ip, dst_port, tcp_flags)) =
                                        extract_tcp_info(&eth)
                                    {
                                        let is_syn = tcp_flags & TcpFlags::SYN != 0
                                            && tcp_flags & TcpFlags::ACK == 0;
                                        let is_stealth = is_unusual_scan(tcp_flags);
                                        if !is_syn && !is_stealth {
                                            continue;
                                        }

                                        if crate::network::is_host_ip(src_ip) {
                                            continue;
                                        }

                                        let now = Instant::now();

                                        // 1. Alerta imediato para portos armadilha
                                        if ports.contains(&dst_port) {
                                            let key = (src_ip, dst_port);
                                            let fresh = trap_dedup
                                                .get(&key)
                                                .map(|t| {
                                                    now.saturating_duration_since(*t)
                                                        >= DEDUP_WINDOW
                                                })
                                                .unwrap_or(true);

                                            if fresh {
                                                trap_dedup.insert(key, now);

                                                let scan_type = if is_stealth {
                                                    describe_scan_type(tcp_flags)
                                                } else {
                                                    "SYN"
                                                };

                                                let tx2 = tx_clone.clone();
                                                let label = scan_type.to_string();
                                                rt.spawn(async move {
                                                    let (country, city, isp) =
                                                        inspect_ip(src_ip).await;
                                                    let rdns = resolve_rdns(src_ip).await;
                                                    let threat_score = crate::models::calculate_threat_score("SCAN", 1, false);
                                                    let _ = tx2.send(Incident {
                                                        timestamp: Local::now()
                                                            .format("%Y-%m-%d %H:%M:%S")
                                                            .to_string(),
                                                        ip: src_ip.to_string(),
                                                        port: dst_port,
                                                        service: format!(
                                                            "SCAN {}→{}",
                                                            label,
                                                            classify_port(dst_port).0
                                                        ),
                                                        severity: "SCAN".to_string(),
                                                        country,
                                                        city,
                                                        isp,
                                                        rdns,
                                                        payload: None,
                                                        threat_score,
                                                        hit_count: 1,
                                                    });
                                                });
                                            }
                                        }

                                        // 2. Deteção inteligente de port sweep (janela deslizante)
                                        {
                                            let history = sweep_tracker.entry(src_ip).or_default();
                                            history.retain(|(_, ts)| {
                                                now.saturating_duration_since(*ts)
                                                    <= sweep_config.window
                                            });
                                            history.push((dst_port, now));

                                            let distinct_ports: HashSet<u16> =
                                                history.iter().map(|(p, _)| *p).collect();

                                            if distinct_ports.len() >= sweep_config.threshold {
                                                let should_alert = sweep_alert_dedup
                                                    .get(&src_ip)
                                                    .map(|t| {
                                                        now.saturating_duration_since(*t)
                                                            >= sweep_config.window
                                                    })
                                                    .unwrap_or(true);

                                                if should_alert {
                                                    sweep_alert_dedup.insert(src_ip, now);
                                                    let mut swept: Vec<u16> =
                                                        distinct_ports.into_iter().collect();
                                                    swept.sort_unstable();
                                                    history.clear();

                                                    let tx2 = tx_clone.clone();
                                                    rt.spawn(async move {
                                                        let (country, city, isp) =
                                                            inspect_ip(src_ip).await;
                                                        let rdns = resolve_rdns(src_ip).await;
                                                        let threat_score = crate::models::calculate_threat_score("SWEEP", 1, false);
                                                        let ports_str = if swept.len() > 6 {
                                                            let sample = swept[..6]
                                                                .iter()
                                                                .map(|p| p.to_string())
                                                                .collect::<Vec<_>>()
                                                                .join(",");
                                                            format!(
                                                                "{},+{}p",
                                                                sample,
                                                                swept.len() - 6
                                                            )
                                                        } else {
                                                            swept
                                                                .iter()
                                                                .map(|p| p.to_string())
                                                                .collect::<Vec<_>>()
                                                                .join(",")
                                                        };
                                                        let _ = tx2.send(Incident {
                                                            timestamp: Local::now()
                                                                .format("%Y-%m-%d %H:%M:%S")
                                                                .to_string(),
                                                            ip: src_ip.to_string(),
                                                            port: 0,
                                                            service: format!(
                                                                "SWEEP [{}]",
                                                                ports_str
                                                            ),
                                                            severity: "SWEEP".to_string(),
                                                            country,
                                                            city,
                                                            isp,
                                                            rdns,
                                                            payload: None,
                                                            threat_score,
                                                            hit_count: 1,
                                                        });
                                                    });
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                if e.kind() != std::io::ErrorKind::TimedOut {
                                    std::thread::sleep(Duration::from_millis(50));
                                }
                            }
                        }
                    }
                });
            }
        }

        started
    }

    /// Extrai (IP origem, porto destino, flags TCP) de um frame Ethernet.
    fn extract_tcp_info(eth: &EthernetPacket) -> Option<(IpAddr, u16, u8)> {
        match eth.get_ethertype() {
            EtherTypes::Ipv4 => {
                let ip = Ipv4Packet::new(eth.payload())?;
                // Descarta fragmentos subsequentes (offset > 0) pois não contêm o cabeçalho TCP
                if (ip.get_fragment_offset() & 0x1fff) != 0 {
                    return None;
                }
                if ip.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
                    return None;
                }
                let tcp = TcpPacket::new(ip.payload())?;
                Some((
                    IpAddr::V4(ip.get_source()),
                    tcp.get_destination(),
                    tcp.get_flags(),
                ))
            }
            EtherTypes::Ipv6 => {
                let ip = Ipv6Packet::new(eth.payload())?;
                if ip.get_next_header() != IpNextHeaderProtocols::Tcp {
                    return None;
                }
                let tcp = TcpPacket::new(ip.payload())?;
                Some((
                    IpAddr::V6(ip.get_source()),
                    tcp.get_destination(),
                    tcp.get_flags(),
                ))
            }
            _ => None,
        }
    }

    /// Deteta scans furtivos por combinações invulgares de flags TCP.
    fn is_unusual_scan(flags: u8) -> bool {
        flags == 0                                                          // NULL scan
            || flags == TcpFlags::FIN                                       // FIN scan
            || (flags & TcpFlags::FIN != 0                                  // XMAS scan
                && flags & TcpFlags::PSH != 0
                && flags & TcpFlags::URG != 0)
    }

    fn describe_scan_type(flags: u8) -> &'static str {
        if flags == 0 {
            "NULL"
        } else if flags == TcpFlags::FIN {
            "FIN"
        } else if flags & TcpFlags::FIN != 0
            && flags & TcpFlags::PSH != 0
            && flags & TcpFlags::URG != 0
        {
            "XMAS"
        } else {
            "SYN"
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::net::Ipv4Addr;

        #[test]
        fn test_cleanup_scanner_maps() {
            let mut trap_dedup = HashMap::new();
            let mut sweep_tracker = HashMap::new();
            let mut sweep_alert_dedup = HashMap::new();

            let now = Instant::now();
            let old_time = now.checked_sub(Duration::from_secs(35)).unwrap();
            let recent_time = now.checked_sub(Duration::from_secs(5)).unwrap();

            let ip_old = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
            let ip_recent = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

            trap_dedup.insert((ip_old, 80), old_time);
            trap_dedup.insert((ip_recent, 80), recent_time);

            sweep_tracker.insert(ip_old, vec![(80, old_time), (443, old_time)]);
            sweep_tracker.insert(ip_recent, vec![(80, old_time), (443, recent_time)]);

            sweep_alert_dedup.insert(ip_old, old_time);
            sweep_alert_dedup.insert(ip_recent, recent_time);

            cleanup_scanner_maps(
                &mut trap_dedup,
                &mut sweep_tracker,
                &mut sweep_alert_dedup,
                now,
                Duration::from_secs(5),
            );

            assert_eq!(trap_dedup.len(), 1);
            assert!(trap_dedup.contains_key(&(ip_recent, 80)));

            assert_eq!(sweep_tracker.len(), 1);
            assert_eq!(sweep_tracker.get(&ip_recent).unwrap().len(), 1);
            assert_eq!(sweep_tracker.get(&ip_recent).unwrap()[0].0, 443);

            assert_eq!(sweep_alert_dedup.len(), 1);
            assert!(sweep_alert_dedup.contains_key(&ip_recent));
        }

        #[test]
        fn test_sweep_sliding_window_threshold() {
            let config = SweepConfig {
                threshold: 4,
                window: Duration::from_secs(5),
            };

            let now = Instant::now();
            let mut history: Vec<(u16, Instant)> = Vec::new();

            history.push((80, now.checked_sub(Duration::from_secs(3)).unwrap()));
            history.push((443, now.checked_sub(Duration::from_secs(2)).unwrap()));
            history.push((8080, now.checked_sub(Duration::from_secs(1)).unwrap()));

            history.retain(|(_, ts)| now.saturating_duration_since(*ts) <= config.window);
            let distinct: HashSet<u16> = history.iter().map(|(p, _)| *p).collect();
            assert_eq!(distinct.len(), 3);
            assert!(distinct.len() < config.threshold);

            history.push((8443, now));
            history.retain(|(_, ts)| now.saturating_duration_since(*ts) <= config.window);
            let distinct: HashSet<u16> = history.iter().map(|(p, _)| *p).collect();
            assert_eq!(distinct.len(), 4);
            assert!(
                distinct.len() >= config.threshold,
                "Deve atingir o limiar de SWEEP!"
            );

            history.push((80, now));
            let distinct_repeated: HashSet<u16> = history.iter().map(|(p, _)| *p).collect();
            assert_eq!(distinct_repeated.len(), 4);
        }

        #[test]
        fn test_stealth_scan_classification() {
            // NULL scan (flags = 0)
            assert!(is_unusual_scan(0));
            assert_eq!(describe_scan_type(0), "NULL");

            // FIN scan (flags = FIN)
            assert!(is_unusual_scan(TcpFlags::FIN));
            assert_eq!(describe_scan_type(TcpFlags::FIN), "FIN");

            // XMAS scan (FIN + PSH + URG)
            let xmas = TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG;
            assert!(is_unusual_scan(xmas));
            assert_eq!(describe_scan_type(xmas), "XMAS");

            // Regular SYN or SYN-ACK não são invulgares
            assert!(!is_unusual_scan(TcpFlags::SYN));
            assert_eq!(describe_scan_type(TcpFlags::SYN), "SYN");
            assert!(!is_unusual_scan(TcpFlags::SYN | TcpFlags::ACK));
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_stealth_scan_classification() {
        // NULL (0), FIN (1), XMAS (0x29), SYN (2)
        assert_eq!(classify_tcp_flags(0), Some("NULL Scan (T1046)"));
        assert_eq!(classify_tcp_flags(1), Some("FIN Scan (T1046)"));
        assert_eq!(classify_tcp_flags(0x29), Some("XMAS Scan (T1046)"));
        assert_eq!(classify_tcp_flags(2), Some("SYN Scan (T1046)"));
        assert_eq!(classify_tcp_flags(0x14), Some("RST-ACK Scan Response"));
        assert_eq!(classify_tcp_flags(0x10), None);
        assert_eq!(classify_tcp_flags(0x12), None);
    }
}


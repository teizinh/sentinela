//! Módulo de guarda ativa contra ARP Spoofing e Envenenamento de Cache ARP (MITRE ATT&CK T1557.002).
//!
//! Monitoriza pacotes ARP e tabelas de vizinhança em tempo real para detetar:
//! - Gateway Spoofing (usurpação do router / default gateway)
//! - MAC Conflicts (conflitos de IP associado a múltiplos MACs)
//! - Gratuitous ARP Flooding (inundação de anúncios ARP não solicitados)

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// Alertas gerados pelo guardião ARP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArpAlert {
    /// O IP do gateway foi reivindicado por um endereço MAC não autorizado.
    GatewaySpoofed {
        gateway_ip: String,
        old_mac: String,
        attacker_mac: String,
    },
    /// Um endereço IP foi reivindicado por dois MACs físicos distintos na rede.
    MacConflict {
        ip: String,
        mac1: String,
        mac2: String,
    },
    /// Detetada uma taxa anómala de pacotes Gratuitous ARP para o mesmo IP.
    GratuitousArpFlood {
        ip: String,
        count: usize,
    },
}

impl ArpAlert {
    /// Código MITRE ATT&CK associado à ameaça.
    pub fn mitre_id(&self) -> &'static str {
        "T1557.002"
    }

    /// Nome descritivo da técnica MITRE ATT&CK.
    pub fn mitre_name(&self) -> &'static str {
        "Adversary-in-the-Middle: ARP Cache Poisoning"
    }

    /// Pontuação de severidade de ameaça (0 a 100).
    pub fn threat_score(&self) -> u8 {
        match self {
            ArpAlert::GatewaySpoofed { .. } => 95,
            ArpAlert::MacConflict { .. } => 85,
            ArpAlert::GratuitousArpFlood { .. } => 75,
        }
    }

    /// Severidade textual para o SOC Sentinela.
    pub fn severity(&self) -> &'static str {
        match self {
            ArpAlert::GatewaySpoofed { .. } => "CRÍTICO",
            ArpAlert::MacConflict { .. } => "ALTO",
            ArpAlert::GratuitousArpFlood { .. } => "MÉDIO",
        }
    }

    /// Converte o alerta num incidente formatado para o pipeline Sentinela.
    pub fn to_incident(&self, interface: &str) -> crate::models::Incident {
        let (ip, service, payload) = match self {
            ArpAlert::GatewaySpoofed {
                gateway_ip,
                old_mac,
                attacker_mac,
            } => (
                gateway_ip.clone(),
                "ARP Guard (Gateway MITM)".to_string(),
                format!(
                    "ALERTA CRÍTICO: GATEWAY SPOOFING DETETADO!\nO IP do Gateway '{gateway_ip}' na interface '{interface}' mudou de MAC:\n  Legítimo: {old_mac}\n  Atacante: {attacker_mac}\nMITRE ATT&CK: T1557.002 (ARP Cache Poisoning)"
                ),
            ),
            ArpAlert::MacConflict { ip, mac1, mac2 } => (
                ip.clone(),
                "ARP Guard (MAC Conflict)".to_string(),
                format!(
                    "ALERTA: CONFLITO DE MAC NO IP '{ip}'!\nMúltiplos endereços físicos a reivindicar o mesmo IP:\n  MAC 1: {mac1}\n  MAC 2: {mac2}\nPossível tentativa de interceção ou duplicação de IP."
                ),
            ),
            ArpAlert::GratuitousArpFlood { ip, count } => (
                ip.clone(),
                "ARP Guard (GARP Flood)".to_string(),
                format!(
                    "ALERTA: INUNDAÇÃO DE GRATUITOUS ARP!\nO IP '{ip}' emitiu {count} anúncios Gratuitous ARP numa janela temporal reduzida.\nPossível tentativa de envenenamento massivo de cache na subnet."
                ),
            ),
        };

        crate::models::Incident {
            timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            ip,
            port: 0,
            service,
            severity: self.severity().to_string(),
            country: "Rede Local (LAN)".to_string(),
            city: interface.to_string(),
            isp: "Interface Local".to_string(),
            rdns: None,
            payload: Some(payload),
            threat_score: self.threat_score(),
            hit_count: 1,
        }
    }
}

impl std::fmt::Display for ArpAlert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArpAlert::GatewaySpoofed {
                gateway_ip,
                old_mac,
                attacker_mac,
            } => {
                write!(
                    f,
                    "Gateway Spoofing: IP {gateway_ip} altered MAC from {old_mac} to {attacker_mac} (MITRE T1557.002)"
                )
            }
            ArpAlert::MacConflict { ip, mac1, mac2 } => {
                write!(
                    f,
                    "MAC Conflict: IP {ip} claimed by multiple MACs ({mac1} vs {mac2})"
                )
            }
            ArpAlert::GratuitousArpFlood { ip, count } => {
                write!(
                    f,
                    "Gratuitous ARP Flood: {count} packets received from {ip}"
                )
            }
        }
    }
}

/// Registo histórico de associação IP -> MAC com carimbo temporal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacHistoryEntry {
    pub mac: String,
    pub first_seen: Instant,
    pub last_seen: Instant,
    pub packet_count: usize,
}

/// Guardião ativo de envenenamento e spoofing ARP.
#[derive(Debug, Clone)]
pub struct ArpGuard {
    /// IP conhecido do Gateway (router default).
    pub gateway_ip: Option<String>,
    /// Mapeamento IP -> MAC ativo.
    ip_to_mac: HashMap<String, String>,
    /// Mapeamento reverso MAC -> Lista de IPs associados.
    mac_to_ips: HashMap<String, HashSet<String>>,
    /// Histórico detalhado de mapeamentos com carimbos temporais.
    history: HashMap<String, Vec<MacHistoryEntry>>,
    /// Rastreio de carimbos temporais de Gratuitous ARP para deteção de flood.
    gratuitous_tracker: HashMap<String, Vec<Instant>>,
    /// Limiar de pacotes GARP para disparar alerta de flood (padrão: 5).
    pub garp_flood_threshold: usize,
    /// Janela deslizante para contabilização de GARP flood (padrão: 5s).
    pub garp_window: Duration,
}

impl ArpGuard {
    /// Cria uma nova instância de `ArpGuard`, com gateway opcional.
    pub fn new(gateway_ip: Option<String>) -> Self {
        Self {
            gateway_ip: gateway_ip.map(|g| g.trim().to_string()),
            ip_to_mac: HashMap::new(),
            mac_to_ips: HashMap::new(),
            history: HashMap::new(),
            gratuitous_tracker: HashMap::new(),
            garp_flood_threshold: 5,
            garp_window: Duration::from_secs(5),
        }
    }

    /// Construtor auxiliar para especificar o gateway e o seu MAC legítimo imediatamente.
    pub fn with_gateway(mut self, gateway_ip: String, gateway_mac: Option<String>) -> Self {
        let clean_ip = gateway_ip.trim().to_string();
        self.gateway_ip = Some(clean_ip.clone());
        if let Some(mac) = gateway_mac {
            self.ip_to_mac.insert(clean_ip, mac.trim().to_string());
        }
        self
    }

    /// Regista e analisa um pacote ARP recebido em tempo real.
    ///
    /// - `sender_ip`: Endereço IP do emissor.
    /// - `sender_mac`: Endereço MAC do emissor.
    /// - `is_gratuitous`: Verdadeiro se o pacote for um anúncio Gratuitous ARP.
    ///
    /// Retorna `Some(ArpAlert)` se for detetado spoofing, conflito ou flood, ou `None` caso legítimo.
    pub fn record_arp_packet(
        &mut self,
        sender_ip: &str,
        sender_mac: &str,
        is_gratuitous: bool,
    ) -> Option<ArpAlert> {
        let ip = sender_ip.trim();
        let mac = sender_mac.trim();

        if ip.is_empty() || mac.is_empty() {
            return None;
        }

        // Ignora endereços multicast/broadcast e MACs nulos
        if mac.eq_ignore_ascii_case("ff:ff:ff:ff:ff:ff")
            || mac.eq_ignore_ascii_case("00:00:00:00:00:00")
        {
            return None;
        }

        let now = Instant::now();

        // 1. Atualiza histórico IP -> MAC com contagens e carimbos temporais
        let hist_entries = self.history.entry(ip.to_string()).or_default();
        if let Some(entry) = hist_entries
            .iter_mut()
            .find(|e| e.mac.eq_ignore_ascii_case(mac))
        {
            entry.last_seen = now;
            entry.packet_count += 1;
        } else {
            hist_entries.push(MacHistoryEntry {
                mac: mac.to_string(),
                first_seen: now,
                last_seen: now,
                packet_count: 1,
            });
        }

        // 2. Atualiza mapeamento reverso MAC -> IPs
        self.mac_to_ips
            .entry(mac.to_ascii_lowercase())
            .or_default()
            .insert(ip.to_string());

        // 3. Rastreia janela deslizante de Gratuitous ARP
        let garp_count = if is_gratuitous {
            let tracker = self.gratuitous_tracker.entry(ip.to_string()).or_default();
            tracker.retain(|ts| now.saturating_duration_since(*ts) <= self.garp_window);
            tracker.push(now);
            tracker.len()
        } else {
            0
        };

        // 4. Verificação de conflito ou usurpação de Gateway
        let is_gateway = self
            .gateway_ip
            .as_deref()
            .map_or(false, |gw| gw.eq_ignore_ascii_case(ip));

        if let Some(known_mac) = self.ip_to_mac.get(ip) {
            if !known_mac.eq_ignore_ascii_case(mac) {
                let old_mac = known_mac.clone();
                if is_gateway {
                    // Gateway Spoofing (MITRE ATT&CK T1557.002)
                    return Some(ArpAlert::GatewaySpoofed {
                        gateway_ip: ip.to_string(),
                        old_mac,
                        attacker_mac: mac.to_string(),
                    });
                } else {
                    // Conflito de endereço MAC para este IP
                    return Some(ArpAlert::MacConflict {
                        ip: ip.to_string(),
                        mac1: old_mac,
                        mac2: mac.to_string(),
                    });
                }
            }
        } else {
            // Primeiro mapeamento para este IP: aprende de forma transparente
            self.ip_to_mac.insert(ip.to_string(), mac.to_string());
        }

        // 5. Verificação de inundação Gratuitous ARP
        if is_gratuitous && garp_count >= self.garp_flood_threshold {
            return Some(ArpAlert::GratuitousArpFlood {
                ip: ip.to_string(),
                count: garp_count,
            });
        }

        None
    }

    /// Retorna o MAC atualmente associado a um IP.
    pub fn get_mac(&self, ip: &str) -> Option<&str> {
        self.ip_to_mac.get(ip.trim()).map(|s| s.as_str())
    }

    /// Retorna o histórico de MACs observados para um IP.
    pub fn get_history(&self, ip: &str) -> Option<&[MacHistoryEntry]> {
        self.history.get(ip.trim()).map(|v| v.as_slice())
    }

    /// Retorna todos os IPs que já utilizaram um determinado MAC.
    pub fn get_ips_for_mac(&self, mac: &str) -> Option<&HashSet<String>> {
        self.mac_to_ips.get(&mac.trim().to_ascii_lowercase())
    }

    /// Atualiza forçadamente o MAC mapeado para um IP.
    pub fn set_mac_for_ip(&mut self, ip: &str, mac: &str) {
        self.ip_to_mac
            .insert(ip.trim().to_string(), mac.trim().to_string());
    }

    /// Processa entradas da tabela ARP (ex: conteúdo de /proc/net/arp).
    pub fn parse_arp_table(&mut self, content: &str) -> Vec<ArpAlert> {
        let mut alerts = Vec::new();
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }
            let ip = parts[0];
            let flags = if parts.len() > 2 { parts[2] } else { "" };
            let mac = parts[3];

            // Ignora entradas incompletas (flags == 0x0 ou MAC nulo)
            if flags == "0x0" || mac == "00:00:00:00:00:00" || mac.len() != 17 {
                continue;
            }

            if let Some(alert) = self.record_arp_packet(ip, mac, false) {
                alerts.push(alert);
            }
        }
        alerts
    }

    /// Lê a tabela ARP do sistema (/proc/net/arp em Linux) e gera alertas em tempo real.
    #[cfg(target_os = "linux")]
    pub fn check_system_arp_table(&mut self) -> Vec<ArpAlert> {
        if let Ok(content) = std::fs::read_to_string("/proc/net/arp") {
            self.parse_arp_table(&content)
        } else {
            Vec::new()
        }
    }

    /// Stub para sistemas não-Linux.
    #[cfg(not(target_os = "linux"))]
    pub fn check_system_arp_table(&mut self) -> Vec<ArpAlert> {
        Vec::new()
    }
}

impl Default for ArpGuard {
    fn default() -> Self {
        Self::new(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normal_arp_learning() {
        let mut guard = ArpGuard::new(Some("192.168.1.1".to_string()));

        // Primeiro pacote do gateway: aprende normalmente
        assert_eq!(
            guard.record_arp_packet("192.168.1.1", "00:11:22:33:44:55", false),
            None
        );
        assert_eq!(guard.get_mac("192.168.1.1"), Some("00:11:22:33:44:55"));

        // Primeiro pacote de um nó comum
        assert_eq!(
            guard.record_arp_packet("192.168.1.50", "aa:bb:cc:dd:ee:01", false),
            None
        );
        assert_eq!(guard.get_mac("192.168.1.50"), Some("aa:bb:cc:dd:ee:01"));

        // Repetição dos mesmos pacotes: sem alertas
        assert_eq!(
            guard.record_arp_packet("192.168.1.1", "00:11:22:33:44:55", false),
            None
        );
        assert_eq!(
            guard.record_arp_packet("192.168.1.50", "aa:bb:cc:dd:ee:01", false),
            None
        );

        // Repetição com maiúsculas/minúsculas diferentes (case-insensitive)
        assert_eq!(
            guard.record_arp_packet("192.168.1.50", "AA:BB:CC:DD:EE:01", false),
            None
        );

        // Histórico deve registar a contagem correta
        let history = guard.get_history("192.168.1.50").unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].packet_count, 3);
    }

    #[test]
    fn test_gateway_spoofing_detection() {
        let mut guard = ArpGuard::new(Some("192.168.1.1".to_string()));

        // Gateway legítimo envia anúncio inicial
        assert_eq!(
            guard.record_arp_packet("192.168.1.1", "00:11:22:33:44:55", false),
            None
        );

        // Atacante tenta envenenar a cache com outro MAC para o IP do gateway
        let alert = guard.record_arp_packet("192.168.1.1", "de:ad:be:ef:ca:fe", false);
        assert_eq!(
            alert,
            Some(ArpAlert::GatewaySpoofed {
                gateway_ip: "192.168.1.1".to_string(),
                old_mac: "00:11:22:33:44:55".to_string(),
                attacker_mac: "de:ad:be:ef:ca:fe".to_string(),
            })
        );

        // Verificações de metadados MITRE
        if let Some(a) = alert {
            assert_eq!(a.mitre_id(), "T1557.002");
            assert_eq!(a.threat_score(), 95);
            assert_eq!(a.severity(), "CRÍTICO");
        }
    }

    #[test]
    fn test_mac_conflict_detection() {
        let mut guard = ArpGuard::new(Some("192.168.1.1".to_string()));

        // Nó normal 192.168.1.100 regista MAC legítimo
        assert_eq!(
            guard.record_arp_packet("192.168.1.100", "00:aa:bb:cc:dd:ee", false),
            None
        );

        // Outro nó na rede tenta atribuir outro MAC ao mesmo IP (conflito / spoof)
        let alert = guard.record_arp_packet("192.168.1.100", "11:22:33:44:55:66", false);
        assert_eq!(
            alert,
            Some(ArpAlert::MacConflict {
                ip: "192.168.1.100".to_string(),
                mac1: "00:aa:bb:cc:dd:ee".to_string(),
                mac2: "11:22:33:44:55:66".to_string(),
            })
        );

        if let Some(a) = alert {
            assert_eq!(a.mitre_id(), "T1557.002");
            assert_eq!(a.threat_score(), 85);
            assert_eq!(a.severity(), "ALTO");
        }
    }

    #[test]
    fn test_gratuitous_arp_flood() {
        let mut guard = ArpGuard::new(Some("192.168.1.1".to_string()));

        // Envia 4 pacotes Gratuitous ARP: abaixo do limiar (threshold = 5)
        for _ in 0..4 {
            assert_eq!(
                guard.record_arp_packet("192.168.1.75", "00:50:56:c0:00:08", true),
                None
            );
        }

        // 5º pacote Gratuitous ARP: atinge o limiar e dispara alerta
        let alert = guard.record_arp_packet("192.168.1.75", "00:50:56:c0:00:08", true);
        assert_eq!(
            alert,
            Some(ArpAlert::GratuitousArpFlood {
                ip: "192.168.1.75".to_string(),
                count: 5,
            })
        );

        if let Some(a) = alert {
            assert_eq!(a.mitre_id(), "T1557.002");
            assert_eq!(a.threat_score(), 75);
            assert_eq!(a.severity(), "MÉDIO");
        }
    }

    #[test]
    fn test_arp_table_parsing_and_incidents() {
        let mut guard = ArpGuard::new(Some("192.168.1.1".to_string()));

        let table = "IP address       HW type     Flags       HW address            Mask     Device\n\
                     192.168.1.1      0x1         0x2         00:11:22:33:44:55     *        eth0\n\
                     192.168.1.50     0x1         0x2         aa:bb:cc:dd:ee:01     *        eth0\n\
                     192.168.1.99     0x1         0x0         00:00:00:00:00:00     *        eth0\n";

        let alerts = guard.parse_arp_table(table);
        assert!(alerts.is_empty());

        // Segunda leitura com Gateway alterado:
        let spoofed_table = "IP address       HW type     Flags       HW address            Mask     Device\n\
                             192.168.1.1      0x1         0x2         ff:ee:dd:cc:bb:aa     *        eth0\n";
        let alerts = guard.parse_arp_table(spoofed_table);
        assert_eq!(alerts.len(), 1);
        match &alerts[0] {
            ArpAlert::GatewaySpoofed { gateway_ip, old_mac, attacker_mac } => {
                assert_eq!(gateway_ip, "192.168.1.1");
                assert_eq!(old_mac, "00:11:22:33:44:55");
                assert_eq!(attacker_mac, "ff:ee:dd:cc:bb:aa");
            }
            _ => panic!("Esperado GatewaySpoofed"),
        }

        // Converte em Incident do Sentinela
        let incident = alerts[0].to_incident("eth0");
        assert_eq!(incident.threat_score, 95);
        assert_eq!(incident.ip, "192.168.1.1");
        assert!(incident.payload.as_ref().unwrap().contains("GATEWAY SPOOFING"));
    }
}

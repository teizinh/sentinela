//! Módulo de inspeção ICMP: deteção de ping sweep e túneis encobertos (covert channels).

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Alertas gerados pela inspeção de tráfego ICMP.
#[derive(Debug, Clone, PartialEq)]
pub enum IcmpAlert {
    PingSweep {
        src_ip: String,
        targets_pinged: usize,
        threat_score: u8,
    },
    CovertTunnel {
        src_ip: String,
        entropy: f32,
        payload_len: usize,
        threat_score: u8,
    },
}

/// Analisador de tráfego ICMP para deteção de reconhecimento e canais encobertos.
pub struct IcmpAnalyzer {
    ping_targets: HashMap<String, HashMap<String, Instant>>,
}

impl IcmpAnalyzer {
    /// Cria uma nova instância de `IcmpAnalyzer`.
    pub fn new() -> Self {
        Self {
            ping_targets: HashMap::new(),
        }
    }

    /// Analisa um pacote ICMP.
    ///
    /// Se `icmp_type == 8` (Echo Request):
    /// - Monitoriza alvos distintos contactados por `src_ip` numa janela deslizante de 5 segundos.
    ///   Se alvos distintos >= 5, gera `IcmpAlert::PingSweep` com `threat_score: 75`.
    /// - Calcula a entropia de Shannon no payload. Se `payload.len() > 64` e `entropy > 4.5`,
    ///   gera `IcmpAlert::CovertTunnel` com `threat_score: 90` (MITRE T1095).
    /// Caso contrário, devolve `None`.
    pub fn analyze_packet(
        &mut self,
        src_ip: &str,
        target_ip: &str,
        icmp_type: u8,
        payload: &[u8],
        now: Instant,
    ) -> Option<IcmpAlert> {
        if icmp_type != 8 {
            return None;
        }

        let targets = self.ping_targets.entry(src_ip.to_string()).or_default();
        targets.retain(|_, ts| now.saturating_duration_since(*ts) <= Duration::from_secs(5));
        targets.insert(target_ip.to_string(), now);
        let targets_pinged = targets.len();

        if payload.len() > 64 {
            let entropy = calculate_entropy(payload);
            if entropy > 4.5 {
                return Some(IcmpAlert::CovertTunnel {
                    src_ip: src_ip.to_string(),
                    entropy,
                    payload_len: payload.len(),
                    threat_score: 90,
                });
            }
        }

        if targets_pinged >= 5 {
            return Some(IcmpAlert::PingSweep {
                src_ip: src_ip.to_string(),
                targets_pinged,
                threat_score: 75,
            });
        }

        None
    }
}

impl Default for IcmpAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Calcula a entropia de Shannon de uma sequência de bytes.
pub fn calculate_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0usize; 256];
    for &b in data {
        freq[b as usize] += 1;
    }

    let len_f = data.len() as f32;
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f32 / len_f;
            entropy -= p * p.log2();
        }
    }

    entropy
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_icmp_standard_ping_no_alert() {
        let mut analyzer = IcmpAnalyzer::new();
        let payload = [0u8; 32];
        let alert = analyzer.analyze_packet("192.168.1.100", "192.168.1.1", 8, &payload, Instant::now());
        assert_eq!(alert, None);
    }

    #[test]
    fn test_icmp_covert_tunnel_high_entropy() {
        let mut analyzer = IcmpAnalyzer::new();
        let payload: Vec<u8> = (0..128).collect();
        let alert = analyzer.analyze_packet("192.168.1.100", "192.168.1.1", 8, &payload, Instant::now());
        match alert {
            Some(IcmpAlert::CovertTunnel {
                src_ip,
                entropy,
                payload_len,
                threat_score,
            }) => {
                assert_eq!(src_ip, "192.168.1.100");
                assert!(entropy > 4.5);
                assert_eq!(payload_len, 128);
                assert_eq!(threat_score, 90);
            }
            other => panic!("Expected CovertTunnel alert, got {:?}", other),
        }
    }

    #[test]
    fn test_icmp_ping_sweep_detection() {
        let mut analyzer = IcmpAnalyzer::new();
        let now = Instant::now();
        let payload = [0u8; 32];

        // First 4 targets should not trigger alert
        for i in 1..=4 {
            let target = format!("10.0.0.{}", i);
            let alert = analyzer.analyze_packet("192.168.1.100", &target, 8, &payload, now);
            assert_eq!(alert, None);
        }

        // 5th distinct target triggers PingSweep alert
        let alert = analyzer.analyze_packet("192.168.1.100", "10.0.0.5", 8, &payload, now);
        assert_eq!(
            alert,
            Some(IcmpAlert::PingSweep {
                src_ip: "192.168.1.100".to_string(),
                targets_pinged: 5,
                threat_score: 75,
            })
        );
    }

    #[test]
    fn test_icmp_non_echo_request_ignored() {
        let mut analyzer = IcmpAnalyzer::new();
        let now = Instant::now();
        let payload: Vec<u8> = (0..128).collect();

        // Echo Reply (type 0) should return None even with high entropy payload
        let alert = analyzer.analyze_packet("192.168.1.100", "10.0.0.1", 0, &payload, now);
        assert_eq!(alert, None);

        // Destination Unreachable (type 3)
        let alert = analyzer.analyze_packet("192.168.1.100", "10.0.0.1", 3, &payload, now);
        assert_eq!(alert, None);
    }

    #[test]
    fn test_icmp_sliding_window_expiration() {
        let mut analyzer = IcmpAnalyzer::new();
        let start = Instant::now();
        let payload = [0u8; 16];

        // Ping 4 targets at t=0
        for i in 1..=4 {
            let target = format!("10.0.0.{}", i);
            let alert = analyzer.analyze_packet("192.168.1.100", &target, 8, &payload, start);
            assert_eq!(alert, None);
        }

        // Ping 5th target 6 seconds later (> 5s window)
        let later = start + Duration::from_secs(6);
        let alert = analyzer.analyze_packet("192.168.1.100", "10.0.0.5", 8, &payload, later);
        // The first 4 pings expired, so only 1 distinct target is in the window
        assert_eq!(alert, None);
    }

    #[test]
    fn test_icmp_duplicate_targets_no_sweep() {
        let mut analyzer = IcmpAnalyzer::new();
        let now = Instant::now();
        let payload = [0u8; 16];

        // Ping the same target 10 times: distinct count remains 1, no alert
        for _ in 0..10 {
            let alert = analyzer.analyze_packet("192.168.1.100", "10.0.0.1", 8, &payload, now);
            assert_eq!(alert, None);
        }
    }

    #[test]
    fn test_icmp_calculate_entropy_cases() {
        assert_eq!(calculate_entropy(&[]), 0.0);
        assert_eq!(calculate_entropy(&[42u8; 100]), 0.0);

        // 256 distinct bytes should have entropy = 8.0
        let all_bytes: Vec<u8> = (0..=255).collect();
        let entropy_256 = calculate_entropy(&all_bytes);
        assert!((entropy_256 - 8.0).abs() < 1e-5);
    }
}

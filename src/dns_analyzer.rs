//! Módulo de análise DNS: deteção de túneis encobertos (Covert Tunnels),
//! exfiltração de dados (MITRE ATT&CK T1071.004), domínios gerados por algoritmo (DGA)
//! e anomalias de Fast-Flux.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Alertas gerados pela inspeção de consultas DNS.
#[derive(Debug, Clone, PartialEq)]
pub enum DnsAlert {
    CovertTunnel {
        query: String,
        entropy: f32,
        length: usize,
    },
    DgaSuspicious {
        domain: String,
        consonant_ratio: f32,
    },
    FastFluxAnomaly {
        domain: String,
        query_rate: usize,
    },
}

/// Analisador de consultas DNS para deteção de túneis encobertos, DGAs e Fast-Flux.
#[derive(Debug, Clone)]
pub struct DnsAnalyzer {
    domain_queries: HashMap<String, Vec<Instant>>,
    window: Duration,
    fast_flux_threshold: usize,
}

impl DnsAnalyzer {
    /// Cria uma nova instância de `DnsAnalyzer`.
    pub fn new() -> Self {
        Self {
            domain_queries: HashMap::new(),
            window: Duration::from_secs(10),
            fast_flux_threshold: 10,
        }
    }

    /// Analisa uma consulta DNS inspecionando o nome de domínio pesquisado.
    ///
    /// Deteções efetuadas:
    /// - Túneis encobertos / Exfiltração de dados (MITRE ATT&CK T1071.004):
    ///   Sinaliza etiquetas com comprimento > 30 caracteres (ou >= 25) e entropia de Shannon > 3.8
    ///   (p. ex., dnscat2, iodine).
    /// - Domínios DGA (Domain Generation Algorithm):
    ///   Sinaliza etiquetas com elevada proporção consoante/vogal (>= 3.5) com número significativo
    ///   de consoantes (>= 6).
    /// - Anomalias Fast-Flux:
    ///   Sinaliza taxas de consulta anormais para o mesmo domínio numa janela temporal deslizante.
    pub fn inspect_query(&mut self, client_ip: &str, query_name: &str) -> Option<DnsAlert> {
        self.inspect_query_with_time(client_ip, query_name, Instant::now())
    }

    /// Analisa uma consulta DNS com um timestamp explícito para controlo determinístico de testes.
    pub fn inspect_query_with_time(
        &mut self,
        _client_ip: &str,
        query_name: &str,
        now: Instant,
    ) -> Option<DnsAlert> {
        let clean = query_name.trim().trim_end_matches('.');
        if clean.is_empty() {
            return None;
        }

        // 1. Deteção de Túneis Encobertos e Exfiltração de Dados (MITRE ATT&CK T1071.004)
        // Inspeciona etiquetas (labels) do domínio para identificar payloads codificados/cifrados
        for label in clean.split('.') {
            let entropy = calculate_entropy(label);
            // Sinaliza etiquetas com comprimento > 30 (ou payloads de túnel >= 25 caracteres) e entropia > 3.8
            if (label.len() > 30 || label.len() >= 25) && entropy > 3.8 {
                return Some(DnsAlert::CovertTunnel {
                    query: query_name.to_string(),
                    entropy,
                    length: query_name.len(),
                });
            }
        }

        // Também verifica se a consulta global excede 30 caracteres com entropia elevada (> 3.8)
        if clean.len() > 30 {
            let full_entropy = calculate_entropy(clean);
            if full_entropy > 3.8 {
                for label in clean.split('.') {
                    let ent = calculate_entropy(label);
                    if label.len() >= 20 && ent > 3.8 {
                        return Some(DnsAlert::CovertTunnel {
                            query: query_name.to_string(),
                            entropy: ent,
                            length: query_name.len(),
                        });
                    }
                }
            }
        }

        // 2. Deteção de DGA (Domain Generation Algorithm)
        // Analisa proporção consoante/vogal nas etiquetas do domínio
        for label in clean.split('.') {
            if label.len() >= 6 {
                let (consonants, _vowels, ratio) = count_consonants_vowels_and_ratio(label);
                if consonants >= 6 && ratio >= 3.5 {
                    return Some(DnsAlert::DgaSuspicious {
                        domain: query_name.to_string(),
                        consonant_ratio: ratio,
                    });
                }
            }
        }

        // 3. Deteção de Anomalias de Fast-Flux / Taxa Anormal de Consultas
        let domain_key = clean.to_lowercase();
        let timestamps = self.domain_queries.entry(domain_key).or_default();
        timestamps.retain(|ts| now.saturating_duration_since(*ts) <= self.window);
        timestamps.push(now);
        let query_rate = timestamps.len();

        if query_rate >= self.fast_flux_threshold {
            return Some(DnsAlert::FastFluxAnomaly {
                domain: query_name.to_string(),
                query_rate,
            });
        }

        None
    }
}

impl Default for DnsAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Calcula a proporção de consoantes para vogais (C/V ratio) numa cadeia de caracteres.
pub fn calculate_consonant_ratio(s: &str) -> f32 {
    let (_, _, ratio) = count_consonants_vowels_and_ratio(s);
    ratio
}

fn count_consonants_vowels_and_ratio(s: &str) -> (usize, usize, f32) {
    let mut consonants = 0usize;
    let mut vowels = 0usize;

    for c in s.chars() {
        if c.is_ascii_alphabetic() {
            match c.to_ascii_lowercase() {
                'a' | 'e' | 'i' | 'o' | 'u' => vowels += 1,
                _ => consonants += 1,
            }
        }
    }

    let ratio = if consonants == 0 {
        0.0
    } else if vowels == 0 {
        consonants as f32
    } else {
        consonants as f32 / vowels as f32
    };

    (consonants, vowels, ratio)
}

/// Calcula a entropia de Shannon de uma sequência de caracteres em bits por caractere.
pub fn calculate_entropy(s: &str) -> f32 {
    calculate_entropy_bytes(s.as_bytes())
}

/// Calcula a entropia de Shannon de uma sequência de bytes em bits por byte.
pub fn calculate_entropy_bytes(data: &[u8]) -> f32 {
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
    fn test_legitimate_queries_no_alert() {
        let mut analyzer = DnsAnalyzer::new();
        assert_eq!(analyzer.inspect_query("192.168.1.10", "google.com"), None);
        assert_eq!(
            analyzer.inspect_query("192.168.1.10", "repo.security.org"),
            None
        );
        assert_eq!(
            analyzer.inspect_query("192.168.1.10", "www.github.com"),
            None
        );
        assert_eq!(
            analyzer.inspect_query("192.168.1.10", "api.cloudflare.com"),
            None
        );
    }

    #[test]
    fn test_covert_tunnel_high_entropy() {
        let mut analyzer = DnsAnalyzer::new();
        let query = "7a8f9c1b2e3d4f5a6b7c8d9e0f.exfil.target.com";
        let alert = analyzer.inspect_query("192.168.1.50", query);
        match alert {
            Some(DnsAlert::CovertTunnel {
                query: q,
                entropy,
                length,
            }) => {
                assert_eq!(q, query);
                assert!(entropy > 3.8);
                assert_eq!(length, query.len());
                assert!(length > 30);
            }
            other => panic!("Expected CovertTunnel alert, got {:?}", other),
        }
    }

    #[test]
    fn test_covert_tunnel_long_label_over_30_chars() {
        let mut analyzer = DnsAnalyzer::new();
        let query = "c2E3ZjRhOGI5YzFkMmUzZjRhOGI5YzFkMmUzZjRhOGI.tunnel.dnscat2.org";
        let alert = analyzer.inspect_query("10.0.0.5", query);
        match alert {
            Some(DnsAlert::CovertTunnel {
                query: q,
                entropy,
                length,
            }) => {
                assert_eq!(q, query);
                assert!(entropy > 3.8);
                assert!(length > 30);
            }
            other => panic!("Expected CovertTunnel alert, got {:?}", other),
        }
    }

    #[test]
    fn test_dga_detection() {
        let mut analyzer = DnsAnalyzer::new();
        let dga_domain = "xrtkqwvmpz.com";
        let alert = analyzer.inspect_query("10.0.0.1", dga_domain);
        match alert {
            Some(DnsAlert::DgaSuspicious {
                domain,
                consonant_ratio,
            }) => {
                assert_eq!(domain, dga_domain);
                assert!(consonant_ratio >= 3.5);
            }
            other => panic!("Expected DgaSuspicious alert, got {:?}", other),
        }

        let dga_all_consonants = "bcdfghjklmn.net";
        let alert2 = analyzer.inspect_query("10.0.0.2", dga_all_consonants);
        match alert2 {
            Some(DnsAlert::DgaSuspicious {
                domain,
                consonant_ratio,
            }) => {
                assert_eq!(domain, dga_all_consonants);
                assert!(consonant_ratio >= 10.0);
            }
            other => panic!("Expected DgaSuspicious alert, got {:?}", other),
        }
    }

    #[test]
    fn test_entropy_calculation() {
        assert_eq!(calculate_entropy(""), 0.0);
        assert_eq!(calculate_entropy("aaaa"), 0.0);
        assert_eq!(calculate_entropy("abab"), 1.0);
        assert_eq!(calculate_entropy("abcd"), 2.0);
        assert_eq!(calculate_entropy("0123456789abcdef"), 4.0);

        let all_bytes: Vec<u8> = (0..=255).collect();
        let entropy_256 = calculate_entropy_bytes(&all_bytes);
        assert!((entropy_256 - 8.0).abs() < 1e-5);
    }

    #[test]
    fn test_consonant_ratio_calculation() {
        assert_eq!(calculate_consonant_ratio(""), 0.0);
        assert_eq!(calculate_consonant_ratio("aeiou"), 0.0);
        assert_eq!(calculate_consonant_ratio("bcdf"), 4.0);
        assert_eq!(calculate_consonant_ratio("google"), 1.0);
        assert!((calculate_consonant_ratio("security") - 1.6666666).abs() < 1e-4);
    }

    #[test]
    fn test_fast_flux_anomaly() {
        let mut analyzer = DnsAnalyzer::new();
        let target_domain = "rotator.service-mesh.com";
        let now = Instant::now();

        // First 9 queries within window should not trigger alert
        for _ in 0..9 {
            let alert = analyzer.inspect_query_with_time("10.0.0.1", target_domain, now);
            assert_eq!(alert, None);
        }

        // 10th query triggers FastFluxAnomaly alert
        let alert = analyzer.inspect_query_with_time("10.0.0.1", target_domain, now);
        assert_eq!(
            alert,
            Some(DnsAlert::FastFluxAnomaly {
                domain: target_domain.to_string(),
                query_rate: 10,
            })
        );
    }

    #[test]
    fn test_fast_flux_sliding_window_expiration() {
        let mut analyzer = DnsAnalyzer::new();
        let target_domain = "cluster.api-node.net";
        let start = Instant::now();

        // 5 queries at t=0
        for _ in 0..5 {
            let alert = analyzer.inspect_query_with_time("10.0.0.1", target_domain, start);
            assert_eq!(alert, None);
        }

        // 5 queries 15 seconds later (> 10s window)
        let later = start + Duration::from_secs(15);
        for _ in 0..4 {
            let alert = analyzer.inspect_query_with_time("10.0.0.1", target_domain, later);
            assert_eq!(alert, None);
        }
        // Total in new window is 5, not >= 10, so no alert
        let alert = analyzer.inspect_query_with_time("10.0.0.1", target_domain, later);
        assert_eq!(alert, None);
    }
}

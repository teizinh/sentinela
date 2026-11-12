use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Language {
    Pt,
    En,
}

/// Temas visuais da dashboard do Sentinela
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Theme {
    Cyber,
    Matrix,
    Midnight,
    HighContrast,
}

impl Theme {
    pub fn next(self) -> Self {
        match self {
            Theme::Cyber => Theme::Matrix,
            Theme::Matrix => Theme::Midnight,
            Theme::Midnight => Theme::HighContrast,
            Theme::HighContrast => Theme::Cyber,
        }
    }

    pub fn label(self, lang: Language) -> &'static str {
        match (self, lang) {
            (Theme::Cyber, Language::Pt) => "Cyber SOC",
            (Theme::Cyber, Language::En) => "Cyber SOC",
            (Theme::Matrix, Language::Pt) => "Matrix Hacker",
            (Theme::Matrix, Language::En) => "Matrix Hacker",
            (Theme::Midnight, Language::Pt) => "Midnight Violet",
            (Theme::Midnight, Language::En) => "Midnight Violet",
            (Theme::HighContrast, Language::Pt) => "Alto Contraste",
            (Theme::HighContrast, Language::En) => "High Contrast",
        }
    }

    pub fn border_color(self) -> ratatui::style::Color {
        match self {
            Theme::Cyber => ratatui::style::Color::Cyan,
            Theme::Matrix => ratatui::style::Color::Green,
            Theme::Midnight => ratatui::style::Color::Rgb(100, 149, 237),
            Theme::HighContrast => ratatui::style::Color::White,
        }
    }

    pub fn header_title_color(self) -> ratatui::style::Color {
        match self {
            Theme::Cyber => ratatui::style::Color::Yellow,
            Theme::Matrix => ratatui::style::Color::LightGreen,
            Theme::Midnight => ratatui::style::Color::Magenta,
            Theme::HighContrast => ratatui::style::Color::Yellow,
        }
    }

    pub fn footer_color(self) -> ratatui::style::Color {
        match self {
            Theme::Cyber => ratatui::style::Color::Cyan,
            Theme::Matrix => ratatui::style::Color::Green,
            Theme::Midnight => ratatui::style::Color::Rgb(147, 112, 219),
            Theme::HighContrast => ratatui::style::Color::White,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SysInfo {
    pub distro: String,
    pub kernel: String,
    pub arch: String,
}

/// Representa uma conexão capturada por uma armadilha (honeypot)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Incident {
    pub timestamp: String,
    pub ip: String,
    pub port: u16,
    pub service: String,
    pub severity: String,
    pub country: String,
    pub city: String,
    pub isp: String,
    /// Hostname DNS reverso obtido assincronamente (se disponível)
    pub rdns: Option<String>,
    /// Primeiros bytes de payload/banner capturados (se houver)
    pub payload: Option<String>,
    /// Pontuação de perigo de 0 a 100 baseada em severidade, repetições e payload
    pub threat_score: u8,
    /// Número total de vezes que este IP foi visto na sessão atual
    pub hit_count: usize,
}

impl Incident {
    /// The UI and keyboard actions must operate on the same filtered records.
    pub fn matches_filter(&self, severity: SeverityFilter, query: &str) -> bool {
        severity.matches(&self.severity)
            && (query.is_empty()
                || self.ip.to_lowercase().contains(query)
                || self.service.to_lowercase().contains(query)
                || self.port.to_string().starts_with(query)
                || self.severity.to_lowercase().contains(query))
    }
}

/// Calcula uma pontuação de perigo (0 a 100) para priorização e triagem no SOC
pub fn calculate_threat_score(severity: &str, hit_count: usize, has_payload: bool) -> u8 {
    let base = match severity {
        "CRÍTICO" => 60,
        "SWEEP" => 75,
        "MÉDIO" => 40,
        "SCAN" => 35,
        "ALERTA" => 20,
        _ => 15,
    };
    let hit_bonus = if hit_count >= 10 {
        20
    } else if hit_count >= 5 {
        15
    } else if hit_count >= 2 {
        10
    } else {
        0
    };
    let payload_bonus = if has_payload { 15 } else { 0 };
    (base + hit_bonus + payload_bonus).min(100)
}

/// Aviso sobre uma porta localmente vulnerável
#[derive(Clone, Debug)]
pub struct PortWarning {
    pub port: u16,
    pub service: String,
    pub risk_level: &'static str,
    pub reason: String,
    pub fix_command: String,
}

/// Filtro de severidade aplicado à tabela de deteções
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeverityFilter {
    All,
    CriticalOnly,
    MediumAndAbove,
}

impl SeverityFilter {
    /// Alterna para o próximo filtro em ciclo
    pub fn next(self) -> Self {
        match self {
            SeverityFilter::All => SeverityFilter::CriticalOnly,
            SeverityFilter::CriticalOnly => SeverityFilter::MediumAndAbove,
            SeverityFilter::MediumAndAbove => SeverityFilter::All,
        }
    }

    pub fn label(self, lang: Language) -> &'static str {
        match (self, lang) {
            (SeverityFilter::All, Language::Pt) => "Todos",
            (SeverityFilter::All, Language::En) => "All",
            (SeverityFilter::CriticalOnly, Language::Pt) => "Críticos",
            (SeverityFilter::CriticalOnly, Language::En) => "Critical",
            (SeverityFilter::MediumAndAbove, Language::Pt) => "Médio+",
            (SeverityFilter::MediumAndAbove, Language::En) => "Medium+",
        }
    }

    /// Devolve true se o incidente passa este filtro
    pub fn matches(self, severity: &str) -> bool {
        match self {
            SeverityFilter::All => true,
            SeverityFilter::CriticalOnly => severity == "CRÍTICO" || severity == "SWEEP",
            SeverityFilter::MediumAndAbove => {
                severity == "CRÍTICO" || severity == "SWEEP" || severity == "MÉDIO"
            }
        }
    }
}

/// Resposta da API GeoIP (ip-api.com)
#[derive(Clone, Debug, Deserialize)]
pub struct GeoResponse {
    pub country: Option<String>,
    pub city: Option<String>,
    pub isp: Option<String>,
    pub status: Option<String>,
}

/// Mapeamento de ameaças para a Matriz MITRE ATT&CK para análise SOC
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MitreTechnique {
    pub id: String,
    pub name: String,
    pub tactic: String,
    pub url: String,
}

/// Representa uma conexão ou socket de rede ativo no sistema hospedeiro
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SocketInfo {
    pub proto: String,
    pub state: String,
    pub local_addr: String,
    pub foreign_addr: String,
    pub pid_process: String,
    pub is_honeypot: bool,
    pub is_external: bool,
}

/// Determina a técnica e tática MITRE ATT&CK correspondente ao incidente
pub fn map_to_mitre(severity: &str, port: u16, payload: Option<&str>) -> MitreTechnique {
    if severity == "ARP" || payload.map_or(false, |p| p.contains("ARP")) {
        return MitreTechnique {
            id: "T1557.002".to_string(),
            name: "Adversary-in-the-Middle: ARP Cache Poisoning".to_string(),
            tactic: "Credential Access / Collection (TA0006)".to_string(),
            url: "https://attack.mitre.org/techniques/T1557/002/".to_string(),
        };
    }
    if severity == "SWEEP" {
        return MitreTechnique {
            id: "T1046".to_string(),
            name: "Network Service Discovery (Horizontal Sweep)".to_string(),
            tactic: "Discovery (TA0007)".to_string(),
            url: "https://attack.mitre.org/techniques/T1046/".to_string(),
        };
    }
    if severity == "SCAN" {
        return MitreTechnique {
            id: "T1046".to_string(),
            name: "Network Service Discovery (Port Scan)".to_string(),
            tactic: "Discovery (TA0007)".to_string(),
            url: "https://attack.mitre.org/techniques/T1046/".to_string(),
        };
    }

    match port {
        22 | 2222 => MitreTechnique {
            id: "T1110.001".to_string(),
            name: "Brute Force: Password Guessing (SSH)".to_string(),
            tactic: "Credential Access (TA0006)".to_string(),
            url: "https://attack.mitre.org/techniques/T1110/001/".to_string(),
        },
        21 | 2121 => MitreTechnique {
            id: "T1110.001".to_string(),
            name: "Brute Force: Password Guessing (FTP)".to_string(),
            tactic: "Credential Access (TA0006)".to_string(),
            url: "https://attack.mitre.org/techniques/T1110/001/".to_string(),
        },
        23 | 2323 => MitreTechnique {
            id: "T1021.002".to_string(),
            name: "Remote Services: SMB/Telnet".to_string(),
            tactic: "Lateral Movement (TA0008)".to_string(),
            url: "https://attack.mitre.org/techniques/T1021/002/".to_string(),
        },
        25 => MitreTechnique {
            id: "T1595.002".to_string(),
            name: "Active Scanning: Vulnerability Scanning (SMTP)".to_string(),
            tactic: "Reconnaissance (TA0043)".to_string(),
            url: "https://attack.mitre.org/techniques/T1595/002/".to_string(),
        },
        80 | 8080 | 8443 | 443 => {
            if let Some(p) = payload {
                let p_lower = p.to_lowercase();
                if p_lower.contains("admin")
                    || p_lower.contains(".env")
                    || p_lower.contains("wp-")
                    || p_lower.contains("setup")
                    || p_lower.contains("config")
                {
                    MitreTechnique {
                        id: "T1190".to_string(),
                        name: "Exploit Public-Facing Application (Web Probe)".to_string(),
                        tactic: "Initial Access (TA0001)".to_string(),
                        url: "https://attack.mitre.org/techniques/T1190/".to_string(),
                    }
                } else {
                    MitreTechnique {
                        id: "T1595.002".to_string(),
                        name: "Active Scanning: Vulnerability Scanning (HTTP)".to_string(),
                        tactic: "Reconnaissance (TA0043)".to_string(),
                        url: "https://attack.mitre.org/techniques/T1595/002/".to_string(),
                    }
                }
            } else {
                MitreTechnique {
                    id: "T1595.002".to_string(),
                    name: "Active Scanning: Vulnerability Scanning (HTTP)".to_string(),
                    tactic: "Reconnaissance (TA0043)".to_string(),
                    url: "https://attack.mitre.org/techniques/T1595/002/".to_string(),
                }
            }
        }
        3306 | 5432 => MitreTechnique {
            id: "T1078.001".to_string(),
            name: "Valid Accounts: Default / Database Accounts".to_string(),
            tactic: "Initial Access / Defense Evasion".to_string(),
            url: "https://attack.mitre.org/techniques/T1078/001/".to_string(),
        },
        6379 => MitreTechnique {
            id: "T1210".to_string(),
            name: "Exploitation of Remote Services (Redis)".to_string(),
            tactic: "Lateral Movement (TA0008)".to_string(),
            url: "https://attack.mitre.org/techniques/T1210/".to_string(),
        },
        3389 => MitreTechnique {
            id: "T1021.001".to_string(),
            name: "Remote Services: Remote Desktop Protocol (RDP)".to_string(),
            tactic: "Lateral Movement (TA0008)".to_string(),
            url: "https://attack.mitre.org/techniques/T1021/001/".to_string(),
        },
        _ => MitreTechnique {
            id: "T1046".to_string(),
            name: "Network Service Discovery".to_string(),
            tactic: "Discovery (TA0007)".to_string(),
            url: "https://attack.mitre.org/techniques/T1046/".to_string(),
        },
    }
}

/// Formata uma cadeia de bytes ou texto no formato hexdump canónico (estilo xxd / Wireshark)
pub fn format_hexdump(input: &str) -> String {
    let bytes = input.as_bytes();
    if bytes.is_empty() {
        return String::new();
    }

    let mut result = String::new();
    for (chunk_idx, chunk) in bytes.chunks(16).enumerate() {
        let offset = chunk_idx * 16;
        result.push_str(&format!("{:04x}:  ", offset));

        // Bytes em hexadecimal (espaço adicional a cada 8 bytes)
        for (i, byte) in chunk.iter().enumerate() {
            if i == 8 {
                result.push(' ');
            }
            result.push_str(&format!("{:02x} ", byte));
        }

        // Preenchimento de espaços se o último bloco tiver menos de 16 bytes
        if chunk.len() < 16 {
            let missing = 16 - chunk.len();
            let pad_spaces = missing * 3 + if chunk.len() <= 8 { 1 } else { 0 };
            for _ in 0..pad_spaces {
                result.push(' ');
            }
        }

        result.push_str(" |");
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                result.push(*byte as char);
            } else {
                result.push('.');
            }
        }
        result.push_str("|\n");
    }

    result.trim_end().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_and_severity_select_the_same_records() {
        let incident = Incident {
            timestamp: String::new(),
            ip: "2001:db8::1".into(),
            port: 2222,
            service: "SSH Honeypot".into(),
            severity: "MÉDIO".into(),
            country: String::new(),
            city: String::new(),
            isp: String::new(),
            rdns: None,
            payload: None,
            threat_score: 40,
            hit_count: 1,
        };
        for query in ["", "ssh", "2001:db8", "22", "médio"] {
            assert!(incident.matches_filter(SeverityFilter::All, query));
        }
        assert!(!incident.matches_filter(SeverityFilter::All, "http"));
        assert!(!incident.matches_filter(SeverityFilter::CriticalOnly, "ssh"));
    }


    #[test]
    fn test_severity_filter_cycle() {
        let filter = SeverityFilter::All;
        assert_eq!(filter.next(), SeverityFilter::CriticalOnly);
        assert_eq!(filter.next().next(), SeverityFilter::MediumAndAbove);
        assert_eq!(filter.next().next().next(), SeverityFilter::All);
    }

    #[test]
    fn test_severity_filter_matching() {
        let all = SeverityFilter::All;
        assert!(all.matches("CRÍTICO"));
        assert!(all.matches("SWEEP"));
        assert!(all.matches("MÉDIO"));
        assert!(all.matches("ALERTA"));
        assert!(all.matches("SCAN"));

        let crit = SeverityFilter::CriticalOnly;
        assert!(crit.matches("CRÍTICO"));
        assert!(crit.matches("SWEEP"));
        assert!(!crit.matches("MÉDIO"));
        assert!(!crit.matches("ALERTA"));
        assert!(!crit.matches("SCAN"));

        let med_plus = SeverityFilter::MediumAndAbove;
        assert!(med_plus.matches("CRÍTICO"));
        assert!(med_plus.matches("SWEEP"));
        assert!(med_plus.matches("MÉDIO"));
        assert!(!med_plus.matches("ALERTA"));
        assert!(!med_plus.matches("SCAN"));
    }

    #[test]
    fn test_severity_filter_labels() {
        assert_eq!(SeverityFilter::All.label(Language::Pt), "Todos");
        assert_eq!(SeverityFilter::All.label(Language::En), "All");
        assert_eq!(SeverityFilter::CriticalOnly.label(Language::Pt), "Críticos");
        assert_eq!(SeverityFilter::CriticalOnly.label(Language::En), "Critical");
        assert_eq!(SeverityFilter::MediumAndAbove.label(Language::Pt), "Médio+");
        assert_eq!(
            SeverityFilter::MediumAndAbove.label(Language::En),
            "Medium+"
        );
    }

    #[test]
    fn test_calculate_threat_score() {
        assert_eq!(calculate_threat_score("CRÍTICO", 1, false), 60);
        assert_eq!(calculate_threat_score("CRÍTICO", 5, true), 90);
        assert_eq!(calculate_threat_score("SWEEP", 10, true), 100);
        assert_eq!(calculate_threat_score("ALERTA", 1, false), 20);
    }

    #[test]
    fn test_map_to_mitre() {
        let sweep = map_to_mitre("SWEEP", 0, None);
        assert_eq!(sweep.id, "T1046");
        assert!(sweep.name.contains("Horizontal Sweep"));

        let ssh = map_to_mitre("CRÍTICO", 2222, Some("SSH-2.0-OpenSSH"));
        assert_eq!(ssh.id, "T1110.001");
        assert!(ssh.name.contains("SSH"));

        let web_probe = map_to_mitre("MÉDIO", 8080, Some("GET /admin/.env HTTP/1.1"));
        assert_eq!(web_probe.id, "T1190");

        let arp = map_to_mitre("ARP", 0, Some("ARP Spoofing detected"));
        assert_eq!(arp.id, "T1557.002");
        assert!(arp.name.contains("ARP Cache Poisoning"));
    }

    #[test]
    fn test_format_hexdump() {
        assert_eq!(format_hexdump(""), "");
        let dump = format_hexdump("GET /admin");
        assert!(dump.starts_with("0000:  47 45 54 20 2f 61 64 6d"));
        assert!(dump.ends_with("|GET /admin|"));
    }

    #[test]
    fn test_theme_cycle() {
        let theme = Theme::Cyber;
        assert_eq!(theme.next(), Theme::Matrix);
        assert_eq!(theme.next().next(), Theme::Midnight);
        assert_eq!(theme.next().next().next(), Theme::HighContrast);
        assert_eq!(theme.next().next().next().next(), Theme::Cyber);
        assert_eq!(Theme::Matrix.label(Language::Pt), "Matrix Hacker");
    }
}

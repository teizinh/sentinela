use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Estrutura de configuração principal do Sentinela
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct SentinelaConfig {
    #[serde(default)]
    pub traps: TrapsConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub alerts: AlertsConfig,
    #[serde(default)]
    pub ui: UiConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrapsConfig {
    #[serde(default = "default_ports")]
    pub ports: Vec<u16>,
}

impl Default for TrapsConfig {
    fn default() -> Self {
        Self {
            ports: default_ports(),
        }
    }
}

fn default_ports() -> Vec<u16> {
    vec![2121, 2222, 2323, 8080, 8443]
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityConfig {
    #[serde(default)]
    pub auto_ban: bool,
    #[serde(default = "default_threat_threshold")]
    pub threat_threshold: u8,
    #[serde(default)]
    pub whitelist: Vec<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            auto_ban: false,
            threat_threshold: default_threat_threshold(),
            whitelist: Vec::new(),
        }
    }
}

fn default_threat_threshold() -> u8 {
    80
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct AlertsConfig {
    pub webhook_url: Option<String>,
    #[serde(default)]
    pub audio_alerts: bool,
    #[serde(default = "default_desktop_alerts")]
    pub desktop_notifications: bool,
}

fn default_desktop_alerts() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UiConfig {
    #[serde(default = "default_theme")]
    pub theme: String,
    #[serde(default = "default_language")]
    pub language: String,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            theme: default_theme(),
            language: default_language(),
        }
    }
}

fn default_theme() -> String {
    "cyber".to_string()
}

fn default_language() -> String {
    "pt".to_string()
}

/// Procura ficheiro de configuração nos locais padrão ou no caminho customizado
pub fn find_config_path(custom: Option<&str>) -> Option<PathBuf> {
    if let Some(c) = custom {
        let p = PathBuf::from(c);
        if p.exists() {
            return Some(p);
        }
    }

    // 1. Diretório atual: ./sentinela.toml
    let local = PathBuf::from("sentinela.toml");
    if local.exists() {
        return Some(local);
    }

    // 2. Diretório de utilizador: ~/.config/sentinela/config.toml
    if let Ok(home) = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
        let user_cfg = PathBuf::from(home).join(".config").join("sentinela").join("config.toml");
        if user_cfg.exists() {
            return Some(user_cfg);
        }
    }

    None
}

/// Carrega a configuração do ficheiro encontrado ou devolve valores predefinidos
pub fn load_config(custom_path: Option<&str>) -> Result<(SentinelaConfig, Option<PathBuf>), String> {
    if let Some(path) = find_config_path(custom_path) {
        let content = fs::read_to_string(&path)
            .map_err(|e| format!("Não foi possível ler {}: {}", path.display(), e))?;
        let config: SentinelaConfig = toml::from_str(&content)
            .map_err(|e| format!("Erro de sintaxe TOML em {}: {}", path.display(), e))?;
        Ok((config, Some(path)))
    } else {
        Ok((SentinelaConfig::default(), None))
    }
}

/// Cria um ficheiro de configuração predefinido com comentários detalhados
pub fn generate_default_config_file(target_path: &Path) -> Result<(), std::io::Error> {
    let template = r#"# ===================================================================
# FICHEIRO DE CONFIGURAÇÃO - SENTINELA HIDS & HONEYPOT
# ===================================================================
# Este ficheiro pode ser colocado no diretório atual (sentinela.toml)
# ou em ~/.config/sentinela/config.toml

[traps]
# Lista de portas TCP para escuta de armadilhas honeypot interativas
ports = [2121, 2222, 2323, 8080, 8443]

[security]
# Bloqueio automático de atacantes de alto risco no firewall (iptables/nftables)
auto_ban = false

# Limiar de pontuação de ameaça para acionar auto-ban (0-100)
threat_threshold = 80

# Lista de endereços IP confiáveis imunes ao Auto-Ban
whitelist = [
    "127.0.0.1",
    "192.168.1.1"
]

[alerts]
# URL de webhook HTTP (compatível com Discord, Slack, Wazuh ou servidores SIEM)
# webhook_url = "https://discord.com/api/webhooks/SEU_CANAL/TOKEN"

# Alerta sonoro de terminal (Bell acústico) para ameaças críticas
audio_alerts = false

# Notificações visuais no ambiente de trabalho (libnotify / notify-send / PowerShell)
desktop_notifications = true

[ui]
# Tema visual inicial do dashboard: "cyber", "matrix", "midnight", "contrast"
theme = "cyber"

# Idioma predefinido da interface: "pt" ou "en"
language = "pt"
"#;

    if let Some(parent) = target_path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(target_path, template)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_values() {
        let cfg = SentinelaConfig::default();
        assert_eq!(cfg.traps.ports, vec![2121, 2222, 2323, 8080, 8443]);
        assert!(!cfg.security.auto_ban);
        assert_eq!(cfg.security.threat_threshold, 80);
        assert_eq!(cfg.ui.theme, "cyber");
        assert_eq!(cfg.ui.language, "pt");
    }

    #[test]
    fn test_parse_toml_string() {
        let toml_str = r#"
            [traps]
            ports = [2222, 9000]

            [security]
            auto_ban = true
            threat_threshold = 75
            whitelist = ["10.0.0.1", "10.0.0.2"]

            [alerts]
            webhook_url = "https://example.com/webhook"
            audio_alerts = true

            [ui]
            theme = "matrix"
            language = "en"
        "#;

        let parsed: SentinelaConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(parsed.traps.ports, vec![2222, 9000]);
        assert!(parsed.security.auto_ban);
        assert_eq!(parsed.security.threat_threshold, 75);
        assert_eq!(parsed.security.whitelist, vec!["10.0.0.1", "10.0.0.2"]);
        assert_eq!(parsed.alerts.webhook_url.as_deref(), Some("https://example.com/webhook"));
        assert!(parsed.alerts.audio_alerts);
        assert_eq!(parsed.ui.theme, "matrix");
        assert_eq!(parsed.ui.language, "en");
    }

    #[test]
    fn test_generate_default_config_file() {
        let temp_dir = std::env::temp_dir();
        let target = temp_dir.join(format!("sentinela_test_cfg_{}.toml", std::process::id()));
        assert!(generate_default_config_file(&target).is_ok());
        let content = std::fs::read_to_string(&target).unwrap();
        assert!(content.contains("[traps]"));
        assert!(content.contains("ports = [2121, 2222, 2323, 8080, 8443]"));
        assert!(content.contains("[security]"));
        let _ = std::fs::remove_file(target);
    }
}

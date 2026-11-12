use crate::models::Incident;
use chrono::Local;
use std::path::PathBuf;
use tokio::sync::mpsc::UnboundedSender;

pub const DEFAULT_HONEYFILE_PATH: &str = "/tmp/.sentinela_honeyfile_credentials.env";

pub const HONEYFILE_CONTENT: &str = r#"# ====================================================================
# SENTINELA ACTIVE DECEPTION SENSOR (HONEYFILE)
# WARNING: UNAUTHORIZED ACCESS OR MODIFICATION WILL TRIGGER SOC ALARM
# ====================================================================
AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
PRODUCTION_DATABASE_URL="postgres://dba_master:SuperSecretPass2026!@10.0.0.45:5432/core_db"
JWT_SECRET_SIGNING_KEY="c2VudGluZWxhX3NlY3JldF9kZWNlcHRpb25fdG9rZW5fMjAyNg=="
"#;

pub struct HoneyfileWatchdog {
    pub path: PathBuf,
    pub active: bool,
}

impl HoneyfileWatchdog {
    pub fn new(path_str: Option<&str>) -> Self {
        let path = PathBuf::from(path_str.unwrap_or(DEFAULT_HONEYFILE_PATH));
        Self {
            path,
            active: false,
        }
    }

    pub fn deploy(&mut self) -> Result<PathBuf, std::io::Error> {
        std::fs::write(&self.path, HONEYFILE_CONTENT)?;
        self.active = true;
        Ok(self.path.clone())
    }

    pub fn cleanup(&mut self) {
        if self.path.exists() {
            let _ = std::fs::remove_file(&self.path);
        }
        self.active = false;
    }
}

impl Drop for HoneyfileWatchdog {
    fn drop(&mut self) {
        self.cleanup();
    }
}

/// Inicia o monitor de inotify para vigiar tentativas de leitura, modificação ou eliminação do Honeyfile.
pub fn start_honeyfile_watchdog(
    path: PathBuf,
    tx: UnboundedSender<Incident>,
) -> Option<tokio::task::JoinHandle<()>> {
    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;

        let path_str = path.to_string_lossy().to_string();
        let c_path = match CString::new(path_str.as_bytes()) {
            Ok(p) => p,
            Err(_) => return None,
        };

        unsafe {
            let inotify_fd = libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC);
            if inotify_fd < 0 {
                return None;
            }

            // Monitoriza acessos, modificações (ransomware), abertura e eliminação
            let mask = libc::IN_ACCESS
                | libc::IN_MODIFY
                | libc::IN_ATTRIB
                | libc::IN_OPEN
                | libc::IN_DELETE_SELF
                | libc::IN_MOVE_SELF;

            let wd = libc::inotify_add_watch(inotify_fd, c_path.as_ptr(), mask);
            if wd < 0 {
                libc::close(inotify_fd);
                return None;
            }

            let handle = tokio::spawn(async move {
                let mut buffer = [0u8; 1024];
                let mut last_alert_time = std::time::Instant::now() - std::time::Duration::from_secs(5);

                loop {
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;

                    let bytes_read = libc::read(
                        inotify_fd,
                        buffer.as_mut_ptr() as *mut libc::c_void,
                        buffer.len(),
                    );

                    if bytes_read > 0 {
                        // Debounce para não inundar o SOC com múltiplos eventos no mesmo segundo
                        if last_alert_time.elapsed() < std::time::Duration::from_millis(800) {
                            continue;
                        }
                        last_alert_time = std::time::Instant::now();

                        let event_ptr = buffer.as_ptr() as *const libc::inotify_event;
                        let event = &*event_ptr;
                        let event_mask = event.mask;

                        let action = if event_mask & libc::IN_MODIFY != 0 {
                            "Modificação/Tentativa de Encriptação (Ransomware Detectado!)"
                        } else if event_mask & (libc::IN_DELETE_SELF | libc::IN_MOVE_SELF) != 0 {
                            "Eliminação/Movimentação Ilegítima de Honeyfile"
                        } else if event_mask & libc::IN_OPEN != 0 {
                            "Abertura Não Autorizada de Credenciais"
                        } else {
                            "Acesso Suspeito ao Honeyfile"
                        };

                        let now = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                        let incident = Incident {
                            timestamp: now,
                            ip: "127.0.0.1".to_string(),
                            port: 0,
                            service: "Honeyfile (Canário Anti-Ransomware)".to_string(),
                            severity: "CRÍTICO".to_string(),
                            country: "Local (Anfitrião)".to_string(),
                            city: "Sistema de Ficheiros".to_string(),
                            isp: "Watchdog Inotify".to_string(),
                            rdns: Some("honeyfile.canary.local".to_string()),
                            payload: Some(format!("{}: {}", action, path_str)),
                            threat_score: 95,
                            hit_count: 1,
                        };

                        let _ = tx.send(incident);
                    }
                }
            });

            Some(handle)
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, tx);
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_honeyfile_creation_and_cleanup() {
        let temp_dir = std::env::temp_dir();
        let test_path = temp_dir.join(format!("test_canary_{}.env", std::process::id()));
        let mut watchdog = HoneyfileWatchdog::new(test_path.to_str());

        assert!(watchdog.deploy().is_ok());
        assert!(test_path.exists());

        let content = std::fs::read_to_string(&test_path).unwrap();
        assert!(content.contains("AWS_ACCESS_KEY_ID"));

        watchdog.cleanup();
        assert!(!test_path.exists());
    }
}

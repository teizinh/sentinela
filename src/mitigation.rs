use std::collections::HashSet;
use std::net::IpAddr;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BannedIp {
    pub ip: String,
    pub banned_at: Instant,
    pub duration: Duration,
    pub reason: String,
}

#[derive(Debug, Clone, Default)]
pub struct MitigationEngine {
    banned_ips: Vec<BannedIp>,
    custom_whitelist: HashSet<String>,
}

impl MitigationEngine {
    pub fn new() -> Self {
        Self {
            banned_ips: Vec::new(),
            custom_whitelist: HashSet::new(),
        }
    }

    pub fn add_whitelist(&mut self, ip: &str) {
        self.custom_whitelist.insert(ip.trim().to_string());
    }

    pub fn is_whitelisted(&self, ip: &str) -> bool {
        let clean = ip.trim();
        if self.custom_whitelist.contains(clean) {
            return true;
        }

        // Loopback & Common DNS servers
        if clean == "127.0.0.1"
            || clean == "::1"
            || clean == "1.1.1.1"
            || clean == "8.8.8.8"
            || clean == "1.0.0.1"
            || clean == "8.8.4.4"
        {
            return true;
        }

        if let Ok(addr) = clean.parse::<IpAddr>() {
            if addr.is_loopback() {
                return true;
            }

            match addr {
                IpAddr::V4(v4) => {
                    let oct = v4.octets();
                    // RFC 1918 subnets:
                    // 10.0.0.0/8
                    // 172.16.0.0/12
                    // 192.168.0.0/16
                    let is_rfc1918 = oct[0] == 10
                        || (oct[0] == 172 && (16..=31).contains(&oct[1]))
                        || (oct[0] == 192 && oct[1] == 168);

                    // Typical gateway addresses in RFC 1918 subnets end in .1 or .254
                    if is_rfc1918 && (oct[3] == 1 || oct[3] == 254) {
                        return true;
                    }
                }
                IpAddr::V6(v6) => {
                    if v6.is_loopback() {
                        return true;
                    }
                }
            }
        }

        false
    }

    pub fn ban_ip(&mut self, ip: &str, duration: Duration, reason: &str) -> Option<String> {
        let clean_ip = ip.trim();
        if self.is_whitelisted(clean_ip) {
            return None;
        }

        if let Some(existing) = self.banned_ips.iter_mut().find(|b| b.ip == clean_ip) {
            existing.banned_at = Instant::now();
            existing.duration = duration;
            existing.reason = reason.to_string();
        } else {
            self.banned_ips.push(BannedIp {
                ip: clean_ip.to_string(),
                banned_at: Instant::now(),
                duration,
                reason: reason.to_string(),
            });
        }

        Some(Self::ban_command(clean_ip))
    }

    pub fn ban_command(ip: &str) -> String {
        format!("sudo iptables -A INPUT -s {} -j DROP", ip.trim())
    }

    pub fn unban_command(ip: &str) -> String {
        format!("sudo iptables -D INPUT -s {} -j DROP", ip.trim())
    }

    pub fn check_unbans(&mut self, now: Instant) -> Vec<String> {
        let mut unbanned = Vec::new();
        self.banned_ips.retain(|entry| {
            let is_expired = match entry.banned_at.checked_add(entry.duration) {
                Some(expiry) => now >= expiry,
                None => false,
            };

            if is_expired {
                unbanned.push(entry.ip.clone());
                false
            } else {
                true
            }
        });
        unbanned
    }

    pub fn active_bans(&self) -> &[BannedIp] {
        &self.banned_ips
    }

    pub fn should_auto_ban(&self, severity: &str, threat_score: u8) -> bool {
        let sev = severity.to_uppercase();
        threat_score >= 85 || sev == "CRÍTICO" || sev == "CRITICO"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_auto_ban_criteria() {
        let engine = MitigationEngine::new();

        // High threat score triggers ban regardless of severity
        assert!(engine.should_auto_ban("MÉDIO", 85));
        assert!(engine.should_auto_ban("ALERTA", 90));
        assert!(engine.should_auto_ban("INFO", 100));

        // Critical severity triggers ban regardless of threat score
        assert!(engine.should_auto_ban("CRÍTICO", 0));
        assert!(engine.should_auto_ban("crítico", 50));
        assert!(engine.should_auto_ban("CRITICO", 10));

        // Low threat score with non-critical severity should NOT ban
        assert!(!engine.should_auto_ban("MÉDIO", 84));
        assert!(!engine.should_auto_ban("ALERTA", 70));
        assert!(!engine.should_auto_ban("BAIXO", 0));
        assert!(!engine.should_auto_ban("INFO", 20));
    }

    #[test]
    fn test_whitelist_rfc1918_and_loopback() {
        let engine = MitigationEngine::new();
        assert!(engine.is_whitelisted("127.0.0.1"));
        assert!(engine.is_whitelisted("::1"));
        assert!(engine.is_whitelisted("192.168.1.1"));
        assert!(engine.is_whitelisted("192.168.0.1"));
        assert!(engine.is_whitelisted("10.0.0.1"));
        assert!(engine.is_whitelisted("172.16.0.1"));
        assert!(engine.is_whitelisted("192.168.1.254"));
        assert!(engine.is_whitelisted("1.1.1.1"));
        assert!(engine.is_whitelisted("8.8.8.8"));
        assert!(!engine.is_whitelisted("198.51.100.42"));
        assert!(!engine.is_whitelisted("203.0.113.88"));
        assert!(!engine.is_whitelisted("192.168.1.50"));
    }

    #[test]
    fn test_ban_lifecycle_and_auto_unban() {
        let mut engine = MitigationEngine::new();
        let ip = "198.51.100.42";
        let duration = Duration::from_secs(60);
        let reason = "SSH brute force";

        // Whitelisted IP cannot be banned
        let white_res = engine.ban_ip("127.0.0.1", duration, "Should not ban");
        assert!(white_res.is_none());
        assert!(engine.active_bans().is_empty());

        let cmd = engine.ban_ip(ip, duration, reason);
        assert!(cmd.is_some());
        assert_eq!(cmd.unwrap(), "sudo iptables -A INPUT -s 198.51.100.42 -j DROP");
        assert_eq!(engine.active_bans().len(), 1);

        let active_banned_at = engine.active_bans()[0].banned_at;
        assert_eq!(engine.active_bans()[0].ip, ip);
        assert_eq!(engine.active_bans()[0].reason, reason);
        assert_eq!(engine.active_bans()[0].duration, duration);

        // Before expiration: no unbans
        let unbanned_early = engine.check_unbans(active_banned_at + Duration::from_secs(30));
        assert!(unbanned_early.is_empty());
        assert_eq!(engine.active_bans().len(), 1);

        // After expiration: auto-unban triggers
        let unbanned_late = engine.check_unbans(active_banned_at + Duration::from_secs(61));
        assert_eq!(unbanned_late, vec![ip.to_string()]);
        assert_eq!(engine.active_bans().len(), 0);
    }

    #[test]
    fn test_ban_and_unban_command_generation() {
        let ip = "203.0.113.88";
        assert_eq!(
            MitigationEngine::ban_command(ip),
            "sudo iptables -A INPUT -s 203.0.113.88 -j DROP"
        );
        assert_eq!(
            MitigationEngine::unban_command(ip),
            "sudo iptables -D INPUT -s 203.0.113.88 -j DROP"
        );
    }
}

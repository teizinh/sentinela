//! Offline Zero-Dependency IP Reputation & Bogon Matcher.
//!
//! Provides ultra-fast, zero-allocation/zero-latency CIDR-based IP intelligence,
//! pre-seeded with RFC bogons, known Internet scanners (Censys, Shodan,
//! Shadowserver, Project Sonar), and notorious bulletproof hosting subnets.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Categorization tier of an IP address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReputationTier {
    /// Bogon or reserved IP address space (RFC 5735, RFC 6598, RFC 1918, etc.).
    BogonOrReserved,
    /// Known Internet reconnaissance and intelligence scanners (Censys, Shodan, etc.).
    KnownScanner,
    /// Bulletproof, cybercrime, or malicious bulletproof hosting infrastructure.
    MaliciousHosting,
    /// Clean, neutral, or unclassified public IP address.
    Neutral,
}

impl ReputationTier {
    /// Human-readable description of the reputation tier.
    pub fn as_str(&self) -> &'static str {
        match self {
            ReputationTier::BogonOrReserved => "Bogon / Reserved",
            ReputationTier::KnownScanner => "Known Scanner",
            ReputationTier::MaliciousHosting => "Malicious Hosting",
            ReputationTier::Neutral => "Neutral",
        }
    }
}

impl std::fmt::Display for ReputationTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A reputation record returned by the reputation engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReputationRecord {
    /// The threat tier category.
    pub category: ReputationTier,
    /// Threat score boost (0..=100) added to baseline anomaly score.
    pub threat_boost: u8,
    /// Explanatory intelligence label or organization name.
    pub label: String,
}

impl ReputationRecord {
    /// Creates a new reputation record.
    pub fn new(category: ReputationTier, threat_boost: u8, label: impl Into<String>) -> Self {
        Self {
            category,
            threat_boost,
            label: label.into(),
        }
    }

    /// Default neutral record for unclassified or clean public IPs.
    pub fn neutral() -> Self {
        Self {
            category: ReputationTier::Neutral,
            threat_boost: 0,
            label: "Neutral / Unclassified".to_string(),
        }
    }

    /// Returns `true` if the tier is `BogonOrReserved`.
    pub fn is_bogon(&self) -> bool {
        self.category == ReputationTier::BogonOrReserved
    }

    /// Returns `true` if the tier is `KnownScanner`.
    pub fn is_scanner(&self) -> bool {
        self.category == ReputationTier::KnownScanner
    }

    /// Returns `true` if the tier is `MaliciousHosting`.
    pub fn is_malicious(&self) -> bool {
        self.category == ReputationTier::MaliciousHosting
    }

    /// Returns `true` if the tier is `Neutral`.
    pub fn is_neutral(&self) -> bool {
        self.category == ReputationTier::Neutral
    }
}

impl Default for ReputationRecord {
    fn default() -> Self {
        Self::neutral()
    }
}

/// Internal compiled CIDR rule for IPv4.
#[derive(Debug, Clone)]
struct V4Rule {
    prefix: u32,
    mask: u32,
    prefix_len: u8,
    record: ReputationRecord,
}

/// Internal compiled CIDR rule for IPv6.
#[derive(Debug, Clone)]
struct V6Rule {
    prefix: u128,
    mask: u128,
    prefix_len: u8,
    record: ReputationRecord,
}

/// Calculates bitwise mask for an IPv4 prefix length without overflowing.
fn ipv4_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else if prefix_len >= 32 {
        u32::MAX
    } else {
        !((1u32 << (32 - prefix_len)) - 1)
    }
}

/// Calculates bitwise mask for an IPv6 prefix length without overflowing.
fn ipv6_mask(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else if prefix_len >= 128 {
        u128::MAX
    } else {
        !((1u128 << (128 - prefix_len)) - 1)
    }
}

/// Priority value for tie-breaking identical prefix lengths.
fn tier_priority(tier: ReputationTier) -> u8 {
    match tier {
        ReputationTier::MaliciousHosting => 3,
        ReputationTier::KnownScanner => 2,
        ReputationTier::BogonOrReserved => 1,
        ReputationTier::Neutral => 0,
    }
}

/// Robust IP parser supporting plain IPs, bracketed IPs, and socket addresses with ports.
fn parse_ip_str(raw: &str) -> Option<IpAddr> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }

    // Direct IP parse
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(ip);
    }

    // Socket address parse (e.g. 192.168.1.1:8080 or [::1]:8080)
    if let Ok(sock) = s.parse::<std::net::SocketAddr>() {
        return Some(sock.ip());
    }

    // Handle bracketed IPv6 without port: [2001:db8::1]
    if s.starts_with('[') && s.ends_with(']') {
        if let Ok(ip) = s[1..s.len() - 1].parse::<IpAddr>() {
            return Some(ip);
        }
    }

    // Handle IPv4 with port: 192.168.1.1:80 (single colon)
    if let Some((host, _port)) = s.split_once(':') {
        if !host.contains(':') {
            if let Ok(ip) = host.parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }

    None
}

/// Zero-dependency offline IP reputation engine.
#[derive(Debug, Clone)]
pub struct IpReputationEngine {
    v4_rules: Vec<V4Rule>,
    v6_rules: Vec<V6Rule>,
}

impl IpReputationEngine {
    /// Creates and initializes an IP reputation engine pre-seeded with:
    /// - RFC 5735 / 6598 / 1918 Bogons & Reserved subnets
    /// - Known Internet scanners (Censys, Shodan, Shadowserver, Project Sonar)
    /// - Bulletproof hosting CIDRs
    pub fn new() -> Self {
        let mut engine = Self {
            v4_rules: Vec::new(),
            v6_rules: Vec::new(),
        };

        engine.seed_bogons();
        engine.seed_scanners();
        engine.seed_bulletproof_hosting();

        engine.sort_rules();
        engine
    }

    /// Sorts rules for Longest Prefix Match (LPM) and tier priority.
    fn sort_rules(&mut self) {
        self.v4_rules.sort_by(|a, b| {
            b.prefix_len
                .cmp(&a.prefix_len)
                .then_with(|| tier_priority(b.record.category).cmp(&tier_priority(a.record.category)))
        });
        self.v6_rules.sort_by(|a, b| {
            b.prefix_len
                .cmp(&a.prefix_len)
                .then_with(|| tier_priority(b.record.category).cmp(&tier_priority(a.record.category)))
        });
    }

    /// Registers a CIDR prefix rule.
    pub fn add_rule(
        &mut self,
        cidr: &str,
        category: ReputationTier,
        threat_boost: u8,
        label: impl Into<String>,
    ) -> Result<(), String> {
        let trimmed = cidr.trim();
        let (ip_str, prefix_len_opt) = match trimmed.split_once('/') {
            Some((ip, len)) => {
                let plen = len
                    .trim()
                    .parse::<u8>()
                    .map_err(|e| format!("Invalid CIDR prefix length in '{}': {}", cidr, e))?;
                (ip.trim(), Some(plen))
            }
            None => (trimmed, None),
        };

        let ip = ip_str
            .parse::<IpAddr>()
            .map_err(|e| format!("Invalid IP address '{}': {}", ip_str, e))?;

        let label = label.into();
        let record = ReputationRecord {
            category,
            threat_boost,
            label,
        };

        match ip {
            IpAddr::V4(v4) => {
                let prefix_len = prefix_len_opt.unwrap_or(32);
                if prefix_len > 32 {
                    return Err(format!("IPv4 prefix length {} exceeds 32", prefix_len));
                }
                let mask = ipv4_mask(prefix_len);
                let prefix = u32::from(v4) & mask;
                self.v4_rules.push(V4Rule {
                    prefix,
                    mask,
                    prefix_len,
                    record,
                });
            }
            IpAddr::V6(v6) => {
                let prefix_len = prefix_len_opt.unwrap_or(128);
                if prefix_len > 128 {
                    return Err(format!("IPv6 prefix length {} exceeds 128", prefix_len));
                }
                let mask = ipv6_mask(prefix_len);
                let prefix = u128::from(v6) & mask;
                self.v6_rules.push(V6Rule {
                    prefix,
                    mask,
                    prefix_len,
                    record,
                });
            }
        }

        self.sort_rules();
        Ok(())
    }

    /// Helper to register a list of CIDR entries.
    fn register_batch(&mut self, entries: &[(&str, ReputationTier, u8, &str)]) {
        for &(cidr, category, threat_boost, label) in entries {
            if let Err(e) = self.add_rule(cidr, category, threat_boost, label) {
                eprintln!("[IpReputationEngine] Failed to seed CIDR {}: {}", cidr, e);
            }
        }
    }

    /// Pre-seeds Bogons (RFC 5735 / 6598 / 1918 / 1122 / 3927 / 5771 / 1112).
    fn seed_bogons(&mut self) {
        let bogon_entries = [
            // Prompt required RFC 5735/6598 bogons:
            ("0.0.0.0/8", ReputationTier::BogonOrReserved, 25, "Bogon (RFC 1122 - Zero Network)"),
            ("100.64.0.0/10", ReputationTier::BogonOrReserved, 20, "Bogon / CGNAT (RFC 6598 - Shared Address Space)"),
            ("192.0.2.0/24", ReputationTier::BogonOrReserved, 25, "Bogon (RFC 5737 - TEST-NET-1)"),
            ("198.51.100.0/24", ReputationTier::BogonOrReserved, 25, "Bogon (RFC 5737 - TEST-NET-2)"),
            ("203.0.113.0/24", ReputationTier::BogonOrReserved, 25, "Bogon (RFC 5737 - TEST-NET-3)"),
            ("240.0.0.0/4", ReputationTier::BogonOrReserved, 30, "Bogon (RFC 1112 - Reserved for Future Use)"),

            // RFC 1918 Private Address Space:
            ("10.0.0.0/8", ReputationTier::BogonOrReserved, 20, "RFC 1918 Private Network (10.0.0.0/8)"),
            ("172.16.0.0/12", ReputationTier::BogonOrReserved, 20, "RFC 1918 Private Network (172.16.0.0/12)"),
            ("192.168.0.0/16", ReputationTier::BogonOrReserved, 20, "RFC 1918 Private Network (192.168.0.0/16)"),

            // Additional standard bogon and reserved prefixes:
            ("127.0.0.0/8", ReputationTier::BogonOrReserved, 20, "Reserved (RFC 1122 - Loopback)"),
            ("169.254.0.0/16", ReputationTier::BogonOrReserved, 20, "Reserved (RFC 3927 - Link-Local APIPA)"),
            ("192.0.0.0/24", ReputationTier::BogonOrReserved, 25, "Bogon (RFC 6890 - IETF Protocol Assignments)"),
            ("198.18.0.0/15", ReputationTier::BogonOrReserved, 25, "Bogon (RFC 2544 - Benchmark Testing)"),
            ("224.0.0.0/4", ReputationTier::BogonOrReserved, 25, "Reserved (RFC 5771 - Multicast)"),
            ("255.255.255.255/32", ReputationTier::BogonOrReserved, 30, "Reserved (RFC 919 - Limited Broadcast)"),

            // IPv6 Bogon and Reserved prefixes:
            ("::/128", ReputationTier::BogonOrReserved, 25, "Reserved IPv6 (Unspecified)"),
            ("::1/128", ReputationTier::BogonOrReserved, 20, "Reserved IPv6 (Loopback)"),
            ("::ffff:0:0/96", ReputationTier::BogonOrReserved, 20, "Reserved IPv6 (IPv4-mapped)"),
            ("100::/64", ReputationTier::BogonOrReserved, 25, "Bogon IPv6 (Discard Prefix RFC 6666)"),
            ("2001:db8::/32", ReputationTier::BogonOrReserved, 25, "Bogon IPv6 (Documentation RFC 3849)"),
            ("fe80::/10", ReputationTier::BogonOrReserved, 20, "Reserved IPv6 (Link-Local fe80::/10)"),
            ("fc00::/7", ReputationTier::BogonOrReserved, 20, "Reserved IPv6 (Unique Local fc00::/7)"),
            ("ff00::/8", ReputationTier::BogonOrReserved, 25, "Reserved IPv6 (Multicast ff00::/8)"),
        ];

        self.register_batch(&bogon_entries);
    }

    /// Pre-seeds known scanner subnets (Censys, Shodan, Shadowserver, Project Sonar, BinaryEdge, LeakIX).
    fn seed_scanners(&mut self) {
        let scanner_entries = [
            // Censys Enterprise Scanners
            ("162.142.125.0/24", ReputationTier::KnownScanner, 20, "Known Scanner (Censys Enterprise Scanner)"),
            ("167.94.138.0/24", ReputationTier::KnownScanner, 20, "Known Scanner (Censys Enterprise Scanner)"),
            ("167.94.145.0/24", ReputationTier::KnownScanner, 20, "Known Scanner (Censys Enterprise Scanner)"),
            ("167.94.146.0/24", ReputationTier::KnownScanner, 20, "Known Scanner (Censys Enterprise Scanner)"),
            ("167.248.133.0/24", ReputationTier::KnownScanner, 20, "Known Scanner (Censys Enterprise Scanner)"),
            ("192.35.168.0/23", ReputationTier::KnownScanner, 20, "Known Scanner (Censys Enterprise Scanner)"),
            ("206.168.32.0/24", ReputationTier::KnownScanner, 20, "Known Scanner (Censys Enterprise Scanner)"),
            ("206.168.34.0/24", ReputationTier::KnownScanner, 20, "Known Scanner (Censys Enterprise Scanner)"),
            ("74.120.14.0/24", ReputationTier::KnownScanner, 20, "Known Scanner (Censys Enterprise Scanner)"),

            // Shodan Search Engine Scanners
            ("198.20.69.0/24", ReputationTier::KnownScanner, 20, "Known Scanner (Shodan Search Engine)"),
            ("198.20.70.0/24", ReputationTier::KnownScanner, 20, "Known Scanner (Shodan Search Engine)"),
            ("198.20.87.0/24", ReputationTier::KnownScanner, 20, "Known Scanner (Shodan Search Engine)"),
            ("198.20.99.0/24", ReputationTier::KnownScanner, 20, "Known Scanner (Shodan Search Engine)"),
            ("208.180.20.0/24", ReputationTier::KnownScanner, 20, "Known Scanner (Shodan Search Engine)"),
            ("209.20.78.0/24", ReputationTier::KnownScanner, 20, "Known Scanner (Shodan Search Engine)"),
            ("216.117.2.180/32", ReputationTier::KnownScanner, 20, "Known Scanner (Shodan Search Engine)"),
            ("66.240.236.138/31", ReputationTier::KnownScanner, 20, "Known Scanner (Shodan Search Engine)"),
            ("66.240.192.138/32", ReputationTier::KnownScanner, 20, "Known Scanner (Shodan Search Engine)"),
            ("66.240.205.34/32", ReputationTier::KnownScanner, 20, "Known Scanner (Shodan Search Engine)"),
            ("71.6.135.131/32", ReputationTier::KnownScanner, 20, "Known Scanner (Shodan Search Engine)"),
            ("71.6.165.200/32", ReputationTier::KnownScanner, 20, "Known Scanner (Shodan Search Engine)"),
            ("71.6.167.142/32", ReputationTier::KnownScanner, 20, "Known Scanner (Shodan Search Engine)"),
            ("82.221.105.0/24", ReputationTier::KnownScanner, 20, "Known Scanner (Shodan Search Engine)"),
            ("85.25.103.50/32", ReputationTier::KnownScanner, 20, "Known Scanner (Shodan Search Engine)"),
            ("85.25.43.94/32", ReputationTier::KnownScanner, 20, "Known Scanner (Shodan Search Engine)"),
            ("93.120.27.62/32", ReputationTier::KnownScanner, 20, "Known Scanner (Shodan Search Engine)"),
            ("185.180.143.0/24", ReputationTier::KnownScanner, 20, "Known Scanner (Shodan Search Engine)"),
            ("155.138.132.0/24", ReputationTier::KnownScanner, 20, "Known Scanner (Shodan Search Engine)"),
            ("104.131.0.69/32", ReputationTier::KnownScanner, 20, "Known Scanner (Shodan Search Engine)"),

            // Shadowserver Foundation Scanners
            ("184.105.139.64/26", ReputationTier::KnownScanner, 20, "Known Scanner (Shadowserver Foundation)"),
            ("184.105.247.192/26", ReputationTier::KnownScanner, 20, "Known Scanner (Shadowserver Foundation)"),
            ("216.218.206.64/26", ReputationTier::KnownScanner, 20, "Known Scanner (Shadowserver Foundation)"),
            ("64.88.165.0/24", ReputationTier::KnownScanner, 20, "Known Scanner (Shadowserver Foundation)"),
            ("64.125.239.0/24", ReputationTier::KnownScanner, 20, "Known Scanner (Shadowserver Foundation)"),
            ("65.49.20.0/24", ReputationTier::KnownScanner, 20, "Known Scanner (Shadowserver Foundation)"),
            ("66.154.102.0/24", ReputationTier::KnownScanner, 20, "Known Scanner (Shadowserver Foundation)"),

            // Project Sonar / Rapid7 Scanners
            ("71.6.216.224/27", ReputationTier::KnownScanner, 20, "Known Scanner (Project Sonar / Rapid7)"),
            ("71.6.202.192/27", ReputationTier::KnownScanner, 20, "Known Scanner (Project Sonar / Rapid7)"),
            ("71.6.146.160/27", ReputationTier::KnownScanner, 20, "Known Scanner (Project Sonar / Rapid7)"),
            ("146.20.161.0/24", ReputationTier::KnownScanner, 20, "Known Scanner (Project Sonar / Rapid7)"),
            ("192.184.93.0/24", ReputationTier::KnownScanner, 20, "Known Scanner (Project Sonar / Rapid7)"),
            ("192.184.94.0/24", ReputationTier::KnownScanner, 20, "Known Scanner (Project Sonar / Rapid7)"),
            ("208.118.227.0/24", ReputationTier::KnownScanner, 20, "Known Scanner (Project Sonar / Rapid7)"),

            // Additional widely observed security research scanners
            ("65.154.226.0/24", ReputationTier::KnownScanner, 20, "Known Scanner (BinaryEdge)"),
            ("65.154.227.0/24", ReputationTier::KnownScanner, 20, "Known Scanner (BinaryEdge)"),
            ("185.178.208.0/24", ReputationTier::KnownScanner, 20, "Known Scanner (LeakIX)"),
        ];

        self.register_batch(&scanner_entries);
    }

    /// Pre-seeds bulletproof hosting and malicious infrastructure prefixes.
    fn seed_bulletproof_hosting(&mut self) {
        let malicious_entries = [
            ("179.43.128.0/18", ReputationTier::MaliciousHosting, 45, "Malicious / Bulletproof Hosting (PrivatLayer)"),
            ("185.220.101.0/24", ReputationTier::MaliciousHosting, 40, "Malicious Hosting / Tor Exit (Zwiebelfreunde)"),
            ("185.220.102.0/24", ReputationTier::MaliciousHosting, 40, "Malicious Hosting / Tor Exit"),
            ("194.26.29.0/24", ReputationTier::MaliciousHosting, 45, "Malicious / Bulletproof Hosting (Badbox / Dancom)"),
            ("194.135.25.0/24", ReputationTier::MaliciousHosting, 40, "Malicious / Bulletproof Hosting (FlyHosting)"),
            ("45.154.255.0/24", ReputationTier::MaliciousHosting, 45, "Malicious / C2 Hosting (Stark Industries)"),
            ("45.146.164.0/24", ReputationTier::MaliciousHosting, 40, "Malicious / Bulletproof Hosting (MaxiDed / Alexhost)"),
            ("45.153.160.0/24", ReputationTier::MaliciousHosting, 45, "Malicious / Bulletproof Hosting (Yalishanda / Chang Way)"),
            ("193.142.146.0/24", ReputationTier::MaliciousHosting, 40, "Malicious / Bulletproof Hosting (Quasi Networks)"),
            ("185.176.27.0/24", ReputationTier::MaliciousHosting, 40, "Malicious Hosting (Flowspec / Mirai C2)"),
            ("194.38.20.0/24", ReputationTier::MaliciousHosting, 40, "Malicious / Bulletproof Hosting (Hostkey)"),
            ("91.240.118.0/24", ReputationTier::MaliciousHosting, 45, "Malicious / Bulletproof Hosting (CyberBunker)"),
            ("193.36.119.0/24", ReputationTier::MaliciousHosting, 40, "Malicious Infrastructure (VDSina)"),
            ("193.106.191.0/24", ReputationTier::MaliciousHosting, 40, "Malicious Infrastructure (MivoCloud)"),
            ("185.156.73.0/24", ReputationTier::MaliciousHosting, 40, "Malicious Infrastructure (Biterika)"),
            ("45.134.144.0/24", ReputationTier::MaliciousHosting, 40, "Malicious Hosting (Chunghwa Bulletproof)"),
            ("185.193.88.0/24", ReputationTier::MaliciousHosting, 40, "Malicious / Bulletproof Hosting (Alpha Rax)"),
            ("194.169.175.0/24", ReputationTier::MaliciousHosting, 40, "Malicious / Bulletproof Hosting (Trabia)"),
            ("195.123.245.0/24", ReputationTier::MaliciousHosting, 40, "Malicious / Bulletproof Hosting (PQ Hosting)"),
            ("195.178.120.0/24", ReputationTier::MaliciousHosting, 40, "Malicious / Bulletproof Hosting (Inferno Solutions)"),
        ];

        self.register_batch(&malicious_entries);
    }

    /// Looks up an IP address in the local offline database using Longest Prefix Match (LPM).
    ///
    /// Accepts raw IPv4/IPv6 strings, bracketed IPv6 strings, or socket addresses (`IP:Port`).
    /// Returns a `ReputationRecord` indicating the tier, threat boost, and label.
    pub fn lookup(&self, ip: &str) -> ReputationRecord {
        let addr = match parse_ip_str(ip) {
            Some(a) => a,
            None => return ReputationRecord::neutral(),
        };

        match addr {
            IpAddr::V4(v4) => {
                let target = u32::from(v4);
                for rule in &self.v4_rules {
                    if (target & rule.mask) == rule.prefix {
                        return rule.record.clone();
                    }
                }
            }
            IpAddr::V6(v6) => {
                let target = u128::from(v6);
                for rule in &self.v6_rules {
                    if (target & rule.mask) == rule.prefix {
                        return rule.record.clone();
                    }
                }
            }
        }

        ReputationRecord::neutral()
    }

    /// Computes the signed threat score adjustment for an IP address.
    ///
    /// For clean or unclassified IPs, returns `0`.
    /// For bogons, known scanners, or malicious bulletproof hosts, returns
    /// a positive threat boost (e.g. `+20` for scanners, `+40` for bulletproof hosting).
    pub fn score_adjustment(&self, ip: &str) -> i16 {
        self.lookup(ip).threat_boost as i16
    }
}

impl Default for IpReputationEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bogon_classification() {
        let engine = IpReputationEngine::new();
        // RFC 5735 / 6598 specified in requirements:
        // 0.0.0.0/8, 100.64.0.0/10, 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 240.0.0.0/4
        let bogons = [
            ("0.0.0.1", "0.0.0.0/8"),
            ("0.255.255.255", "0.0.0.0/8"),
            ("100.64.0.1", "100.64.0.0/10"),
            ("100.127.255.254", "100.64.0.0/10"),
            ("192.0.2.1", "192.0.2.0/24"),
            ("198.51.100.42", "198.51.100.0/24"),
            ("203.0.113.199", "203.0.113.0/24"),
            ("240.0.0.1", "240.0.0.0/4"),
            ("250.1.2.3", "240.0.0.0/4"),
            ("127.0.0.1", "127.0.0.0/8"),
            ("169.254.1.1", "169.254.0.0/16"),
            ("224.0.0.1", "224.0.0.0/4"),
            ("255.255.255.255", "255.255.255.255/32"),
        ];

        for (ip, subnet_desc) in bogons {
            let record = engine.lookup(ip);
            assert_eq!(
                record.category,
                ReputationTier::BogonOrReserved,
                "IP {} in subnet {} must be BogonOrReserved",
                ip,
                subnet_desc
            );
            assert!(record.is_bogon());
            assert!(record.threat_boost > 0);
            assert!(engine.score_adjustment(ip) > 0);
        }
    }

    #[test]
    fn test_scanner_lookup() {
        let engine = IpReputationEngine::new();
        // Censys, Shodan, Shadowserver, Project Sonar
        let scanners = [
            ("162.142.125.1", "Censys"),
            ("167.94.138.45", "Censys"),
            ("167.248.133.20", "Censys"),
            ("198.20.69.1", "Shodan"),
            ("198.20.70.10", "Shodan"),
            ("208.180.20.5", "Shodan"),
            ("71.6.135.131", "Shodan"),
            ("184.105.139.70", "Shadowserver"),
            ("184.105.247.200", "Shadowserver"),
            ("64.88.165.10", "Shadowserver"),
            ("71.6.216.225", "Project Sonar"),
            ("146.20.161.50", "Project Sonar"),
            ("192.184.93.10", "Project Sonar"),
            ("65.154.226.1", "BinaryEdge"),
            ("185.178.208.5", "LeakIX"),
        ];

        for (ip, expected_label_substr) in scanners {
            let record = engine.lookup(ip);
            assert_eq!(
                record.category,
                ReputationTier::KnownScanner,
                "IP {} must be categorized as KnownScanner",
                ip
            );
            assert!(record.is_scanner());
            assert!(record.threat_boost >= 20);
            assert!(
                record.label.contains(expected_label_substr),
                "Label '{}' for IP {} should contain '{}'",
                record.label,
                ip,
                expected_label_substr
            );
            assert_eq!(engine.score_adjustment(ip), record.threat_boost as i16);
        }
    }

    #[test]
    fn test_clean_public_ip() {
        let engine = IpReputationEngine::new();
        let clean_ips = [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "142.250.190.46",
            "151.101.1.69",
        ];

        for ip in clean_ips {
            let record = engine.lookup(ip);
            assert_eq!(
                record.category,
                ReputationTier::Neutral,
                "IP {} should be Neutral",
                ip
            );
            assert!(record.is_neutral());
            assert_eq!(record.threat_boost, 0);
            assert_eq!(engine.score_adjustment(ip), 0);
        }
    }

    #[test]
    fn test_rfc1918_private_ip() {
        let engine = IpReputationEngine::new();
        // RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        let rfc1918_ips = [
            ("10.0.0.1", "10.0.0.0/8"),
            ("10.254.1.1", "10.0.0.0/8"),
            ("172.16.0.1", "172.16.0.0/12"),
            ("172.24.10.5", "172.16.0.0/12"),
            ("172.31.255.254", "172.16.0.0/12"),
            ("192.168.0.1", "192.168.0.0/16"),
            ("192.168.1.254", "192.168.0.0/16"),
            ("192.168.100.50", "192.168.0.0/16"),
        ];

        for (ip, subnet_desc) in rfc1918_ips {
            let record = engine.lookup(ip);
            assert_eq!(
                record.category,
                ReputationTier::BogonOrReserved,
                "RFC1918 IP {} in {} must be BogonOrReserved",
                ip,
                subnet_desc
            );
            assert!(record.is_bogon());
            assert!(record.threat_boost > 0);
            assert!(record.label.contains("RFC 1918"));
            assert_eq!(engine.score_adjustment(ip), record.threat_boost as i16);
        }
    }

    #[test]
    fn test_bulletproof_malicious_hosting() {
        let engine = IpReputationEngine::new();
        let malicious_ips = [
            "179.43.128.5",
            "185.220.101.99",
            "194.26.29.10",
            "45.154.255.12",
            "45.146.164.7",
            "91.240.118.3",
        ];

        for ip in malicious_ips {
            let record = engine.lookup(ip);
            assert_eq!(
                record.category,
                ReputationTier::MaliciousHosting,
                "IP {} should be MaliciousHosting",
                ip
            );
            assert!(record.is_malicious());
            assert!(record.threat_boost >= 40);
            assert!(engine.score_adjustment(ip) >= 40);
        }
    }

    #[test]
    fn test_ipv6_classification() {
        let engine = IpReputationEngine::new();
        // IPv6 Bogons & Reserved
        assert_eq!(engine.lookup("::1").category, ReputationTier::BogonOrReserved);
        assert_eq!(engine.lookup("fe80::1").category, ReputationTier::BogonOrReserved);
        assert_eq!(engine.lookup("fc00::1").category, ReputationTier::BogonOrReserved);
        assert_eq!(engine.lookup("2001:db8::1234").category, ReputationTier::BogonOrReserved);

        // Public IPv6 Clean
        let clean_v6 = engine.lookup("2606:4700:4700::1111");
        assert_eq!(clean_v6.category, ReputationTier::Neutral);
        assert_eq!(clean_v6.threat_boost, 0);
    }

    #[test]
    fn test_socket_address_and_invalid_inputs() {
        let engine = IpReputationEngine::new();

        // Socket addresses with ports
        let censys_sock = engine.lookup("162.142.125.1:443");
        assert_eq!(censys_sock.category, ReputationTier::KnownScanner);

        let rfc1918_sock = engine.lookup("192.168.1.1:8080");
        assert_eq!(rfc1918_sock.category, ReputationTier::BogonOrReserved);

        let v6_bracketed = engine.lookup("[::1]:80");
        assert_eq!(v6_bracketed.category, ReputationTier::BogonOrReserved);

        // Invalid inputs
        let empty = engine.lookup("");
        assert_eq!(empty.category, ReputationTier::Neutral);
        assert_eq!(engine.score_adjustment(""), 0);

        let invalid = engine.lookup("not-an-ip-address");
        assert_eq!(invalid.category, ReputationTier::Neutral);
        assert_eq!(engine.score_adjustment("not-an-ip-address"), 0);
    }

    #[test]
    fn test_custom_rule_and_lpm() {
        let mut engine = IpReputationEngine::new();

        // Specific /32 rule inside a /24
        // 192.0.2.0/24 is pre-seeded as Bogon
        // Let's add a specific /32 override
        let res = engine.add_rule(
            "192.0.2.99/32",
            ReputationTier::MaliciousHosting,
            90,
            "Specific Malicious Override",
        );
        assert!(res.is_ok());

        // Generic /24 returns Bogon
        let generic = engine.lookup("192.0.2.1");
        assert_eq!(generic.category, ReputationTier::BogonOrReserved);

        // Specific /32 matches MaliciousHosting due to LPM
        let specific = engine.lookup("192.0.2.99");
        assert_eq!(specific.category, ReputationTier::MaliciousHosting);
        assert_eq!(specific.threat_boost, 90);
        assert_eq!(specific.label, "Specific Malicious Override");
    }
}

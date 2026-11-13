//! MITRE ATT&CK 5-Stage Progression Tracker & TUI Kill Chain Visualizer.
//!
//! Tracks attacker progression across the five MITRE ATT&CK stages:
//! 1. Reconnaissance (T1595, T1046, SWEEP)
//! 2. InitialAccess (T1078, T1110, Brute Force)
//! 3. Execution (T1059, Web Probes)
//! 4. Persistence (T1136, Backdoor)
//! 5. Exfiltration (T1095, DNS/ICMP Tunnel)

#![allow(dead_code)]

use std::collections::HashMap;

/// Five core stages of attacker progression mapped to MITRE ATT&CK tactics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KillChainStage {
    Reconnaissance = 0,
    InitialAccess = 1,
    Execution = 2,
    Persistence = 3,
    Exfiltration = 4,
}

impl KillChainStage {
    pub const ALL: [KillChainStage; 5] = [
        KillChainStage::Reconnaissance,
        KillChainStage::InitialAccess,
        KillChainStage::Execution,
        KillChainStage::Persistence,
        KillChainStage::Exfiltration,
    ];

    #[inline]
    pub const fn index(self) -> usize {
        self as usize
    }

    #[allow(dead_code)]
    pub const fn name(self) -> &'static str {
        match self {
            KillChainStage::Reconnaissance => "Reconnaissance",
            KillChainStage::InitialAccess => "InitialAccess",
            KillChainStage::Execution => "Execution",
            KillChainStage::Persistence => "Persistence",
            KillChainStage::Exfiltration => "Exfiltration",
        }
    }

    pub const fn short_label(self) -> &'static str {
        match self {
            KillChainStage::Reconnaissance => "RECON",
            KillChainStage::InitialAccess => "ACCESS",
            KillChainStage::Execution => "EXEC",
            KillChainStage::Persistence => "PERSIST",
            KillChainStage::Exfiltration => "EXFIL",
        }
    }
}

/// Matches MITRE ATT&CK IDs, tactic names, or incident keywords to a kill chain stage.
pub fn match_stage(mitre_id: &str) -> Option<KillChainStage> {
    let s = mitre_id.trim().to_uppercase();
    if s.is_empty() {
        return None;
    }

    // Stage 0: Reconnaissance (T1595, T1046, SWEEP)
    if s.contains("T1595")
        || s.contains("T1046")
        || s.contains("SWEEP")
        || s.contains("RECON")
        || s.contains("SCAN")
    {
        return Some(KillChainStage::Reconnaissance);
    }

    // Stage 1: InitialAccess (T1078, T1110, Brute Force)
    if s.contains("T1078")
        || s.contains("T1110")
        || s.contains("BRUTE")
        || s.contains("ACCESS")
        || s.contains("CREDENTIAL")
    {
        return Some(KillChainStage::InitialAccess);
    }

    // Stage 2: Execution (T1059, Web Probes)
    if s.contains("T1059")
        || s.contains("T1190")
        || s.contains("WEB PROBE")
        || s.contains("WEB PROBES")
        || s.contains("WEB_PROBE")
        || s.contains("WEBPROBE")
        || s.contains("EXECUTION")
        || s.contains("EXEC")
    {
        return Some(KillChainStage::Execution);
    }

    // Stage 3: Persistence (T1136, Backdoor)
    if s.contains("T1136")
        || s.contains("BACKDOOR")
        || s.contains("PERSIST")
    {
        return Some(KillChainStage::Persistence);
    }

    // Stage 4: Exfiltration (T1095, DNS/ICMP Tunnel)
    if s.contains("T1095")
        || s.contains("T1071.004")
        || s.contains("T1048")
        || s.contains("T1041")
        || s.contains("TUNNEL")
        || s.contains("EXFIL")
    {
        return Some(KillChainStage::Exfiltration);
    }

    None
}

/// Detailed per-stage metadata for an attacker IP.
#[derive(Debug, Clone, Default)]
pub struct StageMetadata {
    pub count: usize,
    pub last_mitre_id: String,
    pub severity: String,
}

/// Attack progression tracked for a specific IP.
#[derive(Debug, Clone, Default)]
pub struct IpProgression {
    pub stages: [bool; 5],
    pub metadata: [Option<StageMetadata>; 5],
    pub total_events: usize,
    pub highest_severity: String,
}

/// MITRE ATT&CK Kill Chain progression tracker and visualizer.
#[derive(Debug, Clone, Default)]
pub struct KillChainTracker {
    progression: HashMap<String, IpProgression>,
}

impl KillChainTracker {
    /// Creates a new, empty `KillChainTracker`.
    pub fn new() -> Self {
        Self {
            progression: HashMap::new(),
        }
    }

    /// Records an observed attacker incident with MITRE ID and severity.
    pub fn record(&mut self, ip: &str, mitre_id: &str, severity: &str) {
        let ip_clean = ip.trim();
        if ip_clean.is_empty() {
            return;
        }

        if let Some(stage) = match_stage(mitre_id) {
            let entry = self.progression.entry(ip_clean.to_string()).or_default();
            let idx = stage.index();
            entry.stages[idx] = true;
            entry.total_events += 1;

            let meta = entry.metadata[idx].get_or_insert_with(Default::default);
            meta.count += 1;
            meta.last_mitre_id = mitre_id.trim().to_string();
            meta.severity = severity.trim().to_string();

            if is_higher_severity(severity, &entry.highest_severity) {
                entry.highest_severity = severity.trim().to_string();
            }
        }
    }

    /// Returns boolean status array `[Recon, Access, Exec, Persist, Exfil]` for the given IP.
    pub fn get_stages(&self, ip: &str) -> [bool; 5] {
        self.progression
            .get(ip.trim())
            .map(|p| p.stages)
            .unwrap_or([false; 5])
    }

    /// Renders an ASCII/Unicode progress bar showing active and inactive stages.
    ///
    /// Active stages are highlighted with ANSI color formatting, while inactive
    /// stages are rendered in dimmed gray formatting.
    /// Example: `[RECON] -> [ACCESS] -> [EXEC] -> [PERSIST] -> [EXFIL]`
    pub fn render_progress_bar(&self, ip: &str) -> String {
        let stages = self.get_stages(ip);
        let mut segments = Vec::with_capacity(5);

        for (idx, stage) in KillChainStage::ALL.iter().enumerate() {
            let is_active = stages[idx];
            let label = stage.short_label();

            let stage_box = if is_active {
                // Colored active stage
                let ansi_color = match stage {
                    KillChainStage::Reconnaissance => "\x1b[1;36m", // Bright Cyan
                    KillChainStage::InitialAccess => "\x1b[1;33m",  // Bright Yellow
                    KillChainStage::Execution => "\x1b[1;35m",      // Bright Magenta
                    KillChainStage::Persistence => "\x1b[1;91m",    // Light Red
                    KillChainStage::Exfiltration => "\x1b[1;31m",   // Bold Red
                };
                format!("{}[{}]\x1b[0m", ansi_color, label)
            } else {
                // Dimmed inactive stage
                format!("\x1b[90m[{}]\x1b[0m", label)
            };

            segments.push(stage_box);
        }

        segments.join(" -> ")
    }

    /// Renders a plain ASCII progress bar without ANSI escape codes.
    #[allow(dead_code)]
    pub fn render_progress_bar_plain(&self, ip: &str) -> String {
        let stages = self.get_stages(ip);
        let segments: Vec<String> = KillChainStage::ALL
            .iter()
            .enumerate()
            .map(|(idx, stage)| {
                if stages[idx] {
                    format!("[*{}]", stage.short_label())
                } else {
                    format!("[{}]", stage.short_label())
                }
            })
            .collect();
        segments.join(" -> ")
    }

    /// Returns the number of completed stages for an IP (0 to 5).
    #[allow(dead_code)]
    pub fn active_stage_count(&self, ip: &str) -> usize {
        self.get_stages(ip).iter().filter(|&&active| active).count()
    }

    /// Returns `true` if all 5 kill chain stages have been reached by this attacker.
    #[allow(dead_code)]
    pub fn is_killchain_complete(&self, ip: &str) -> bool {
        self.get_stages(ip).iter().all(|&active| active)
    }

    /// Returns the highest stage reached by this attacker, if any.
    #[allow(dead_code)]
    pub fn highest_stage(&self, ip: &str) -> Option<KillChainStage> {
        let stages = self.get_stages(ip);
        KillChainStage::ALL
            .into_iter()
            .rev()
            .find(|stage| stages[stage.index()])
    }

    /// Returns all tracked IP addresses.
    #[allow(dead_code)]
    pub fn tracked_ips(&self) -> Vec<String> {
        self.progression.keys().cloned().collect()
    }

    /// Clears all tracked kill chain records.
    #[allow(dead_code)]
    pub fn clear(&mut self) {
        self.progression.clear();
    }
}

/// Compares severity levels (CRITICAL > HIGH > MEDIUM/WARNING > LOW > INFO).
fn is_higher_severity(new_sev: &str, current_sev: &str) -> bool {
    severity_rank(new_sev) > severity_rank(current_sev)
}

fn severity_rank(sev: &str) -> u8 {
    match sev.trim().to_uppercase().as_str() {
        "CRITICAL" => 5,
        "HIGH" => 4,
        "MEDIUM" | "WARN" | "WARNING" => 3,
        "LOW" => 2,
        "INFO" => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_killchain_empty_ip() {
        let mut tracker = KillChainTracker::new();

        // Querying empty IP or non-existent IP returns all false
        assert_eq!(tracker.get_stages(""), [false; 5]);
        assert_eq!(tracker.get_stages("192.168.1.1"), [false; 5]);
        assert_eq!(tracker.active_stage_count(""), 0);
        assert_eq!(tracker.highest_stage(""), None);
        assert!(!tracker.is_killchain_complete(""));

        // Recording empty IP does nothing
        tracker.record("", "T1595", "LOW");
        tracker.record("   ", "SWEEP", "LOW");
        assert_eq!(tracker.get_stages(""), [false; 5]);
        assert!(tracker.tracked_ips().is_empty());

        // Rendering progress bar for empty or untracked IP produces valid format with all inactive
        let bar = tracker.render_progress_bar("");
        assert!(bar.contains("[RECON]"));
        assert!(bar.contains("[ACCESS]"));
        assert!(bar.contains("[EXEC]"));
        assert!(bar.contains("[PERSIST]"));
        assert!(bar.contains("[EXFIL]"));
        assert!(bar.contains(" -> "));
    }

    #[test]
    fn test_killchain_single_stage() {
        let mut tracker = KillChainTracker::new();

        // Stage 0: Reconnaissance
        tracker.record("10.0.0.1", "T1595", "LOW");
        assert_eq!(tracker.get_stages("10.0.0.1"), [true, false, false, false, false]);
        assert_eq!(tracker.active_stage_count("10.0.0.1"), 1);
        assert_eq!(tracker.highest_stage("10.0.0.1"), Some(KillChainStage::Reconnaissance));

        // Alternate Stage 0 keyword: SWEEP and T1046
        tracker.record("10.0.0.10", "SWEEP", "LOW");
        assert_eq!(tracker.get_stages("10.0.0.10"), [true, false, false, false, false]);
        tracker.record("10.0.0.11", "T1046", "LOW");
        assert_eq!(tracker.get_stages("10.0.0.11"), [true, false, false, false, false]);

        // Stage 1: InitialAccess
        tracker.record("10.0.0.2", "T1078", "MEDIUM");
        assert_eq!(tracker.get_stages("10.0.0.2"), [false, true, false, false, false]);
        tracker.record("10.0.0.20", "Brute Force", "MEDIUM");
        assert_eq!(tracker.get_stages("10.0.0.20"), [false, true, false, false, false]);
        tracker.record("10.0.0.21", "T1110", "HIGH");
        assert_eq!(tracker.get_stages("10.0.0.21"), [false, true, false, false, false]);

        // Stage 2: Execution
        tracker.record("10.0.0.3", "T1059", "HIGH");
        assert_eq!(tracker.get_stages("10.0.0.3"), [false, false, true, false, false]);
        tracker.record("10.0.0.30", "Web Probes", "HIGH");
        assert_eq!(tracker.get_stages("10.0.0.30"), [false, false, true, false, false]);

        // Stage 3: Persistence
        tracker.record("10.0.0.4", "T1136", "HIGH");
        assert_eq!(tracker.get_stages("10.0.0.4"), [false, false, false, true, false]);
        tracker.record("10.0.0.40", "Backdoor", "CRITICAL");
        assert_eq!(tracker.get_stages("10.0.0.40"), [false, false, false, true, false]);

        // Stage 4: Exfiltration
        tracker.record("10.0.0.5", "T1095", "CRITICAL");
        assert_eq!(tracker.get_stages("10.0.0.5"), [false, false, false, false, true]);
        tracker.record("10.0.0.50", "DNS/ICMP Tunnel", "CRITICAL");
        assert_eq!(tracker.get_stages("10.0.0.50"), [false, false, false, false, true]);
    }

    #[test]
    fn test_killchain_full_progression() {
        let mut tracker = KillChainTracker::new();
        let ip = "192.168.1.150";

        // Initial state
        assert_eq!(tracker.get_stages(ip), [false; 5]);
        assert!(!tracker.is_killchain_complete(ip));

        // Step 1: Reconnaissance
        tracker.record(ip, "T1595", "LOW");
        assert_eq!(tracker.get_stages(ip), [true, false, false, false, false]);
        assert_eq!(tracker.highest_stage(ip), Some(KillChainStage::Reconnaissance));

        // Step 2: InitialAccess
        tracker.record(ip, "T1110", "MEDIUM");
        assert_eq!(tracker.get_stages(ip), [true, true, false, false, false]);
        assert_eq!(tracker.highest_stage(ip), Some(KillChainStage::InitialAccess));

        // Step 3: Execution
        tracker.record(ip, "Web Probes", "HIGH");
        assert_eq!(tracker.get_stages(ip), [true, true, true, false, false]);
        assert_eq!(tracker.highest_stage(ip), Some(KillChainStage::Execution));

        // Step 4: Persistence
        tracker.record(ip, "Backdoor", "CRITICAL");
        assert_eq!(tracker.get_stages(ip), [true, true, true, true, false]);
        assert_eq!(tracker.highest_stage(ip), Some(KillChainStage::Persistence));

        // Step 5: Exfiltration
        tracker.record(ip, "DNS/ICMP Tunnel", "CRITICAL");
        assert_eq!(tracker.get_stages(ip), [true, true, true, true, true]);
        assert_eq!(tracker.highest_stage(ip), Some(KillChainStage::Exfiltration));

        // Kill chain is now complete
        assert!(tracker.is_killchain_complete(ip));
        assert_eq!(tracker.active_stage_count(ip), 5);
    }

    #[test]
    fn test_killchain_rendering_format() {
        let mut tracker = KillChainTracker::new();
        let empty_ip = "10.0.0.99";
        let partial_ip = "10.0.0.100";
        let full_ip = "10.0.0.101";

        tracker.record(partial_ip, "T1595", "LOW");
        tracker.record(partial_ip, "T1059", "HIGH");

        tracker.record(full_ip, "SWEEP", "LOW");
        tracker.record(full_ip, "Brute Force", "MEDIUM");
        tracker.record(full_ip, "Web Probes", "HIGH");
        tracker.record(full_ip, "Backdoor", "HIGH");
        tracker.record(full_ip, "T1095", "CRITICAL");

        let empty_bar = tracker.render_progress_bar(empty_ip);
        let partial_bar = tracker.render_progress_bar(partial_ip);
        let full_bar = tracker.render_progress_bar(full_ip);

        // All bars should have the standard stage labels and delimiters
        for bar in [&empty_bar, &partial_bar, &full_bar] {
            assert!(bar.contains("[RECON]"));
            assert!(bar.contains("[ACCESS]"));
            assert!(bar.contains("[EXEC]"));
            assert!(bar.contains("[PERSIST]"));
            assert!(bar.contains("[EXFIL]"));
            assert!(bar.contains(" -> "));
        }

        // Active stages have distinct ANSI escape codes compared to empty
        assert_ne!(empty_bar, partial_bar);
        assert_ne!(partial_bar, full_bar);
        assert_ne!(empty_bar, full_bar);

        // Plain text version check
        let plain = tracker.render_progress_bar_plain(full_ip);
        assert_eq!(
            plain,
            "[*RECON] -> [*ACCESS] -> [*EXEC] -> [*PERSIST] -> [*EXFIL]"
        );

        let empty_plain = tracker.render_progress_bar_plain(empty_ip);
        assert_eq!(
            empty_plain,
            "[RECON] -> [ACCESS] -> [EXEC] -> [PERSIST] -> [EXFIL]"
        );
    }

    #[test]
    fn test_killchain_unmatched_technique() {
        let mut tracker = KillChainTracker::new();
        tracker.record("10.0.0.1", "UNKNOWN_TECHNIQUE_9999", "LOW");
        assert_eq!(tracker.get_stages("10.0.0.1"), [false; 5]);
        assert_eq!(tracker.active_stage_count("10.0.0.1"), 0);
    }

    #[test]
    fn test_killchain_stage_names_and_clear() {
        assert_eq!(KillChainStage::Reconnaissance.name(), "Reconnaissance");
        assert_eq!(KillChainStage::InitialAccess.name(), "InitialAccess");
        assert_eq!(KillChainStage::Execution.name(), "Execution");
        assert_eq!(KillChainStage::Persistence.name(), "Persistence");
        assert_eq!(KillChainStage::Exfiltration.name(), "Exfiltration");

        let mut tracker = KillChainTracker::new();
        tracker.record("1.2.3.4", "T1595", "LOW");
        assert_eq!(tracker.tracked_ips().len(), 1);
        tracker.clear();
        assert!(tracker.tracked_ips().is_empty());
        assert_eq!(tracker.get_stages("1.2.3.4"), [false; 5]);
    }
}

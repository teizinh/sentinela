use serde::{Deserialize, Serialize};

/// Represents an authentication attempt captured by a honeypot decoy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturedCredential {
    pub ip: String,
    pub service: String,
    pub username: String,
    pub password: Option<String>,
    pub timestamp: String,
}

impl CapturedCredential {
    pub fn new(
        ip: impl Into<String>,
        service: impl Into<String>,
        username: impl Into<String>,
        password: Option<String>,
        timestamp: impl Into<String>,
    ) -> Self {
        Self {
            ip: ip.into(),
            service: service.into(),
            username: username.into(),
            password,
            timestamp: timestamp.into(),
        }
    }
}

/// In-memory storage for captured credentials with JSON export capabilities.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CredentialStore {
    credentials: Vec<CapturedCredential>,
}

impl CredentialStore {
    pub fn new() -> Self {
        Self {
            credentials: Vec::new(),
        }
    }

    pub fn record(&mut self, cred: CapturedCredential) {
        self.credentials.push(cred);
    }

    pub fn get_all(&self) -> &[CapturedCredential] {
        &self.credentials
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(&self.credentials).unwrap_or_else(|_| "[]".to_string())
    }
}

/// Decodes a standard or URL-safe base64 string without external dependencies.
fn decode_base64(input: &str) -> Option<Vec<u8>> {
    let mut output = Vec::with_capacity(input.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0;

    for &byte in input.as_bytes() {
        if byte.is_ascii_whitespace() {
            continue;
        }
        if byte == b'=' {
            break;
        }
        let val = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        };
        buffer = (buffer << 6) | (val as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(output)
}

/// Filters out Telnet IAC sequences and converts raw bytes into a UTF-8 string.
fn clean_payload(payload: &[u8]) -> String {
    let mut i = 0;
    let mut filtered = Vec::new();
    while i < payload.len() {
        if payload[i] == 0xFF {
            // Telnet IAC command sequence: IAC (0xFF), COMMAND, OPTION
            if i + 1 < payload.len() && payload[i + 1] >= 0xFA && payload[i + 1] <= 0xFE {
                i += 3;
                continue;
            } else if i + 1 < payload.len() && payload[i + 1] == 0xFF {
                filtered.push(0xFF);
                i += 2;
                continue;
            } else {
                i += 2;
                continue;
            }
        }
        filtered.push(payload[i]);
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

/// Searches for an HTTP Authorization: Basic <base64> header and extracts (username, Some(password)).
fn parse_http_basic_auth(text: &str) -> Option<(String, Option<String>)> {
    for line in text.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_ascii_lowercase();

        let b64_part = if let Some(idx) = lower.find("authorization:") {
            let rest = trimmed[idx + "authorization:".len()..].trim_start();
            if rest.to_ascii_lowercase().starts_with("basic ") {
                Some(rest[6..].trim())
            } else {
                None
            }
        } else if lower.starts_with("basic ") {
            Some(trimmed[6..].trim())
        } else {
            None
        };

        if let Some(b64) = b64_part {
            let token = b64.split_whitespace().next().unwrap_or(b64);
            if let Some(decoded_bytes) = decode_base64(token) {
                if let Ok(decoded_str) = String::from_utf8(decoded_bytes) {
                    if let Some(pos) = decoded_str.find(':') {
                        let (u, p) = decoded_str.split_at(pos);
                        return Some((u.to_string(), Some(p[1..].to_string())));
                    } else {
                        return Some((decoded_str, None));
                    }
                }
            }
        }
    }
    None
}

/// Extracts credentials from URL-encoded parameters (user=...&pass=...).
fn parse_key_value_params(text: &str) -> Option<(String, Option<String>)> {
    let mut username = None;
    let mut password = None;

    for line in text.lines() {
        let trimmed = line.trim();
        for chunk in trimmed.split(['&', ';', '?']) {
            let chunk = chunk.trim();
            if let Some((k, v)) = chunk.split_once('=') {
                let k_clean = k.trim().to_ascii_lowercase();
                let v_clean = percent_decode(v.trim());
                if !v_clean.is_empty() {
                    match k_clean.as_str() {
                        "user" | "username" | "login" | "u" | "usr" | "account" | "email"
                            if username.is_none() =>
                        {
                            username = Some(v_clean);
                        }
                        "pass" | "password" | "pwd" | "passwd" | "p"
                            if password.is_none() =>
                        {
                            password = Some(v_clean);
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    username.map(|u| (u, password))
}

/// Extracts credentials from JSON body payloads ({"username": "...", "password": "..."}).
fn parse_json_credentials(text: &str) -> Option<(String, Option<String>)> {
    if let Some(start) = text.find('{') {
        if let Some(end) = text.rfind('}') {
            if end > start {
                let json_slice = &text[start..=end];
                if let Ok(serde_json::Value::Object(map)) = serde_json::from_str(json_slice) {
                    let mut username = None;
                    let mut password = None;
                    for (k, v) in map {
                        let k_lower = k.to_ascii_lowercase();
                        if let Some(s) = v.as_str() {
                            match k_lower.as_str() {
                                "user" | "username" | "login" | "email"
                                    if username.is_none() =>
                                {
                                    username = Some(s.to_string());
                                }
                                "pass" | "password" | "pwd" if password.is_none() => {
                                    password = Some(s.to_string());
                                }
                                _ => {}
                            }
                        }
                    }
                    if let Some(u) = username {
                        return Some((u, password));
                    }
                }
            }
        }
    }
    None
}

/// Checks if a line is a generic username:password pair, filtering out HTTP headers.
fn parse_username_colon_password(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim();
    if let Some(pos) = trimmed.find(':') {
        let (user, pass) = trimmed.split_at(pos);
        let pass = pass[1..].trim();
        let user = user.trim();

        let user_lower = user.to_ascii_lowercase();
        const IGNORED_HEADERS: &[&str] = &[
            "host",
            "user-agent",
            "accept",
            "accept-language",
            "accept-encoding",
            "connection",
            "upgrade-insecure-requests",
            "content-type",
            "content-length",
            "referer",
            "origin",
            "cookie",
            "cache-control",
            "pragma",
            "date",
            "server",
            "authorization",
            "x-forwarded-for",
            "x-requested-with",
            "transfer-encoding",
            "sec-ch-ua",
            "sec-ch-ua-mobile",
            "sec-ch-ua-platform",
            "sec-fetch-dest",
            "sec-fetch-mode",
            "sec-fetch-site",
            "sec-fetch-user",
        ];

        if !user.is_empty()
            && !user.contains(' ')
            && !IGNORED_HEADERS.contains(&user_lower.as_str())
            && !user_lower.starts_with("http/")
            && !user_lower.starts_with("get")
            && !user_lower.starts_with("post")
            && !user_lower.starts_with("put")
            && !user_lower.starts_with("head")
            && !user_lower.starts_with("delete")
        {
            return Some((user.to_string(), pass.to_string()));
        }
    }
    None
}

/// Extracts credentials from Telnet dialogs (multiline lines or prompt prefixes).
fn parse_telnet(text: &str) -> Option<(String, Option<String>)> {
    let lines: Vec<&str> = text
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect();

    if lines.is_empty() {
        return None;
    }

    let strip_prompt = |s: &str, prompts: &[&str]| -> Option<String> {
        let lower = s.to_ascii_lowercase();
        for &p in prompts {
            if let Some(rest) = lower.strip_prefix(p) {
                let clean = s[s.len() - rest.len()..].trim();
                return Some(clean.to_string());
            }
        }
        None
    };

    let user_prompts = &["login:", "username:", "user:"];
    let pass_prompts = &["password:", "passwd:", "pass:"];

    // Check if line 0 has a login prompt prefix, e.g. "login: admin"
    if let Some(user) = strip_prompt(lines[0], user_prompts) {
        let password = if lines.len() > 1 {
            if let Some(p) = strip_prompt(lines[1], pass_prompts) {
                Some(p)
            } else {
                Some(lines[1].to_string())
            }
        } else {
            None
        };
        return Some((user, password));
    }

    // Check if line 0 is in username:password format
    if let Some((u, p)) = parse_username_colon_password(lines[0]) {
        return Some((u, Some(p)));
    }

    // Line 0 is raw username (e.g. "admin\r\n123456")
    let user = lines[0].to_string();
    let password = if lines.len() > 1 {
        if let Some(p) = strip_prompt(lines[1], pass_prompts) {
            Some(p)
        } else {
            Some(lines[1].to_string())
        }
    } else {
        None
    };

    Some((user, password))
}

/// Parses captured credentials from incoming honeypot payload according to the decoy service.
pub fn parse_credential_from_payload(
    service: &str,
    payload: &[u8],
) -> Option<(String, Option<String>)> {
    if payload.is_empty() {
        return None;
    }

    let text = clean_payload(payload);
    if text.trim().is_empty() {
        return None;
    }

    let service_lower = service.to_ascii_lowercase();

    // 1. HTTP decoys
    if service_lower.contains("http") {
        if let Some(cred) = parse_http_basic_auth(&text) {
            return Some(cred);
        }
        if let Some(cred) = parse_key_value_params(&text) {
            return Some(cred);
        }
        if let Some(cred) = parse_json_credentials(&text) {
            return Some(cred);
        }
        for line in text.lines() {
            if let Some((u, p)) = parse_username_colon_password(line) {
                return Some((u, Some(p)));
            }
        }
        return None;
    }

    // 2. Telnet decoys
    if service_lower.contains("telnet") {
        if let Some(cred) = parse_telnet(&text) {
            return Some(cred);
        }
        if let Some(cred) = parse_key_value_params(&text) {
            return Some(cred);
        }
        return None;
    }

    // 3. Generic / SSH / fallback
    if let Some(cred) = parse_http_basic_auth(&text) {
        return Some(cred);
    }
    if let Some(cred) = parse_key_value_params(&text) {
        return Some(cred);
    }
    if let Some(cred) = parse_json_credentials(&text) {
        return Some(cred);
    }
    if !text.starts_with("GET ") && !text.starts_with("POST ") && !text.starts_with("HEAD ") {
        for line in text.lines() {
            if let Some((u, p)) = parse_username_colon_password(line) {
                return Some((u, Some(p)));
            }
        }
        if let Some(cred) = parse_telnet(&text) {
            return Some(cred);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_http_basic_auth_credential() {
        let payload = b"GET /admin HTTP/1.1\r\nHost: router\r\nAuthorization: Basic YWRtaW46cGFzc3dvcmQxMjM=\r\n\r\n";
        let parsed = parse_credential_from_payload("HTTP", payload);
        assert_eq!(
            parsed,
            Some(("admin".to_string(), Some("password123".to_string())))
        );

        let raw_header = b"Authorization: Basic YWRtaW46cGFzc3dvcmQxMjM=";
        let parsed_raw = parse_credential_from_payload("HTTP", raw_header);
        assert_eq!(
            parsed_raw,
            Some(("admin".to_string(), Some("password123".to_string())))
        );
    }

    #[test]
    fn test_parse_telnet_text_credential() {
        let payload = b"admin\r\n123456\r\n";
        let parsed = parse_credential_from_payload("Telnet", payload);
        assert_eq!(
            parsed,
            Some(("admin".to_string(), Some("123456".to_string())))
        );

        let prompt_payload = b"login: admin\r\n";
        let parsed_prompt = parse_credential_from_payload("Telnet", prompt_payload);
        assert_eq!(parsed_prompt, Some(("admin".to_string(), None)));

        let full_dialog = b"login: admin\r\npassword: secret\r\n";
        let parsed_dialog = parse_credential_from_payload("Telnet", full_dialog);
        assert_eq!(
            parsed_dialog,
            Some(("admin".to_string(), Some("secret".to_string())))
        );
    }

    #[test]
    fn test_credential_store_record_and_json() {
        let mut store = CredentialStore::new();
        assert!(store.get_all().is_empty());

        let cred = CapturedCredential::new(
            "192.168.1.100",
            "HTTP",
            "admin",
            Some("password123".to_string()),
            "2026-11-13T10:30:00Z",
        );
        store.record(cred.clone());

        assert_eq!(store.get_all().len(), 1);
        assert_eq!(store.get_all()[0], cred);

        let json = store.to_json();
        assert!(json.contains("192.168.1.100"));
        assert!(json.contains("admin"));
        assert!(json.contains("password123"));

        let deserialized: Vec<CapturedCredential> =
            serde_json::from_str(&json).expect("valid JSON array");
        assert_eq!(deserialized.len(), 1);
        assert_eq!(deserialized[0], cred);
    }

    #[test]
    fn test_parse_generic_and_url_encoded_credentials() {
        let generic_pair = b"admin:password123\n";
        assert_eq!(
            parse_credential_from_payload("generic", generic_pair),
            Some(("admin".to_string(), Some("password123".to_string())))
        );

        let form_data = b"user=admin&pass=secret123";
        assert_eq!(
            parse_credential_from_payload("generic", form_data),
            Some(("admin".to_string(), Some("secret123".to_string())))
        );

        let json_body = br#"{"username": "root", "password": "toor"}"#;
        assert_eq!(
            parse_credential_from_payload("HTTP", json_body),
            Some(("root".to_string(), Some("toor".to_string())))
        );

        let empty = b"";
        assert_eq!(parse_credential_from_payload("generic", empty), None);

        let http_request_without_creds = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(
            parse_credential_from_payload("HTTP", http_request_without_creds),
            None
        );
    }
}

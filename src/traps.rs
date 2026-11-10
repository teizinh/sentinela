use crate::models::Incident;
use crate::network::{inspect_ip, resolve_rdns};
use chrono::Local;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc::UnboundedSender;

/// Portas armadilha padrão se não forem especificadas pelo utilizador
pub const DEFAULT_TRAP_PORTS: &[u16] = &[2121, 2222, 2323, 8080, 8443];

pub fn get_log_filename() -> String {
    Local::now().format("sentinela_%Y-%m-%d.log").to_string()
}

/// Inicia o registo do logger, criando o ficheiro de log diário com cabeçalho.
pub async fn init_logger() {
    let filename = get_log_filename();
    let header = format!(
        "\n========================================================\n\
         [SESSÃO INICIADA] - {}\n\
         ========================================================\n",
        Local::now().format("%Y-%m-%d %H:%M:%S")
    );

    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&filename)
        .await
    {
        let _ = file.write_all(header.as_bytes()).await;
    }
}

/// Classifica uma porta com o seu respetivo nível de risco.
pub fn classify_port(port: u16) -> (&'static str, &'static str) {
    match port {
        20 | 21 | 2121 => ("FTP", "MÉDIO"),
        22 | 2222 => ("SSH", "CRÍTICO"),
        23 | 2323 => ("Telnet", "CRÍTICO"),
        25 => ("SMTP", "MÉDIO"),
        53 => ("DNS", "ALERTA"),
        80 | 8080 => ("HTTP", "ALERTA"),
        443 | 8443 => ("HTTPS", "ALERTA"),
        3306 => ("MySQL", "MÉDIO"),
        5432 => ("PostgreSQL", "MÉDIO"),
        6379 => ("Redis", "CRÍTICO"),
        27017 => ("MongoDB", "CRÍTICO"),
        3389 => ("RDP", "MÉDIO"),
        _ => ("Custom", "ALERTA"),
    }
}

/// Estrutura para enfileirar conexões aceites e processá-las fora do caminho crítico
struct TrapConnection {
    attacker_ip: std::net::IpAddr,
    port: u16,
    timestamp: String,
    payload: Option<String>,
}

/// Atualiza o valor de "Hits" da entrada correspondente no log em disco.
/// Procura a última entrada correspondente ao IP fornecido e substitui o valor de Hits
/// pelo valor agregado em tempo real.
#[allow(dead_code)]
pub fn update_log_hit_count(filename: &str, ip: &str, hit_count: usize) {
    if let Ok(content) = std::fs::read_to_string(filename) {
        let lines: Vec<&str> = content.lines().collect();
        let mut last_match_idx = None;

        for (i, line) in lines.iter().enumerate().rev() {
            if line_matches_ip(line, ip) {
                last_match_idx = Some(i);
                break;
            }
        }

        if let Some(idx) = last_match_idx {
            let target_line = lines[idx];
            if let Some((prefix, _)) = target_line.rsplit_once("| Hits:") {
                let updated_line = format!("{}| Hits: {}", prefix, hit_count);
                let mut new_lines = lines;
                new_lines[idx] = &updated_line;
                let mut updated_content = new_lines.join("\n");
                if content.ends_with('\n') {
                    updated_content.push('\n');
                }
                let _ = std::fs::write(filename, updated_content);
            }
        }
    }
}

fn line_matches_ip(line: &str, ip: &str) -> bool {
    if let Some(ip_part) = line.split('|').next() {
        if let Some((_, addr)) = ip_part.split_once("IP:") {
            return addr.trim() == ip.trim();
        }
    }
    false
}

/// Regista um lote de incidentes no ficheiro de log em disco numa única operação de escrita,
/// minimizando syscalls e atrasos de I/O sob volumes elevados de tráfego.
pub async fn log_incidents_to_disk(incidents: &[Incident]) {
    if incidents.is_empty() {
        return;
    }

    let filename = get_log_filename();
    let mut batch_text = String::with_capacity(incidents.len() * 120);

    for incident in incidents {
        let location = if incident.city.is_empty() || incident.city == "?" {
            incident.country.clone()
        } else {
            format!("{}, {}", incident.city, incident.country)
        };

        let target_desc = if incident.port == 0 {
            format!("{:<17}", incident.service)
        } else {
            format!("Porta: {:<5} ({:<11})", incident.port, incident.service)
        };

        batch_text.push_str(&format!(
            "[{}] [{:<7}] IP: {:<15} | {} | Local: {:<22} | ISP: {} | Hits: {}\n",
            incident.timestamp,
            incident.severity,
            incident.ip,
            target_desc,
            location,
            incident.isp,
            incident.hit_count,
        ));
    }

    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&filename)
        .await
    {
        let _ = file.write_all(batch_text.as_bytes()).await;
    }
}

/// Regista um incidente individual no ficheiro de log em disco
#[allow(dead_code)]
pub async fn log_incident_to_disk(incident: &Incident) {
    log_incidents_to_disk(std::slice::from_ref(incident)).await;
}

/// Sanitiza uma sequência de bytes convertendo caracteres imprimíveis para texto legível.
pub fn sanitize_bytes(bytes: &[u8]) -> String {
    let sanitized: String = bytes
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else if b == b'\r' || b == b'\n' {
                ' '
            } else {
                '.'
            }
        })
        .collect();
    let clean = sanitized.trim();
    clean.chars().take(120).collect()
}

/// Simula diálogos de protocolos em portas comuns para atrair e capturar payloads e assinaturas dos atacantes.
pub async fn interact_with_probe(mut socket: tokio::net::TcpStream, port: u16) -> Option<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::{timeout, Duration};

    let mut buf = [0u8; 512];

    match port {
        22 | 2222 => {
            // SSH (RFC 4253): O servidor transmite primeiro a identificação do protocolo
            let banner = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n";
            let _ = socket.write_all(banner).await;
            let _ = socket.flush().await;

            // Aguarda a resposta do cliente SSH (ex.: "SSH-2.0-libssh_0.9.0", PuTTY, Nmap NSE)
            if let Ok(Ok(n)) = timeout(Duration::from_millis(500), socket.read(&mut buf)).await {
                if n > 0 {
                    let client_id = sanitize_bytes(&buf[..n]);
                    if !client_id.is_empty() {
                        return Some(format!("SSH: {}", client_id));
                    }
                }
            }
            Some("SSH: handshake iniciado".to_string())
        }
        21 | 2121 => {
            // FTP: Servidor envia banner 220 de boas-vindas
            let banner = b"220 (vsFTPd 3.0.5 ready)\r\n";
            let _ = socket.write_all(banner).await;
            let _ = socket.flush().await;

            if let Ok(Ok(n)) = timeout(Duration::from_millis(500), socket.read(&mut buf)).await {
                if n > 0 {
                    let cmd = sanitize_bytes(&buf[..n]);
                    if cmd.to_uppercase().starts_with("USER") {
                        let _ = socket.write_all(b"331 Please specify the password.\r\n").await;
                        let _ = socket.flush().await;
                        let mut pass_buf = [0u8; 256];
                        if let Ok(Ok(pn)) = timeout(Duration::from_millis(500), socket.read(&mut pass_buf)).await {
                            if pn > 0 {
                                let pass_cmd = sanitize_bytes(&pass_buf[..pn]);
                                let _ = socket.write_all(b"530 Login incorrect.\r\n").await;
                                return Some(format!("FTP: {} | {}", cmd, pass_cmd));
                            }
                        }
                    }
                    return Some(format!("FTP: {}", cmd));
                }
            }
            Some("FTP: banner enviado".to_string())
        }
        23 | 2323 => {
            // Telnet: Envia prompt de login realista
            let banner = b"\r\nDebian GNU/Linux 12\r\nlogin: ";
            let _ = socket.write_all(banner).await;
            let _ = socket.flush().await;

            if let Ok(Ok(n)) = timeout(Duration::from_millis(500), socket.read(&mut buf)).await {
                if n > 0 {
                    let login = sanitize_bytes(&buf[..n]);
                    if !login.is_empty() {
                        return Some(format!("Telnet: login '{}'", login));
                    }
                }
            }
            Some("Telnet: prompt enviado".to_string())
        }
        25 => {
            // SMTP: Envia banner 220 de servidor de e-mail
            let banner = b"220 mail.internal ESMTP Postfix\r\n";
            let _ = socket.write_all(banner).await;
            let _ = socket.flush().await;

            if let Ok(Ok(n)) = timeout(Duration::from_millis(500), socket.read(&mut buf)).await {
                if n > 0 {
                    let cmd = sanitize_bytes(&buf[..n]);
                    if !cmd.is_empty() {
                        return Some(format!("SMTP: {}", cmd));
                    }
                }
            }
            Some("SMTP: banner enviado".to_string())
        }
        80 | 8080 => {
            // HTTP: O cliente fala primeiro (GET/POST). Lemos o pedido e respondemos 401 Unauthorized
            if let Ok(Ok(n)) = timeout(Duration::from_millis(400), socket.read(&mut buf)).await {
                if n > 0 {
                    let req = sanitize_bytes(&buf[..n]);
                    let resp = b"HTTP/1.1 401 Unauthorized\r\nServer: nginx/1.18.0\r\nContent-Type: text/plain; charset=utf-8\r\nWWW-Authenticate: Basic realm=\"Restricted\"\r\nContent-Length: 17\r\nConnection: close\r\n\r\n401 Unauthorized\n";
                    let _ = socket.write_all(resp).await;
                    let _ = socket.flush().await;
                    if !req.is_empty() {
                        return Some(format!("HTTP: {}", req));
                    }
                }
            }
            None
        }
        6379 => {
            // Redis: Lemos comandos como PING/INFO e avisamos que requer autenticação
            if let Ok(Ok(n)) = timeout(Duration::from_millis(400), socket.read(&mut buf)).await {
                if n > 0 {
                    let cmd = sanitize_bytes(&buf[..n]);
                    let _ = socket.write_all(b"-NOAUTH Authentication required.\r\n").await;
                    let _ = socket.flush().await;
                    if !cmd.is_empty() {
                        return Some(format!("Redis: {}", cmd));
                    }
                }
            }
            None
        }
        _ => {
            // Outras portas: Tenta ler o que o atacante enviar nos primeiros 300ms
            if let Ok(Ok(n)) = timeout(Duration::from_millis(300), socket.read(&mut buf)).await {
                if n > 0 {
                    let clean = sanitize_bytes(&buf[..n]);
                    if !clean.is_empty() {
                        return Some(clean);
                    }
                }
            }
            None
        }
    }
}

/// Inicia armadilhas TCP nas portas fornecidas.
/// Devolve (portas_ativas, portas_com_erro).
pub async fn start_traps(
    tx: UnboundedSender<Incident>,
    trap_ports: &[u16],
) -> (Vec<u16>, Vec<u16>) {
    let mut active = Vec::new();
    let mut failed = Vec::new();

    // Fila assíncrona para mover lookups GeoIP e I/O de disco para fora do ciclo accept()
    let (queue_tx, mut queue_rx) = tokio::sync::mpsc::unbounded_channel::<TrapConnection>();

    // Worker assíncrono dedicado a processar eventos GeoIP e gravação em disco
    let tx_worker = tx.clone();
    tokio::spawn(async move {
        while let Some(conn) = queue_rx.recv().await {
            let (country, city, isp) = inspect_ip(conn.attacker_ip).await;
            let rdns = resolve_rdns(conn.attacker_ip).await;
            let (service, severity) = classify_port(conn.port);
            let threat_score = crate::models::calculate_threat_score(severity, 1, conn.payload.is_some());

            let incident = Incident {
                timestamp: conn.timestamp,
                ip: conn.attacker_ip.to_string(),
                port: conn.port,
                service: service.to_string(),
                severity: severity.to_string(),
                country,
                city,
                isp,
                rdns,
                payload: conn.payload,
                threat_score,
                hit_count: 1, // Inicializado a 1; atualizado pelo ciclo principal com base na contagem real
            };

            let _ = tx_worker.send(incident);
        }
    });

    for &port in trap_ports {
        // Tenta bind IPv6 dual-stack ([::]) para aceitar IPv4 e IPv6;
        // Se falhar (ex.: IPv6 desativado no kernel), faz fallback para IPv4 (0.0.0.0)
        let listener_res = match TcpListener::bind(format!("[::]:{}", port)).await {
            Ok(l) => Ok(l),
            Err(_) => TcpListener::bind(format!("0.0.0.0:{}", port)).await,
        };

        match listener_res {
            Ok(listener) => {
                active.push(port);
                let q_tx = queue_tx.clone();
                tokio::spawn(async move {
                    loop {
                        match listener.accept().await {
                            Ok((socket, peer_addr)) => {
                                // Converte endereços IPv4-mapped em IPv6 para IPv4 nativo para consistência
                                let attacker_ip = match peer_addr.ip() {
                                    std::net::IpAddr::V6(v6) => v6
                                        .to_ipv4_mapped()
                                        .map(std::net::IpAddr::V4)
                                        .unwrap_or(std::net::IpAddr::V6(v6)),
                                    std::net::IpAddr::V4(v4) => std::net::IpAddr::V4(v4),
                                };

                                // Descarta conexões locais (loopback e IPs locais da própria máquina)
                                if crate::network::is_host_ip(attacker_ip) {
                                    continue;
                                }

                                let now = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                                let q_tx_clone = q_tx.clone();

                                // Trata a conexão e executa o diálogo interativo do protocolo da porta
                                tokio::spawn(async move {
                                    let payload = interact_with_probe(socket, port).await;

                                    let _ = q_tx_clone.send(TrapConnection {
                                        attacker_ip,
                                        port,
                                        timestamp: now,
                                        payload,
                                    });
                                });
                            }
                            Err(_) => {
                                // Em caso de erro transitório de socket (ex.: descritores de ficheiro esgotados),
                                // pausa brevemente para evitar busy-loop a 100% de CPU
                                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                            }
                        }
                    }
                });
            }
            Err(_) => {
                failed.push(port);
            }
        }
    }

    (active, failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update_log_hit_count() {
        let temp_dir = std::env::temp_dir();
        let test_log = temp_dir.join(format!("test_sentinela_hits_{}.log", std::process::id()));
        let test_log_path = test_log.to_str().unwrap();

        let initial_content = "\
[2026-10-02 10:00:00] [ALERTA ] IP: 192.168.1.136   | Porta: 8080  (HTTP       ) | Local: Rede Local (LAN)       | ISP: Dispositivo Interno | Hits: 1
[2026-10-02 10:00:05] [CRÍTICO] IP: 10.0.0.99       | Porta: 2222  (SSH        ) | Local: Rede Local (LAN)       | ISP: Dispositivo Interno | Hits: 1
[2026-10-02 10:01:00] [ALERTA ] IP: 192.168.1.136   | Porta: 8443  (HTTPS      ) | Local: Rede Local (LAN)       | ISP: Dispositivo Interno | Hits: 1
";
        std::fs::write(test_log_path, initial_content).unwrap();

        // Atualiza para hit 2 do IP 192.168.1.136 (deve atualizar a última linha desse IP)
        update_log_hit_count(test_log_path, "192.168.1.136", 2);

        let updated = std::fs::read_to_string(test_log_path).unwrap();
        let lines: Vec<&str> = updated.lines().collect();
        assert_eq!(lines.len(), 3);
        // Primeira linha permanece Hits: 1
        assert!(lines[0].ends_with("| Hits: 1"));
        // Segunda linha de outro IP permanece Hits: 1
        assert!(lines[1].ends_with("| Hits: 1"));
        // Terceira linha (última correspondente a 192.168.1.136) foi atualizada para Hits: 2!
        assert!(lines[2].ends_with("| Hits: 2"));

        let _ = std::fs::remove_file(test_log_path);
    }

    #[test]
    fn test_line_matches_ip_exact() {
        let line = "[2026-10-02 10:00:00] [ALERTA ] IP: 192.168.1.10    | Porta: 8080  | Hits: 1";
        assert!(line_matches_ip(line, "192.168.1.10"));
        assert!(!line_matches_ip(line, "192.168.1.1"));
        assert!(!line_matches_ip(line, "192.168.1.100"));
    }

    #[test]
    fn test_classify_port() {
        assert_eq!(classify_port(21), ("FTP", "MÉDIO"));
        assert_eq!(classify_port(22), ("SSH", "CRÍTICO"));
        assert_eq!(classify_port(2222), ("SSH", "CRÍTICO"));
        assert_eq!(classify_port(23), ("Telnet", "CRÍTICO"));
        assert_eq!(classify_port(80), ("HTTP", "ALERTA"));
        assert_eq!(classify_port(8080), ("HTTP", "ALERTA"));
        assert_eq!(classify_port(443), ("HTTPS", "ALERTA"));
        assert_eq!(classify_port(3306), ("MySQL", "MÉDIO"));
        assert_eq!(classify_port(5432), ("PostgreSQL", "MÉDIO"));
        assert_eq!(classify_port(6379), ("Redis", "CRÍTICO"));
        assert_eq!(classify_port(27017), ("MongoDB", "CRÍTICO"));
        assert_eq!(classify_port(3389), ("RDP", "MÉDIO"));
        assert_eq!(classify_port(9999), ("Custom", "ALERTA"));
    }

    #[test]
    fn test_get_log_filename() {
        let name = get_log_filename();
        assert!(name.starts_with("sentinela_"));
        assert!(name.ends_with(".log"));
    }

    #[test]
    fn test_sanitize_bytes() {
        assert_eq!(sanitize_bytes(b"GET /admin HTTP/1.1\r\nHost: local\r\n"), "GET /admin HTTP/1.1  Host: local");
        assert_eq!(sanitize_bytes(&[0x00, 0x01, b'A', b'B', 0xFF]), "..AB.");
        assert_eq!(sanitize_bytes(b"   "), "");
    }
}

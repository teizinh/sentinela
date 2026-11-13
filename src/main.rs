mod canary;
mod config;
pub mod credentials;
pub mod icmp;
pub mod mitigation;
mod models;
mod network;
mod pcap;
mod scanner;
mod traps;
mod ui;

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use models::{Incident, Language, PortWarning, SeverityFilter, Theme};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::{
    collections::{HashMap, HashSet},
    env,
    error::Error,
    io::{self, IsTerminal, Write},
    time::{Duration, Instant},
};
use tokio::sync::mpsc;

struct TerminalGuard;
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore_terminal();
    }
}

fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen);
    let _ = execute!(io::stdout(), crossterm::cursor::Show);
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Configura hook de pânico para restaurar o terminal antes de abortar
    let default_panic_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        restore_terminal();
        default_panic_hook(panic_info);
    }));

    // Configura canal de escuta para SIGINT (Ctrl+C)
    let (sigint_tx, mut sigint_rx) = mpsc::channel::<()>(1);
    tokio::spawn(async move {
        if let Ok(()) = tokio::signal::ctrl_c().await {
            let _ = sigint_tx.send(()).await;
        }
    });

    let raw_args: Vec<String> = env::args().skip(1).collect();
    if raw_args.iter().any(|a| a == "-h" || a == "--help") {
        print_help();
        return Ok(());
    }
    if raw_args.iter().any(|a| a == "-v" || a == "--version") {
        println!("sentinela {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if raw_args.iter().any(|a| a == "--init-config") {
        let p = std::path::Path::new("sentinela.toml");
        match config::generate_default_config_file(p) {
            Ok(()) => {
                println!("\x1b[1;32m[✓] Ficheiro de configuração '{}' gerado com sucesso!\x1b[0m", p.display());
                println!("Podes editá-lo para personalizar portas, auto-ban, whitelist, webhook e temas.");
                return Ok(());
            }
            Err(e) => {
                eprintln!("\x1b[1;31m[!] Erro ao gerar '{}': {}\x1b[0m", p.display(), e);
                return Err(Box::new(e) as Box<dyn Error>);
            }
        }
    }

    // Carregamento de ficheiro de configuração (sentinela.toml ou caminho customizado)
    let mut custom_config_path: Option<String> = None;
    let mut i = 0;
    while i < raw_args.len() {
        if (raw_args[i] == "-c" || raw_args[i] == "--config") && i + 1 < raw_args.len() {
            custom_config_path = Some(raw_args[i + 1].clone());
            break;
        }
        i += 1;
    }

    let (file_config, loaded_config_path) = match config::load_config(custom_config_path.as_deref()) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("\x1b[1;33m[!] Aviso de Configuração: {}\x1b[0m", e);
            (config::SentinelaConfig::default(), None)
        }
    };

    // Opções de linha de comandos: --auto-ban, --webhook <URL>, --whitelist <IPS>, --theme <THEME>, --simulate
    let auto_ban_cli = raw_args.iter().any(|a| a == "--auto-ban");
    let mut auto_ban = auto_ban_cli || file_config.security.auto_ban;

    let mut webhook_url: Option<String> = env::var("SENTINELA_WEBHOOK")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or(file_config.alerts.webhook_url.clone());

    let mut hub_url: Option<String> = env::var("SENTINELA_HUB_URL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let mut theme = match file_config.ui.theme.to_lowercase().as_str() {
        "matrix" => Theme::Matrix,
        "midnight" => Theme::Midnight,
        "contrast" | "highcontrast" | "high-contrast" => Theme::HighContrast,
        _ => Theme::Cyber,
    };
    if let Ok(env_theme) = env::var("SENTINELA_THEME") {
        match env_theme.to_lowercase().as_str() {
            "matrix" => theme = Theme::Matrix,
            "midnight" => theme = Theme::Midnight,
            "contrast" | "highcontrast" | "high-contrast" => theme = Theme::HighContrast,
            _ => {}
        }
    }

    let simulate_on_startup = raw_args.iter().any(|a| a == "--simulate" || a == "--test-mode");

    let ssh_session = env::var_os("SSH_CONNECTION").is_some() || env::var_os("SSH_TTY").is_some();
    let mut whitelisted_ips: HashSet<String> = HashSet::new();
    // Never auto-ban the address carrying the current SSH session.
    if let Ok(connection) = env::var("SSH_CONNECTION") {
        if let Some(peer) = connection.split_whitespace().next() {
            if peer.parse::<std::net::IpAddr>().is_ok() {
                whitelisted_ips.insert(peer.to_owned());
            }
        }
    }
    for ip in &file_config.security.whitelist {
        let clean = ip.trim();
        if !clean.is_empty() {
            whitelisted_ips.insert(clean.to_string());
        }
    }
    if let Ok(env_white) = env::var("SENTINELA_WHITELIST") {
        for ip in env_white.split(&[',', ' ', ';'][..]) {
            let clean = ip.trim();
            if !clean.is_empty() {
                whitelisted_ips.insert(clean.to_string());
            }
        }
    }

    let mut i = 0;
    while i < raw_args.len() {
        if raw_args[i] == "--webhook" && i + 1 < raw_args.len() {
            webhook_url = Some(raw_args[i + 1].clone());
            i += 2;
        } else if raw_args[i] == "--hub" && i + 1 < raw_args.len() {
            hub_url = Some(raw_args[i + 1].clone());
            i += 2;
        } else if raw_args[i] == "--whitelist" && i + 1 < raw_args.len() {
            for ip in raw_args[i + 1].split(&[',', ' ', ';'][..]) {
                let clean = ip.trim();
                if !clean.is_empty() {
                    whitelisted_ips.insert(clean.to_string());
                }
            }
            i += 2;
        } else if raw_args[i] == "--theme" && i + 1 < raw_args.len() {
            match raw_args[i + 1].to_lowercase().as_str() {
                "matrix" => theme = Theme::Matrix,
                "midnight" => theme = Theme::Midnight,
                "contrast" | "highcontrast" | "high-contrast" => theme = Theme::HighContrast,
                _ => {}
            }
            i += 2;
        } else if (raw_args[i] == "-c" || raw_args[i] == "--config") && i + 1 < raw_args.len() {
            i += 2;
        } else {
            i += 1;
        }
    }

    // Lê portas custom passadas como argumento: ./sentinela 2222 8080 9999
    // Se nenhuma for passada, usa as portas do ficheiro de configuração ou padrão
    let parsed_ports: Vec<u16> = raw_args
        .iter()
        .filter_map(|a| a.parse::<u16>().ok())
        .collect();

    let mut trap_ports: Vec<u16> = if !parsed_ports.is_empty() {
        parsed_ports
    } else if !file_config.traps.ports.is_empty() {
        file_config.traps.ports.clone()
    } else {
        traps::DEFAULT_TRAP_PORTS.to_vec()
    };

    let test_mode = env::var_os("SENTINELA_TEST_MODE").is_some() || raw_args.iter().any(|a| a == "--test-mode");

    if (!io::stdin().is_terminal() || !io::stdout().is_terminal()) && !test_mode {
        return Err("O dashboard requer um terminal: usa ssh -t host sentinela".into());
    }

    let kill_existing_cli = raw_args
        .iter()
        .any(|a| a == "-k" || a == "--kill-existing" || a == "--replace");

    // Deteção de instâncias concorrentes do Sentinela
    let other_instances = network::find_other_sentinela_instances();
    if !other_instances.is_empty() && !test_mode {
        let pids_str = other_instances
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ");

        if kill_existing_cli {
            println!("\x1b[1;33m[!] A fechar instância(s) anterior(es) do Sentinela (PID: {})...\x1b[0m", pids_str);
            for &pid in &other_instances {
                let _ = network::kill_process_by_pid(pid);
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
            println!("\x1b[1;32m[✓] Instâncias anteriores terminadas com sucesso.\x1b[0m");
        } else if io::stdin().is_terminal() && io::stdout().is_terminal() {
            println!("\n\x1b[1;33m[!] AVISO: Foi detetada outra instância do Sentinela em execução! (PID: {})\x1b[0m", pids_str);
            println!("\x1b[1;37m    As portas de armadilha (honeypot) podem estar ocupadas por essa instância.\x1b[0m");
            print!("\x1b[1;36m[?] Desejas fechar a(s) instância(s) anterior(es) e continuar? [S/n]: \x1b[0m");
            io::stdout().flush()?;

            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let answer = input.trim().to_lowercase();

            if answer.is_empty() || answer == "s" || answer == "sim" || answer == "y" || answer == "yes" {
                for &pid in &other_instances {
                    match network::kill_process_by_pid(pid) {
                        Ok(_) => println!("\x1b[1;32m[✓] Processo PID {} terminado.\x1b[0m", pid),
                        Err(e) => eprintln!("\x1b[1;31m[!] Aviso ao terminar PID {}: {}\x1b[0m", pid, e),
                    }
                }
                tokio::time::sleep(Duration::from_millis(350)).await;
                println!("\x1b[1;32m[✓] Portas libertadas com sucesso. A iniciar o Sentinela...\x1b[0m");
                tokio::time::sleep(Duration::from_millis(300)).await;
            } else {
                print!("\x1b[1;33m[?] Desejas iniciar o Sentinela mesmo assim (sem as portas ocupadas)? [s/N]: \x1b[0m");
                io::stdout().flush()?;

                let mut input2 = String::new();
                io::stdin().read_line(&mut input2)?;
                let answer2 = input2.trim().to_lowercase();

                if answer2 != "s" && answer2 != "sim" && answer2 != "y" && answer2 != "yes" {
                    println!("\x1b[1;37m[-] Operação cancelada. Sentinela encerrado.\x1b[0m");
                    return Ok(());
                }
            }
        }
    }

    let (tx, mut rx) = mpsc::unbounded_channel::<Incident>();

    traps::init_logger().await;
    let log_file_name = traps::get_log_filename();
    let local_ips = network::get_all_local_ips();
    let sys_info = network::get_system_info();
    let default_hostname = env::var("HOSTNAME")
        .or_else(|_| env::var("HOST"))
        .unwrap_or_else(|_| "sentinela-host".to_string());
    let node_id = env::var("SENTINELA_NODE_ID").unwrap_or_else(|_| default_hostname.clone());
    let node_name = env::var("SENTINELA_NODE_NAME").unwrap_or_else(|_| format!("{} ({})", default_hostname, sys_info.distro));
    let node_ip = local_ips.clone();

    if let Some(ref hub) = hub_url {
        network::send_hub_heartbeat(hub, &node_id, &node_name, &node_ip, env!("CARGO_PKG_VERSION"));
    }

    let mut lang = match file_config.ui.language.to_lowercase().as_str() {
        "en" => Language::En,
        _ => network::detect_language(),
    };

    let (_active_traps, failed_traps, queue_tx) = traps::start_traps(tx.clone(), &trap_ports).await;

    // Tenta iniciar o scanner de pacotes raw (requer CAP_NET_RAW / sudo).
    // Se falhar por falta de permissão, continua apenas com deteção de ligações completas.
    let scanner_active = scanner::start_packet_scanner(tx.clone(), trap_ports.clone());

    // Inicia Canário Anti-Ransomware / Honeyfile Deception Watchdog
    let mut honeyfile_watchdog = canary::HoneyfileWatchdog::new(None);
    let canary_active = honeyfile_watchdog.deploy().is_ok();
    let _canary_handle = if canary_active {
        canary::start_honeyfile_watchdog(honeyfile_watchdog.path.clone(), tx.clone())
    } else {
        None
    };

    let mut throughput_sampler = network::ThroughputSampler::default();
    let mut current_throughput_str = String::new();
    let mut last_throughput_sample = Instant::now() - Duration::from_secs(1);

    enable_raw_mode()?;
    let _terminal_guard = TerminalGuard;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut incidents: Vec<Incident> = Vec::new();
    let mut killswitch_active = false;
    let mut killswitch_failed = false;
    let mut show_help = false;
    let mut show_warnings = false;
    let mut show_incident_modal = false;
    let mut show_metrics = false;
    let mut show_port_modal = false;
    let mut port_input = String::new();
    let mut show_sockets = false;
    let mut show_geoip = false;
    let mut sockets_list: Vec<crate::models::SocketInfo> = Vec::new();
    let mut banned_ips: HashSet<String> = HashSet::new();
    let mut audio_alerts = file_config.alerts.audio_alerts;
    let mut toast_message: Option<(String, Instant)> = loaded_config_path.map(|p| {
        let msg = match lang {
            Language::Pt => format!("[⚙️] Configuração carregada: {}", p.display()),
            Language::En => format!("[⚙️] Configuration loaded: {}", p.display()),
        };
        (msg, Instant::now())
    });
    let mut activity_history: Vec<u64> = vec![0; 24];
    let mut last_activity_tick = Instant::now();
    let mut recent_interval_events: u64 = 0;
    let mut cached_warnings: Vec<PortWarning> = Vec::new();
    let mut scroll_offset: usize = 0;
    let mut modal_scroll: u16 = 0;
    let mut severity_filter = SeverityFilter::All;
    let mut search_active = false;
    let mut search_query = String::new();
    let mut known_arp: HashMap<String, (String, String)> = HashMap::new();
    let mut last_arp_check = Instant::now();

    let simulate_attack = |target_tx: &mpsc::UnboundedSender<Incident>| {
        let now_str = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let _ = target_tx.send(Incident {
            timestamp: now_str.clone(),
            ip: "198.51.100.42".to_string(),
            port: 2222,
            service: "SSH Honeypot".to_string(),
            severity: "CRÍTICO".to_string(),
            country: "US".to_string(),
            city: "North Bergen".to_string(),
            isp: "DigitalOcean, LLC".to_string(),
            rdns: Some("scanner-nyc.digitalocean.com".to_string()),
            payload: Some("SSH-2.0-libssh_0.9.6".to_string()),
            threat_score: 85,
            hit_count: 3,
        });
        let _ = target_tx.send(Incident {
            timestamp: now_str.clone(),
            ip: "203.0.113.88".to_string(),
            port: 8080,
            service: "HTTP Honeypot".to_string(),
            severity: "MÉDIO".to_string(),
            country: "RU".to_string(),
            city: "Moscow".to_string(),
            isp: "Selectel Network".to_string(),
            rdns: None,
            payload: Some("GET /wp-admin/setup-config.php HTTP/1.1".to_string()),
            threat_score: 55,
            hit_count: 2,
        });
        let _ = target_tx.send(Incident {
            timestamp: now_str.clone(),
            ip: "185.220.101.5".to_string(),
            port: 2323,
            service: "Telnet Honeypot".to_string(),
            severity: "CRÍTICO".to_string(),
            country: "DE".to_string(),
            city: "Frankfurt".to_string(),
            isp: "Hetzner Online GmbH".to_string(),
            rdns: Some("tor-exit.hetzner.de".to_string()),
            payload: Some("root\x00admin123\r\n".to_string()),
            threat_score: 95,
            hit_count: 4,
        });
        let _ = target_tx.send(Incident {
            timestamp: now_str.clone(),
            ip: "177.18.204.12".to_string(),
            port: 445,
            service: "SMB Probe".to_string(),
            severity: "ALERTA".to_string(),
            country: "BR".to_string(),
            city: "São Paulo".to_string(),
            isp: "Claro Telecom Participacoes".to_string(),
            rdns: None,
            payload: None,
            threat_score: 40,
            hit_count: 1,
        });
        let _ = target_tx.send(Incident {
            timestamp: now_str.clone(),
            ip: "192.0.2.14".to_string(),
            port: 0,
            service: "Port Sweep".to_string(),
            severity: "SWEEP".to_string(),
            country: "CN".to_string(),
            city: "Shenzhen".to_string(),
            isp: "China Telecom".to_string(),
            rdns: None,
            payload: None,
            threat_score: 90,
            hit_count: 5,
        });
        let _ = target_tx.send(Incident {
            timestamp: now_str.clone(),
            ip: "198.51.100.99".to_string(),
            port: 53,
            service: "DNS (Tunneling/Exfil)".to_string(),
            severity: "CRÍTICO".to_string(),
            country: "FR".to_string(),
            city: "Paris".to_string(),
            isp: "OVH SAS".to_string(),
            rdns: Some("ns1.tunnel-exfil-c2.net".to_string()),
            payload: Some("QNAME: dGVzdF9leGZpbF8xMjM0NTY=.tunnel.evilc2.org (Entropia: 3.82)".to_string()),
            threat_score: 92,
            hit_count: 7,
        });
        let _ = target_tx.send(Incident {
            timestamp: now_str,
            ip: "127.0.0.1".to_string(),
            port: 0,
            service: "Honeyfile (Anti-Ransomware)".to_string(),
            severity: "CRÍTICO".to_string(),
            country: "Local".to_string(),
            city: "Sistema de Ficheiros".to_string(),
            isp: "Watchdog Inotify".to_string(),
            rdns: Some("honeyfile.canary.local".to_string()),
            payload: Some("Modificação/Tentativa de Encriptação (Ransomware Detectado!): /tmp/.sentinela_honeyfile_credentials.env".to_string()),
            threat_score: 98,
            hit_count: 1,
        });
    };

    if simulate_on_startup {
        simulate_attack(&tx);
    }

    // Mapa de hit_count por IP (acumula ao longo da sessão)
    let mut ip_hit_counts: HashMap<String, usize> = HashMap::new();

    let start_time = Instant::now();
    let mut total_detections_count: usize = 0;
    let mut unique_ips: HashSet<String> = HashSet::new();
    let mut port_stats: HashMap<u16, usize> = HashMap::new();
    let mut severity_stats: HashMap<String, usize> = HashMap::new();

    loop {
        // Verifica se recebeu SIGINT (Ctrl+C) em segundo plano
        if sigint_rx.try_recv().is_ok() {
            break;
        }

        // Amostragem periódica de débito de rede (Throughput TX/RX)
        if last_throughput_sample.elapsed() >= Duration::from_millis(800) {
            let tp = network::sample_network_throughput(&mut throughput_sampler);
            current_throughput_str = format!("↓ {} | ↑ {}", network::format_bandwidth(tp.rx_bytes_per_sec), network::format_bandwidth(tp.tx_bytes_per_sec));
            last_throughput_sample = Instant::now();
        }

        // Verificação periódica da tabela ARP para proteção contra ARP Spoofing / MITM
        if last_arp_check.elapsed() >= Duration::from_secs(3) {
            last_arp_check = Instant::now();
            let arp_alerts = network::check_arp_table(&mut known_arp);
            for alert in arp_alerts {
                let _ = tx.send(alert);
            }
        }

        let mut batch_count = 0;
        let mut log_batch = Vec::new();
        while let Ok(mut incident) = rx.try_recv() {
            batch_count += 1;
            total_detections_count += 1;
            unique_ips.insert(incident.ip.clone());
            if incident.port != 0 {
                *port_stats.entry(incident.port).or_insert(0) += 1;
            }
            *severity_stats.entry(incident.severity.clone()).or_insert(0) += 1;

            // Atualiza hit_count cumulativo por IP (usando HashMap - O(1) ao invés de O(n))
            let count = ip_hit_counts.entry(incident.ip.clone()).or_insert(0);
            *count += 1;
            incident.hit_count = *count;
            incident.threat_score = crate::models::calculate_threat_score(
                &incident.severity,
                incident.hit_count,
                incident.payload.is_some(),
            );

            // Alerta sonoro de terminal (bell) para ameaças críticas ou varrimentos
            if audio_alerts && (incident.severity == "CRÍTICO" || incident.severity == "SWEEP") {
                use std::io::Write;
                print!("\x07");
                let _ = std::io::stdout().flush();
            }

            recent_interval_events += 1;

            // Dispara notificação nativa no ambiente gráfico (não bloqueante e com rate limit)
            if file_config.alerts.desktop_notifications
                && env::var_os("SSH_CONNECTION").is_none()
                && env::var_os("SSH_TTY").is_none()
            {
                network::send_desktop_alert(&incident);
            }

            // Bloqueio automático de atacantes de alto risco quando auto-ban estiver ativo
            let mut was_auto_banned = false;
            let is_whitelisted = whitelisted_ips.contains(&incident.ip);
            if auto_ban && !is_whitelisted && (incident.threat_score >= file_config.security.threat_threshold || incident.severity == "SWEEP") {
                let is_host = incident
                    .ip
                    .parse::<std::net::IpAddr>()
                    .map(network::is_host_ip)
                    .unwrap_or(false);

                if !banned_ips.contains(&incident.ip) && !is_host {
                    if let Ok(()) = network::ban_ip(&incident.ip) {
                        banned_ips.insert(incident.ip.clone());
                        was_auto_banned = true;
                        let toast = match lang {
                            Language::Pt => format!(
                                "[🛡️ AUTO-BAN] IP {} bloqueado no firewall (Score: {})",
                                incident.ip, incident.threat_score
                            ),
                            Language::En => format!(
                                "[🛡️ AUTO-BAN] IP {} blocked on firewall (Score: {})",
                                incident.ip, incident.threat_score
                            ),
                        };
                        toast_message = Some((toast, Instant::now()));
                    }
                }
            }

            // Dispara notificação de webhook assíncrona para Discord/Slack se configurado
            if let Some(ref url) = webhook_url {
                if was_auto_banned
                    || incident.severity == "CRÍTICO"
                    || incident.severity == "SWEEP"
                    || incident.threat_score >= 70
                {
                    network::send_webhook_alert(url, &incident, was_auto_banned);
                }
            }

            // Encaminha telemetria de incidentes em tempo real para o Sentinela Hub
            if let Some(ref hub) = hub_url {
                network::send_hub_incident(hub, &node_id, &incident);
            }

            log_batch.push(incident.clone());
            incidents.insert(0, incident);
            // Guarda mais incidentes em memória (100) para permitir scroll
            if incidents.len() > 100 {
                incidents.pop();
            }
            // Preserva a posição de scroll do utilizador ao receber novos incidentes

            if batch_count >= 30 {
                break; // Processa no máximo 30 incidentes por ciclo para a UI nunca encravar
            }
        }

        if !log_batch.is_empty() {
            traps::log_incidents_to_disk(&log_batch).await;
        }

        // Atualiza a janela deslizante de pulso de tráfego por segundo para o Sparkline
        if last_activity_tick.elapsed() >= Duration::from_secs(1) {
            activity_history.remove(0);
            activity_history.push(recent_interval_events);
            recent_interval_events = 0;
            last_activity_tick = Instant::now();
        }

        // Calcula a lista filtrada para passar à UI e para gerir scroll
        let search_clean = search_query.trim().to_lowercase();
        let filtered_incidents: Vec<&Incident> = incidents
            .iter()
            .filter(|i| i.matches_filter(severity_filter, &search_clean))
            .collect();
        let filtered_count = filtered_incidents.len();
        scroll_offset = scroll_offset.min(filtered_count.saturating_sub(1));

        let selected_incident: Option<&Incident> = if filtered_count > 0 {
            filtered_incidents.get(scroll_offset).copied()
        } else {
            None
        };

        let active_toast = toast_message.as_ref().and_then(|(msg, inst)| {
            let timeout_ms = if msg.len() > 40 {
                3500 + ((msg.len() - 40) as u64 * 80).min(3500)
            } else {
                3500
            };
            if inst.elapsed() < Duration::from_millis(timeout_ms) {
                Some(msg.as_str())
            } else {
                None
            }
        });

        let animation_tick = (start_time.elapsed().as_millis() / 250) as u64;

        terminal.draw(|f| {
            let ui_ctx = ui::UiContext {
                incidents: &incidents,
                killswitch_active,
                killswitch_failed,
                local_ips: &local_ips,
                log_name: &log_file_name,
                sys_info: &sys_info,
                lang,
                show_help,
                show_warnings,
                warnings: &cached_warnings,
                failed_traps: &failed_traps,
                scroll_offset,
                modal_scroll,
                severity_filter,
                severity_stats: &severity_stats,
                port_stats: &port_stats,
                trap_ports: &trap_ports,
                scanner_active,
                selected_incident,
                show_incident_modal,
                banned_ips: &banned_ips,
                whitelisted_ips: &whitelisted_ips,
                toast_message: active_toast,
                audio_alerts,
                auto_ban,
                webhook_active: webhook_url.is_some(),
                activity_history: &activity_history,
                animation_tick,
                theme,
                search_query: if search_query.is_empty() && !search_active { None } else { Some(&search_query) },
                search_active,
                show_metrics,
                show_port_modal,
                port_input: &port_input,
                show_sockets,
                sockets_list: &sockets_list,
                show_geoip,
                throughput_str: &current_throughput_str,
                canary_active,
            };
            ui::render_ui(f, &ui_ctx);
        })?;

        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }

                // Interceta Ctrl+C para saída graciosa com restauração de terminal
                if let KeyCode::Char('c') = key.code {
                    if key.modifiers.contains(event::KeyModifiers::CONTROL) {
                        break;
                    }
                }

                // Modo de introdução da pesquisa forense (Tecla /)
                if search_active {
                    match key.code {
                        KeyCode::Esc => {
                            search_active = false;
                            search_query.clear();
                        }
                        KeyCode::Enter => {
                            search_active = false;
                        }
                        KeyCode::Backspace => {
                            search_query.pop();
                            scroll_offset = 0;
                        }
                        KeyCode::Char(c) => {
                            search_query.push(c);
                            scroll_offset = 0;
                        }
                        _ => {}
                    }
                    continue;
                }

                // Diálogo interativo para abrir nova porta armadilha (Tecla O)
                if show_port_modal {
                    match key.code {
                        KeyCode::Esc => {
                            show_port_modal = false;
                            port_input.clear();
                        }
                        KeyCode::Enter => {
                            let raw = port_input.trim();
                            if let Ok(port) = raw.parse::<u16>() {
                                if port == 0 {
                                    toast_message = Some(("[!] Porta 0 inválida".to_string(), Instant::now()));
                                } else if trap_ports.contains(&port) {
                                    let msg = match lang {
                                        Language::Pt => format!("[!] A porta {} já está ativa no Sentinela", port),
                                        Language::En => format!("[!] Port {} is already active on Sentinela", port),
                                    };
                                    toast_message = Some((msg, Instant::now()));
                                } else {
                                    match traps::spawn_trap_listener(port, queue_tx.clone()).await {
                                        Ok(()) => {
                                            trap_ports.push(port);
                                            let (svc, _) = traps::classify_port(port);
                                            let msg = match lang {
                                                Language::Pt => format!("[🎯 TRAP] Armadilha ativada na porta TCP {} ({})", port, svc),
                                                Language::En => format!("[🎯 TRAP] Live honeypot active on TCP port {} ({})", port, svc),
                                            };
                                            toast_message = Some((msg, Instant::now()));
                                        }
                                        Err(e) => {
                                            let msg = match lang {
                                                Language::Pt => format!("[!] Falha ao abrir porta {}: {}", port, e),
                                                Language::En => format!("[!] Failed to open port {}: {}", port, e),
                                            };
                                            toast_message = Some((msg, Instant::now()));
                                        }
                                    }
                                }
                            } else {
                                let msg = match lang {
                                    Language::Pt => "[!] Porta inválida! Digite um número entre 1 e 65535".to_string(),
                                    Language::En => "[!] Invalid port! Enter a number between 1 and 65535".to_string(),
                                };
                                toast_message = Some((msg, Instant::now()));
                            }
                            show_port_modal = false;
                            port_input.clear();
                        }
                        KeyCode::Backspace => {
                            port_input.pop();
                        }
                        KeyCode::Char(c) if c.is_ascii_digit() && port_input.len() < 5 => {
                            port_input.push(c);
                        }
                        _ => {}
                    }
                    continue;
                }

                if show_help || show_warnings || show_incident_modal || show_metrics || show_sockets || show_geoip {
                    match key.code {
                        KeyCode::Char('a' | 'A') => {
                            audio_alerts = !audio_alerts;
                            let msg = if audio_alerts {
                                match lang {
                                    Language::Pt => "[🔔] Alertas sonoros & desktop: ATIVADOS",
                                    Language::En => "[🔔] Audio & desktop alerts: ENABLED",
                                }
                            } else {
                                match lang {
                                    Language::Pt => "[🔕] Alertas sonoros: DESATIVADOS",
                                    Language::En => "[🔕] Audio alerts: DISABLED",
                                }
                            };
                            toast_message = Some((msg.to_string(), Instant::now()));
                        }
                        KeyCode::Char('c' | 'C') => {
                            show_sockets = false;
                            modal_scroll = 0;
                        }
                        KeyCode::Char('g' | 'G') => {
                            show_geoip = false;
                            modal_scroll = 0;
                        }
                        KeyCode::Char('i' | 'I') => {
                            show_help = false;
                            show_incident_modal = false;
                            show_metrics = false;
                            show_sockets = false;
                            show_geoip = false;
                            modal_scroll = 0;
                        }
                        KeyCode::Char('w' | 'W') => {
                            show_warnings = false;
                            show_incident_modal = false;
                            show_metrics = false;
                            show_sockets = false;
                            show_geoip = false;
                            modal_scroll = 0;
                        }
                        KeyCode::Char('m' | 'M') => {
                            show_metrics = false;
                            show_sockets = false;
                            show_geoip = false;
                            modal_scroll = 0;
                        }
                        KeyCode::Esc | KeyCode::Enter => {
                            show_help = false;
                            show_warnings = false;
                            show_incident_modal = false;
                            show_metrics = false;
                            show_sockets = false;
                            show_geoip = false;
                            modal_scroll = 0;
                        }
                        // Terminar cirurgicamente processo do socket no Inspetor de Sockets (Tecla K ou D)
                        KeyCode::Char('k' | 'K' | 'd' | 'D') if show_sockets => {
                            let idx = modal_scroll as usize;
                            if let Some(s) = sockets_list.get(idx) {
                                let pid_opt = s.pid_process
                                    .split('(')
                                    .nth(1)
                                    .and_then(|p| p.trim_end_matches(')').parse::<u32>().ok());

                                if let Some(pid) = pid_opt {
                                    match network::kill_process_by_pid(pid) {
                                        Ok(msg) => {
                                            toast_message = Some((format!("[🎯] {}", msg), Instant::now()));
                                            sockets_list = network::get_active_sockets(&trap_ports);
                                        }
                                        Err(e) => {
                                            toast_message = Some((format!("[!] {}", e), Instant::now()));
                                        }
                                    }
                                } else {
                                    toast_message = Some((match lang {
                                        Language::Pt => "[!] Este socket pertence ao kernel ou processo sem PID acessível".to_string(),
                                        Language::En => "[!] This socket belongs to kernel or inaccessible PID".to_string(),
                                    }, Instant::now()));
                                }
                            }
                        }
                        // Banir / Desbanir IP do atacante dentro da modal de raio-X
                        KeyCode::Char('b' | 'B') if show_incident_modal => {
                            if let Some(inc) = selected_incident {
                                let target_ip = inc.ip.clone();
                                if banned_ips.contains(&target_ip) {
                                    match network::unban_ip(&target_ip) {
                                        Ok(()) => {
                                            banned_ips.remove(&target_ip);
                                            toast_message = Some((
                                                format!("[✓] IP {} desbanido do firewall", target_ip),
                                                Instant::now(),
                                            ));
                                        }
                                        Err(e) => {
                                            toast_message = Some((format!("[!] Erro: {}", e), Instant::now()));
                                        }
                                    }
                                } else {
                                    match network::ban_ip(&target_ip) {
                                        Ok(()) => {
                                            banned_ips.insert(target_ip.clone());
                                            toast_message = Some((
                                                format!("[🚨] IP {} bloqueado com sucesso (DROP)", target_ip),
                                                Instant::now(),
                                            ));
                                        }
                                        Err(e) => {
                                            toast_message = Some((format!("[!] Erro: {}", e), Instant::now()));
                                        }
                                    }
                                }
                            }
                        }
                        // Adicionar / Remover da Whitelist dentro da modal de raio-X
                        KeyCode::Char('u' | 'U') if show_incident_modal => {
                            if let Some(inc) = selected_incident {
                                let target_ip = inc.ip.clone();
                                if whitelisted_ips.contains(&target_ip) {
                                    whitelisted_ips.remove(&target_ip);
                                    let msg = match lang {
                                        Language::Pt => format!("[✓] IP {} removido da Whitelist", target_ip),
                                        Language::En => format!("[✓] IP {} removed from Whitelist", target_ip),
                                    };
                                    toast_message = Some((msg, Instant::now()));
                                } else {
                                    whitelisted_ips.insert(target_ip.clone());
                                    if banned_ips.contains(&target_ip) {
                                        let _ = network::unban_ip(&target_ip);
                                        banned_ips.remove(&target_ip);
                                    }
                                    let msg = match lang {
                                        Language::Pt => format!("[🛡️] IP {} adicionado à Whitelist (imune a auto-ban)", target_ip),
                                        Language::En => format!("[🛡️] IP {} added to Whitelist (immune to auto-ban)", target_ip),
                                    };
                                    toast_message = Some((msg, Instant::now()));
                                }
                            }
                        }
                        // Exportar relatório completo de Threat Intel (JSON, CSV, PCAP, CEF, Syslog, Markdown e HTML)
                        KeyCode::Char('e' | 'E') => {
                            match network::export_threat_report(&incidents, &banned_ips, &whitelisted_ips, &sys_info, lang) {
                                Ok((json_f, _csv_f, _pcap_f, _cef_f, _syslog_f, _md_f, _html_f)) => {
                                    let base = json_f.trim_end_matches(".json");
                                    let msg = match lang {
                                        Language::Pt => format!("[✓] 7 Relatórios exportados (JSON, CSV, PCAP, CEF, Syslog, MD, HTML): {}", base),
                                        Language::En => format!("[✓] 7 Reports exported (JSON, CSV, PCAP, CEF, Syslog, MD, HTML): {}", base),
                                    };
                                    toast_message = Some((msg, Instant::now()));
                                }
                                Err(e) => {
                                    toast_message = Some((format!("[!] Falha na exportação: {}", e), Instant::now()));
                                }
                            }
                        }
                        KeyCode::Down | KeyCode::Char('j' | 'J') => {
                            modal_scroll = modal_scroll.saturating_add(1).min(200);
                        }
                        KeyCode::Up | KeyCode::Char('k' | 'K') => {
                            modal_scroll = modal_scroll.saturating_sub(1);
                        }
                        KeyCode::PageDown => {
                            modal_scroll = modal_scroll.saturating_add(5).min(200);
                        }
                        KeyCode::PageUp => {
                            modal_scroll = modal_scroll.saturating_sub(5);
                        }
                        KeyCode::Home => {
                            modal_scroll = 0;
                        }
                        _ => {}
                    }
                } else {
                    match key.code {
                        KeyCode::Char('q' | 'Q') => break,
                        // Abrir raio-X detalhado do incidente selecionado
                        KeyCode::Enter => {
                            if selected_incident.is_some() {
                                show_incident_modal = true;
                                modal_scroll = 0;
                            }
                        }
                        // Banir / Desbanir cirurgicamente o IP selecionado
                        KeyCode::Char('b' | 'B') => {
                            if let Some(inc) = selected_incident {
                                let target_ip = inc.ip.clone();
                                if banned_ips.contains(&target_ip) {
                                    match network::unban_ip(&target_ip) {
                                        Ok(()) => {
                                            banned_ips.remove(&target_ip);
                                            toast_message = Some((
                                                format!("[✓] IP {} desbanido do firewall", target_ip),
                                                Instant::now(),
                                            ));
                                        }
                                        Err(e) => {
                                            toast_message = Some((format!("[!] Erro: {}", e), Instant::now()));
                                        }
                                    }
                                } else {
                                    match network::ban_ip(&target_ip) {
                                        Ok(()) => {
                                            banned_ips.insert(target_ip.clone());
                                            toast_message = Some((
                                                format!("[🚨] IP {} bloqueado com sucesso (DROP)", target_ip),
                                                Instant::now(),
                                            ));
                                        }
                                        Err(e) => {
                                            toast_message = Some((format!("[!] Erro: {}", e), Instant::now()));
                                        }
                                    }
                                }
                            }
                        }
                        // Adicionar / Remover IP selecionado da Whitelist
                        KeyCode::Char('u' | 'U') => {
                            if let Some(inc) = selected_incident {
                                let target_ip = inc.ip.clone();
                                if whitelisted_ips.contains(&target_ip) {
                                    whitelisted_ips.remove(&target_ip);
                                    let msg = match lang {
                                        Language::Pt => format!("[✓] IP {} removido da Whitelist", target_ip),
                                        Language::En => format!("[✓] IP {} removed from Whitelist", target_ip),
                                    };
                                    toast_message = Some((msg, Instant::now()));
                                } else {
                                    whitelisted_ips.insert(target_ip.clone());
                                    if banned_ips.contains(&target_ip) {
                                        let _ = network::unban_ip(&target_ip);
                                        banned_ips.remove(&target_ip);
                                    }
                                    let msg = match lang {
                                        Language::Pt => format!("[🛡️] IP {} adicionado à Whitelist (imune a auto-ban)", target_ip),
                                        Language::En => format!("[🛡️] IP {} added to Whitelist (immune to auto-ban)", target_ip),
                                    };
                                    toast_message = Some((msg, Instant::now()));
                                }
                            }
                        }
                        // Inspecionar conexões e sockets ativos do sistema em tempo real
                        KeyCode::Char('c' | 'C') => {
                            sockets_list = network::get_active_sockets(&trap_ports);
                            show_sockets = true;
                            modal_scroll = 0;
                        }
                        // Exportar relatório completo de Threat Intel (JSON, CSV, PCAP, CEF, Syslog, Markdown e HTML)
                        KeyCode::Char('e' | 'E') => {
                            match network::export_threat_report(&incidents, &banned_ips, &whitelisted_ips, &sys_info, lang) {
                                Ok((json_f, _csv_f, _pcap_f, _cef_f, _syslog_f, _md_f, _html_f)) => {
                                    let base = json_f.trim_end_matches(".json");
                                    let msg = match lang {
                                        Language::Pt => format!("[✓] 7 Relatórios exportados (JSON, CSV, PCAP, CEF, Syslog, MD, HTML): {}", base),
                                        Language::En => format!("[✓] 7 Reports exported (JSON, CSV, PCAP, CEF, Syslog, MD, HTML): {}", base),
                                    };
                                    toast_message = Some((msg, Instant::now()));
                                }
                                Err(e) => {
                                    toast_message = Some((format!("[!] Falha na exportação: {}", e), Instant::now()));
                                }
                            }
                        }
                        // Abrir painel executivo de métricas e telemetria SOC
                        KeyCode::Char('m' | 'M') => {
                            show_metrics = true;
                            modal_scroll = 0;
                        }
                        // Ativar armadilha honeypot dinâmica em direto (porta TCP)
                        KeyCode::Char('o' | 'O') => {
                            show_port_modal = true;
                            port_input.clear();
                        }
                        KeyCode::Char('a' | 'A') => {
                            audio_alerts = !audio_alerts;
                            let msg = if audio_alerts {
                                match lang {
                                    Language::Pt => "[🔔] Alertas sonoros & desktop: ATIVADOS",
                                    Language::En => "[🔔] Audio & desktop alerts: ENABLED",
                                }
                            } else {
                                match lang {
                                    Language::Pt => "[🔕] Alertas sonoros: DESATIVADOS",
                                    Language::En => "[🔕] Audio alerts: DISABLED",
                                }
                            };
                            toast_message = Some((msg.to_string(), Instant::now()));
                        }
                        KeyCode::Char('g' | 'G') => {
                            show_geoip = true;
                            modal_scroll = 0;
                        }
                        KeyCode::Char('?' | 'i' | 'I') => {
                            show_help = true;
                            modal_scroll = 0;
                        }
                        KeyCode::Char('w' | 'W') => {
                            cached_warnings = network::scan_open_ports_warnings(&trap_ports, lang);
                            show_warnings = true;
                            modal_scroll = 0;
                        }
                        KeyCode::Char('l' | 'L') => {
                            lang = match lang {
                                Language::Pt => Language::En,
                                Language::En => Language::Pt,
                            };
                        }
                        KeyCode::Char('k' | 'K') if ssh_session => {
                            toast_message = Some(("SSH: killswitch desativado para preservar a ligação".into(), Instant::now()));
                        }
                        KeyCode::Char('k' | 'K') => {
                            let target = !killswitch_active;
                            if !target {
                                // Desativa o killswitch e restaura a rede
                                match network::toggle_network(false) {
                                    Ok(()) => {
                                        killswitch_active = false;
                                        killswitch_failed = false;
                                    }
                                    Err(_) => {
                                        killswitch_active = false;
                                        killswitch_failed = true;
                                    }
                                }
                            } else {
                                match network::toggle_network(true) {
                                    Ok(()) => {
                                        killswitch_active = true;
                                        killswitch_failed = false;
                                    }
                                    Err(errs) => {
                                        killswitch_active = true;
                                        killswitch_failed = true;
                                        let msg = match lang {
                                             Language::Pt => "Falha no Killswitch: Requer privilégios de root (sudo)!",
                                             Language::En => "Killswitch failed: Root/sudo privileges required!",
                                        };
                                        network::send_desktop_notification_raw(
                                            "[!] Sentinela: Killswitch",
                                            &format!(
                                                "{}\n{}",
                                                msg,
                                                errs.first().cloned().unwrap_or_default()
                                            ),
                                            "critical",
                                        );
                                    }
                                }
                            }
                        }
                        KeyCode::Char('r' | 'R') => match network::toggle_network(false) {
                            Ok(()) => {
                                killswitch_active = false;
                                killswitch_failed = false;
                            }
                            Err(_) => {
                                killswitch_active = false;
                                killswitch_failed = true;
                            }
                        },
                        // Alternar Auto-Ban (bloqueio automático de atacantes de alto risco)
                        KeyCode::Char('x' | 'X') => {
                            auto_ban = !auto_ban;
                            let msg = if auto_ban {
                                match lang {
                                    Language::Pt => "[🛡️] Auto-Ban: ATIVADO (Threat Score ≥ 80)",
                                    Language::En => "[🛡️] Auto-Ban: ENABLED (Threat Score ≥ 80)",
                                }
                            } else {
                                match lang {
                                    Language::Pt => "[🛡️] Auto-Ban: DESATIVADO",
                                    Language::En => "[🛡️] Auto-Ban: DISABLED",
                                }
                            };
                            toast_message = Some((msg.to_string(), Instant::now()));
                        }
                        // Alternar tema visual (Cyber -> Matrix -> Midnight -> HighContrast)
                        KeyCode::Char('t' | 'T') => {
                            theme = theme.next();
                            let msg = match lang {
                                Language::Pt => format!("[🎨] Tema alterado: {}", theme.label(lang)),
                                Language::En => format!("[🎨] Theme changed: {}", theme.label(lang)),
                            };
                            toast_message = Some((msg, Instant::now()));
                        }
                        // Abrir pesquisa forense em direto
                        KeyCode::Char('/') => {
                            search_active = true;
                        }
                        // Injetar simulação de ataques para demonstração e diagnóstico
                        KeyCode::Char('s' | 'S') => {
                            simulate_attack(&tx);
                            let msg = match lang {
                                Language::Pt => "[⚡] Simulação: 3 incidentes de teste injetados no SOC".to_string(),
                                Language::En => "[⚡] Simulation: 3 test incidents injected into SOC".to_string(),
                            };
                            toast_message = Some((msg, Instant::now()));
                        }
                        // Filtro de severidade
                        KeyCode::Char('f' | 'F') => {
                            severity_filter = severity_filter.next();
                            scroll_offset = 0;
                        }
                        // Scroll na tabela
                        KeyCode::Down | KeyCode::Char('j' | 'J' | 'n' | 'N') => {
                            if scroll_offset + 1 < filtered_count {
                                scroll_offset += 1;
                            }
                        }
                        KeyCode::Up | KeyCode::Char('p' | 'P') => {
                            scroll_offset = scroll_offset.saturating_sub(1);
                        }
                        KeyCode::PageDown => {
                            scroll_offset =
                                (scroll_offset + 5).min(filtered_count.saturating_sub(1));
                        }
                        KeyCode::PageUp => {
                            scroll_offset = scroll_offset.saturating_sub(5);
                        }
                        KeyCode::Home => {
                            scroll_offset = 0;
                        }
                        KeyCode::End => {
                            scroll_offset = filtered_count.saturating_sub(1);
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    // Se o killswitch ficou ativo, repõe a rede automaticamente ao sair
    if killswitch_active {
        let _ = network::toggle_network(false);
    }

    // Se foram banidos IPs com DROP no firewall, remove as regras ao sair
    for ip in &banned_ips {
        let _ = network::unban_ip(ip);
    }

    restore_terminal();

    let duration = start_time.elapsed();
    let minutes = duration.as_secs() / 60;
    let seconds = duration.as_secs() % 60;

    let full_log_path = match env::current_dir() {
        Ok(dir) => dir.join(&log_file_name).to_string_lossy().into_owned(),
        Err(_) => log_file_name.clone(),
    };

    let top_port_info = port_stats
        .into_iter()
        .max_by_key(|&(_, count)| count)
        .map(|(p, c)| format!("Porta {} ({}x)", p, c))
        .unwrap_or_else(|| match lang {
            Language::Pt => "Nenhuma".to_string(),
            Language::En => "None".to_string(),
        });

    let top_ip_info = ip_hit_counts
        .into_iter()
        .max_by_key(|(_, c)| *c)
        .map(|(ip, c)| format!("{} ({}x)", ip, c))
        .unwrap_or_else(|| match lang {
            Language::Pt => "Nenhum".to_string(),
            Language::En => "None".to_string(),
        });

    let critical_count = severity_stats.get("CRÍTICO").copied().unwrap_or(0);
    let medium_count = severity_stats.get("MÉDIO").copied().unwrap_or(0);
    let alert_count = severity_stats.get("ALERTA").copied().unwrap_or(0);
    let scan_count = severity_stats.get("SCAN").copied().unwrap_or(0);
    let sweep_count = severity_stats.get("SWEEP").copied().unwrap_or(0);

    let (title, time_lbl, det_lbl, ip_lbl, top_ip_lbl, port_lbl, sev_lbl, ban_lbl, log_lbl) = match lang {
        Language::Pt => (
            "[#]  RELATÓRIO DE SESSÃO - SENTINELA",
            "Tempo em Guarda",
            "Deteções Totais",
            "Invasores Únicos",
            "IP Mais Ativo",
            "Porta Mais Visada",
            "Severidade",
            "IPs Bloqueados",
            "Registo Diário",
        ),
        Language::En => (
            "[#]  SENTINELA SESSION AUDIT REPORT",
            "Active Uptime",
            "Total Alerts",
            "Unique IPs",
            "Most Active IP",
            "Top Target Port",
            "Severity Breakdown",
            "Blocked IPs",
            "Daily Log File",
        ),
    };

    let (term_w, _) = crossterm::terminal::size().unwrap_or((70, 24));
    let term_w = (term_w as usize).clamp(38, 70);
    let bar = "=".repeat(term_w);
    let subbar = "-".repeat(term_w);

    let sev_breakdown = if term_w < 65 {
        match lang {
            Language::Pt => format!(
                "\x1b[1;31m{} Crit\x1b[0m \x1b[1;33m{} Med\x1b[0m \x1b[1;34m{} Alrt\x1b[0m \x1b[1;35m{} Scan\x1b[0m \x1b[1;31m{} Var\x1b[0m",
                critical_count, medium_count, alert_count, scan_count, sweep_count
            ),
            Language::En => format!(
                "\x1b[1;31m{} Crit\x1b[0m \x1b[1;33m{} Med\x1b[0m \x1b[1;34m{} Alrt\x1b[0m \x1b[1;35m{} Scan\x1b[0m \x1b[1;31m{} Swp\x1b[0m",
                critical_count, medium_count, alert_count, scan_count, sweep_count
            ),
        }
    } else {
        match lang {
            Language::Pt => format!(
                "\x1b[1;31m{} Críticos\x1b[0m | \x1b[1;33m{} Médios\x1b[0m | \x1b[1;34m{} Alertas\x1b[0m | \x1b[1;35m{} Scans\x1b[0m | \x1b[1;31m{} Varrimentos\x1b[0m",
                critical_count, medium_count, alert_count, scan_count, sweep_count
            ),
            Language::En => format!(
                "\x1b[1;31m{} Critical\x1b[0m | \x1b[1;33m{} Medium\x1b[0m | \x1b[1;34m{} Alerts\x1b[0m | \x1b[1;35m{} Scans\x1b[0m | \x1b[1;31m{} Sweeps\x1b[0m",
                critical_count, medium_count, alert_count, scan_count, sweep_count
            ),
        }
    };

    let lbl_w = if term_w < 55 { 13 } else { 18 };
    let display_log = if term_w < 55 {
        &log_file_name
    } else {
        &full_log_path
    };
    let os_line = if term_w < 55 {
        format!("{} ({})", sys_info.distro, sys_info.arch)
    } else {
        format!(
            "{} ({}) [{}]",
            sys_info.distro, sys_info.kernel, sys_info.arch
        )
    };

    println!("\n\x1b[1;36m{bar}\x1b[0m");
    println!("\x1b[1;32m{:^width$}\x1b[0m", title, width = term_w);
    println!("\x1b[1;36m{bar}\x1b[0m");
    println!(" [*] {time_lbl:<lbl_w$} : \x1b[1m{minutes:02}m {seconds:02}s\x1b[0m");
    println!(" [+] {det_lbl:<lbl_w$} : \x1b[1;33m{total_detections_count}\x1b[0m");
    println!(" [*] {ip_lbl:<lbl_w$} : \x1b[1m{}\x1b[0m", unique_ips.len());
    println!(" [!] {top_ip_lbl:<lbl_w$} : \x1b[1;31m{top_ip_info}\x1b[0m");
    println!(" [>] {port_lbl:<lbl_w$} : \x1b[1;31m{top_port_info}\x1b[0m");
    println!(" [!] {sev_lbl:<lbl_w$} : {sev_breakdown}");
    if !banned_ips.is_empty() {
        println!(" [🛡] {ban_lbl:<lbl_w$} : \x1b[1;31m{} (DROP)\x1b[0m", banned_ips.len());
    }
    println!("{subbar}");
    println!(" [#] {:<lbl_w$} : {os_line}", "SO / Kernel");
    println!(" [#] {log_lbl:<lbl_w$} : \x1b[1;32m{display_log}\x1b[0m");
    println!("\x1b[1;36m{bar}\x1b[0m\n");

    Ok(())
}

fn print_help() {
    println!(
        "\x1b[1;36mSentinela v{}\x1b[0m - Sistema Leve de Deteção de Intrusões e Armadilhas de Rede\n",
        env!("CARGO_PKG_VERSION")
    );
    println!("\x1b[1mUSO:\x1b[0m");
    println!("  sentinela [OPÇÕES] [PORTAS...]\n");
    println!("\x1b[1mARGUMENTOS:\x1b[0m");
    println!("  [PORTAS...]     Portas adicionais para escuta de armadilhas (ex: 2222 8080 9999)");
    println!("                  Padrão: 2121, 2222, 2323, 8080, 8443\n");
    println!("\x1b[1mOPÇÕES:\x1b[0m");
    println!("  -h, --help        Apresenta esta mensagem de ajuda");
    println!("  -v, --version     Apresenta a versão do Sentinela");
    println!("  -c, --config <ARQ>Carrega ficheiro de configuração personalizado (sentinela.toml)");
    println!("  --init-config     Gera ficheiro sentinela.toml com definições recomendadas");
    println!("  --auto-ban        Ativa bloqueio automático no firewall (Threat Score >= 80)");
    println!("  --webhook <URL>   Dispara alertas em tempo real para webhook Discord/Slack");
    println!("  --hub <URL>       Agrega e correlaciona telemetria no Sentinela Hub (ex: http://127.0.0.1:8765)");
    println!("  --whitelist <IPS> Lista de IPs confiáveis imunes ao Auto-Ban (ex: 192.168.1.1,10.0.0.1)");
    println!("  --theme <TEMA>    Tema visual inicial: cyber, matrix, midnight, contrast");
    println!("  --simulate        Injeta incidentes simulados no arranque para testes e demos");
    println!("  -k, --kill-existing Termina automaticamente instâncias anteriores em conflito\n");
    println!("\x1b[1mATALHOS NO DASHBOARD:\x1b[0m");
    println!("  q / Ctrl+C      Sair do Sentinela e restaurar terminal");
    println!("  ↵ (Enter)       Raio-X forense detalhado do incidente selecionado");
    println!("  b               Banir / Desbanir IP do atacante (DROP firewall)");
    println!("  u               Adicionar / Remover IP selecionado da Whitelist");
    println!("  x               Alternar Auto-Ban (bloqueio automático de alto risco)");
    println!("  t               Alternar tema visual (Cyber / Matrix / Midnight / Alto Contraste)");
    println!("  /               Pesquisa forense em direto (filtra por IP, Porta ou Serviço)");
    println!("  o               Ativar armadilha honeypot dinâmica em direto (porta TCP)");
    println!("  m               Painel executivo de métricas forenses e telemetria SOC");
    println!("  s               Simulação diagnóstica de ataques no SOC");
    println!("  c               Inspecionar sockets e conexões ativas do sistema (LISTEN, ESTABLISHED)");
    println!("  e               Exportar Threat Intel (JSON, CSV, PCAP, CEF, Syslog, Markdown e HTML)");
    println!("  a               Ativar / Desativar alerta sonoro (Bell) e notificações");
    println!("  i               Abrir / Fechar janela de ajuda (Help Modal)");
    println!("  w               Consultar auditor de portas vulneráveis abertas");
    println!("  l               Alternar idioma entre Português e Inglês");
    println!("  k               Ativar / Desativar Emergency Network Killswitch");
    println!("  f               Alternar filtro de severidade (Todos -> Críticos -> Médio+)");
    println!("  r               Repor estado da rede (desativar killswitch)");
    println!("  ↑ / ↓, PgUp/Dn  Navegar na tabela (modais: ↑/↓ ou j/k)");
    println!("  PgUp / PgDn     Deslocar 5 linhas");
    println!("  Home / End      Saltar para o topo ou fim da lista");
}

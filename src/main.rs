mod models;
mod network;
mod scanner;
mod traps;
mod ui;

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use models::{Incident, Language, PortWarning, SeverityFilter};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::{
    collections::{HashMap, HashSet},
    env,
    error::Error,
    io,
    time::{Duration, Instant},
};
use tokio::sync::mpsc;

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

    // Lê portas custom passadas como argumento: ./sentinela 2222 8080 9999
    // Se nenhuma for passada, usa as portas padrão
    let trap_ports: Vec<u16> = if raw_args.is_empty() {
        traps::DEFAULT_TRAP_PORTS.to_vec()
    } else {
        let parsed: Vec<u16> = raw_args
            .iter()
            .filter_map(|a| a.parse::<u16>().ok())
            .collect();
        if parsed.is_empty() {
            eprintln!("Portas inválidas. A usar portas padrão.");
            traps::DEFAULT_TRAP_PORTS.to_vec()
        } else {
            parsed
        }
    };

    let (tx, mut rx) = mpsc::unbounded_channel::<Incident>();

    traps::init_logger().await;
    let log_file_name = traps::get_log_filename();
    let local_ips = network::get_all_local_ips();
    let sys_info = network::get_system_info();
    let mut lang = network::detect_language();

    let (_active_traps, failed_traps) = traps::start_traps(tx.clone(), &trap_ports).await;

    // Tenta iniciar o scanner de pacotes raw (requer CAP_NET_RAW / sudo).
    // Se falhar por falta de permissão, continua apenas com deteção de ligações completas.
    let scanner_active = scanner::start_packet_scanner(tx, trap_ports.clone());

    enable_raw_mode()?;
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
    let mut banned_ips: HashSet<String> = HashSet::new();
    let mut toast_message: Option<(String, Instant)> = None;
    let mut audio_alerts = false;
    let mut activity_history: Vec<u64> = vec![0; 24];
    let mut last_activity_tick = Instant::now();
    let mut recent_interval_events: u64 = 0;
    let mut cached_warnings: Vec<PortWarning> = Vec::new();
    let mut scroll_offset: usize = 0;
    let mut modal_scroll: u16 = 0;
    let mut severity_filter = SeverityFilter::All;

    // Mapa de hit_count por IP (acumula ao longo da sessão)
    let mut ip_hit_counts: HashMap<String, usize> = HashMap::new();

    let start_time = Instant::now();
    let mut total_detections_count: usize = 0;
    let mut unique_ips: HashSet<String> = HashSet::new();
    let mut port_stats: HashMap<u16, usize> = HashMap::new();
    let mut severity_stats: HashMap<String, usize> = HashMap::new();

    // Garante limpeza preventiva de quaisquer regras de firewall residuais no arranque (Linux)
    #[cfg(target_os = "linux")]
    {
        network::cleanup_firewall_rules();
    }

    loop {
        // Verifica se recebeu SIGINT (Ctrl+C) em segundo plano
        if sigint_rx.try_recv().is_ok() {
            break;
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
            network::send_desktop_alert(&incident);

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
        let filtered_incidents: Vec<&Incident> = incidents
            .iter()
            .filter(|i| severity_filter.matches(&i.severity))
            .collect();
        let filtered_count = filtered_incidents.len();

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
                toast_message: active_toast,
                audio_alerts,
                activity_history: &activity_history,
                animation_tick,
            };
            ui::render_ui(f, &ui_ctx);
        })?;

        if event::poll(Duration::from_millis(50))? {
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

                if show_help || show_warnings || show_incident_modal {
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
                        KeyCode::Char('i' | 'I') => {
                            show_help = false;
                            show_incident_modal = false;
                            modal_scroll = 0;
                        }
                        KeyCode::Char('w' | 'W') => {
                            show_warnings = false;
                            show_incident_modal = false;
                            modal_scroll = 0;
                        }
                        KeyCode::Esc | KeyCode::Enter => {
                            show_help = false;
                            show_warnings = false;
                            show_incident_modal = false;
                            modal_scroll = 0;
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
                        // Exportar relatório completo de Threat Intel
                        KeyCode::Char('e' | 'E') => {
                            match network::export_threat_report(&incidents, &banned_ips, &sys_info, lang) {
                                Ok((json_f, csv_f)) => {
                                    toast_message = Some((
                                        format!("[✓] Relatório exportado: {} e {}", json_f, csv_f),
                                        Instant::now(),
                                    ));
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
                        // Exportar relatório completo de Threat Intel (JSON e CSV)
                        KeyCode::Char('e' | 'E') => {
                            match network::export_threat_report(&incidents, &banned_ips, &sys_info, lang) {
                                Ok((json_f, csv_f)) => {
                                    toast_message = Some((
                                        format!("[✓] Relatório exportado: {} e {}", json_f, csv_f),
                                        Instant::now(),
                                    ));
                                }
                                Err(e) => {
                                    toast_message = Some((format!("[!] Falha na exportação: {}", e), Instant::now()));
                                }
                            }
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
                        KeyCode::Char('i' | 'I') => {
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
    println!("  -h, --help      Apresenta esta mensagem de ajuda");
    println!("  -v, --version   Apresenta a versão do Sentinela\n");
    println!("\x1b[1mATALHOS NO DASHBOARD:\x1b[0m");
    println!("  q / Ctrl+C      Sair do Sentinela e restaurar terminal");
    println!("  ↵ (Enter)       Raio-X forense detalhado do incidente selecionado");
    println!("  b               Banir / Desbanir IP do atacante (DROP firewall)");
    println!("  e               Exportar Threat Intelligence da sessão (JSON + CSV)");
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

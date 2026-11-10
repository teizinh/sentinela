use crate::models::{GeoResponse, Incident, Language, PortWarning, SysInfo};
use get_if_addrs::get_if_addrs;
#[cfg(target_os = "linux")]
use std::fs;
use std::{
    collections::{HashMap, HashSet},
    env,
    net::IpAddr,
    process::{Command, Stdio},
    sync::{OnceLock, RwLock as StdRwLock},
    time::Duration,
};
use tokio::sync::RwLock;

#[derive(Clone, Debug)]
pub struct GeoCacheEntry {
    pub geo: (String, String, String),
    /// Data/hora de expiração para entradas de cache negativas (falhas de lookup).
    /// Se `None`, a entrada é positiva (sucesso) e permanece válida durante toda a sessão.
    pub expires_at: Option<std::time::Instant>,
}

static GEO_CACHE: OnceLock<RwLock<HashMap<IpAddr, GeoCacheEntry>>> = OnceLock::new();

pub fn get_geo_cache() -> &'static RwLock<HashMap<IpAddr, GeoCacheEntry>> {
    GEO_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

static RDNS_CACHE: OnceLock<RwLock<HashMap<IpAddr, Option<String>>>> = OnceLock::new();

pub fn get_rdns_cache() -> &'static RwLock<HashMap<IpAddr, Option<String>>> {
    RDNS_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Efetua resolução de DNS Reverso (rDNS / PTR) assíncrona com cache e timeout.
/// Previne bloqueios na captura caso o servidor DNS demore a responder.
pub async fn resolve_rdns(ip: IpAddr) -> Option<String> {
    if ip.is_loopback() {
        return Some("localhost".to_string());
    }
    if is_private_or_local(ip) {
        return Some("lan.local".to_string());
    }

    {
        let cache = get_rdns_cache().read().await;
        if let Some(cached) = cache.get(&ip) {
            return cached.clone();
        }
    }

    let ip_copy = ip;
    let res = tokio::time::timeout(
        Duration::from_millis(1500),
        tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip_copy).ok()),
    )
    .await;

    let hostname = match res {
        Ok(Ok(Some(h))) if !h.is_empty() && h != ip.to_string() => Some(h),
        _ => None,
    };

    let mut cache = get_rdns_cache().write().await;
    cache.insert(ip, hostname.clone());
    hostname
}

/// Cliente HTTP partilhado por todos os lookups GeoIP.
/// Criado uma vez — reutiliza pool de ligações e sessão TLS em vez de
/// abrir uma nova ligação TCP+TLS a cada pedido.
static HTTP_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

fn get_http_client() -> &'static reqwest::Client {
    HTTP_CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .user_agent(concat!("sentinela/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("Falha ao construir cliente HTTP")
    })
}

pub fn detect_language() -> Language {
    let lang_var = env::var("LANG")
        .or_else(|_| env::var("LC_ALL"))
        .unwrap_or_default()
        .to_lowercase();

    if lang_var.starts_with("pt") {
        Language::Pt
    } else {
        Language::En
    }
}

struct HostIpsCache {
    ips: HashSet<IpAddr>,
    expires_at: std::time::Instant,
}

static HOST_IPS_CACHE: StdRwLock<Option<HostIpsCache>> = StdRwLock::new(None);

pub fn is_host_ip(ip: IpAddr) -> bool {
    if ip.is_loopback() {
        return true;
    }

    let now = std::time::Instant::now();

    // Fast path: leitura da cache sem contenção caso ainda esteja válida (TTL de 10 segundos)
    if let Ok(guard) = HOST_IPS_CACHE.read() {
        if let Some(cache) = &*guard {
            if now < cache.expires_at {
                return cache.ips.contains(&ip);
            }
        }
    }

    // Refresh path: atualiza as interfaces locais evitando tempestades de chamadas netlink
    if let Ok(mut guard) = HOST_IPS_CACHE.write() {
        // Double-check após adquirir o lock de escrita
        if let Some(cache) = &*guard {
            if now < cache.expires_at {
                return cache.ips.contains(&ip);
            }
        }

        let mut fresh_ips = HashSet::new();
        if let Ok(interfaces) = get_if_addrs() {
            for iface in interfaces {
                fresh_ips.insert(iface.ip());
            }
        }

        let is_host = fresh_ips.contains(&ip);
        *guard = Some(HostIpsCache {
            ips: fresh_ips,
            expires_at: now + Duration::from_secs(10),
        });
        return is_host;
    }

    // Fallback de segurança se o lock estiver corrompido
    if let Ok(interfaces) = get_if_addrs() {
        for iface in interfaces {
            if iface.ip() == ip {
                return true;
            }
        }
    }

    false
}

#[cfg(target_os = "linux")]
pub fn get_system_info() -> SysInfo {
    let distro = fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|content| {
            for line in content.lines() {
                if line.starts_with("PRETTY_NAME=") {
                    return Some(
                        line.trim_start_matches("PRETTY_NAME=")
                            .trim_matches(|c| c == '"' || c == '\'')
                            .to_string(),
                    );
                }
            }
            None
        })
        .unwrap_or_else(|| "Linux Genérico".to_string());

    let kernel = fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|k| k.trim().to_string())
        .unwrap_or_else(|_| "Desconhecido".to_string());

    let arch = env::consts::ARCH.to_string();

    SysInfo {
        distro,
        kernel,
        arch,
    }
}

#[cfg(target_os = "windows")]
pub fn get_system_info() -> SysInfo {
    let distro = "Windows".to_string();
    let kernel = match Command::new("cmd").args(["/c", "ver"]).output() {
        Ok(out) => {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if s.is_empty() {
                "Windows 10/11".to_string()
            } else {
                s
            }
        }
        Err(_) => "Windows".to_string(),
    };
    let arch = env::consts::ARCH.to_string();

    SysInfo {
        distro,
        kernel,
        arch,
    }
}

#[cfg(target_os = "macos")]
pub fn get_system_info() -> SysInfo {
    let distro = match Command::new("sw_vers").arg("-productVersion").output() {
        Ok(out) => format!("macOS {}", String::from_utf8_lossy(&out.stdout).trim()),
        Err(_) => "macOS".to_string(),
    };
    let kernel = match Command::new("uname").arg("-r").output() {
        Ok(out) => format!("Darwin {}", String::from_utf8_lossy(&out.stdout).trim()),
        Err(_) => "Darwin".to_string(),
    };
    let arch = env::consts::ARCH.to_string();

    SysInfo {
        distro,
        kernel,
        arch,
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
pub fn get_system_info() -> SysInfo {
    SysInfo {
        distro: env::consts::OS.to_string(),
        kernel: "Unix".to_string(),
        arch: env::consts::ARCH.to_string(),
    }
}

pub fn get_all_local_ips() -> String {
    match get_if_addrs() {
        Ok(interfaces) => {
            let mut list = Vec::new();
            for iface in interfaces {
                if let IpAddr::V4(ipv4) = iface.addr.ip() {
                    if !ipv4.is_loopback() {
                        list.push(format!("{}: {}", iface.name, ipv4));
                    }
                }
            }
            if list.is_empty() {
                "Sem IPs".into()
            } else {
                list.join(" | ")
            }
        }
        Err(_) => "Erro de IP".into(),
    }
}

pub fn is_private_or_local(ip: IpAddr) -> bool {
    if ip.is_loopback() {
        return true;
    }
    match ip {
        IpAddr::V4(ipv4) => ipv4.is_private() || ipv4.is_link_local(),
        IpAddr::V6(ipv6) => {
            let segments = ipv6.segments();
            // fe80::/10 (Link-Local)
            let is_link_local = (segments[0] & 0xffc0) == 0xfe80;
            // fc00::/7 (Unique Local Address - ULA)
            let is_ula = (segments[0] & 0xfe00) == 0xfc00;
            is_link_local || is_ula
        }
    }
}

/// Classifica sub-redes locais e privadas (RFC 1918, RFC 6598, Link-Local) com detalhe
pub fn classify_local_ip(ip: IpAddr) -> (String, String, String) {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            if v4.is_loopback() {
                ("Loopback".to_string(), "".to_string(), "Host Interno (127.0.0.1)".to_string())
            } else if octets[0] == 10 {
                ("Rede Privada".to_string(), "Classe A (10.0.0.0/8)".to_string(), "Intranet Corporativa / Lab".to_string())
            } else if octets[0] == 172 && (16..=31).contains(&octets[1]) {
                ("Rede Privada".to_string(), "Classe B (172.16.0.0/12)".to_string(), "Sub-rede / Docker / VPN".to_string())
            } else if octets[0] == 192 && octets[1] == 168 {
                ("Rede Local (LAN)".to_string(), "Classe C (192.168.0.0/16)".to_string(), "Router / Dispositivo LAN".to_string())
            } else if octets[0] == 100 && (64..=127).contains(&octets[1]) {
                ("CGNAT (RFC 6598)".to_string(), "100.64.0.0/10".to_string(), "Operadora ISP Compartilhada".to_string())
            } else if octets[0] == 169 && octets[1] == 254 {
                ("Link-Local (APIPA)".to_string(), "169.254.0.0/16".to_string(), "Autoconfiguração de Rede".to_string())
            } else {
                ("Rede Local (LAN)".to_string(), "".to_string(), "Dispositivo Interno".to_string())
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                ("Loopback (IPv6)".to_string(), "".to_string(), "Host Interno (::1)".to_string())
            } else {
                let segments = v6.segments();
                if (segments[0] & 0xffc0) == 0xfe80 {
                    ("Link-Local (IPv6)".to_string(), "fe80::/10".to_string(), "Interface Local".to_string())
                } else if (segments[0] & 0xfe00) == 0xfc00 {
                    ("Rede Local Única (ULA)".to_string(), "fc00::/7".to_string(), "Intranet IPv6 Privada".to_string())
                } else {
                    ("Rede Local (LAN)".to_string(), "".to_string(), "Dispositivo Interno".to_string())
                }
            }
        }
    }
}

/// Devolve (country, city, isp) para o IP fornecido.
/// Usa cache em memória com TTL de 2 minutos para falhas para permitir novas tentativas.
pub async fn inspect_ip(ip: IpAddr) -> (String, String, String) {
    if ip.is_loopback() || is_private_or_local(ip) {
        return classify_local_ip(ip);
    }

    // 1. Verifica cache em memória primeiro (respeitando TTL para entradas negativas)
    {
        let now = std::time::Instant::now();
        let cache = get_geo_cache().read().await;
        if let Some(entry) = cache.get(&ip) {
            match entry.expires_at {
                Some(exp) if now < exp => return entry.geo.clone(),
                Some(_) => {} // Cache negativa expirada (passaram > 2 min): tentar novamente
                None => return entry.geo.clone(), // Cache positiva válida
            }
        }
    }

    // 2. Efetua pedido HTTP se não estiver na cache ou se a cache negativa tiver expirado
    let url = format!(
        "http://ip-api.com/json/{}?fields=status,country,city,isp",
        ip
    );
    let (result, is_negative) = match get_http_client().get(&url).send().await {
        Ok(resp) => {
            if let Ok(geo) = resp.json::<GeoResponse>().await {
                if geo.status.as_deref() == Some("success") {
                    (
                        (
                            geo.country.unwrap_or_else(|| "Desconhecido".to_string()),
                            geo.city.unwrap_or_default(),
                            geo.isp.unwrap_or_else(|| "Desconhecido".to_string()),
                        ),
                        false, // Sucesso: resposta positiva
                    )
                } else {
                    (
                        (
                            "Internet (WAN)".to_string(),
                            "".to_string(),
                            "Consulta Externa".to_string(),
                        ),
                        true,
                    )
                }
            } else {
                (
                    (
                        "Internet (WAN)".to_string(),
                        "".to_string(),
                        "Consulta Externa".to_string(),
                    ),
                    true,
                )
            }
        }
        Err(_) => (
            (
                "Internet (WAN)".to_string(),
                "".to_string(),
                "Sem resposta GeoIP".to_string(),
            ),
            true,
        ),
    };

    // 3. Guarda em cache: respostas com falha recebem TTL curto (2 min) para retentativa futura
    {
        let expires_at = if is_negative {
            Some(std::time::Instant::now() + Duration::from_secs(120)) // 2 minutos
        } else {
            None
        };
        let mut cache = get_geo_cache().write().await;
        // Evita crescimento ilimitado da cache se milhares de IPs diferentes forem inspecionados
        if cache.len() > 5000 {
            let now = std::time::Instant::now();
            cache.retain(|_, entry| match entry.expires_at {
                Some(exp) => now < exp,
                None => true,
            });
            if cache.len() > 5000 {
                cache.clear();
            }
        }
        cache.insert(
            ip,
            GeoCacheEntry {
                geo: result.clone(),
                expires_at,
            },
        );
    }

    result
}

#[cfg(target_os = "linux")]
fn run_cmd(cmd: &str, args: &[&str]) -> bool {
    // 1. Tenta execução direta (processo com privilégios de root ou capabilities)
    if let Ok(output) = Command::new(cmd).args(args).output() {
        if output.status.success() {
            return true;
        }
    }

    // 2. Tenta via sudo não-interativo (-n) caso o utilizador tenha permissões sudoers
    let mut sudo_args = vec!["-n", cmd];
    sudo_args.extend_from_slice(args);
    if let Ok(output) = Command::new("sudo").args(&sudo_args).output() {
        if output.status.success() {
            return true;
        }
    }

    false
}

#[cfg(target_os = "linux")]
pub fn get_all_linux_interfaces() -> Vec<String> {
    let mut ifaces = Vec::new();
    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name != "lo" {
                ifaces.push(name);
            }
        }
    }
    // Fallback para get_if_addrs caso /sys não esteja acessível
    if ifaces.is_empty() {
        if let Ok(addrs) = get_if_addrs() {
            for iface in addrs {
                if !iface.is_loopback() && !ifaces.contains(&iface.name) {
                    ifaces.push(iface.name);
                }
            }
        }
    }
    ifaces
}

#[cfg(target_os = "linux")]
pub fn cleanup_firewall_rules() {
    for _ in 0..5 {
        let d1 = run_cmd("iptables", &["-D", "INPUT", "!", "-i", "lo", "-j", "DROP"]);
        let d2 = run_cmd("iptables", &["-D", "OUTPUT", "!", "-o", "lo", "-j", "DROP"]);
        let d3 = run_cmd("ip6tables", &["-D", "INPUT", "!", "-i", "lo", "-j", "DROP"]);
        let d4 = run_cmd(
            "ip6tables",
            &["-D", "OUTPUT", "!", "-o", "lo", "-j", "DROP"],
        );
        if !d1 && !d2 && !d3 && !d4 {
            break;
        }
    }
}

/// Bloqueio cirúrgico de um IP de atacante através de regra DROP no topo da cadeia INPUT.
#[cfg(target_os = "linux")]
pub fn ban_ip(ip: &str) -> Result<(), String> {
    if ip.parse::<IpAddr>().is_err() {
        return Err("Endereço IP inválido para bloqueio".to_string());
    }
    let is_v6 = ip.contains(':');
    let cmd = if is_v6 { "ip6tables" } else { "iptables" };
    if run_cmd(cmd, &["-I", "INPUT", "1", "-s", ip, "-j", "DROP"]) {
        Ok(())
    } else {
        Err("Falha ao banir IP: requer privilégios de root (sudo)".to_string())
    }
}

/// Remove a regra de bloqueio cirúrgico do IP especificado.
#[cfg(target_os = "linux")]
pub fn unban_ip(ip: &str) -> Result<(), String> {
    if ip.parse::<IpAddr>().is_err() {
        return Err("Endereço IP inválido".to_string());
    }
    let is_v6 = ip.contains(':');
    let cmd = if is_v6 { "ip6tables" } else { "iptables" };
    if run_cmd(cmd, &["-D", "INPUT", "-s", ip, "-j", "DROP"]) {
        Ok(())
    } else {
        Err("Falha ao desbanir IP: regra não encontrada ou sem permissão".to_string())
    }
}

#[cfg(target_os = "windows")]
pub fn ban_ip(ip: &str) -> Result<(), String> {
    if ip.parse::<IpAddr>().is_err() {
        return Err("Endereço IP inválido para bloqueio".to_string());
    }
    let rule_name = format!("Sentinela_Block_{}", ip);
    let output = std::process::Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={}", rule_name),
            "dir=in",
            "action=block",
            &format!("remoteip={}", ip),
            "description=Bloqueio cirurgico gerado pelo Sentinela SOC",
        ])
        .output();
    match output {
        Ok(out) if out.status.success() => Ok(()),
        Ok(_) => Err("Falha ao banir IP no Windows Firewall (requer privilégios de Administrador)".to_string()),
        Err(e) => Err(format!("Erro ao executar netsh: {}", e)),
    }
}

#[cfg(target_os = "windows")]
pub fn unban_ip(ip: &str) -> Result<(), String> {
    let rule_name = format!("Sentinela_Block_{}", ip);
    let output = std::process::Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={}", rule_name),
        ])
        .output();
    match output {
        Ok(out) if out.status.success() => Ok(()),
        Ok(_) => Err("Falha ao remover regra do Windows Firewall (requer privilégios de Administrador)".to_string()),
        Err(e) => Err(format!("Erro ao executar netsh: {}", e)),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub fn ban_ip(_ip: &str) -> Result<(), String> {
    Err("Bloqueio cirúrgico de IP suportado em Linux e Windows".to_string())
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub fn unban_ip(_ip: &str) -> Result<(), String> {
    Err("Bloqueio cirúrgico de IP suportado em Linux e Windows".to_string())
}

/// Exporta todos os incidentes registados na sessão para relatórios estruturados JSON e CSV.
pub fn export_threat_report(
    incidents: &[Incident],
    banned_ips: &std::collections::HashSet<String>,
    whitelisted_ips: &std::collections::HashSet<String>,
    sys_info: &SysInfo,
    _lang: Language,
) -> Result<(String, String), String> {
    let now = chrono::Local::now();
    let base_name = now.format("sentinela_report_%Y-%m-%d_%H-%M-%S").to_string();
    let json_name = format!("{}.json", base_name);
    let csv_name = format!("{}.csv", base_name);

    #[derive(serde::Serialize)]
    struct ThreatReport<'a> {
        report_generated_at: String,
        sentinela_version: &'static str,
        total_incidents: usize,
        unique_attackers: usize,
        banned_ips: Vec<&'a String>,
        whitelisted_ips: Vec<&'a String>,
        system_info: &'a SysInfo,
        incidents: &'a [Incident],
    }

    let mut unique_ips = std::collections::HashSet::new();
    for inc in incidents {
        unique_ips.insert(&inc.ip);
    }

    let report = ThreatReport {
        report_generated_at: now.to_rfc3339(),
        sentinela_version: env!("CARGO_PKG_VERSION"),
        total_incidents: incidents.len(),
        unique_attackers: unique_ips.len(),
        banned_ips: banned_ips.iter().collect(),
        whitelisted_ips: whitelisted_ips.iter().collect(),
        system_info: sys_info,
        incidents,
    };

    let json_content = serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?;
    std::fs::write(&json_name, json_content).map_err(|e| format!("Erro ao gravar JSON: {}", e))?;

    let mut csv = String::from("Timestamp,IP,Port,Service,Severity,Score,MitreID,MitreTactic,Country,City,ISP,rDNS,Payload,Hits,Banned,Whitelisted\n");
    for inc in incidents {
        let is_banned = if banned_ips.contains(&inc.ip) { "SIM" } else { "NAO" };
        let is_white = if whitelisted_ips.contains(&inc.ip) { "SIM" } else { "NAO" };
        let mitre = crate::models::map_to_mitre(&inc.severity, inc.port, inc.payload.as_deref());
        let rdns = inc.rdns.as_deref().unwrap_or("");
        let payload = inc.payload.as_deref().unwrap_or("");
        csv.push_str(&format!(
            "\"{}\",\"{}\",{},\"{}\",\"{}\",{},\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",{},\"{}\",\"{}\"\n",
            inc.timestamp,
            inc.ip,
            inc.port,
            inc.service,
            inc.severity,
            inc.threat_score,
            mitre.id,
            mitre.tactic.replace('"', "\"\""),
            inc.country,
            inc.city,
            inc.isp.replace('"', "\"\""),
            rdns.replace('"', "\"\""),
            payload.replace('"', "\"\""),
            inc.hit_count,
            is_banned,
            is_white
        ));
    }
    std::fs::write(&csv_name, csv).map_err(|e| format!("Erro ao gravar CSV: {}", e))?;

    Ok((json_name, csv_name))
}

/// Dispara uma notificação assíncrona para um webhook (compatível com Discord, Slack e automações HTTP)
pub fn send_webhook_alert(webhook_url: &str, incident: &Incident, is_auto_banned: bool) {
    let url = webhook_url.trim().to_string();
    if url.is_empty() {
        return;
    }

    let inc = incident.clone();
    tokio::spawn(async move {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build();

        if let Ok(client) = client {
            let title = if is_auto_banned {
                format!("🛑 [SENTINELA AUTO-BAN] Ameaça Bloqueada: {}", inc.ip)
            } else {
                format!("🚨 [SENTINELA ALERTA] Deteção {}: {}", inc.severity, inc.ip)
            };

            let color = match inc.severity.as_str() {
                "CRÍTICO" => 0xE74C3C, // Vermelho vivo
                "SWEEP" => 0xE67E22,   // Laranja
                "MÉDIO" => 0xF1C40F,   // Amarelo
                _ => 0x3498DB,         // Azul
            };

            let payload_str = inc.payload.as_deref().unwrap_or("Nenhum");
            let location_str = if inc.city.is_empty() || inc.city == "?" {
                inc.country.clone()
            } else {
                format!("{}, {}", inc.city, inc.country)
            };

            // Payload padrão com embeds para Discord/Slack/Mattermost
            let body = serde_json::json!({
                "username": "Sentinela SOC",
                "embeds": [{
                    "title": title,
                    "color": color,
                    "fields": [
                        {"name": "IP Origem", "value": inc.ip, "inline": true},
                        {"name": "Localização", "value": location_str, "inline": true},
                        {"name": "Alvo", "value": format!("Porta {} ({})", inc.port, inc.service), "inline": true},
                        {"name": "Threat Score", "value": format!("{}/100", inc.threat_score), "inline": true},
                        {"name": "Hits Sessão", "value": inc.hit_count.to_string(), "inline": true},
                        {"name": "ISP / Rede", "value": inc.isp, "inline": true},
                        {"name": "Payload Capturado", "value": format!("`{}`", payload_str), "inline": false}
                    ],
                    "footer": {
                        "text": format!("Sentinela v{} • {}", env!("CARGO_PKG_VERSION"), inc.timestamp)
                    }
                }]
            });

            let _ = client.post(&url).json(&body).send().await;
        }
    });
}

/// Altera o estado da rede (isolamento / restauro).
/// No Linux, utiliza prioritariamente regras Netfilter (iptables / ip6tables) para bloquear 100%
/// do tráfego de entrada e saída. Isto garante o isolamento absoluto sem desligar as interfaces
/// físicas, preservando as concessões DHCP, rotas predeterminadas (gateway) e endereços IP.
/// Caso o iptables não esteja disponível, recorre ao desligamento dos links físicos (ip link set down).
/// No restauro, remove as regras de firewall, garante que todas as interfaces de /sys/class/net/
/// estão UP, e sinaliza a renovação de DHCP/rotas (compatível com OpenRC/Gentoo, systemd e NetworkManager).
#[cfg(target_os = "linux")]
pub fn toggle_network(isolate: bool) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    let mut successes = 0;

    if isolate {
        // --- 1. ISOLAMENTO VIA FIREWALL (MÉTODO PRIMÁRIO) ---
        // Bloqueia todo o tráfego que não seja loopback local (lo)
        let ipt_in = run_cmd(
            "iptables",
            &["-I", "INPUT", "1", "!", "-i", "lo", "-j", "DROP"],
        );
        let ipt_out = run_cmd(
            "iptables",
            &["-I", "OUTPUT", "1", "!", "-o", "lo", "-j", "DROP"],
        );
        let _ = run_cmd(
            "ip6tables",
            &["-I", "INPUT", "1", "!", "-i", "lo", "-j", "DROP"],
        );
        let _ = run_cmd(
            "ip6tables",
            &["-I", "OUTPUT", "1", "!", "-o", "lo", "-j", "DROP"],
        );

        let mut fw_active = false;
        if ipt_in || ipt_out {
            fw_active = true;
            successes += 1;
        }

        // Bloqueia rádio Wi-Fi/Bluetooth via rfkill
        let _ = run_cmd("rfkill", &["block", "all"]);

        // --- 2. FALLBACK FÍSICO: SE O FIREWALL NÃO PUDER SER ATIVADO ---
        if !fw_active {
            let ifaces = get_all_linux_interfaces();
            for iface in &ifaces {
                if run_cmd("ip", &["link", "set", "dev", iface, "down"]) {
                    successes += 1;
                } else {
                    errors.push(format!(
                        "Interface {}: permissão negada ao desativar link (requer sudo)",
                        iface
                    ));
                }
            }
            let _ = run_cmd("nmcli", &["networking", "off"]);
            let _ = run_cmd("nmcli", &["radio", "all", "off"]);
        }

        if successes == 0 {
            if errors.is_empty() {
                errors.push(
                    "Nenhuma interface de rede ou firewall disponível para isolamento".to_string(),
                );
            } else {
                errors.push("O Killswitch requer privilégios de root para isolar a rede (executa com: sudo ./sentinela)".to_string());
            }

            let filename = crate::traps::get_log_filename();
            let err_log = format!(
                "[{}] [FALHA  ] Killswitch: Falha ao isolar rede!\nErros detalhados:\n• {}\n",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                errors.join("\n• ")
            );
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&filename)
            {
                let _ = std::io::Write::write_all(&mut f, err_log.as_bytes());
            }

            return Err(errors);
        }
    } else {
        // --- RESTAURO COMPLETO DA REDE ---
        // 1. Remove quaisquer regras DROP adicionadas pelo Sentinela
        cleanup_firewall_rules();

        // 2. Levanta links de todas as interfaces listadas em /sys/class/net/
        // CRÍTICO: Nunca usar get_if_addrs() porque interfaces DOWN perdem os IPs e são ignoradas!
        let ifaces = get_all_linux_interfaces();
        for iface in &ifaces {
            let _ = run_cmd("ip", &["link", "set", "dev", iface, "up"]);
        }

        // 3. Desbloqueia rádio Wi-Fi/Bluetooth via rfkill
        let _ = run_cmd("rfkill", &["unblock", "all"]);

        // 4. Reativa conectividade no NetworkManager (se instalado)
        let _ = run_cmd("nmcli", &["radio", "all", "on"]);
        let _ = run_cmd("nmcli", &["networking", "on"]);

        // 5. Restauração de IP e rotas (Gentoo / OpenRC / systemd / dhcpcd)
        let _ = run_cmd("dhcpcd", &["-n"]);
        for iface in &ifaces {
            let _ = run_cmd(
                "rc-service",
                &["--ifexists", &format!("net.{}", iface), "restart"],
            );
        }
        let _ = run_cmd("rc-service", &["--ifexists", "dhcpcd", "restart"]);
        let _ = run_cmd("networkctl", &["renew"]);
    }

    Ok(())
}

#[cfg(target_os = "windows")]
pub fn toggle_network(isolate: bool) -> Result<(), Vec<String>> {
    let ps_cmd = if isolate {
        "Get-NetAdapter | Disable-NetAdapter -Confirm:$false"
    } else {
        "Get-NetAdapter | Enable-NetAdapter -Confirm:$false"
    };

    match Command::new("powershell")
        .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", ps_cmd])
        .output()
    {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => {
            let err = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let msg = if err.is_empty() {
                "PowerShell falhou ao alterar estado das placas de rede (requer privilégios de Administrador)".to_string()
            } else {
                err
            };
            Err(vec![msg])
        }
        Err(e) => Err(vec![format!("Falha ao invocar PowerShell: {}", e)]),
    }
}

#[cfg(target_os = "macos")]
pub fn toggle_network(isolate: bool) -> Result<(), Vec<String>> {
    let state = if isolate { "off" } else { "on" };
    match Command::new("networksetup")
        .args(["-setairportpower", "en0", state])
        .output()
    {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => {
            let err = String::from_utf8_lossy(&output.stderr).trim().to_string();
            if err.is_empty() {
                Ok(())
            } else {
                Err(vec![err])
            }
        }
        Err(e) => Err(vec![format!("Falha ao invocar networksetup: {}", e)]),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
pub fn toggle_network(_isolate: bool) -> Result<(), Vec<String>> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn is_local_only_binding(ip_hex: &str) -> bool {
    if ip_hex.len() == 8 {
        if let Ok(val) = u32::from_str_radix(ip_hex, 16) {
            // Em /proc/net/tcp (little-endian em x86):
            // 127.x.x.x tem 0x7F no byte menos significativo lido em u32
            if (val & 0xFF) == 127 {
                return true;
            }
        }
    } else if ip_hex.len() == 32 {
        // Em /proc/net/tcp6, ::1 loopback é codificado como 00000000000000000000000001000000
        if ip_hex == "00000000000000000000000001000000" {
            return true;
        }
    }
    false
}

#[cfg(target_os = "linux")]
fn get_listening_ports() -> Vec<u16> {
    let mut listening_ports = Vec::new();
    for path in &["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 && parts[3] == "0A" {
                    if let Some((ip_hex, port_hex)) = parts[1].split_once(':') {
                        // Ignora serviços locais seguros (bind exclusivo em 127.0.0.1 / ::1)
                        if is_local_only_binding(ip_hex) {
                            continue;
                        }
                        if let Ok(port) = u16::from_str_radix(port_hex, 16) {
                            if !listening_ports.contains(&port) {
                                listening_ports.push(port);
                            }
                        }
                    }
                }
            }
        }
    }
    listening_ports
}

#[cfg(target_os = "windows")]
fn get_listening_ports() -> Vec<u16> {
    let mut listening_ports = Vec::new();
    if let Ok(output) = Command::new("netstat").args(["-ano", "-p", "tcp"]).output() {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            // Formato típico Windows: TCP    0.0.0.0:8080    0.0.0.0:0    LISTENING    1234
            if parts.len() >= 4
                && parts[0].eq_ignore_ascii_case("TCP")
                && parts[3].eq_ignore_ascii_case("LISTENING")
            {
                let local_addr = parts[1];
                if local_addr.starts_with("127.") || local_addr.starts_with("[::1]") {
                    continue;
                }
                if let Some((_ip, port_str)) = local_addr.rsplit_once(':') {
                    if let Ok(port) = port_str.parse::<u16>() {
                        if !listening_ports.contains(&port) {
                            listening_ports.push(port);
                        }
                    }
                }
            }
        }
    }
    listening_ports
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn get_listening_ports() -> Vec<u16> {
    let mut listening_ports = Vec::new();
    if let Ok(output) = Command::new("netstat").args(["-an", "-p", "tcp"]).output() {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            if line.contains("LISTEN") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                for part in parts {
                    if let Some((_ip, port_str)) = part.rsplit_once('.') {
                        if let Ok(port) = port_str.parse::<u16>() {
                            if !listening_ports.contains(&port) {
                                listening_ports.push(port);
                            }
                        }
                    }
                }
            }
        }
    }
    listening_ports
}

pub fn scan_open_ports_warnings(trap_ports: &[u16], lang: Language) -> Vec<PortWarning> {
    let mut warnings = Vec::new();
    let listening_ports = get_listening_ports();

    for port in listening_ports {
        if trap_ports.contains(&port) {
            continue;
        }

        let (service, risk, pt_msg, en_msg, fix) = match port {
            21 => (
                "FTP",
                "ALTO",
                "Credenciais e ficheiros transmitidos em texto claro (inseguro).",
                "Cleartext credentials & files exposed over network.",
                "sudo /etc/init.d/vsftpd stop  |  sudo systemctl stop vsftpd",
            ),
            23 => (
                "Telnet",
                "CRÍTICO",
                "Shell remota sem qualquer cifra! Palavras-passe visíveis a sniffers.",
                "Unencrypted remote shell! Plaintext passwords on wire.",
                "sudo killall in.telnetd  |  sudo iptables -A INPUT -p tcp --dport 23 -j DROP",
            ),
            139 | 445 => (
                "SMB / Samba",
                "ALTO",
                "Partilha de ficheiros exposta. Alvo clássico de ransomware.",
                "Exposed Windows file sharing. Frequent ransomware vector.",
                "sudo /etc/init.d/samba stop  |  sudo systemctl stop smb",
            ),
            3306 => (
                "MySQL / MariaDB",
                "MÉDIO",
                "Base de dados acessível na rede. Deve escutar apenas em 127.0.0.1.",
                "Database listening publicly. Restrict bind to 127.0.0.1.",
                "Mudar 'bind-address = 127.0.0.1' no my.cnf",
            ),
            5432 => (
                "PostgreSQL",
                "MÉDIO",
                "Porta PostgreSQL exposta a ligações de fora.",
                "PostgreSQL port exposed to external probes.",
                "Configurar listen_addresses = 'localhost' no postgresql.conf",
            ),
            6379 => (
                "Redis",
                "CRÍTICO",
                "Base de dados em cache exposta e habitualmente sem autenticação.",
                "In-memory Redis exposed with no authentication.",
                "Configurar 'bind 127.0.0.1' no redis.conf",
            ),
            27017 => (
                "MongoDB",
                "CRÍTICO",
                "MongoDB exposto sem autenticação por defeito em versões antigas.",
                "MongoDB exposed — older versions have no auth by default.",
                "Configurar 'bindIp: 127.0.0.1' no mongod.conf",
            ),
            3389 => (
                "RDP",
                "MÉDIO",
                "Ambiente de trabalho remoto exposto a força bruta.",
                "Remote desktop open to brute-force dictionaries.",
                "sudo systemctl stop xrdp  |  Isolar na firewall",
            ),
            5900..=5905 => (
                "VNC",
                "ALTO",
                "Acesso gráfico remoto vulnerável se não passar por túnel seguro.",
                "VNC desktop exposed without TLS/SSH encapsulation.",
                "sudo killall x11vnc  |  Usar apenas por túnel SSH",
            ),
            9200 | 9300 => (
                "Elasticsearch",
                "CRÍTICO",
                "Elasticsearch exposto sem autenticação — dados acessíveis publicamente.",
                "Elasticsearch with no auth — full data exposure risk.",
                "Configurar 'network.host: localhost' no elasticsearch.yml",
            ),
            _ => continue,
        };

        let reason = match lang {
            Language::Pt => pt_msg.to_string(),
            Language::En => en_msg.to_string(),
        };

        warnings.push(PortWarning {
            port,
            service: service.to_string(),
            risk_level: risk,
            reason,
            fix_command: fix.to_string(),
        });
    }

    warnings
}

use std::sync::atomic::{AtomicU64, Ordering};
static LAST_NOTIFICATION_MILLIS: AtomicU64 = AtomicU64::new(0);

pub fn send_desktop_alert(incident: &Incident) {
    let now_millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    // Rate limit atómico: no máximo 1 notificação desktop a cada 3 segundos (sem race conditions)
    let mut current = LAST_NOTIFICATION_MILLIS.load(Ordering::Relaxed);
    loop {
        if now_millis.saturating_sub(current) < 3000 {
            return;
        }
        match LAST_NOTIFICATION_MILLIS.compare_exchange_weak(
            current,
            now_millis,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(actual) => current = actual,
        }
    }

    let _urgency = match incident.severity.as_str() {
        "CRÍTICO" => "critical".to_string(),
        _ => "normal".to_string(),
    };

    let location = if incident.city.is_empty() {
        incident.country.clone()
    } else {
        format!("{}, {}", incident.city, incident.country)
    };

    let title = format!("🚨 Sentinela: Intrusão [{}]", incident.severity);
    let target = if incident.port == 0 {
        format!("Alvo: {}", incident.service)
    } else {
        format!("Alvo: Porta {} ({})", incident.port, incident.service)
    };
    let body = format!(
        "IP: {} ({}x)\n{}\nOrigem: {}",
        incident.ip, incident.hit_count, target, location
    );

    // Executa notificação em thread separada para nunca bloquear o loop principal da TUI
    #[cfg(target_os = "linux")]
    std::thread::spawn(move || {
        let _ = Command::new("notify-send")
            .args([
                "-u",
                &_urgency,
                "-a",
                "Sentinela HIDS",
                "-i",
                "security-high",
                &title,
                &body,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
    });

    #[cfg(target_os = "windows")]
    std::thread::spawn(move || {
        let ps_script = format!(
            r#"[void] [System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');
$notify = New-Object System.Windows.Forms.NotifyIcon;
$notify.Icon = [System.Drawing.SystemIcons]::Warning;
$notify.BalloonTipIcon = 'Warning';
$notify.BalloonTipTitle = '{}';
$notify.BalloonTipText = '{}';
$notify.Visible = $True;
$notify.ShowBalloonTip(4000);
Start-Sleep -Seconds 4;
$notify.Dispose();"#,
            title.replace('\'', "''"),
            body.replace('\'', "''")
        );

        let _ = Command::new("powershell")
            .args([
                "-NoProfile",
                "-WindowStyle",
                "Hidden",
                "-Command",
                &ps_script,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    });

    #[cfg(target_os = "macos")]
    std::thread::spawn(move || {
        let script = format!(
            "display notification \"{}\" with title \"{}\"",
            body.replace('"', "\\\""),
            title.replace('"', "\\\"")
        );
        let _ = Command::new("osascript")
            .args(["-e", &script])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
    });

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        // Outros SOs sem interface gráfica direta
    }
}

pub fn send_desktop_notification_raw(title: &str, body: &str, urgency: &str) {
    let t = title.to_string();
    let b = body.to_string();
    let _u = urgency.to_string();

    #[cfg(target_os = "linux")]
    std::thread::spawn(move || {
        let _ = Command::new("notify-send")
            .args([
                "-u",
                &_u,
                "-a",
                "Sentinela HIDS",
                "-i",
                "dialog-error",
                &t,
                &b,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
    });

    #[cfg(target_os = "windows")]
    std::thread::spawn(move || {
        let ps_script = format!(
            r#"[void] [System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');
$notify = New-Object System.Windows.Forms.NotifyIcon;
$notify.Icon = [System.Drawing.SystemIcons]::Error;
$notify.BalloonTipIcon = 'Error';
$notify.BalloonTipTitle = '{}';
$notify.BalloonTipText = '{}';
$notify.Visible = $True;
$notify.ShowBalloonTip(4000);
Start-Sleep -Seconds 4;
$notify.Dispose();"#,
            t.replace('\'', "''"),
            b.replace('\'', "''")
        );

        let _ = Command::new("powershell")
            .args([
                "-NoProfile",
                "-WindowStyle",
                "Hidden",
                "-Command",
                &ps_script,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    });

    #[cfg(target_os = "macos")]
    std::thread::spawn(move || {
        let script = format!(
            "display notification \"{}\" with title \"{}\"",
            b.replace('"', "\\\""),
            t.replace('"', "\\\"")
        );
        let _ = Command::new("osascript")
            .args(["-e", &script])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
    });

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        // No-op
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_geo_cache_negative_ttl() {
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)); // RFC 5737 TEST-NET-2

        // Insere entrada negativa que já expirou
        {
            let mut cache = get_geo_cache().write().await;
            cache.insert(
                ip,
                GeoCacheEntry {
                    geo: (
                        "Internet (WAN)".to_string(),
                        "".to_string(),
                        "Sem resposta GeoIP".to_string(),
                    ),
                    expires_at: Some(std::time::Instant::now() - Duration::from_secs(1)), // já expirado
                },
            );
        }

        // Ao ler a cache, a entrada expirada deve ser considerada inválida
        {
            let now = std::time::Instant::now();
            let cache = get_geo_cache().read().await;
            let entry = cache.get(&ip).unwrap();
            let is_valid = match entry.expires_at {
                Some(exp) => now < exp,
                None => true,
            };
            assert!(
                !is_valid,
                "Entrada negativa expirada não deve ser considerada válida!"
            );
        }

        // Insere entrada negativa válida (dentro dos 5 min de TTL)
        {
            let mut cache = get_geo_cache().write().await;
            cache.insert(
                ip,
                GeoCacheEntry {
                    geo: (
                        "Internet (WAN)".to_string(),
                        "".to_string(),
                        "Sem resposta GeoIP".to_string(),
                    ),
                    expires_at: Some(std::time::Instant::now() + Duration::from_secs(300)),
                },
            );
        }

        {
            let now = std::time::Instant::now();
            let cache = get_geo_cache().read().await;
            let entry = cache.get(&ip).unwrap();
            let is_valid = match entry.expires_at {
                Some(exp) => now < exp,
                None => true,
            };
            assert!(
                is_valid,
                "Entrada negativa dentro do TTL deve ser considerada válida!"
            );
        }

        // Insere entrada positiva permanente (expires_at == None)
        {
            let mut cache = get_geo_cache().write().await;
            cache.insert(
                ip,
                GeoCacheEntry {
                    geo: (
                        "Portugal".to_string(),
                        "Lisbon".to_string(),
                        "MEO".to_string(),
                    ),
                    expires_at: None,
                },
            );
        }

        {
            let cache = get_geo_cache().read().await;
            let entry = cache.get(&ip).unwrap();
            assert!(
                entry.expires_at.is_none(),
                "Entrada positiva deve ter expires_at == None"
            );
            assert_eq!(entry.geo.0, "Portugal");
        }
    }

    #[test]
    fn test_is_host_ip_loopback() {
        use std::net::{Ipv4Addr, Ipv6Addr};
        assert!(is_host_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(is_host_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!is_host_ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))));
    }

    #[test]
    fn test_is_private_or_local() {
        use std::net::{Ipv4Addr, Ipv6Addr};
        // Loopback
        assert!(is_private_or_local(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(is_private_or_local(IpAddr::V6(Ipv6Addr::LOCALHOST)));

        // IPv4 Privados e Link-Local
        assert!(is_private_or_local(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_private_or_local(IpAddr::V4(Ipv4Addr::new(
            192, 168, 1, 1
        ))));
        assert!(is_private_or_local(IpAddr::V4(Ipv4Addr::new(
            172, 16, 0, 1
        ))));
        assert!(is_private_or_local(IpAddr::V4(Ipv4Addr::new(
            169, 254, 1, 1
        ))));

        // IPv6 Link-Local (fe80::/10) e ULA (fc00::/7 / fd00::/8)
        let fe80 = "fe80::1".parse::<IpAddr>().unwrap();
        assert!(is_private_or_local(fe80));
        let fd00 = "fd12:3456:789a::1".parse::<IpAddr>().unwrap();
        assert!(is_private_or_local(fd00));

        // IPs Públicos
        assert!(!is_private_or_local(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_private_or_local(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        let pub_v6 = "2001:4860:4860::8888".parse::<IpAddr>().unwrap();
        assert!(!is_private_or_local(pub_v6));
    }

    #[test]
    fn test_classify_local_ip() {
        let (country, city, isp) = classify_local_ip("192.168.1.100".parse().unwrap());
        assert_eq!(country, "Rede Local (LAN)");
        assert!(city.contains("Classe C"));
        assert!(isp.contains("Router"));

        let (country, city, _) = classify_local_ip("10.10.5.1".parse().unwrap());
        assert_eq!(country, "Rede Privada");
        assert!(city.contains("Classe A"));

        let (country, _, _) = classify_local_ip("127.0.0.1".parse().unwrap());
        assert_eq!(country, "Loopback");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_is_local_only_binding() {
        // 127.0.0.1 em little-endian /proc/net/tcp
        assert!(is_local_only_binding("0100007F"));
        // 0.0.0.0 (escuta pública em todas as interfaces)
        assert!(!is_local_only_binding("00000000"));
        // ::1 loopback em /proc/net/tcp6
        assert!(is_local_only_binding("00000000000000000000000001000000"));
        // :: (escuta pública em IPv6)
        assert!(!is_local_only_binding("00000000000000000000000000000000"));
    }

    #[test]
    fn test_export_threat_report() {
        use crate::models::{Incident, Language, SysInfo};
        use std::collections::HashSet;

        let incidents = vec![Incident {
            timestamp: "2026-10-26 14:00:00".to_string(),
            ip: "192.168.1.150".to_string(),
            port: 2222,
            service: "SSH Honeypot".to_string(),
            severity: "CRÍTICO".to_string(),
            country: "Local".to_string(),
            city: "LAN".to_string(),
            isp: "Internal Router".to_string(),
            hit_count: 3,
            rdns: Some("gateway.lan".to_string()),
            payload: Some("SSH-2.0-OpenSSH_9.0".to_string()),
            threat_score: 85,
        }];

        let mut banned = HashSet::new();
        banned.insert("192.168.1.150".to_string());
        let mut whitelisted = HashSet::new();
        whitelisted.insert("192.168.1.1".to_string());

        let sys_info = SysInfo {
            distro: "Fedora Linux 41".to_string(),
            kernel: "Linux 6.12.0".to_string(),
            arch: "x86_64".to_string(),
        };

        let res = export_threat_report(&incidents, &banned, &whitelisted, &sys_info, Language::Pt);
        assert!(res.is_ok());
        let (json_file, csv_file) = res.unwrap();

        // Verifica existência e conteúdo dos ficheiros
        assert!(std::path::Path::new(&json_file).exists());
        assert!(std::path::Path::new(&csv_file).exists());

        let json_content = std::fs::read_to_string(&json_file).unwrap();
        assert!(json_content.contains("192.168.1.150"));
        assert!(json_content.contains("gateway.lan"));

        let csv_content = std::fs::read_to_string(&csv_file).unwrap();
        assert!(csv_content.contains("MitreID,MitreTactic"));
        assert!(csv_content.contains("Whitelisted"));
        assert!(csv_content.contains("gateway.lan"));
        assert!(csv_content.contains("SSH-2.0-OpenSSH_9.0"));
        assert!(csv_content.contains("\"SIM\""));

        // Limpeza dos ficheiros de teste
        let _ = std::fs::remove_file(json_file);
        let _ = std::fs::remove_file(csv_file);
    }

    #[tokio::test]
    async fn test_rdns_cache_lookup() {
        use std::net::Ipv4Addr;
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let host = resolve_rdns(ip).await;
        // Em muitas máquinas locais, 127.0.0.1 resolve para localhost ou similar
        // O cache deve guardar o valor retornado
        let host2 = resolve_rdns(ip).await;
        assert_eq!(host, host2);
    }
}

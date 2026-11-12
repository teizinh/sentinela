use crate::models::{GeoResponse, Incident, Language, PortWarning, SocketInfo, SysInfo};
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

/// Gera formato CEF (ArcSight Common Event Format) compatível com Splunk, ArcSight, Wazuh e SIEMs
pub fn generate_cef(incidents: &[Incident], banned_ips: &std::collections::HashSet<String>) -> String {
    let mut out = String::new();
    let version = env!("CARGO_PKG_VERSION");

    for inc in incidents {
        let mitre = crate::models::map_to_mitre(&inc.severity, inc.port, inc.payload.as_deref());
        let sev_num = match inc.severity.as_str() {
            "CRÍTICO" => 10,
            "SWEEP" => 8,
            "MÉDIO" => 6,
            "ALERTA" => 4,
            _ => 3,
        };
        let act = if banned_ips.contains(&inc.ip) { "blocked" } else { "alerted" };
        let msg = inc.payload.as_deref().unwrap_or(&inc.service).replace('|', "\\|");

        out.push_str(&format!(
            "CEF:0|Sentinela|HIDS|{}|{}|{}|{}|src={} dstPort={} proto=TCP act={} cs1={} cs1Label=Country cs2={} cs2Label=ISP cn1={} cn1Label=ThreatScore msg={}\n",
            version,
            mitre.id,
            mitre.name.replace('|', "\\|"),
            sev_num,
            inc.ip,
            inc.port,
            act,
            inc.country.replace(' ', "_"),
            inc.isp.replace(' ', "_"),
            inc.threat_score,
            msg
        ));
    }
    out
}

/// Gera formato Syslog RFC 5424 compatível com rsyslog, syslog-ng, Logstash e Graylog
pub fn generate_syslog_rfc5424(incidents: &[Incident], banned_ips: &std::collections::HashSet<String>, hostname: &str) -> String {
    let mut out = String::new();
    let pid = std::process::id();

    for inc in incidents {
        let mitre = crate::models::map_to_mitre(&inc.severity, inc.port, inc.payload.as_deref());
        let pri = match inc.severity.as_str() {
            "CRÍTICO" | "SWEEP" => 130, // local0.crit (16*8 + 2)
            "MÉDIO" => 132,            // local0.warning (16*8 + 4)
            _ => 134,                  // local0.info (16*8 + 6)
        };
        let is_banned = if banned_ips.contains(&inc.ip) { "true" } else { "false" };
        let payload = inc.payload.as_deref().unwrap_or("-");

        // Formato RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [STRUCTURED-DATA] MSG
        let iso_time = inc.timestamp.replace(' ', "T") + "Z";
        out.push_str(&format!(
            "<{}>1 {} {} sentinela {} {} [incident@sentinela src=\"{}\" dstPort=\"{}\" severity=\"{}\" score=\"{}\" hits=\"{}\" banned=\"{}\" mitre=\"{}\"] {} probe detected: {}\n",
            pri,
            iso_time,
            hostname,
            pid,
            mitre.id,
            inc.ip,
            inc.port,
            inc.severity,
            inc.threat_score,
            inc.hit_count,
            is_banned,
            mitre.id,
            inc.service,
            payload
        ));
    }
    out
}

/// Exporta todos os incidentes registados na sessão para relatórios estruturados JSON, CSV, captura PCAP (Wireshark), CEF, Syslog RFC 5424, Markdown e HTML.
#[allow(clippy::type_complexity)]
pub fn export_threat_report(
    incidents: &[Incident],
    banned_ips: &std::collections::HashSet<String>,
    whitelisted_ips: &std::collections::HashSet<String>,
    sys_info: &SysInfo,
    _lang: Language,
) -> Result<(String, String, String, String, String, String, String), String> {
    let now = chrono::Local::now();
    let base_name = now.format("sentinela_report_%Y-%m-%d_%H-%M-%S").to_string();
    let json_name = format!("{}.json", base_name);
    let csv_name = format!("{}.csv", base_name);
    let pcap_name = format!("{}.pcap", base_name);
    let cef_name = format!("{}.cef", base_name);
    let syslog_name = format!("{}.syslog", base_name);

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

    crate::pcap::write_pcap_file(&pcap_name, incidents)?;

    let cef_content = generate_cef(incidents, banned_ips);
    std::fs::write(&cef_name, cef_content).map_err(|e| format!("Erro ao gravar CEF: {}", e))?;

    let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "sentinela-node".to_string());
    let syslog_content = generate_syslog_rfc5424(incidents, banned_ips, &hostname);
    std::fs::write(&syslog_name, syslog_content).map_err(|e| format!("Erro ao gravar Syslog: {}", e))?;

    let now_str = now.to_rfc3339();
    let md_content = generate_markdown_report(incidents, banned_ips, whitelisted_ips, sys_info, &now_str);
    let md_name = format!("{}.md", base_name);
    std::fs::write(&md_name, md_content).map_err(|e| format!("Erro ao gravar Markdown: {}", e))?;

    let html_content = generate_html_report(incidents, banned_ips, whitelisted_ips, sys_info, &now_str);
    let html_name = format!("{}.html", base_name);
    std::fs::write(&html_name, html_content).map_err(|e| format!("Erro ao gravar HTML: {}", e))?;

    Ok((json_name, csv_name, pcap_name, cef_name, syslog_name, md_name, html_name))
}

/// Gera um relatório executivo de Threat Intelligence estruturado em formato Markdown profissional
pub fn generate_markdown_report(
    incidents: &[Incident],
    banned_ips: &std::collections::HashSet<String>,
    whitelisted_ips: &std::collections::HashSet<String>,
    sys_info: &SysInfo,
    now_str: &str,
) -> String {
    let mut unique_ips = std::collections::HashSet::new();
    let mut max_score = 0;
    let mut mitre_counts: std::collections::HashMap<String, (String, String, usize)> = std::collections::HashMap::new();
    let mut port_counts: std::collections::HashMap<u16, (String, usize)> = std::collections::HashMap::new();

    for inc in incidents {
        unique_ips.insert(&inc.ip);
        if inc.threat_score > max_score {
            max_score = inc.threat_score;
        }
        let mitre = crate::models::map_to_mitre(&inc.severity, inc.port, inc.payload.as_deref());
        let entry = mitre_counts.entry(mitre.id.clone()).or_insert((mitre.name, mitre.tactic, 0));
        entry.2 += 1;

        let p_entry = port_counts.entry(inc.port).or_insert((inc.service.clone(), 0));
        p_entry.1 += inc.hit_count.max(1);
    }

    let mut md = String::new();
    md.push_str("# 🛡️ Sentinela — Relatório Executivo de Incidentes e Threat Intelligence\n\n");
    md.push_str(&format!("**Data de Geração:** `{}`  \n", now_str));
    md.push_str(&format!("**Versão:** `v{}`  \n", env!("CARGO_PKG_VERSION")));
    md.push_str(&format!("**Sistema Anfitrião:** {} ({}) | Kernel {}\n\n", sys_info.distro, sys_info.arch, sys_info.kernel));
    md.push_str("---\n\n");

    md.push_str("## 1. Resumo Executivo da Sessão\n\n");
    md.push_str("| Métrica | Valor |\n|---|---|\n");
    md.push_str(&format!("| **Total de Incidentes Capturados** | {} |\n", incidents.len()));
    md.push_str(&format!("| **Endereços IP Maliciosos Únicos** | {} |\n", unique_ips.len()));
    md.push_str(&format!("| **IPs Bloqueados no Firewall (DROP)** | {} |\n", banned_ips.len()));
    md.push_str(&format!("| **IPs Confiáveis na Whitelist** | {} |\n", whitelisted_ips.len()));
    md.push_str(&format!("| **Threat Score Máximo Registado** | {} / 100 |\n\n", max_score));

    md.push_str("## 2. Mapeamento da Matriz MITRE ATT&CK®\n\n");
    md.push_str("| ID Técnica | Nome da Técnica | Tática | Ocorrências |\n|---|---|---|---|\n");
    let mut sorted_mitre: Vec<(&String, &(String, String, usize))> = mitre_counts.iter().collect();
    sorted_mitre.sort_by_key(|a| std::cmp::Reverse(a.1 .2));
    for (id, (name, tactic, count)) in sorted_mitre {
        md.push_str(&format!("| `{}` | {} | {} | **{}** |\n", id, name, tactic, count));
    }
    if mitre_counts.is_empty() {
        md.push_str("| - | Nenhuma técnica identificada | - | 0 |\n");
    }
    md.push('\n');

    md.push_str("## 3. Top Portas e Armadilhas Visadas\n\n");
    md.push_str("| Porto | Serviço / Protocolo | Total de Hits |\n|---|---|---|\n");
    let mut sorted_ports: Vec<(&u16, &(String, usize))> = port_counts.iter().collect();
    sorted_ports.sort_by_key(|a| std::cmp::Reverse(a.1 .1));
    for (port, (svc, hits)) in sorted_ports.iter().take(8) {
        md.push_str(&format!("| `{}` | {} | **{}** |\n", port, svc, hits));
    }
    if port_counts.is_empty() {
        md.push_str("| - | Nenhuma atividade de porto registada | 0 |\n");
    }
    md.push('\n');

    md.push_str("## 4. Top Ameaças e Atacantes Identificados\n\n");
    md.push_str("| Endereço IP | País / Cidade | ISP / Organização | Threat Score | Hits | Firewall |\n|---|---|---|---|---|---|\n");
    let mut top_incidents = incidents.to_vec();
    top_incidents.sort_by_key(|a| std::cmp::Reverse(a.threat_score));
    let mut seen_ips = std::collections::HashSet::new();
    for inc in top_incidents.iter().filter(|i| seen_ips.insert(&i.ip)).take(15) {
        let is_banned = if banned_ips.contains(&inc.ip) { "⛔ BLOQUEADO" } else { "⚠️ ATIVO" };
        let geo = format!("{} ({})", inc.country, inc.city);
        md.push_str(&format!(
            "| `{}` | {} | {} | **{}/100** | {} | {} |\n",
            inc.ip, geo, inc.isp, inc.threat_score, inc.hit_count, is_banned
        ));
    }
    if incidents.is_empty() {
        md.push_str("| - | - | - | - | - | - |\n");
    }
    md.push('\n');

    md.push_str("## 5. Medidas de Mitigação e Comandos de Firewall Recomendados\n\n");
    md.push_str("```bash\n# Executar no terminal do host (com privilégios de root) para bloquear atacantes de alto risco:\n");
    for ip in banned_ips {
        md.push_str(&format!("iptables -A INPUT -s {} -j DROP\n", ip));
    }
    for inc in top_incidents.iter().filter(|i| i.threat_score >= 80 && !banned_ips.contains(&i.ip)).take(5) {
        md.push_str(&format!("iptables -A INPUT -s {} -j DROP  # Score: {} ({})\n", inc.ip, inc.threat_score, inc.service));
    }
    md.push_str("```\n\n");
    md.push_str("---\n*Relatório gerado automaticamente pelo **Sentinela HIDS & Honeypot** — Desenvolvido por Salvador Pontes.*\n");

    md
}

/// Gera um relatório executivo de Threat Intelligence estruturado em formato HTML interativo com design Dark SOC
pub fn generate_html_report(
    incidents: &[Incident],
    banned_ips: &std::collections::HashSet<String>,
    _whitelisted_ips: &std::collections::HashSet<String>,
    sys_info: &SysInfo,
    now_str: &str,
) -> String {
    let mut unique_ips = std::collections::HashSet::new();
    let mut max_score = 0;
    for inc in incidents {
        unique_ips.insert(&inc.ip);
        if inc.threat_score > max_score {
            max_score = inc.threat_score;
        }
    }

    let mut html = String::new();
    html.push_str("<!DOCTYPE html>\n<html lang=\"pt\">\n<head>\n<meta charset=\"UTF-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
    html.push_str("<title>Sentinela - Relatório Executivo de Ameaças</title>\n");
    html.push_str("<style>\n");
    html.push_str("body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0b0f19; color: #e2e8f0; margin: 0; padding: 24px; }\n");
    html.push_str(".container { max-width: 1100px; margin: 0 auto; }\n");
    html.push_str(".header { background: linear-gradient(135deg, #1e1b4b 0%, #0f172a 100%); border: 1px solid #312e81; border-radius: 12px; padding: 24px; margin-bottom: 24px; }\n");
    html.push_str(".header h1 { margin: 0 0 8px 0; color: #38bdf8; font-size: 26px; display: flex; align-items: center; gap: 10px; }\n");
    html.push_str(".meta { color: #94a3b8; font-size: 13px; }\n");
    html.push_str(".grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }\n");
    html.push_str(".card { background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 18px; text-align: center; }\n");
    html.push_str(".card-val { font-size: 32px; font-weight: bold; color: #f8fafc; margin-top: 6px; }\n");
    html.push_str(".card-val.crit { color: #ef4444; }\n");
    html.push_str(".card-val.warn { color: #f59e0b; }\n");
    html.push_str(".card-val.safe { color: #10b981; }\n");
    html.push_str(".card-lbl { color: #94a3b8; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; }\n");
    html.push_str("table { width: 100%; border-collapse: collapse; margin-bottom: 24px; background: #1e293b; border-radius: 8px; overflow: hidden; }\n");
    html.push_str("th, td { padding: 12px 16px; text-align: left; border-bottom: 1px solid #334155; font-size: 14px; }\n");
    html.push_str("th { background: #0f172a; color: #38bdf8; font-weight: 600; text-transform: uppercase; font-size: 12px; }\n");
    html.push_str("tr:hover { background: #283548; }\n");
    html.push_str(".badge { display: inline-block; padding: 3px 8px; border-radius: 6px; font-size: 11px; font-weight: bold; }\n");
    html.push_str(".badge-crit { background: #7f1d1d; color: #fecaca; border: 1px solid #b91c1c; }\n");
    html.push_str(".badge-high { background: #7c2d12; color: #fed7aa; border: 1px solid #c2410c; }\n");
    html.push_str(".badge-med { background: #713f12; color: #fef08a; border: 1px solid #a16207; }\n");
    html.push_str(".badge-low { background: #164e63; color: #a5f3fc; border: 1px solid #0891b2; }\n");
    html.push_str(".badge-ban { background: #450a0a; color: #fca5a5; }\n");
    html.push_str(".code-block { background: #020617; border: 1px solid #1e293b; border-radius: 8px; padding: 16px; font-family: monospace; font-size: 13px; color: #38bdf8; overflow-x: auto; }\n");
    html.push_str("footer { text-align: center; color: #64748b; font-size: 12px; margin-top: 32px; }\n");
    html.push_str("</style>\n</head>\n<body>\n<div class=\"container\">\n");

    html.push_str("<div class=\"header\">\n");
    html.push_str(&format!("<h1>🛡️ Sentinela SOC — Relatório de Incidentes v{}</h1>\n", env!("CARGO_PKG_VERSION")));
    html.push_str(&format!("<div class=\"meta\">Gerado em: <strong>{}</strong> | Sistema: <strong>{} ({}) - Kernel {}</strong></div>\n", now_str, sys_info.distro, sys_info.arch, sys_info.kernel));
    html.push_str("</div>\n");

    html.push_str("<div class=\"grid\">\n");
    html.push_str(&format!("<div class=\"card\"><div class=\"card-lbl\">Total Incidentes</div><div class=\"card-val\">{}</div></div>\n", incidents.len()));
    html.push_str(&format!("<div class=\"card\"><div class=\"card-lbl\">Atacantes Únicos</div><div class=\"card-val warn\">{}</div></div>\n", unique_ips.len()));
    html.push_str(&format!("<div class=\"card\"><div class=\"card-lbl\">IPs Bloqueados</div><div class=\"card-val crit\">{}</div></div>\n", banned_ips.len()));
    html.push_str(&format!("<div class=\"card\"><div class=\"card-lbl\">Score Máximo</div><div class=\"card-val crit\">{}/100</div></div>\n", max_score));
    html.push_str("</div>\n");

    html.push_str("<h2>Incidentes e Ameaças Registadas</h2>\n");
    html.push_str("<table><thead><tr><th>Timestamp</th><th>IP de Origem</th><th>Porto</th><th>Serviço</th><th>Gravidade</th><th>Score</th><th>País</th><th>ISP</th><th>Mitre ATT&CK</th><th>Ação</th></tr></thead><tbody>\n");
    for inc in incidents.iter().take(30) {
        let (badge_class, sev_label) = match inc.severity.as_str() {
            "CRÍTICO" | "SWEEP" => ("badge-crit", "CRÍTICO"),
            "SCAN" => ("badge-high", "SCAN"),
            "MÉDIO" => ("badge-med", "MÉDIO"),
            _ => ("badge-low", "ALERTA"),
        };
        let is_banned = banned_ips.contains(&inc.ip);
        let action_badge = if is_banned { "<span class=\"badge badge-ban\">⛔ DROP</span>" } else { "<span class=\"meta\">Monitorizado</span>" };
        let mitre = crate::models::map_to_mitre(&inc.severity, inc.port, inc.payload.as_deref());

        html.push_str(&format!(
            "<tr><td><code>{}</code></td><td><strong><code>{}</code></strong></td><td>{}</td><td>{}</td><td><span class=\"badge {}\">{}</span></td><td><strong>{}</strong></td><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td></tr>\n",
            inc.timestamp, inc.ip, inc.port, inc.service, badge_class, sev_label, inc.threat_score, inc.country, inc.isp, mitre.id, action_badge
        ));
    }
    if incidents.is_empty() {
        html.push_str("<tr><td colspan=\"10\" style=\"text-align:center;color:#64748b;\">Nenhum incidente registado nesta sessão</td></tr>\n");
    }
    html.push_str("</tbody></table>\n");

    html.push_str("<h2>Comandos de Mitigação no Firewall</h2>\n");
    html.push_str("<div class=\"code-block\">\n# Bloquear imediatamente atacantes com elevado risco via iptables:<br>\n");
    for ip in banned_ips {
        html.push_str(&format!("iptables -A INPUT -s {} -j DROP<br>\n", ip));
    }
    for inc in incidents.iter().filter(|i| i.threat_score >= 80 && !banned_ips.contains(&i.ip)).take(5) {
        html.push_str(&format!("iptables -A INPUT -s {} -j DROP  # Score: {} ({})<br>\n", inc.ip, inc.threat_score, inc.service));
    }
    html.push_str("</div>\n");

    html.push_str("<footer>Relatório gerado automaticamente pelo <strong>Sentinela HIDS</strong> | Desenvolvido por Salvador Pontes</footer>\n");
    html.push_str("</div>\n</body>\n</html>\n");

    html
}

/// Decodifica endereço IPv4 codificado em hexadecimal (ordem little-endian no Linux /proc/net/tcp)
pub fn parse_ipv4_hex(hex_str: &str) -> Option<String> {
    if hex_str.len() != 8 {
        return None;
    }
    let b3 = u8::from_str_radix(&hex_str[6..8], 16).ok()?;
    let b2 = u8::from_str_radix(&hex_str[4..6], 16).ok()?;
    let b1 = u8::from_str_radix(&hex_str[2..4], 16).ok()?;
    let b0 = u8::from_str_radix(&hex_str[0..2], 16).ok()?;
    Some(format!("{}.{}.{}.{}", b3, b2, b1, b0))
}

/// Decodifica endereço IPv6 codificado em hexadecimal no Linux /proc/net/tcp6
pub fn parse_ipv6_hex(hex_str: &str) -> Option<String> {
    if hex_str.len() != 32 {
        return None;
    }
    if hex_str.chars().all(|c| c == '0') {
        return Some("::".to_string());
    }
    let mut bytes = [0u8; 16];
    for w in 0..4 {
        let chunk = &hex_str[w * 8..(w + 1) * 8];
        bytes[w * 4] = u8::from_str_radix(&chunk[6..8], 16).ok()?;
        bytes[w * 4 + 1] = u8::from_str_radix(&chunk[4..6], 16).ok()?;
        bytes[w * 4 + 2] = u8::from_str_radix(&chunk[2..4], 16).ok()?;
        bytes[w * 4 + 3] = u8::from_str_radix(&chunk[0..2], 16).ok()?;
    }
    let ip = std::net::Ipv6Addr::from(bytes);
    Some(ip.to_string())
}

/// Converte o código de estado TCP do kernel (/proc/net/tcp) para formato textual padrão (ss/netstat)
pub fn translate_tcp_state(st_hex: &str) -> &'static str {
    match st_hex {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        _ => "UNKNOWN",
    }
}

/// Converte o código de estado UDP para formato legível
pub fn translate_udp_state(st_hex: &str) -> &'static str {
    match st_hex {
        "01" => "ESTABLISHED",
        "07" => "UNCONN",
        _ => "UNCONN",
    }
}

/// Mapeia cada inode de socket ao respetivo processo e PID lendo os descritores em /proc/[pid]/fd
#[cfg(target_os = "linux")]
pub fn build_inode_process_map() -> std::collections::HashMap<u64, String> {
    let mut map = std::collections::HashMap::new();
    let proc_dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return map,
    };

    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }

        let pid_path = entry.path();
        let comm_path = pid_path.join("comm");
        let comm = std::fs::read_to_string(&comm_path)
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| name_str.to_string());

        let fd_path = pid_path.join("fd");
        if let Ok(fds) = std::fs::read_dir(fd_path) {
            for fd_entry in fds.flatten() {
                if let Ok(link) = std::fs::read_link(fd_entry.path()) {
                    let link_str = link.to_string_lossy();
                    if link_str.starts_with("socket:[") && link_str.ends_with(']') {
                        let inode_str = &link_str[8..link_str.len() - 1];
                        if let Ok(inode) = inode_str.parse::<u64>() {
                            map.insert(inode, format!("{} ({})", comm, name_str));
                        }
                    }
                }
            }
        }
    }
    map
}

#[cfg(not(target_os = "linux"))]
pub fn build_inode_process_map() -> std::collections::HashMap<u64, String> {
    std::collections::HashMap::new()
}

/// Obtém a lista atualizada de conexões e sockets ativos no sistema hospedeiro
pub fn get_active_sockets(trap_ports: &[u16]) -> Vec<SocketInfo> {
    let mut sockets = Vec::new();
    let inode_map = build_inode_process_map();

    let files = [
        ("/proc/net/tcp", "TCP", true),
        ("/proc/net/tcp6", "TCP6", true),
        ("/proc/net/udp", "UDP", false),
        ("/proc/net/udp6", "UDP6", false),
    ];

    for (file_path, proto, is_tcp) in files {
        if let Ok(content) = std::fs::read_to_string(file_path) {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 10 {
                    continue;
                }

                let local_parts: Vec<&str> = parts[1].split(':').collect();
                let rem_parts: Vec<&str> = parts[2].split(':').collect();
                if local_parts.len() != 2 || rem_parts.len() != 2 {
                    continue;
                }

                let local_ip = if proto.ends_with('6') {
                    parse_ipv6_hex(local_parts[0]).unwrap_or_else(|| local_parts[0].to_string())
                } else {
                    parse_ipv4_hex(local_parts[0]).unwrap_or_else(|| local_parts[0].to_string())
                };

                let local_port = u16::from_str_radix(local_parts[1], 16).unwrap_or(0);

                let foreign_ip = if proto.ends_with('6') {
                    parse_ipv6_hex(rem_parts[0]).unwrap_or_else(|| rem_parts[0].to_string())
                } else {
                    parse_ipv4_hex(rem_parts[0]).unwrap_or_else(|| rem_parts[0].to_string())
                };

                let foreign_port = u16::from_str_radix(rem_parts[1], 16).unwrap_or(0);

                let state = if is_tcp {
                    translate_tcp_state(parts[3]).to_string()
                } else {
                    translate_udp_state(parts[3]).to_string()
                };

                let inode = parts[9].parse::<u64>().unwrap_or(0);
                let pid_process = inode_map.get(&inode).cloned().unwrap_or_else(|| "-".to_string());

                let is_honeypot = trap_ports.contains(&local_port);

                let is_external = if foreign_ip != "0.0.0.0" && foreign_ip != "::" && foreign_port > 0 {
                    if let Ok(parsed_ip) = foreign_ip.parse::<std::net::IpAddr>() {
                        !is_private_or_local(parsed_ip) && !parsed_ip.is_loopback()
                    } else {
                        false
                    }
                } else {
                    false
                };

                let local_addr = format!("{}:{}", local_ip, local_port);
                let foreign_addr = if foreign_port == 0 && (foreign_ip == "0.0.0.0" || foreign_ip == "::") {
                    "*:*".to_string()
                } else {
                    format!("{}:{}", foreign_ip, foreign_port)
                };

                sockets.push(SocketInfo {
                    proto: proto.to_string(),
                    state,
                    local_addr,
                    foreign_addr,
                    pid_process,
                    is_honeypot,
                    is_external,
                });
            }
        }
    }

    // Ordenar: primeiro Honeypots, depois conexões Externas, depois Listeners locais
    sockets.sort_by(|a, b| {
        let score_a = if a.is_honeypot { 3 } else if a.is_external { 2 } else if a.state == "LISTEN" { 1 } else { 0 };
        let score_b = if b.is_honeypot { 3 } else if b.is_external { 2 } else if b.state == "LISTEN" { 1 } else { 0 };
        score_b.cmp(&score_a).then_with(|| a.local_addr.cmp(&b.local_addr))
    });

    sockets
}

/// Deteta alterações suspeitas ou falsificação de endereços na tabela ARP do sistema (Ataques MITM / ARP Poisoning)
pub fn check_arp_table(
    known_arp: &mut std::collections::HashMap<String, (String, String)>,
) -> Vec<crate::models::Incident> {
    let mut alerts = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/net/arp") {
            let mut current_mac_to_ip: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();

            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 6 {
                    continue;
                }
                let ip = parts[0];
                let flags = parts[2];
                let mac = parts[3].to_lowercase();
                let dev = parts[5];

                // Ignora entradas incompletas ou inválidas
                if flags == "0x0" || mac == "00:00:00:00:00:00" || mac.len() != 17 {
                    continue;
                }

                current_mac_to_ip
                    .entry(format!("{}_{}", mac, dev))
                    .or_default()
                    .push(ip.to_string());

                if let Some((old_mac, old_dev)) = known_arp.get(ip) {
                    if old_dev == dev && old_mac != &mac {
                        let payload_msg = format!(
                            "POSSÍVEL ATAQUE MITM / ARP CACHE POISONING!\nO IP '{}' na interface '{}' mudou de MAC:\n  Anterior: {}\n  Atual:    {}\nMITRE ATT&CK: T1557.002",
                            ip, dev, old_mac, mac
                        );
                        alerts.push(crate::models::Incident {
                            timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                            ip: ip.to_string(),
                            port: 0,
                            service: "ARP Guard (MITM)".to_string(),
                            severity: "CRÍTICO".to_string(),
                            country: "Rede Local (LAN)".to_string(),
                            city: dev.to_string(),
                            isp: "Interface Local".to_string(),
                            rdns: None,
                            payload: Some(payload_msg),
                            threat_score: 95,
                            hit_count: 1,
                        });
                    }
                }

                // Atualiza / regista o mapeamento conhecido
                known_arp.insert(ip.to_string(), (mac, dev.to_string()));
            }

            // Deteção adicional: se um mesmo MAC físico estiver a responder por múltiplos IPs distintos na mesma interface
            for (mac_dev, ips) in current_mac_to_ip {
                if ips.len() >= 3 {
                    let parts: Vec<&str> = mac_dev.split('_').collect();
                    let mac = parts[0];
                    let dev = if parts.len() > 1 { parts[1] } else { "" };
                    if !dev.starts_with("docker") && !dev.starts_with("br-") && !dev.starts_with("virbr") {
                        let payload_msg = format!(
                            "ALERTA ARP SPOOFING / DUPLICAÇÃO DE MAC!\nO MAC '{}' na interface '{}' está associado a múltiplos IPs ({:?}).\nPossível nó a intercetar todo o tráfego da subnet.",
                            mac, dev, ips
                        );
                        let first_ip = ips[0].clone();
                        if !alerts.iter().any(|a| a.ip == first_ip) {
                            alerts.push(crate::models::Incident {
                                timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                                ip: first_ip,
                                port: 0,
                                service: "ARP Guard (Clone)".to_string(),
                                severity: "CRÍTICO".to_string(),
                                country: "Rede Local (LAN)".to_string(),
                                city: dev.to_string(),
                                isp: "Interface Local".to_string(),
                                rdns: None,
                                payload: Some(payload_msg),
                                threat_score: 90,
                                hit_count: 1,
                            });
                        }
                    }
                }
            }
        }
    }

    alerts
}

/// Termina cirurgicamente um processo no sistema operacional com base no PID
pub fn kill_process_by_pid(pid: u32) -> Result<String, String> {
    if pid <= 1 {
        return Err("Não é permitido terminar o processo init / systemd (PID <= 1)".to_string());
    }
    let my_pid = std::process::id();
    if pid == my_pid {
        return Err("Não é permitido auto-terminar o processo do Sentinela".to_string());
    }

    #[cfg(target_os = "linux")]
    {
        let status = std::process::Command::new("kill")
            .args(["-9", &pid.to_string()])
            .status();

        match status {
            Ok(s) if s.success() => Ok(format!("Processo PID {} terminado com sucesso (SIGKILL)", pid)),
            Ok(s) => Err(format!("Falha ao terminar processo PID {} (código {})", pid, s.code().unwrap_or(-1))),
            Err(e) => Err(format!("Erro ao executar kill no PID {}: {}", pid, e)),
        }
    }

    #[cfg(target_os = "windows")]
    {
        let status = std::process::Command::new("taskkill")
            .args(["/F", "/PID", &pid.to_string()])
            .status();

        match status {
            Ok(s) if s.success() => Ok(format!("Processo PID {} terminado com sucesso (Taskkill)", pid)),
            Ok(s) => Err(format!("Falha ao terminar processo PID {}", pid)),
            Err(e) => Err(format!("Erro ao executar taskkill no PID {}: {}", pid, e)),
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = pid;
        Err("Terminação de processos não suportada nesta plataforma".to_string())
    }
}

/// Deteta se existem outras instâncias do executável Sentinela em execução no sistema.
pub fn find_other_sentinela_instances() -> Vec<u32> {
    let mut instances = Vec::new();
    let my_pid = std::process::id();

    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if let Ok(pid) = name_str.parse::<u32>() {
                    if pid == my_pid || pid <= 1 {
                        continue;
                    }
                    let comm_path = entry.path().join("comm");
                    if let Ok(comm) = std::fs::read_to_string(&comm_path) {
                        let comm_trimmed = comm.trim();
                        if comm_trimmed == "sentinela" {
                            instances.push(pid);
                            continue;
                        }
                    }
                    // Verificação secundária via cmdline caso o processo tenha sido invocado com caminho direto
                    let cmdline_path = entry.path().join("cmdline");
                    if let Ok(cmdline) = std::fs::read_to_string(&cmdline_path) {
                        if let Some(first_arg) = cmdline.split('\0').next() {
                            if first_arg.ends_with("/sentinela") || first_arg == "sentinela" {
                                instances.push(pid);
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        // Em outras plataformas
    }

    instances.sort_unstable();
    instances.dedup();
    instances
}

#[derive(Clone, Debug, Default)]
pub struct NetworkThroughput {
    pub rx_bytes_per_sec: f64,
    pub tx_bytes_per_sec: f64,
    #[allow(dead_code)]
    pub rx_packets_per_sec: f64,
    #[allow(dead_code)]
    pub tx_packets_per_sec: f64,
}

#[derive(Clone, Debug)]
pub struct ThroughputSampler {
    pub last_sample_time: Option<std::time::Instant>,
    pub last_rx_bytes: u64,
    pub last_tx_bytes: u64,
    pub last_rx_packets: u64,
    pub last_tx_packets: u64,
    pub rx_history: Vec<u64>,
    pub tx_history: Vec<u64>,
}

impl Default for ThroughputSampler {
    fn default() -> Self {
        Self {
            last_sample_time: None,
            last_rx_bytes: 0,
            last_tx_bytes: 0,
            last_rx_packets: 0,
            last_tx_packets: 0,
            rx_history: Vec::new(),
            tx_history: Vec::new(),
        }
    }
}

/// Amostra o débito de rede (RX/TX bytes e pacotes por segundo) lendo /proc/net/dev no Linux
pub fn sample_network_throughput(sampler: &mut ThroughputSampler) -> NetworkThroughput {
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/net/dev") {
            let mut total_rx_bytes = 0u64;
            let mut total_tx_bytes = 0u64;
            let mut total_rx_packets = 0u64;
            let mut total_tx_packets = 0u64;

            for line in content.lines().skip(2) {
                if let Some((iface, data)) = line.split_once(':') {
                    let iface_name = iface.trim();
                    if iface_name == "lo" {
                        continue;
                    }

                    let fields: Vec<&str> = data.split_whitespace().collect();
                    if fields.len() >= 9 {
                        let rx_b = fields[0].parse::<u64>().unwrap_or(0);
                        let rx_p = fields[1].parse::<u64>().unwrap_or(0);
                        let tx_b = fields[8].parse::<u64>().unwrap_or(0);
                        let tx_p = fields[9].parse::<u64>().unwrap_or(0);

                        total_rx_bytes += rx_b;
                        total_rx_packets += rx_p;
                        total_tx_bytes += tx_b;
                        total_tx_packets += tx_p;
                    }
                }
            }

            let now = std::time::Instant::now();
            if let Some(prev_time) = sampler.last_sample_time {
                let delta = now.duration_since(prev_time).as_secs_f64();
                if delta > 0.05 {
                    let rx_diff = total_rx_bytes.saturating_sub(sampler.last_rx_bytes);
                    let tx_diff = total_tx_bytes.saturating_sub(sampler.last_tx_bytes);
                    let rx_p_diff = total_rx_packets.saturating_sub(sampler.last_rx_packets);
                    let tx_p_diff = total_tx_packets.saturating_sub(sampler.last_tx_packets);

                    let rx_rate = rx_diff as f64 / delta;
                    let tx_rate = tx_diff as f64 / delta;

                    sampler.rx_history.push((rx_rate / 1024.0) as u64);
                    sampler.tx_history.push((tx_rate / 1024.0) as u64);
                    if sampler.rx_history.len() > 30 {
                        sampler.rx_history.remove(0);
                    }
                    if sampler.tx_history.len() > 30 {
                        sampler.tx_history.remove(0);
                    }

                    sampler.last_sample_time = Some(now);
                    sampler.last_rx_bytes = total_rx_bytes;
                    sampler.last_tx_bytes = total_tx_bytes;
                    sampler.last_rx_packets = total_rx_packets;
                    sampler.last_tx_packets = total_tx_packets;

                    return NetworkThroughput {
                        rx_bytes_per_sec: rx_rate,
                        tx_bytes_per_sec: tx_rate,
                        rx_packets_per_sec: rx_p_diff as f64 / delta,
                        tx_packets_per_sec: tx_p_diff as f64 / delta,
                    };
                }
            }

            sampler.last_sample_time = Some(now);
            sampler.last_rx_bytes = total_rx_bytes;
            sampler.last_tx_bytes = total_tx_bytes;
            sampler.last_rx_packets = total_rx_packets;
            sampler.last_tx_packets = total_tx_packets;
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = sampler;
    }

    NetworkThroughput::default()
}

/// Formata taxa de transferência de bytes por segundo em formato legível (B/s, KB/s, MB/s)
pub fn format_bandwidth(bytes_per_sec: f64) -> String {
    if bytes_per_sec < 1024.0 {
        format!("{:.0} B/s", bytes_per_sec)
    } else if bytes_per_sec < 1024.0 * 1024.0 {
        format!("{:.1} KB/s", bytes_per_sec / 1024.0)
    } else {
        format!("{:.2} MB/s", bytes_per_sec / (1024.0 * 1024.0))
    }
}

/// Calcula a entropia de Shannon de uma sequência de caracteres (usada para detetar dados ofuscados/cifrados)
#[allow(dead_code)]
pub fn calculate_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq = [0usize; 256];
    let mut len = 0;
    for b in s.bytes() {
        freq[b as usize] += 1;
        len += 1;
    }
    let len_f = len as f32;
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f32 / len_f;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Avalia se um nome de domínio DNS (QNAME) apresenta padrões de DNS Tunneling / Exfiltração de dados
#[allow(dead_code)]
pub fn evaluate_dns_tunneling(qname: &str) -> Option<(f32, &'static str)> {
    let clean = qname.trim().trim_end_matches('.');
    if clean.is_empty() {
        return None;
    }

    let labels: Vec<&str> = clean.split('.').collect();
    for label in &labels {
        if label.len() >= 18 {
            let entropy = calculate_entropy(label);
            if entropy >= 3.4 || label.len() >= 32 {
                return Some((entropy, "Alta entropia / Exfiltração de dados"));
            }
            let is_hex = label.len() >= 24 && label.chars().all(|c| c.is_ascii_hexdigit());
            if is_hex {
                return Some((entropy, "Possível túnel DNS (Codificação Hexadecimal)"));
            }
        }
    }

    if clean.len() >= 45 {
        let entropy = calculate_entropy(clean);
        if entropy >= 3.3 {
            return Some((entropy, "Comprimento anormal e entropia de túnel DNS"));
        }
    }

    None
}

/// Extrai os maiores geradores de tráfego (Top Talkers) ordenados por número de incidentes/hits
pub fn get_top_talkers(incidents: &[Incident], limit: usize) -> Vec<(String, usize, String, String, u8)> {
    let mut stats: std::collections::HashMap<String, (usize, String, String, u8)> = std::collections::HashMap::new();

    for inc in incidents {
        let entry = stats.entry(inc.ip.clone()).or_insert((0, inc.country.clone(), inc.isp.clone(), inc.threat_score));
        entry.0 += inc.hit_count.max(1);
        if inc.threat_score > entry.3 {
            entry.3 = inc.threat_score;
        }
    }

    let mut list: Vec<(String, usize, String, String, u8)> = stats
        .into_iter()
        .map(|(ip, (hits, country, isp, score))| (ip, hits, country, isp, score))
        .collect();

    list.sort_by(|a, b| b.1.cmp(&a.1));
    list.truncate(limit);
    list
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
        let (json_file, csv_file, pcap_file, cef_file, syslog_file, md_file, html_file) = res.unwrap();

        // Verifica existência e conteúdo dos ficheiros
        assert!(std::path::Path::new(&json_file).exists());
        assert!(std::path::Path::new(&csv_file).exists());
        assert!(std::path::Path::new(&pcap_file).exists());
        assert!(std::path::Path::new(&cef_file).exists());
        assert!(std::path::Path::new(&syslog_file).exists());
        assert!(std::path::Path::new(&md_file).exists());
        assert!(std::path::Path::new(&html_file).exists());

        let json_content = std::fs::read_to_string(&json_file).unwrap();
        assert!(json_content.contains("192.168.1.150"));
        assert!(json_content.contains("gateway.lan"));

        let csv_content = std::fs::read_to_string(&csv_file).unwrap();
        assert!(csv_content.contains("MitreID,MitreTactic"));
        assert!(csv_content.contains("Whitelisted"));
        assert!(csv_content.contains("gateway.lan"));
        assert!(csv_content.contains("SSH-2.0-OpenSSH_9.0"));
        assert!(csv_content.contains("\"SIM\""));

        let cef_content = std::fs::read_to_string(&cef_file).unwrap();
        assert!(cef_content.contains("CEF:0|Sentinela|HIDS"));
        assert!(cef_content.contains("src=192.168.1.150"));

        let syslog_content = std::fs::read_to_string(&syslog_file).unwrap();
        assert!(syslog_content.contains("sentinela"));
        assert!(syslog_content.contains("src=\"192.168.1.150\""));

        let md_content = std::fs::read_to_string(&md_file).unwrap();
        assert!(md_content.contains("Relatório Executivo de Incidentes"));
        assert!(md_content.contains("192.168.1.150"));
        assert!(md_content.contains("T1110.001"));

        let html_content = std::fs::read_to_string(&html_file).unwrap();
        assert!(html_content.contains("Sentinela SOC"));
        assert!(html_content.contains("192.168.1.150"));

        // Limpeza dos ficheiros de teste
        let _ = std::fs::remove_file(json_file);
        let _ = std::fs::remove_file(csv_file);
        let _ = std::fs::remove_file(pcap_file);
        let _ = std::fs::remove_file(cef_file);
        let _ = std::fs::remove_file(syslog_file);
        let _ = std::fs::remove_file(md_file);
        let _ = std::fs::remove_file(html_file);
    }

    #[test]
    fn test_parse_hex_ips_and_socket_states() {
        assert_eq!(parse_ipv4_hex("0100007F").as_deref(), Some("127.0.0.1"));
        assert_eq!(parse_ipv4_hex("00000000").as_deref(), Some("0.0.0.0"));
        assert_eq!(parse_ipv4_hex("C9C814AC").as_deref(), Some("172.20.200.201"));
        assert_eq!(parse_ipv4_hex("INVALID"), None);

        assert_eq!(parse_ipv6_hex("00000000000000000000000000000000").as_deref(), Some("::"));
        assert_eq!(parse_ipv6_hex("00000000000000000000000001000000").as_deref(), Some("::1"));
        assert_eq!(parse_ipv6_hex("SHORT"), None);

        assert_eq!(translate_tcp_state("01"), "ESTABLISHED");
        assert_eq!(translate_tcp_state("0A"), "LISTEN");
        assert_eq!(translate_tcp_state("06"), "TIME_WAIT");
        assert_eq!(translate_udp_state("07"), "UNCONN");
    }

    #[test]
    fn test_get_active_sockets() {
        let trap_ports = [2121, 2222, 8080];
        let sockets = get_active_sockets(&trap_ports);
        // Em qualquer máquina Linux a correr o teste, existem sockets abertos
        assert!(!sockets.is_empty());
        for s in &sockets {
            assert!(!s.local_addr.is_empty());
            assert!(!s.proto.is_empty());
            assert!(!s.state.is_empty());
        }
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

    #[test]
    fn test_kill_process_safety_checks() {
        // PID 0 ou 1 não podem ser mortos por proteção
        assert!(kill_process_by_pid(0).is_err());
        assert!(kill_process_by_pid(1).is_err());
        // Sentinela não se pode auto-matar
        assert!(kill_process_by_pid(std::process::id()).is_err());
    }

    #[test]
    fn test_find_other_sentinela_instances() {
        let instances = find_other_sentinela_instances();
        let my_pid = std::process::id();
        assert!(!instances.contains(&my_pid));
        assert!(!instances.contains(&0));
        assert!(!instances.contains(&1));
    }

    #[test]
    fn test_check_arp_table_runs() {
        let mut known = std::collections::HashMap::new();
        let alerts = check_arp_table(&mut known);
        // Na primeira execução inicial, mapeia a tabela sem disparar falso positivo
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_calculate_entropy_and_dns_tunneling() {
        // String monótona tem entropia 0.0
        assert_eq!(calculate_entropy("aaaaaaaaaa"), 0.0);

        // String curta normal
        assert!(calculate_entropy("google") < 3.0);

        // Subdomínio normal não dispara alarme
        assert!(evaluate_dns_tunneling("www.google.com").is_none());
        assert!(evaluate_dns_tunneling("api.github.com").is_none());

        // Subdomínio longo com alta entropia (exfiltração / beaconing)
        let exfil_domain = "dGVzdF9leGZpbHRyYXRpb25fZGF0YV8xMjM0NTY=.tunnel.evil.com";
        let res = evaluate_dns_tunneling(exfil_domain);
        assert!(res.is_some());
        let (entropy, _) = res.unwrap();
        assert!(entropy >= 3.4);

        // Subdomínio hexadecimal longo (túnel tipo dnscat2)
        let hex_tunnel = "4a667364666b6c6a7364666b6c6a7364.c2.attacker.net";
        assert!(evaluate_dns_tunneling(hex_tunnel).is_some());
    }

    #[test]
    fn test_format_bandwidth() {
        assert_eq!(format_bandwidth(500.0), "500 B/s");
        assert_eq!(format_bandwidth(1500.0), "1.5 KB/s");
        assert_eq!(format_bandwidth(2_500_000.0), "2.38 MB/s");
    }

    #[test]
    fn test_sample_network_throughput_runs() {
        let mut sampler = ThroughputSampler::default();
        let _ = sample_network_throughput(&mut sampler);
    }

    #[test]
    fn test_get_top_talkers() {
        let incidents = vec![
            Incident {
                timestamp: "2026-11-12 12:00:00".to_string(),
                ip: "10.0.0.1".to_string(),
                port: 22,
                service: "SSH".to_string(),
                severity: "CRÍTICO".to_string(),
                country: "PT".to_string(),
                city: "Porto".to_string(),
                isp: "Vodafone".to_string(),
                rdns: Some("-".to_string()),
                payload: None,
                threat_score: 80,
                hit_count: 5,
            },
            Incident {
                timestamp: "2026-11-12 12:01:00".to_string(),
                ip: "10.0.0.2".to_string(),
                port: 80,
                service: "HTTP".to_string(),
                severity: "ALERTA".to_string(),
                country: "US".to_string(),
                city: "NY".to_string(),
                isp: "Cloudflare".to_string(),
                rdns: Some("-".to_string()),
                payload: None,
                threat_score: 40,
                hit_count: 10,
            },
        ];

        let top = get_top_talkers(&incidents, 5);
        assert_eq!(top.len(), 2);
        // 10.0.0.2 teve 10 hits, deve ser o primeiro
        assert_eq!(top[0].0, "10.0.0.2");
        assert_eq!(top[0].1, 10);
        // 10.0.0.1 teve 5 hits
        assert_eq!(top[1].0, "10.0.0.1");
        assert_eq!(top[1].1, 5);
    }
}

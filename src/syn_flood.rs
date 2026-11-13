//! Módulo de deteção e mitigação de TCP SYN Flood e conexões half-open (MITRE ATT&CK T1498.001).
//!
//! Este componente implementa um analisador em tempo real baseado em janela deslizante (sliding window)
//! por IP de origem, quantificando o ritmo de pacotes SYN e monitorando conexões embrionárias (half-open)
//! para prevenir a exaustão da tabela de estados do kernel e da fila de backlog (SYN backlog).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Identificador da técnica no framework MITRE ATT&CK.
pub const MITRE_TECHNIQUE_ID: &str = "T1498.001";
/// Nome descritivo da técnica MITRE ATT&CK.
pub const MITRE_TECHNIQUE_NAME: &str =
    "Network Denial of Service: Direct Network Flood (SYN Flood)";

/// Nível de severidade da taxa de pacotes SYN de um determinado IP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FloodSeverity {
    /// Taxa normal de conexões dentro dos parâmetros esperados.
    Normal,
    /// Taxa elevada aproximando-se do limiar crítico (>= 75% do limiar).
    Warning,
    /// Inundação ativa de pacotes SYN detectada (>= limiar crítico).
    CriticalFlood,
}

impl FloodSeverity {
    /// Representação textual do nível de severidade.
    pub fn as_str(&self) -> &'static str {
        match self {
            FloodSeverity::Normal => "NORMAL",
            FloodSeverity::Warning => "WARNING",
            FloodSeverity::CriticalFlood => "CRITICAL_FLOOD",
        }
    }
}

impl std::fmt::Display for FloodSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Registro individual de um pacote SYN observado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SynRecord {
    /// Timestamp Unix (em segundos) em que o pacote foi recebido.
    pub timestamp: u64,
    /// Porta de destino visada pelo pacote SYN.
    pub dst_port: u16,
    /// Indica se o handshake TCP de 3 vias foi concluído (ACK recebido).
    pub acknowledged: bool,
}

/// Rastreador de pacotes TCP SYN com janela deslizante e deteção de conexões half-open.
#[derive(Debug, Clone)]
pub struct SynTracker {
    /// Limiar de pacotes SYN tolerados por janela deslizante.
    pub threshold_per_sec: usize,
    /// Duração da janela deslizante em segundos.
    pub window_secs: u64,
    /// Histórico de pacotes SYN indexado por endereço IP de origem.
    syn_history: HashMap<String, Vec<SynRecord>>,
}

impl SynTracker {
    /// Cria uma nova instância de `SynTracker`.
    ///
    /// - `threshold_per_sec`: número de pacotes SYN no intervalo da janela que despoleta `CriticalFlood`.
    /// - `window_secs`: tamanho da janela deslizante em segundos (ex: 1s, 2s ou 5s).
    pub fn new(threshold_per_sec: usize, window_secs: u64) -> Self {
        Self {
            threshold_per_sec,
            window_secs: window_secs.max(1),
            syn_history: HashMap::new(),
        }
    }

    /// Retorna o limiar efetivo para detecção de flood crítico.
    #[inline]
    fn critical_threshold(&self) -> usize {
        self.threshold_per_sec.max(1)
    }

    /// Retorna o limiar de alerta intermediário (`Warning`).
    #[inline]
    fn warning_threshold(&self) -> usize {
        let crit = self.critical_threshold();
        if crit <= 3 {
            crit
        } else {
            (crit * 75) / 100
        }
    }

    /// Limpa entradas expiradas de todos os IPs e descarta IPs sem registros ativos.
    pub fn cleanup_expired(&mut self, now_ts: u64) {
        let window = self.window_secs;
        self.syn_history.retain(|_, records| {
            records.retain(|rec| rec.timestamp <= now_ts && now_ts - rec.timestamp <= window);
            !records.is_empty()
        });
    }

    /// Registra um novo pacote SYN e avalia o nível de severidade para o IP.
    ///
    /// Executa automaticamente a purga de entradas expiradas dentro da janela deslizante.
    pub fn record_syn(&mut self, src_ip: &str, dst_port: u16, now_ts: u64) -> FloodSeverity {
        // Limpeza de entradas fora da janela deslizante
        self.cleanup_expired(now_ts);

        let records = self.syn_history.entry(src_ip.to_string()).or_default();
        records.push(SynRecord {
            timestamp: now_ts,
            dst_port,
            acknowledged: false,
        });

        let active_count = records.len();
        let crit = self.critical_threshold();
        let warn = self.warning_threshold();

        if active_count >= crit {
            FloodSeverity::CriticalFlood
        } else if active_count >= warn {
            FloodSeverity::Warning
        } else {
            FloodSeverity::Normal
        }
    }

    /// Conta o número de pacotes SYN ativos dentro da janela deslizante para um IP específico.
    pub fn active_syn_count(&self, src_ip: &str, now_ts: u64) -> usize {
        match self.syn_history.get(src_ip) {
            Some(records) => {
                let window = self.window_secs;
                records
                    .iter()
                    .filter(|rec| rec.timestamp <= now_ts && now_ts - rec.timestamp <= window)
                    .count()
            }
            None => 0,
        }
    }

    /// Verifica se determinado IP está atualmente excedendo o limiar de SYN flood na janela.
    pub fn is_ip_flooding(&self, src_ip: &str, now_ts: u64) -> bool {
        self.active_syn_count(src_ip, now_ts) >= self.critical_threshold()
    }

    /// Retorna todos os endereços IP que excedem o limiar de flood na janela temporal,
    /// acompanhados da sua respetiva contagem de pacotes, ordenados de forma decrescente por volume.
    pub fn get_flooding_ips(&self, now_ts: u64) -> Vec<(String, usize)> {
        let crit = self.critical_threshold();
        let window = self.window_secs;
        let mut flooding = Vec::new();

        for (ip, records) in &self.syn_history {
            let count = records
                .iter()
                .filter(|rec| rec.timestamp <= now_ts && now_ts - rec.timestamp <= window)
                .count();
            if count >= crit {
                flooding.push((ip.clone(), count));
            }
        }

        // Ordena por contagem descrescente e depois por IP alfabeticamente para determinismo
        flooding.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        flooding
    }

    /// Registra a recepção de um pacote ACK (conclusão do handshake TCP de 3 vias),
    /// retirando a conexão do estado embrionário / half-open.
    pub fn record_ack(&mut self, src_ip: &str, dst_port: u16) -> bool {
        if let Some(records) = self.syn_history.get_mut(src_ip) {
            // Marca o primeiro SYN não-reconhecido para aquela porta como estabelecido
            if let Some(pending) = records
                .iter_mut()
                .find(|r| !r.acknowledged && r.dst_port == dst_port)
            {
                pending.acknowledged = true;
                return true;
            }
        }
        false
    }

    /// Retorna a quantidade de conexões half-open (embrionárias) pendentes para o IP fornecido.
    pub fn half_open_count(&self, src_ip: &str, now_ts: u64) -> usize {
        match self.syn_history.get(src_ip) {
            Some(records) => {
                let window = self.window_secs;
                records
                    .iter()
                    .filter(|rec| {
                        !rec.acknowledged
                            && rec.timestamp <= now_ts
                            && now_ts - rec.timestamp <= window
                    })
                    .count()
            }
            None => 0,
        }
    }

    /// Retorna o número total de conexões half-open no sistema dentro da janela deslizante atual.
    pub fn total_half_open(&self, now_ts: u64) -> usize {
        let window = self.window_secs;
        self.syn_history
            .values()
            .map(|records| {
                records
                    .iter()
                    .filter(|rec| {
                        !rec.acknowledged
                            && rec.timestamp <= now_ts
                            && now_ts - rec.timestamp <= window
                    })
                    .count()
            })
            .sum()
    }

    /// Retorna a lista de portas de destino visadas por um IP na janela ativa.
    pub fn targeted_ports(&self, src_ip: &str, now_ts: u64) -> Vec<u16> {
        let window = self.window_secs;
        let mut ports: Vec<u16> = self
            .syn_history
            .get(src_ip)
            .map(|records| {
                records
                    .iter()
                    .filter(|rec| rec.timestamp <= now_ts && now_ts - rec.timestamp <= window)
                    .map(|rec| rec.dst_port)
                    .collect()
            })
            .unwrap_or_default();
        ports.sort_unstable();
        ports.dedup();
        ports
    }

    /// Identificador da técnica MITRE ATT&CK associada.
    pub fn mitre_id(&self) -> &'static str {
        MITRE_TECHNIQUE_ID
    }

    /// Nome da técnica MITRE ATT&CK associada.
    pub fn mitre_technique(&self) -> &'static str {
        MITRE_TECHNIQUE_NAME
    }
}

impl Default for SynTracker {
    fn default() -> Self {
        // Padrão de segurança: 50 conexões/segundo com janela deslizante de 2 segundos
        Self::new(50, 2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normal_syn_rate_under_threshold() {
        let mut tracker = SynTracker::new(10, 1);
        let now = 1_700_000_000;

        for _ in 0..5 {
            let severity = tracker.record_syn("192.168.1.100", 80, now);
            assert_eq!(severity, FloodSeverity::Normal);
        }

        assert!(!tracker.is_ip_flooding("192.168.1.100", now));
        assert!(tracker.get_flooding_ips(now).is_empty());
        assert_eq!(tracker.active_syn_count("192.168.1.100", now), 5);
    }

    #[test]
    fn test_syn_flood_trigger_critical() {
        let mut tracker = SynTracker::new(10, 1);
        let now = 1_700_000_000;

        // Dispara 9 pacotes (abaixo do limiar crítico)
        for _ in 0..9 {
            tracker.record_syn("10.0.0.99", 443, now);
        }
        assert!(!tracker.is_ip_flooding("10.0.0.99", now));

        // O 10º pacote atinge o limiar crítico
        let severity = tracker.record_syn("10.0.0.99", 443, now);
        assert_eq!(severity, FloodSeverity::CriticalFlood);
        assert!(tracker.is_ip_flooding("10.0.0.99", now));

        let flooding = tracker.get_flooding_ips(now);
        assert_eq!(flooding.len(), 1);
        assert_eq!(flooding[0].0, "10.0.0.99");
        assert_eq!(flooding[0].1, 10);
    }

    #[test]
    fn test_sliding_window_expiration() {
        let mut tracker = SynTracker::new(5, 2);
        let now = 1000;

        for _ in 0..5 {
            tracker.record_syn("192.168.1.50", 80, now);
        }
        assert!(tracker.is_ip_flooding("192.168.1.50", now));
        assert_eq!(tracker.get_flooding_ips(now).len(), 1);

        // Avança o tempo além da janela de 2 segundos (now + 3 > 2s)
        let later = now + 3;
        assert!(!tracker.is_ip_flooding("192.168.1.50", later));
        assert!(tracker.get_flooding_ips(later).is_empty());

        // Nova conexão no tempo posterior deve reiniciar contagem normal
        let severity = tracker.record_syn("192.168.1.50", 80, later);
        assert_eq!(severity, FloodSeverity::Normal);
        assert_eq!(tracker.active_syn_count("192.168.1.50", later), 1);
    }

    #[test]
    fn test_multi_ip_isolation() {
        let mut tracker = SynTracker::new(5, 1);
        let now = 2000;

        // IP A gera inundação SYN
        for _ in 0..5 {
            tracker.record_syn("192.168.1.10", 80, now);
        }

        // IP B envia apenas 1 conexão normal
        let b_sev = tracker.record_syn("192.168.1.20", 80, now);
        assert_eq!(b_sev, FloodSeverity::Normal);

        // Verifica que o estado de A não afeta B
        assert!(tracker.is_ip_flooding("192.168.1.10", now));
        assert!(!tracker.is_ip_flooding("192.168.1.20", now));

        let flooding = tracker.get_flooding_ips(now);
        assert_eq!(flooding.len(), 1);
        assert_eq!(flooding[0].0, "192.168.1.10");
        assert_eq!(flooding[0].1, 5);
    }

    #[test]
    fn test_warning_severity_threshold() {
        let mut tracker = SynTracker::new(10, 1);
        let now = 5000;

        // 1 a 6 pacotes -> Normal
        for _ in 0..6 {
            let s = tracker.record_syn("10.10.10.10", 80, now);
            assert_eq!(s, FloodSeverity::Normal);
        }

        // 7 a 9 pacotes -> Warning (75% de 10)
        let s7 = tracker.record_syn("10.10.10.10", 80, now);
        assert_eq!(s7, FloodSeverity::Warning);

        let s8 = tracker.record_syn("10.10.10.10", 80, now);
        assert_eq!(s8, FloodSeverity::Warning);

        let s9 = tracker.record_syn("10.10.10.10", 80, now);
        assert_eq!(s9, FloodSeverity::Warning);

        // 10 pacotes -> CriticalFlood
        let s10 = tracker.record_syn("10.10.10.10", 80, now);
        assert_eq!(s10, FloodSeverity::CriticalFlood);
    }

    #[test]
    fn test_half_open_handshake_lifecycle() {
        let mut tracker = SynTracker::new(10, 5);
        let now = 6000;

        tracker.record_syn("172.16.0.5", 8080, now);
        tracker.record_syn("172.16.0.5", 8081, now);
        assert_eq!(tracker.half_open_count("172.16.0.5", now), 2);
        assert_eq!(tracker.total_half_open(now), 2);

        // Conclui handshake na porta 8080 com ACK
        let ack_ok = tracker.record_ack("172.16.0.5", 8080);
        assert!(ack_ok);
        assert_eq!(tracker.half_open_count("172.16.0.5", now), 1);
        assert_eq!(tracker.total_half_open(now), 1);

        // ACK para porta inexistente retorna false
        let fake_ack = tracker.record_ack("172.16.0.5", 9999);
        assert!(!fake_ack);
        assert_eq!(tracker.half_open_count("172.16.0.5", now), 1);
    }

    #[test]
    fn test_cleanup_expired_entries() {
        let mut tracker = SynTracker::new(10, 2);
        tracker.record_syn("10.0.0.1", 80, 100);
        assert_eq!(tracker.active_syn_count("10.0.0.1", 100), 1);

        // Ao limpar no timestamp 105 (> 2s), o histórico deve esvaziar
        tracker.cleanup_expired(105);
        assert_eq!(tracker.active_syn_count("10.0.0.1", 105), 0);
        assert_eq!(tracker.syn_history.len(), 0);
    }

    #[test]
    fn test_get_flooding_ips_sorted() {
        let mut tracker = SynTracker::new(5, 1);
        let now = 1000;

        // IP A: 6 pacotes
        for _ in 0..6 {
            tracker.record_syn("192.168.1.1", 80, now);
        }
        // IP B: 8 pacotes (mais crítico)
        for _ in 0..8 {
            tracker.record_syn("192.168.1.2", 80, now);
        }

        let flooding = tracker.get_flooding_ips(now);
        assert_eq!(flooding.len(), 2);
        assert_eq!(flooding[0].0, "192.168.1.2");
        assert_eq!(flooding[0].1, 8);
        assert_eq!(flooding[1].0, "192.168.1.1");
        assert_eq!(flooding[1].1, 6);
    }

    #[test]
    fn test_targeted_ports_and_metadata() {
        let mut tracker = SynTracker::default();
        let now = 2000;

        tracker.record_syn("10.0.0.1", 80, now);
        tracker.record_syn("10.0.0.1", 443, now);
        tracker.record_syn("10.0.0.1", 80, now);

        let ports = tracker.targeted_ports("10.0.0.1", now);
        assert_eq!(ports, vec![80, 443]);

        assert_eq!(tracker.mitre_id(), "T1498.001");
        assert!(tracker.mitre_technique().contains("SYN Flood"));
        assert_eq!(FloodSeverity::CriticalFlood.to_string(), "CRITICAL_FLOOD");
    }
}

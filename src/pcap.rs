use crate::models::Incident;
use std::fs::File;
use std::io::Write;
use std::net::IpAddr;

/// Calcula o checksum de cabeçalhos de rede da Internet (RFC 1071)
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum = sum.wrapping_add(word as u32);
    }
    while (sum >> 16) > 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Calcula o checksum TCP incluindo o pseudo-cabeçalho IPv4
fn tcp_checksum(src_ip: [u8; 4], dst_ip: [u8; 4], tcp_segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    // Pseudo-cabeçalho IPv4
    sum = sum.wrapping_add(u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32);
    sum = sum.wrapping_add(u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32);
    sum = sum.wrapping_add(u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32);
    sum = sum.wrapping_add(u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32);
    sum = sum.wrapping_add(6u32); // Protocolo TCP (6)
    sum = sum.wrapping_add(tcp_segment.len() as u32);

    for chunk in tcp_segment.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum = sum.wrapping_add(word as u32);
    }
    while (sum >> 16) > 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Sintetiza e exporta uma captura de pacotes forense (.pcap) compatível com Wireshark,
/// tcpdump e ferramentas SIEM a partir dos incidentes registados na sessão.
pub fn write_pcap_file(filepath: &str, incidents: &[Incident]) -> Result<(), String> {
    let mut file = File::create(filepath).map_err(|e| format!("Erro ao criar ficheiro PCAP: {}", e))?;

    // 1. Cabeçalho Global PCAP (24 bytes, formato libpcap little-endian)
    let mut global_header = Vec::with_capacity(24);
    global_header.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes()); // Magic number (microsegundos)
    global_header.extend_from_slice(&2u16.to_le_bytes());           // Versão Major: 2
    global_header.extend_from_slice(&4u16.to_le_bytes());           // Versão Minor: 4
    global_header.extend_from_slice(&0i32.to_le_bytes());           // Timezone GMT offset: 0
    global_header.extend_from_slice(&0u32.to_le_bytes());           // Sigfigs: 0
    global_header.extend_from_slice(&65535u32.to_le_bytes());       // Snaplen máxima: 65535 bytes
    global_header.extend_from_slice(&1u32.to_le_bytes());           // LinkType: LINKTYPE_ETHERNET (1)

    file.write_all(&global_header)
        .map_err(|e| format!("Erro ao gravar cabeçalho global PCAP: {}", e))?;

    // 2. Grava cada incidente como um pacote Ethernet / IPv4 / TCP sintetizado
    for (idx, inc) in incidents.iter().enumerate() {
        let src_ip_bytes: [u8; 4] = match inc.ip.parse::<IpAddr>() {
            Ok(IpAddr::V4(v4)) => v4.octets(),
            Ok(IpAddr::V6(v6)) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    v4.octets()
                } else {
                    [198, 51, 100, 1] // Fallback para IP de documentação se IPv6 nativo
                }
            }
            Err(_) => [198, 51, 100, 1],
        };
        let dst_ip_bytes: [u8; 4] = [127, 0, 0, 1];

        let payload_bytes = inc.payload.as_deref().map(|p| p.as_bytes()).unwrap_or(&[]);
        let payload_len = payload_bytes.len();

        let dst_port = if inc.port != 0 { inc.port } else { 80 };
        let src_port = 40000 + (idx as u16 % 20000);

        // Cabeçalho Ethernet (14 bytes)
        let mut eth_header = [0u8; 14];
        eth_header[0..6].copy_from_slice(&[0x00, 0x16, 0x3e, 0x00, 0x00, 0x01]); // MAC Destino
        eth_header[6..12].copy_from_slice(&[0x00, 0x16, 0x3e, 0x00, 0x00, 0x02]); // MAC Origem
        eth_header[12..14].copy_from_slice(&0x0800u16.to_be_bytes()); // EtherType IPv4

        // Cabeçalho IPv4 (20 bytes)
        let ip_total_len = (20 + 20 + payload_len) as u16;
        let mut ip_header = [0u8; 20];
        ip_header[0] = 0x45; // Versão 4, IHL 5
        ip_header[1] = 0x00; // DSCP
        ip_header[2..4].copy_from_slice(&ip_total_len.to_be_bytes());
        ip_header[4..6].copy_from_slice(&(0x2000u16.wrapping_add(idx as u16)).to_be_bytes());
        ip_header[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // Don't Fragment
        ip_header[8] = 64;   // TTL
        ip_header[9] = 6;    // Protocolo TCP (6)
        ip_header[10..12].copy_from_slice(&[0, 0]); // Checksum inicial a zero
        ip_header[12..16].copy_from_slice(&src_ip_bytes);
        ip_header[16..20].copy_from_slice(&dst_ip_bytes);
        let ip_cksum = internet_checksum(&ip_header);
        ip_header[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

        // Cabeçalho TCP (20 bytes)
        let tcp_flags: u8 = if payload_len > 0 { 0x18 } else { 0x02 }; // PSH+ACK se tiver dados, senão SYN
        let mut tcp_header = [0u8; 20];
        tcp_header[0..2].copy_from_slice(&src_port.to_be_bytes());
        tcp_header[2..4].copy_from_slice(&dst_port.to_be_bytes());
        tcp_header[4..8].copy_from_slice(&(1000u32.wrapping_add((idx as u32) * 500)).to_be_bytes());
        tcp_header[8..12].copy_from_slice(&1u32.to_be_bytes());
        tcp_header[12] = 0x50; // Data Offset (5 palavras de 32 bits = 20 bytes)
        tcp_header[13] = tcp_flags;
        tcp_header[14..16].copy_from_slice(&64240u16.to_be_bytes()); // Window size
        tcp_header[16..18].copy_from_slice(&[0, 0]); // Checksum inicial a zero
        tcp_header[18..20].copy_from_slice(&[0, 0]); // Urgent pointer

        let mut tcp_segment = Vec::with_capacity(20 + payload_len);
        tcp_segment.extend_from_slice(&tcp_header);
        tcp_segment.extend_from_slice(payload_bytes);
        let tcp_cksum = tcp_checksum(src_ip_bytes, dst_ip_bytes, &tcp_segment);
        tcp_segment[16..18].copy_from_slice(&tcp_cksum.to_be_bytes());

        // Monta o frame Ethernet completo
        let mut packet_data = Vec::with_capacity(14 + 20 + tcp_segment.len());
        packet_data.extend_from_slice(&eth_header);
        packet_data.extend_from_slice(&ip_header);
        packet_data.extend_from_slice(&tcp_segment);

        // Converte timestamp do incidente para segundos unix
        let ts_sec = chrono::NaiveDateTime::parse_from_str(&inc.timestamp, "%Y-%m-%d %H:%M:%S")
            .map(|dt| dt.and_utc().timestamp() as u32)
            .unwrap_or_else(|_| chrono::Utc::now().timestamp() as u32);
        let ts_usec = ((idx as u32) * 25000) % 1_000_000;

        let frame_len = packet_data.len() as u32;

        // Cabeçalho do Registo PCAP (16 bytes)
        let mut record_header = [0u8; 16];
        record_header[0..4].copy_from_slice(&ts_sec.to_le_bytes());
        record_header[4..8].copy_from_slice(&ts_usec.to_le_bytes());
        record_header[8..12].copy_from_slice(&frame_len.to_le_bytes()); // Comprimento capturado
        record_header[12..16].copy_from_slice(&frame_len.to_le_bytes()); // Comprimento original

        file.write_all(&record_header)
            .map_err(|e| format!("Erro ao gravar cabeçalho de registo PCAP: {}", e))?;
        file.write_all(&packet_data)
            .map_err(|e| format!("Erro ao gravar dados de pacote PCAP: {}", e))?;
    }

    file.flush()
        .map_err(|e| format!("Erro ao descarregar ficheiro PCAP para disco: {}", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_pcap_structure() {
        let test_incident = Incident {
            timestamp: "2026-11-10 14:30:00".to_string(),
            ip: "192.168.1.150".to_string(),
            port: 8080,
            service: "HTTP Honeypot".to_string(),
            severity: "MÉDIO".to_string(),
            country: "Local".to_string(),
            city: "LAN".to_string(),
            isp: "Localhost".to_string(),
            rdns: None,
            payload: Some("GET /admin HTTP/1.1".to_string()),
            threat_score: 55,
            hit_count: 1,
        };

        let temp_pcap = "test_sample_capture.pcap";
        let res = write_pcap_file(temp_pcap, &[test_incident]);
        assert!(res.is_ok());

        // Verifica cabeçalho magic do ficheiro PCAP
        let data = std::fs::read(temp_pcap).unwrap();
        assert!(data.len() > 24);
        assert_eq!(&data[0..4], &[0xd4, 0xc3, 0xb2, 0xa1]); // Magic number
        assert_eq!(&data[4..6], &[0x02, 0x00]); // Major version 2
        assert_eq!(&data[6..8], &[0x04, 0x00]); // Minor version 4

        // Limpeza
        let _ = std::fs::remove_file(temp_pcap);
    }
}

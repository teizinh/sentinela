# 🗺️ Roadmap de Evolução — Sentinela

Este documento mantém o registo planeado das próximas grandes funcionalidades e melhorias técnicas para o **Sentinela** (Sensor / Probe) e a sua integração com o **Sentinela-Hub**.

---

## 🎯 Prioridades Planeadas

### 1. 🧪 Simulador de Ataques / Modo Demo (`sentinela-sim`)
- [ ] Subcomando `sentinela sim` ou gerador de tráfego sintético local.
- [ ] Cenários integrados:
  - Rajadas TCP SYN Flood para ativação do `syn_flood.rs`.
  - Consultas DNS com alta entropia para ativação do `dns_analyzer.rs`.
  - Varreduras furtivas de portas (SYN/FIN/NULL scans).
  - Traps Web (Log4Shell `${jndi:...}`, WordPress scanning) para validação do `web_probes.rs`.
  - Falsificação de pacotes ARP para teste do `arp_guard.rs`.
- [ ] Suporte a reprodução (*replay*) de capturas PCAP offline.

### 2. 🕵️ Fingerprinting TLS Client Hello (JA3 & JA4)
- [ ] Descodificação do handshake TLS Client Hello (`src/tls_fingerprint.rs`).
- [ ] Cálculo de hashes JA3 (MD5 normalizado de cipher suites/extensões) e JA4.
- [ ] Catálogo offline de assinaturas para identificação de ferramentas de pentest (Metasploit, Cobalt Strike, Nuclei, scanners automatizados) mesmo em sessões encriptadas.
- [ ] Exibição na TUI e telemetria para o Hub.

### 3. 📡 Telemetria e Robustez de Rede
- [ ] Suporte a buffer circular de pacotes em memória para exportação PCAP sob demanda no momento do disparo de um alerta.
- [ ] Compressão de telemetria Zstandard para envio eficiente para o Hub através de ligações de baixa largura de banda.

---

*Registo mantido por Salvador Teixeira Pontes (`teizinh`) — CTeSP CRSI, ESTG P.PORTO.*

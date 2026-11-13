# 🛡️ Sentinela

<p align="center">
  <img src="https://img.shields.io/badge/Language-Rust_1.70+-orange.svg?style=for-the-badge&logo=rust" alt="Rust 1.70+">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-blue.svg?style=for-the-badge&logo=linux" alt="Cross Platform">
  <img src="https://img.shields.io/badge/Engine-Raw_Pcap_%2F_eBPF_Sockets-purple.svg?style=for-the-badge" alt="Raw Pcap / Sockets">
  <img src="https://img.shields.io/badge/Version-v0.4.0-success.svg?style=for-the-badge" alt="Version v0.4.0">
  <img src="https://img.shields.io/badge/Architecture-100%25_Pure_Rust-red.svg?style=for-the-badge" alt="100% Pure Rust">
  <img src="https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge" alt="MIT License">
</p>

```text
  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗      █████╗ 
  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     ██╔══██╗
  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     ███████║
  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     ██╔══██║
  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗██║  ██║
  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝  ╚═╝
  ─── [ NEXT-GEN NETWORK INTRUSION DETECTION & ACTIVE DECEPTION SENSOR ] ───
```

<p align="center">
  <strong>High-Performance Network Intrusion Detection System (NIDS), Multi-Protocol Decoy Honeypots, Covert Tunnel Watchdog & SOC Defense Terminal — Engineered in 100% Pure Rust.</strong>
</p>

---

## 📑 Table of Contents

- [Overview](#-overview)
- [System Architecture](#-system-architecture)
  - [Architecture Pipeline Diagram](#architecture-pipeline-diagram)
  - [Layer Breakdown](#layer-breakdown)
- [MITRE ATT&CK Enterprise Matrix](#-mitre-attck-enterprise-matrix)
- [Feature Catalog](#-feature-catalog)
  - [Multi-Protocol Decoy Honeypot Traps](#1-multi-protocol-decoy-honeypot-traps)
  - [Covert Tunnel & Shannon Entropy Watchdog](#2-covert-tunnel--shannon-entropy-watchdog)
  - [In-Flight Credential Harvester](#3-in-flight-credential-harvester)
  - [Active Mitigation & Automated Firewall Defense](#4-active-mitigation--automated-firewall-defense)
  - [Anti-Ransomware Canary Watcher](#5-anti-ransomware-canary-watcher)
  - [ARP Cache Poisoning & MITM Guard](#6-arp-cache-poisoning--mitm-guard)
  - [Threat Intel & SIEM Multi-Format Exporter](#7-threat-intel--siem-multi-format-exporter)
  - [Multi-Theme SOC Terminal Dashboard (Ratatui)](#8-multi-theme-soc-terminal-dashboard-ratatui)
  - [Remote & Headless Hardening](#9-remote--headless-hardening)
- [Installation & Setup](#-installation--setup)
  - [One-Line Automated Installer](#one-line-automated-installer)
  - [Pre-Built Binary Packages](#pre-built-binary-packages)
  - [Building from Source](#building-from-source)
- [CLI Reference](#-cli-reference)
- [Configuration Reference (`sentinela.toml`)](#-configuration-reference-sentinelatoml)
- [Dashboard Keyboard Shortcuts](#-dashboard-keyboard-shortcuts)
- [Platform Support & Security Notes](#-platform-support--security-notes)
- [License](#-license)

---

## ⚡ Overview

**Sentinela** is a lightweight, zero-dependency Network Intrusion Detection System (NIDS), active deception honeypot suite, and real-time Security Operations Center (SOC) dashboard. Written entirely in **safe, memory-efficient Rust**, Sentinela operates directly on raw network interfaces and application sockets without external runtime dependencies, cloud services, or heavy databases.

- **Pre-Handshake Detection:** Sniffs incoming raw packets at L2/L3 (`AF_PACKET`) to flag stealth reconnaissance (**SYN**, **NULL**, **FIN**, **XMAS** scans) before the operating system's TCP handshake finishes.
- **Deception Honeypot Sensors:** Binds dual-stack IPv4/IPv6 decoy listeners (SSH, FTP, Telnet, HTTP, Redis, SMTP, MySQL, PostgreSQL) that actively converse with threat actors to extract payloads, tools, and credentials.
- **Deep Statistical Analysis:** Computes real-time Shannon entropy on ICMP payloads and DNS queries to uncover covert exfiltration channels, C2 beacons, and DNS tunneling.
- **Active Autonomous Mitigation:** Automatically evaluates threat scores (0–100) and executes surgical firewall bans (`iptables` / `netsh`), while protecting trusted management subnets and active SSH sessions with anti-lockout safeguards.
- **Tactical SOC Interface:** Features a terminal UI powered by Ratatui with sparkline traffic monitors, canonical `xxd` hexdump modals, GeoIP/ASN intelligence, and one-touch exports to PCAP, CEF, Syslog, JSON, CSV, Markdown, and HTML.

---

## 🏛️ System Architecture

Sentinela follows a modular, non-blocking pipeline structured into four coordinated tiers:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                    SENTINELA PIPELINE                                  │
└────────────────────────────────────────────────────────────────────────────────────────┘

    [ Sensor Layer ]               [ Analysis Engine ]             [ Active Mitigation ]
  ┌──────────────────┐           ┌───────────────────────┐       ┌───────────────────────┐
  │ AF_PACKET Sniffer│           │ TCP Flags Classifier  │       │ Auto-Ban Engine       │
  │ (Raw L2/L3 Pcap) │ ────────> │ (SYN, NULL, FIN, XMAS)│ ────> │ (iptables / netsh)    │
  └──────────────────┘           └───────────────────────┘       └───────────────────────┘
                                             │                               ▲
  ┌──────────────────┐           ┌───────────────────────┐                   │
  │ Decoy Honeypots  │           │ ICMP & DNS Watchdog   │                   │
  │ (SSH,FTP,Tel,Web)│ ────────> │ (Shannon Entropy H(X))│ ──────────────────┤
  └──────────────────┘           └───────────────────────┘                   │
                                             │                               │
  ┌──────────────────┐           ┌───────────────────────┐                   │
  │ Canary Honeyfile │           │ Credential Harvester  │                   │
  │ (Kernel inotify) │ ────────> │ (HTTP/Telnet/FTP/JSON)│ ──────────────────┤
  └──────────────────┘           └───────────────────────┘                   │
                                             │                               │
  ┌──────────────────┐           ┌───────────────────────┐                   │
  │ ARP Table Poll   │           │ Threat Scoring Engine │                   │
  │ (/proc/net/arp)  │ ────────> │ (Score 0-100 & MITRE) │ ──────────────────┘
  └──────────────────┘           └───────────────────────┘
                                             │
                                             ▼
                      ┌─────────────────────────────────────────────┐
                      │    Real-Time Presentation & Hub Telemetry   │
                      ├─────────────────────────────────────────────┤
                      │ • Ratatui Terminal UI (4 Visual Themes)     │
                      │ • Deep Forensic Inspector (xxd Hexdump)     │
                      │ • SIEM Multi-Export (PCAP, CEF, Syslog, MD) │
                      │ • Discord / Slack Webhook & Sentinela Hub   │
                      └─────────────────────────────────────────────┘
```

### Layer Breakdown

#### 1. Sensor Layer (Decoy Traps & Ingestion)
- **Raw Packet Ingestion:** Uses low-level `AF_PACKET` raw sockets (Linux) through `pnet` to monitor network interfaces directly at the datalink layer. Intercepts L2/L3 packets without waiting for OS transport-layer binding.
- **Asynchronous Decoy Listeners:** Spawns asynchronous Tokio TCP tasks bound across IPv4 and IPv6 (`[::]:<port>`) on configurable decoy ports (e.g., 2121, 2222, 2323, 8080, 8443, 6379).
- **Canary Honeyfile Watchdog:** Deploys monitored credential decoys (`/tmp/.sentinela_honeyfile_credentials.env`) watched by Linux kernel `inotify` for unauthorized reads, edits, or ransomware encryption attempts.
- **Kernel ARP Table Watchdog:** Continually inspects `/proc/net/arp` to catch rogue MAC switches, gateway cloning, and ARP spoofing.

#### 2. Analysis Engine (ICMP, Stealth Scans, Tunnels & Entropy)
- **TCP Flag Heuristics:** Inspects packet flags at zero latency to identify stealth scan patterns:
  - `0x02 (SYN)`: Half-open stealth sweep before handshake completion.
  - `0x00 (NULL)`: Packets with zero flags set.
  - `0x01 (FIN)`: Probe packets containing only FIN.
  - `0x29 (XMAS)`: Lights up FIN, PSH, and URG simultaneously.
- **Shannon Entropy Engine ($H(X)$):**
  $$\text{Entropy: } H(X) = - \sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
  Computes information density over variable payloads to identify:
  - *ICMP Covert Tunnels:* Payload $> 64$ bytes with $H(X) > 4.5$ flags data encapsulation inside echo requests.
  - *DNS Exfiltration:* Query strings (QNAME) on port 53 with $H(X) > 3.8$ or abnormal length flag encoded beacons.
- **Credential Dissector:** Ingests intercepted payload streams to parse HTTP Basic Auth, JSON credentials, URL-encoded parameters, and Telnet/FTP dialogues into structured authentication logs.
- **Threat Scoring Algorithm:** Evaluates each incident's risk level ($0\text{--}100$) dynamically based on targeted port sensitivity, repeat probe cadence, payload traits, and MITRE categorization.

#### 3. Active Mitigation Layer (Auto-Ban, Whitelist, Killswitch)
- **Automated Firewall Injection:** Automatically issues kernel firewall drop commands (`iptables -I INPUT 1 -s <IP> -j DROP` or Windows `netsh advfirewall`) whenever an attacker's Threat Score reaches $\ge 80$ or a port sweep is detected.
- **Anti-Lockout & Trusted Whitelisting:** Automatically parses `$SSH_CONNECTION` to protect the administrator's remote connection. Pre-configured RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback, and public DNS servers are immune to automated blocks.
- **Surgical Process & Socket Kill:** Inspects open sockets directly from the UI (`[C]`), enabling operators to terminate rogue listening or established processes via `SIGKILL`.
- **Emergency System Killswitch (`[K]`):** Cuts all inbound/outbound traffic in emergencies (`iptables DROP` + `rfkill block all`). Safely intercepts executions during active SSH sessions to prevent self-lockout.

#### 4. Real-time Presentation & Telemetry Layer
- **Responsive Ratatui TUI:** 60 FPS terminal dashboard that dynamically rescales columns across small mobile terminals, standard laptops, and multi-monitor SOC displays.
- **SIEM & Intel Multi-Exporter:** Generates RFC 1071-compliant PCAP packet traces, ArcSight CEF, RFC 5424 Syslog, JSON, CSV, Markdown, and HTML reports in a single operation.
- **Centralized Hub & Webhook Streamer:** Asynchronously posts incidents and system health heartbeats to Discord/Slack webhooks or a centralized Sentinela Hub.

---

## 🎯 MITRE ATT&CK Enterprise Matrix

Sentinela maps detected threats directly to the **MITRE ATT&CK Enterprise Framework**:

| Technique ID | Technique Name | Tactic | Detection & Mitigation Mechanism in Sentinela |
|---|---|---|---|
| **T1046** | Network Service Discovery | Discovery (`TA0007`) | Sniffs raw SYN, NULL, FIN, and XMAS stealth scans; flags horizontal port sweeps ($\ge 5$ distinct ports in 5 seconds). |
| **T1595.002** | Vulnerability Scanning | Reconnaissance (`TA0043`) | Traps automated web vulnerability scanners (HTTP path fuzzers, directory traversal) and ESMTP reconnaissance bots. |
| **T1110.001** | Brute Force: Password Guessing | Credential Access (`TA0006`) | Intercepts repeated authentication attempts on SSH (22, 2222) and FTP (21, 2121) decoy honeypot listeners. |
| **T1021.001** | Remote Services: Remote Desktop Protocol | Lateral Movement (`TA0008`) | Identifies unauthorized connection probes on RDP port 3389 decoy traps. |
| **T1021.002** | Remote Services: SMB / Telnet | Lateral Movement (`TA0008`) | Emulates Telnet login terminals (23, 2323), capturing login dialogue keystrokes and lateral movement attempts. |
| **T1078.001** | Valid Accounts: Default Accounts | Initial Access (`TA0001`) / Defense Evasion | Catches brute-force reconnaissance against database decoy services (MySQL 3306, PostgreSQL 5432). |
| **T1190** | Exploit Public-Facing Application | Initial Access (`TA0001`) | Detects HTTP vulnerability probes scanning for `.env`, `/admin`, `/wp-login.php`, `/setup`, and `/config`. |
| **T1210** | Exploitation of Remote Services | Lateral Movement (`TA0008`) | Emulates Redis (6379), returning `-NOAUTH Authentication required.` while logging unauthorized commands (`PING`, `INFO`, `CONFIG`). |
| **T1071.004** | DNS Tunneling & Exfiltration | Command and Control (`TA0011`) / Exfiltration (`TA0010`) | Runs Shannon entropy analysis ($H(X) > 3.8$) and length tests on port 53 QNAME requests to expose covert DNS channels. |
| **T1095** | Non-Application Protocol (ICMP Tunneling) | Command and Control (`TA0011`) | Inspects ICMP Echo Requests: payloads $> 64$ bytes with Shannon entropy $> 4.5$ trigger immediate covert tunnel alarms (Score: 90). |
| **T1048** | Exfiltration Over Alternative Protocol | Exfiltration (`TA0010`) | Identifies data exfiltration attempts hiding inside ICMP and DNS transport protocols. |
| **T1557.002** | Adversary-in-the-Middle: ARP Cache Poisoning | Credential Access (`TA0006`) / Collection | Kernel `/proc/net/arp` polling daemon detects unauthorized gateway MAC changes and ARP spoofing attacks. |
| **T1486** | Data Encrypted for Impact (Ransomware Canary) | Impact (`TA0040`) / Credential Access | Linux kernel `inotify` watchdog flags read, write, and deletion attempts on honeyfile credentials (`.env`). |
| **T1059** | Command and Scripting Interpreter | Execution (`TA0002`) | Analyzes incoming probe payloads for injected shell commands, reverse shells, and malicious command-line strings. |
| **M1037** | Filter Network Traffic | Mitigation | Autonomous firewall auto-ban (`-b`, `--auto-ban`) drops attacker IPs via `iptables` / `netsh`. |
| **M1035** | Limit Access to Resource over Network | Mitigation | Emergency network killswitch (`[K]`) immediately shuts down ingress/egress during critical breaches. |

---

## 🚀 Feature Catalog

### 1. Multi-Protocol Decoy Honeypot Traps

Sentinela includes built-in protocol emulators that interact with scanners and attackers to gather intelligence:

```
Attacker Probe ────────> [ Sentinela Decoy Listener ]
                             │
                             ├─► SSH (22/2222)   : Transmits OpenSSH 8.9p1 Banner -> Captures Client Ident
                             ├─► FTP (21/2121)   : Sends vsFTPd 220 Banner -> Solicits USER/PASS -> Captures Creds
                             ├─► Telnet (23/2323): Presents Debian Login Banner -> Logs Interactive Keystrokes
                             ├─► HTTP (80/8080)  : Returns 401 Unauthorized + Nginx Header -> Captures Auth & Paths
                             ├─► Redis (6379)    : Replies with -NOAUTH -> Captures Auth Tokens & Probes
                             └─► SMTP (25)       : Postfix ESMTP 220 Banner -> Records HELO / EHLO Payloads
```

- **SSH Trap (Ports 22, 2222):** Transmits standard OpenSSH identification (`SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6`), eliciting and recording the attacker's client banner (e.g., `libssh`, `PuTTY`, Paramiko, Nmap NSE scripts).
- **FTP Trap (Ports 21, 2121):** Emulates vsFTPd 3.0.5. Responds to `USER` with `331 Please specify the password.`, intercepts the subsequent `PASS` command, and returns `530 Login incorrect.`, capturing credentials in flight.
- **Telnet Trap (Ports 23, 2323):** Displays an authentic Debian GNU/Linux login prompt. Records all username and password sequences sent by automated IoT botnets (Mirai, Gafgyt).
- **HTTP / Web Trap (Ports 80, 8080, 8443, 8000):** Emulates an Nginx web server. Automatically responds with `HTTP/1.1 401 Unauthorized` and `WWW-Authenticate: Basic realm="Restricted Access"`. Captures Basic Auth headers, request paths, and query parameters.
- **Redis Trap (Port 6379):** Simulates a protected Redis instance. Intercepts `PING`, `INFO`, and `AUTH <password>` commands, returning `-NOAUTH Authentication required.` while logging authentication keys.
- **SMTP Trap (Port 25):** Transmits a Postfix ESMTP banner (`220 mail.internal ESMTP Postfix`) to log mail relay scans and `HELO`/`EHLO` probes.
- **Dynamic On-the-Fly Trap Spawner (`[O]`):** Operators can press `o` in the dashboard to bind a new decoy listener to any TCP port instantly, without restarting the monitoring daemon.

---

### 2. Covert Tunnel & Shannon Entropy Watchdog

Adversaries often use ICMP and DNS tunnels to bypass firewalls and establish covert command-and-control (C2) or exfiltrate data. Sentinela evaluates every packet's payload through Shannon entropy calculations:

$$H(X) = - \sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$

```text
Payload Byte Distribution:
Low Entropy  [AAAAAAA...] -> H(X) ~ 0.0 (Standard Ping / Pad Bytes)
Medium Entropy [Text / HTML] -> H(X) ~ 2.5 - 3.5 (Normal Network Traffic)
High Entropy [Encrypted/Base64] -> H(X) > 4.5  --> [ ALERT: Covert Tunnel / Exfiltration ]
```

- **ICMP Covert Channel Detection (MITRE T1095):**
  - Standard ICMP echo requests typically carry repetitive patterns (e.g., `0x00`, sequential alphabets).
  - Sentinela inspects payloads $> 64$ bytes. If Shannon entropy exceeds **$4.5$**, Sentinela flags an active **Covert ICMP Tunnel** with a Critical Threat Score of **90**.
- **ICMP Ping Sweep Detection (MITRE T1046 / T1595):**
  - Monitors destination targets using a 5-second sliding window. An address hitting $\ge 5$ distinct local IPs via ICMP triggers a Ping Sweep alert (Threat Score: **75**).
- **DNS Tunneling Watchdog (MITRE T1071.004 / T1048):**
  - Evaluates QNAME queries on port 53. Unusually long subdomains ($> 30$ characters) with Shannon entropy exceeding **$3.8$** trigger a DNS Tunneling and Exfiltration warning.

---

### 3. In-Flight Credential Harvester

Sentinela includes an in-memory credential dissection engine (`CredentialStore`) that parses authentication attempts across decoy protocols without third-party dependencies:

```
Incoming Stream ──► Protocol Dissector
                         │
                         ├─► HTTP Authorization: Basic <base64>  ──► Decodes User:Password
                         ├─► URL-Encoded Body (user=...&pass=..)  ──► Extracts Parameters
                         ├─► JSON Payload ({"user":..,"pass":..})──► Parses Key-Values
                         ├─► Plaintext Lines (admin:123456)      ──► Regex Fallback
                         └─► Interactive Shells (Telnet / FTP)   ──► Sanitizes Keystrokes
                                      │
                                      ▼
                        [ Captured Credential Store ]
                        • JSON Audit Trail (`to_json()`)
                        • Forensic Modal Display
                        • Threat Intelligence Report Attachment
```

- Decodes standard and URL-safe Base64 strings.
- Strips non-printable characters to ensure safe logging and terminal display.
- Records source IP, target service, extracted username, password (if provided), and microsecond timestamps.
- Captured credentials export alongside threat intelligence reports.

---

### 4. Active Mitigation & Automated Firewall Defense

Sentinela provides automated and manual remediation options to neutralize threats in real time:

- **Autonomous Auto-Ban (`-b`, `--auto-ban`):**
  - Monitors an internal threat scoring engine (0–100).
  - Any attacker reaching **Threat Score $\ge 80$** or executing a port sweep is automatically dropped via the kernel firewall.
  - Automatically unbans IPs after a configurable duration (default: 600 seconds) to prevent stale firewall rules.
- **Surgical Per-IP Ban/Unban (`[B]`):**
  - Operators can select any incident and press `b` to insert an immediate firewall drop rule:
    ```bash
    sudo iptables -I INPUT 1 -s <IP> -j DROP     # Linux
    netsh advfirewall firewall add rule ...      # Windows
    ```
  - Banned addresses display a red `[BAN]` badge in the dashboard. Pressing `b` again removes the rule.
- **Trusted Whitelist & Anti-Lockout Safeguards (`[U]`):**
  - Pressing `u` toggles an address on the trusted whitelist (marked with a green `[OK]` badge), preventing automated bans.
  - **SSH Auto-Whitelist:** Parses `$SSH_CONNECTION` on startup to whitelist the current administrator's IP address.
  - **Subnet Protection:** Local loopbacks (`127.0.0.1`, `::1`), RFC 1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and standard public DNS resolvers are automatically protected.
- **Emergency Network Killswitch (`[K]`):**
  - Pressing `k` immediately cuts all network traffic by dropping INPUT and OUTPUT chains and engaging `rfkill block all`.
  - Pressing `k` again restores normal connectivity.
  - **Remote Safety Lockout Interception:** If Sentinela detects an active SSH session, pressing `k` is safely intercepted with a warning toast to avoid locking the operator out of the server.
- **Active Sockets & Process Inspector (`[C]` + `[K]`):**
  - Pressing `c` opens a live audit modal showing all active sockets (`LISTEN`, `ESTABLISHED`).
  - Operators can select an offending process and press `k` to send a surgical `SIGKILL`.

---

### 5. Anti-Ransomware Canary Watcher

The Honeyfile Canary Watcher acts as an active deception sensor to detect host-level compromise and ransomware activity:

- Deploys an enticing decoy credentials file to `/tmp/.sentinela_honeyfile_credentials.env` containing fake AWS, database, and JWT tokens.
- Leverages the Linux kernel `inotify` API to monitor file access.
- Any unauthorized read, modification, or deletion triggers a Critical SOC alert mapped to **MITRE T1486** (Data Encrypted for Impact).
- Uses RAII wrappers to clean up canary files automatically when Sentinela exits.

---

### 6. ARP Cache Poisoning & MITM Guard

Local network attackers often use ARP spoofing to intercept traffic:

- Continuously samples `/proc/net/arp` to track IP-to-MAC associations for local gateways.
- Flags rogue MAC address modifications, unexpected duplicate hardware addresses, and gateway cloning attacks.
- Maps detections directly to **MITRE T1557.002** (Adversary-in-the-Middle: ARP Cache Poisoning).

---

### 7. Threat Intel & SIEM Multi-Format Exporter

Pressing `e` in the dashboard exports all session data into **7 standard formats** simultaneously:

```text
Exports Generated:
├── sentinela_report_YYYY-MM-DD_HH-MM-SS.pcap   (Synthesized Wireshark Packet Trace)
├── sentinela_report_YYYY-MM-DD_HH-MM-SS.cef    (Micro Focus ArcSight CEF for SIEMs)
├── sentinela_report_YYYY-MM-DD_HH-MM-SS.syslog (RFC 5424 Structured Syslog Stream)
├── sentinela_report_YYYY-MM-DD_HH-MM-SS.json   (Full Machine-Readable SOC Audit Dump)
├── sentinela_report_YYYY-MM-DD_HH-MM-SS.csv    (Tabular Forensic Analysis Format)
├── sentinela_report_YYYY-MM-DD_HH-MM-SS.md     (Executive Threat Summary Report)
└── sentinela_report_YYYY-MM-DD_HH-MM-SS.html   (Dark-Themed Self-Contained Web Report)
```

1. **Synthesized PCAP Trace (`.pcap`):** Generates a binary capture file containing synthesized Ethernet, IPv4, and TCP frames with valid RFC 1071 internet and pseudo-header checksums. Can be analyzed directly in **Wireshark** or **tcpdump**.
2. **ArcSight CEF Export (`.cef`):** Formatted for direct ingestion into **Splunk**, **Wazuh**, **Elasticsearch**, and **IBM QRadar**.
3. **Structured RFC 5424 Syslog (`.syslog`):** Ready for ingestion by **rsyslog**, **Logstash**, or **Graylog**.
4. **Machine-Readable JSON (`.json`):** Full telemetry dump including system info, active honeypots, whitelists, MITRE breakdowns, and incident logs.
5. **Spreadsheet CSV (`.csv`):** Tabular format detailing timestamps, IPs, ports, services, threat scores, MITRE IDs, and geographic data.
6. **Executive Markdown Report (`.md`):** Formatted markdown document with incident distribution and top-talker rankings.
7. **Executive HTML Report (`.html`):** Dark-mode report ready for distribution to stakeholders.

---

### 8. Multi-Theme SOC Terminal Dashboard (Ratatui)

Sentinela's user interface is built with Ratatui to deliver a modern, responsive SOC console:

```
┌─ Sentinela SOC v0.4.0 ─────────────────────────────────────────── [Traffic Pulse: ▅█▃▆ 24s] ─┐
│ Host: sentinela-node | IP: 192.168.1.100 | Raw Scanner: ACTIVE | Mode: AUTO-BAN (DROP)     │
├─────────────────────────────────────────────────────────────────────────────────────────────┤
│ TIME     │ RISK     │ SOURCE IP       │ TARGET PORT  │ LOCATION        │ HITS │ ISP         │
├──────────┼──────────┼─────────────────┼──────────────┼─────────────────┼──────┼─────────────┤
│ 14:22:01 │ CRITICAL │ 198.51.100.42*  │ 22/tcp (SSH) │ US, Ashburn     │    7 │ CloudHost   │
│ 14:22:05 │ SWEEP    │ 203.0.113.88    │ 5 Distinct   │ DE, Frankfurt   │   12 │ Datacenter  │
│ 14:22:12 │ MEDIUM   │ 192.0.2.15      │ 2121/tcp(FTP)│ BR, São Paulo   │    2 │ Telecom     │
│ 14:22:18 │ TUNNEL   │ 198.51.100.99   │ ICMP (H:4.8) │ NL, Amsterdam   │    4 │ FiberNet    │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
  [↵] Inspect  [B] Ban/Unban  [U] Whitelist  [X] Auto-Ban  [C] Sockets  [G] GeoIP  [K] Killswitch
  [M] Metrics  [O] Spawn Trap [T] Theme      [/] Filter    [E] Export   [S] Sim    [Q] Quit
```

- **4 Visual Themes (`[T]`):**
  - **Cyber SOC (Default):** High-tech cyan, yellow, and red layout.
  - **Matrix Hacker:** Monochromatic phosphor green on deep black.
  - **Midnight Violet:** Indigo borders with magenta and cyan highlights.
  - **High Contrast:** Bold white and yellow layout designed for bright environments.
- **Deep Incident Inspector (`Enter`):**
  - Opens a full forensic modal showing reverse DNS (PTR), GeoIP/ASN info, and MITRE ATT&CK classifications.
  - Displays captured packet headers and payload bytes in a canonical `xxd` hexdump.
  - Automatically suggests firewall remediation commands.
- **GeoIP & Attack Distribution Modal (`[G]`):**
  - Displays ASCII horizontal bar charts showing top attacking countries and autonomous systems (ASNs).
- **Executive SOC Metrics Modal (`[M]`):**
  - Visualizes port attack distributions, MITRE technique breakdowns, and threat severity tiers.
- **Live Search & Filter (`/`):**
  - Live filtering by IP, port, severity, or service keyword.
- **Real-Time Traffic Sparkline:**
  - Rolling 24-second unicode sparkline graph (` ▂▃▄▅▆▇█`) indicating incoming probe intensity.

---

### 9. Remote & Headless Hardening

Designed to run reliably across remote cloud servers, headless VPS instances, and mobile SSH clients:

- **RAII TerminalGuard:** Automatically restores the terminal (`disable_raw_mode` and `LeaveAlternateScreen`) on normal exits, unhandled errors, or panics.
- **Low-Bandwidth Idle Polling (4 Hz):** Drops to 250 ms event polling during idle periods, reducing SSH packet traffic, mobile data usage, and battery consumption.
- **O(n) Sliced Rendering:** Slices visible rows to maintain fast rendering speeds even with thousands of logged events.
- **Instance Conflict Watchdog:** Detects existing Sentinela processes on startup and offers to terminate them gracefully (`[S/n]` or `-k` / `--kill-existing`) to reclaim honeypot ports.

---

## 📦 Installation & Setup

### One-Line Automated Installer

**Linux:**
```bash
curl -fsSL https://raw.githubusercontent.com/teizinh/sentinela/main/install.sh | bash
```

**Windows (PowerShell as Administrator):**
```powershell
irm https://raw.githubusercontent.com/teizinh/sentinela/main/scripts/install.ps1 | iex
```

---

### Pre-Built Binary Packages

Download pre-compiled binaries from the [Releases Page](https://github.com/teizinh/sentinela/releases). Every release includes a verified `SHA256SUMS.txt` checksum file:

| Platform | Format | Package File |
|---|---|---|
| **Debian / Ubuntu / Mint** | `.deb` | `sentinela-linux-x86_64.deb` |
| **Fedora / RHEL / openSUSE** | `.rpm` | `sentinela-linux-x86_64.rpm` |
| **Linux (Universal)** | `.tar.gz` | `sentinela-linux-x86_64.tar.gz` |
| **Linux ARM64** | `.deb`, `.tar.gz` | `sentinela-linux-arm64.*` |
| **macOS Intel** | `.tar.gz` | `sentinela-macos-x86_64.tar.gz` |
| **macOS Apple Silicon** | `.tar.gz` | `sentinela-macos-arm64.tar.gz` |
| **Windows x64** | Installer | `sentinela-windows-x64-setup.exe` |
| **Windows x64** | Portable ZIP | `sentinela-windows-x64.zip` |

---

### Building from Source

#### Prerequisites
- Rust and Cargo (version 1.70 or newer).
- Linux dependencies: `libpcap` and `libcap`.

```bash
# Ubuntu / Debian / Mint
sudo apt update && sudo apt install -y build-essential libpcap-dev libcap2-bin

# Fedora / RHEL / CentOS
sudo dnf install -y gcc libpcap-devel libcap

# Arch Linux
sudo pacman -S base-devel libpcap libcap
```

#### Compile & Grant Capabilities
```bash
# Clone the repository
git clone https://github.com/teizinh/sentinela.git
cd sentinela

# Build release binary
cargo build --release

# Grant raw packet capture and firewall privileges without requiring full root
sudo setcap cap_net_raw,cap_net_admin+eip target/release/sentinela

# Launch Sentinela
./target/release/sentinela
```

#### Using the Included Run Script
```bash
chmod +x run.sh
./run.sh

# Or launch with custom decoy ports:
./run.sh 22 80 3306 6379
```

---

## 💻 CLI Reference

```text
USAGE:
  sentinela [OPTIONS] [PORTS...]

ARGUMENTS:
  [PORTS...]            Custom TCP decoy honeypot ports (e.g. 22 80 3306 6379)
                        Defaults: 2121, 2222, 2323, 8080, 8443

OPTIONS:
  -h, --help            Print help information and exit
  -v, --version         Print version information and exit
  -c, --config <FILE>   Load a custom TOML configuration file
  --init-config         Generate a recommended sentinela.toml template in current dir
  -b, --auto-ban        Enable automated firewall auto-ban for threats (Threat Score >= 80)
  --webhook <URL>       Stream alerts to a Discord or Slack webhook URL
  --hub <URL>           Stream telemetry and heartbeats to a Sentinela Hub
  --whitelist <IPS>     Comma-separated list of IPs immune to auto-ban
  --theme <THEME>       Initial dashboard theme: cyber, matrix, midnight, contrast
  --simulate            Inject simulated attack scenarios on startup for testing/demos
  -k, --kill-existing   Automatically terminate conflicting Sentinela instances
```

### Environment Variables

| Variable | Description |
|---|---|
| `SENTINELA_CONFIG` | Path to custom configuration file |
| `SENTINELA_WEBHOOK` | Default Discord or Slack webhook URL |
| `SENTINELA_HUB_URL` | URL of the central Sentinela Hub |
| `SENTINELA_WHITELIST` | Comma-separated list of whitelisted IPs |
| `SENTINELA_THEME` | Default UI visual theme (`cyber`, `matrix`, `midnight`, `contrast`) |
| `SENTINELA_TEST_MODE` | Headless test execution mode (bypasses terminal check) |

---

## ⚙️ Configuration Reference (`sentinela.toml`)

Generate a clean configuration template using `sentinela --init-config`:

```toml
# ====================================================================
# SENTINELA CONFIGURATION FILE (sentinela.toml)
# ====================================================================

# Global switch for automated firewall auto-ban (Threat Score >= 80)
auto_ban = false

# Duration of temporary firewall bans in seconds (default: 600s = 10 minutes)
ban_duration_secs = 600

[traps]
# Decoy ports to bind as honeypots on startup
# Privileged ports (<1024) require CAP_NET_RAW / CAP_NET_ADMIN or root
ports = [2121, 2222, 2323, 8080, 8443]

[security]
# Enable automated kernel firewall dropping (iptables / netsh)
auto_ban = false
ban_duration_secs = 600

# Minimum threat score (0-100) required to trigger an automated ban
threat_threshold = 80

# List of trusted IP addresses immune to auto-ban
# Loopback and the current SSH session IP are always automatically whitelisted
whitelist = [
    "127.0.0.1",
    "192.168.1.1",
    "10.0.0.50"
]

[alerts]
# Webhook URL for real-time notifications (Discord, Slack, or SIEM receiver)
# webhook_url = "https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN"

# Enable audible terminal bell (\x07) on Critical and Sweep alerts
audio_alerts = false

# Enable desktop notifications (via notify-send on Linux or PowerShell on Windows)
desktop_notifications = true

[ui]
# Initial visual theme: "cyber", "matrix", "midnight", or "contrast"
theme = "cyber"

# Default interface language: "pt" (Portuguese) or "en" (English)
language = "en"
```

---

## ⌨️ Dashboard Keyboard Shortcuts

The dashboard controls are grouped into four functional categories:

### Threat Investigation & Modals
| Key | Action |
|---|---|
| `↵` (`Enter`) | Open deep forensic inspection modal for the highlighted incident (hexdump, rDNS, GeoIP, MITRE) |
| `c` | Open live system sockets inspector (`LISTEN`, `ESTABLISHED`) with process termination |
| `g` | Open GeoIP & Attack Origins distribution modal (top nations and ASNs) |
| `m` | Open executive SOC metrics and telemetry analytics modal |
| `w` | Open local port security audit modal |
| `i` | Open help and keyboard shortcut reference modal |
| `Esc` | Close any open modal and return to the main incident table |

### Active Defense & Mitigation
| Key | Action |
|---|---|
| `b` | Surgically ban or unban the selected attacker IP (`DROP` firewall rule) |
| `u` | Add or remove the selected IP to/from the trusted whitelist |
| `x` | Toggle automated firewall auto-ban on/off |
| `k` | Toggle emergency network killswitch (intercepted safely during active SSH sessions) |
| `r` | Restore network connectivity (undo emergency killswitch) |

### Search, Navigation & Filtering
| Key | Action |
|---|---|
| `/` | Open live interactive search bar (filters by IP, port, service, or severity) |
| `f` | Cycle severity filter: `All` → `Critical` → `Medium and above` |
| `↑` / `↓` / `j` / `k` | Navigate incidents line by line |
| `PgUp` / `PgDn` | Scroll incident list 5 lines at a time |
| `Home` / `End` | Jump directly to the top or bottom of the incident table |

### System & Telemetry Controls
| Key | Action |
|---|---|
| `t` | Cycle visual dashboard themes (`Cyber SOC` → `Matrix` → `Midnight` → `High Contrast`) |
| `o` | Open dynamic live honeypot trap spawner to bind a new TCP port |
| `e` | Export Threat Intel session reports (PCAP, CEF, Syslog, JSON, CSV, Markdown, HTML) |
| `s` | Inject diagnostic test attack simulation sequence (validates webhooks and UI) |
| `a` | Toggle terminal audio bell alarm and desktop notifications |
| `l` | Toggle UI interface language between English and Portuguese |
| `q` / `Ctrl+C` | Gracefully quit Sentinela, cleaning up killswitches and temporary bans |

---

## 🔒 Platform Support & Security Notes

### Feature Support Matrix

| Security Capability | Linux | Windows | macOS |
|---|:---:|:---:|:---:|
| Multi-Protocol Honeypot Traps | ✅ | ✅ | ✅ |
| Raw Packet Sniffer (Pre-Handshake SYN/NULL/FIN/XMAS) | ✅ (`AF_PACKET`) | ⚠️ *(Trap Mode)* | ⚠️ *(Trap Mode)* |
| Automated Firewall Auto-Ban | ✅ (`iptables`) | ✅ (`netsh`) | ⚠️ *(Manual)* |
| Trusted IP Whitelisting & Anti-Lockout | ✅ | ✅ | ✅ |
| ICMP Covert Tunnel & Ping Sweep Detection | ✅ | ✅ | ✅ |
| DNS Tunneling & Shannon Entropy Analysis | ✅ | ✅ | ✅ |
| In-Flight Credential Harvester | ✅ | ✅ | ✅ |
| Anti-Ransomware Honeyfile Canary Watchdog | ✅ (`inotify`) | ⚠️ *(N/A)* | ⚠️ *(N/A)* |
| ARP Cache Poisoning & MITM Guard | ✅ (`/proc/net/arp`) | ⚠️ *(N/A)* | ⚠️ *(N/A)* |
| Emergency Network Killswitch | ✅ (`iptables`+`rfkill`) | ✅ (`PowerShell`) | ⚠️ *(Manual)* |
| Synthesized Wireshark PCAP Export | ✅ | ✅ | ✅ |
| CEF, Syslog, JSON, CSV, MD & HTML Reports | ✅ | ✅ | ✅ |
| Live Socket & Process Killer | ✅ | ✅ | ✅ |
| Ratatui SOC Terminal Dashboard | ✅ | ✅ | ✅ |

### Linux Capabilities & Permissions

Sentinela is engineered with the principle of least privilege in mind. You **do not need to run as root**:
- **`CAP_NET_RAW`:** Allows opening `AF_PACKET` raw sockets to sniff stealth scans and pre-handshake packets.
- **`CAP_NET_ADMIN`:** Allows managing firewall rules (`iptables`) for auto-ban and the emergency killswitch.

Set these capabilities on the compiled binary with:
```bash
sudo setcap cap_net_raw,cap_net_admin+eip /usr/local/bin/sentinela
```
If executed without these capabilities, Sentinela degrades gracefully: raw packet sniffing is disabled, but all decoy honeypot traps, Shannon entropy watchdogs, SIEM exporters, and TUI functions remain operational.

---

## 📄 License

Sentinela is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

<p align="center">
  <sub>Developed by <a href="https://github.com/teizinh">teizinh</a>. Built with Rust, Ratatui, and Tokio. Special thanks to <a href="https://github.com/SirEntr0pyy">SirEntr0pyy</a> for SSH and mobile optimization insights.</sub>
</p>

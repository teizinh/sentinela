# Sentinela

<p align="center">
  <strong>Network Intrusion Detection, Honeypot Traps and Traffic Monitor — written in Rust</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Language-Rust-orange.svg" alt="Rust">
  <img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="MIT License">
  <img src="https://img.shields.io/badge/Interface-Ratatui%20TUI-purple.svg" alt="Ratatui TUI">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg" alt="Platforms">
  <img src="https://img.shields.io/badge/Version-0.3.9-green.svg" alt="Version 0.3.9">
</p>

---

Sentinela runs on your machine and watches your network interfaces in real time. It detects port scans (including Nmap SYN stealth, NULL, FIN and XMAS scans), catches anything that connects to configurable honeypot ports, and lets you cut all network access instantly if needed. Everything is visible through a terminal dashboard that works from a desktop down to an SSH session on a phone.

It does not require a separate server, database or cloud account. It runs as a single binary.

---

## Security Operations & Threat Intel (v0.3.9)

- **🌍 [G] GeoIP & Attack Origins Modal:** Interactive SOC distribution modal featuring ASCII bar charts of top attacking nations (with flag mappings) and top attacking ISPs/ASNs.
- **🛡️ ARP Cache Poisoning & MITM Guard:** Continuous `/proc/net/arp` watchdog that alerts on rogue MAC changes or gateway cloning attacks (mapped to MITRE ATT&CK `T1557.002`).
- **🎛️ 2-Line Categorized Action Footer:** Responsive control panel organizing quick-response defensive actions (`[↵]`, `[B]`, `[U]`, `[X]`, `[G]`, `[C]`, `[K]`) and analysis tools (`[M]`, `[O]`, `[T]`, `[/]`, `[E]`, `[S]`, `[I]`, `[Q]`) with styled color keycaps.
- **🎯 Surgical Socket & Process Kill (`[C]` + `[K]`):** Direct process termination (SIGKILL) on offending sockets directly from the Active Sockets Inspector.

---

## Remote & SSH Hardening (Mobile & Headless)

Sentinela includes first-class protections for running over SSH on remote servers, cloud VPS instances and mobile terminals:
- **Anti-Lockout SSH Whitelist:** Automatically parses `$SSH_CONNECTION` on startup and permanently whitelists your peer IP so auto-ban never cuts off your own SSH session.
- **Remote Killswitch Safety:** If an active SSH session is detected (`$SSH_CONNECTION` or `$SSH_TTY`), pressing `[K]` is safely intercepted with an on-screen toast to prevent locking yourself out of the remote machine.
- **RAII TerminalGuard:** Restores terminal state (`disable_raw_mode` and `LeaveAlternateScreen`) cleanly on normal exit, error propagation, or unwinding panics.
- **Low-Bandwidth 4 Hz Idle Polling:** Dynamically idles at 250 ms event polling (~4 FPS) to reduce mobile data usage, SSH packet overhead, and battery drain.
- **Linear O(n) Marquee & Visible Row Viewport:** Optimized column calculations and table viewport slicing (`.take()`) for blazing-fast rendering even with thousands of logged incidents.

---

## Install

**Linux:**
```bash
curl -fsSL https://raw.githubusercontent.com/teizinh/sentinela/main/install.sh | bash
```

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/teizinh/sentinela/main/scripts/install.ps1 | iex
```

### Pre-built packages

| Platform | Format | File |
|---|---|---|
| Linux (Debian / Ubuntu / Mint) | `.deb` | `sentinela-linux-x86_64.deb` |
| Linux (Fedora / RHEL / openSUSE) | `.rpm` | `sentinela-linux-x86_64.rpm` |
| Linux (universal) | `.tar.gz` | `sentinela-linux-x86_64.tar.gz` |
| Linux ARM64 | `.deb`, `.tar.gz` | `sentinela-linux-arm64.*` |
| macOS Intel | `.tar.gz` | `sentinela-macos-x86_64.tar.gz` |
| macOS Apple Silicon | `.tar.gz` | `sentinela-macos-arm64.tar.gz` |
| Windows | Installer | `sentinela-windows-x64-setup.exe` |
| Windows | Portable zip | `sentinela-windows-x64.zip` |

All releases are on the [Releases page](https://github.com/teizinh/sentinela/releases). A combined `SHA256SUMS.txt` is included in every release.

---

## What it does

### Port scan detection
On Linux, Sentinela reads raw packets directly from the network interface using `pnet` (requires `CAP_NET_RAW`). This lets it catch SYN stealth scans before the TCP handshake completes — the kind that `nmap -sS` and `masscan` use specifically to avoid leaving traces in application logs. It also detects NULL, FIN and XMAS scans. If a single IP hits five or more distinct ports within five seconds, it is flagged as a port sweep.

On Windows and macOS — or on Linux without the raw socket capability — the scanner degrades gracefully. Honeypot traps continue to work normally.

### Honeypot trap ports
Sentinela binds a set of ports and waits. Any incoming connection triggers an alert. Default trap ports: `2121`, `2222`, `2323`, `8080`, `8443`. You can pass your own list at startup:
```bash
sentinela 22 3306 5432 9200
```

### Emergency killswitch
Press `k` to drop all network traffic instantly. On Linux this inserts blocking rules into `iptables`/`ip6tables` and calls `rfkill block all`. Press `k` again to restore everything. If Sentinela exits while the killswitch is active, it cleans up automatically.

### Deep incident forensic inspection, reverse DNS & MITRE ATT&CK mapping
Press `Enter` on any highlighted incident to open a full forensic modal showing detailed SOC telemetry:
- **MITRE ATT&CK Enterprise Matrix:** Automatically classifies probes into techniques (e.g., `T1046: Network Service Discovery`, `T1110.001: Brute Force Password Guessing`, `T1190: Exploit Public-Facing Application`, `T1210: Exploitation of Remote Services`, `T1021: Remote Services`).
- **Forensic Hexdump Viewer:** Displays captured packet headers and payload bytes in canonical `xxd` / Wireshark hexdump formatting.
- **Network Telemetry:** Async Reverse DNS (PTR), Geolocation (with detailed RFC 1918 / RFC 6598 CGNAT local subnet classification), ISP entity, target port, Threat Score, and firewall remediation command.

### Trusted IP whitelisting
Manage a local whitelist of trusted IP addresses (gateways, internal scanners, management workstations) that are immune to auto-ban. Press `u` in the dashboard or forensic modal to add or remove an IP. You can also supply initial whitelisted addresses via `--whitelist <IP1,IP2>` or the `SENTINELA_WHITELIST` environment variable. Whitelisted addresses are rendered with a distinct green `[OK]` badge.

### Interactive honeypot protocol emulation & banner sniffing
When an attacker connects to an active honeypot port, Sentinela dynamically interacts using authentic protocol handshakes:
- **SSH (22/2222):** Transmits standard OpenSSH banner (`SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6`), capturing scanner identities and tool strings (e.g. libssh, PuTTY, Nmap NSE).
- **FTP (21/2121):** Emulates vsFTPd, accepts anonymous or named users and prompts for credentials, logging captured authentication attempts.
- **Telnet (23/2323):** Displays authentic Debian login prompt and captures user inputs.
- **SMTP (25):** Emulates Postfix ESMTP server and captures `HELO`/`EHLO` probes.
- **HTTP (80/8080):** Returns authentic `401 Unauthorized` responses with Nginx server headers and Basic Auth prompts to lure automated path discovery bots.
- **Redis (6379):** Simulates protected mode with `-NOAUTH Authentication required.`.

Captured banners and payloads are sanitized, displayed in the forensic modal, and included in threat reports.

### Automated threat auto-ban
Toggle automated firewall enforcement with `x` in the dashboard or launch with `--auto-ban`. Sentinela continuously evaluates attacker risk based on port sensitivity, payload signatures, and frequency. Any address reaching a **Threat Score ≥ 80** or performing a port sweep is instantaneously blocked at the firewall level (`DROP`). Built-in loopback and local subnet whitelisting prevents self-lockout. Temporary bans are cleanly removed on exit.

### Real-time Discord / Slack webhook dispatcher
Launch with `--webhook <URL>` or set the `SENTINELA_WEBHOOK` environment variable to stream critical threat detections and auto-ban events straight to your security operations Discord or Slack channel with rich color-coded embed payloads and zero terminal UI latency.

### Real-time traffic pulse & sparkline
On wider terminal screens, Sentinela renders a live unicode `Sparkline` graph in the header displaying attack intensity and frequency over rolling 24-second windows.

### Surgical per-IP firewall ban & unban
Press `b` in the dashboard or within the inspection modal to immediately block the attacker IP with an active firewall rule (`iptables -I INPUT 1 -s <IP> -j DROP` on Linux or `netsh advfirewall` on Windows). Banned addresses are marked with a distinct `[BAN]` badge in the incident table. Pressing `b` again unbans the IP. All surgical bans are cleaned up automatically on exit to prevent orphaned rules.

### Audio & desktop alert toggle
Press `a` to toggle immediate audio terminal bell (`\x07`) sounds and high-urgency OS desktop notifications for incoming Critical and Port Sweep alerts.

### Threat intelligence & SIEM multi-format export
Press `e` at any time to dump complete session threat intelligence in 5 industry-standard formats:
- `sentinela_report_YYYY-MM-DD_HH-MM-SS.json`: Full machine-readable SOC audit report including system metadata, active honeypots, whitelist, MITRE tactics, and incident scoring.
- `sentinela_report_YYYY-MM-DD_HH-MM-SS.csv`: Tabular forensic format for spreadsheet analysis.
- `sentinela_capture_YYYY-MM-DD_HH-MM-SS.pcap`: Fully valid libpcap binary packet trace containing synthesized Ethernet/IP/TCP frames and payloads for every captured probe — inspectable directly in **Wireshark** and **tcpdump**!
- `sentinela_report_YYYY-MM-DD_HH-MM-SS.cef`: Micro Focus ArcSight Common Event Format (CEF) compatible with **Splunk**, **Wazuh**, **Elastic**, and **QRadar**.
- `sentinela_report_YYYY-MM-DD_HH-MM-SS.syslog`: Standard RFC 5424 structured syslog stream ready for **rsyslog**, **Logstash**, and **Graylog** ingestion.

### Dynamic live honeypot trap deployment
Press `o` in the dashboard to open the live trap spawner prompt. Type any TCP port (e.g. `3306`, `5432`, `8000`) and press `Enter`. Sentinela immediately binds an asynchronous listener dual-stack (IPv4 & IPv6) and attaches protocol handshake emulation without restarting the monitoring daemon.

### Executive SOC metrics & telemetry dashboard
Press `m` to toggle the dedicated Metrics and Forensic Analytics modal:
- **Target Port Distribution:** Real-time proportional ASCII histogram of top attacked ports.
- **MITRE ATT&CK Matrix:** Ranked breakdown of observed adversarial tactics (Discovery, Initial Access, Lateral Movement).
- **Severity Breakdown:** Incident count across Critical, Sweep, Medium, and Alert tiers.
- **Active Defense Posture:** Live count of active firewall drops, whitelisted assets, and raw kernel packet sniffer status.

### Persistent TOML configuration
Sentinela automatically looks for configuration in `./sentinela.toml` or `~/.config/sentinela/config.toml`.
- Run `sentinela --init-config` to generate a well-commented template in your current directory.
- Pass a custom configuration file anytime with `--config <PATH>` or `-c <PATH>`.
- Configure default trap ports, firewall auto-ban thresholds, trusted IP whitelist, webhook URLs, and visual themes persistently.

### Visual dashboard themes
Press `t` to cycle through 4 distinct visual themes:
- **Cyber SOC (Default):** High-tech cyan, yellow, and red SOC aesthetics.
- **Matrix Hacker:** Classic monochrome phosphor green and dark shades.
- **Midnight Violet:** Dark indigo borders with magenta and cyan highlights.
- **High Contrast:** Crisp white and bold yellow layout designed for bright environments or classroom projectors.
You can also launch with a specific theme using `--theme matrix` or set `SENTINELA_THEME=matrix`.

### Real-time forensic search & filter
Press `/` in the dashboard to open an inline search bar. Type any IP, port number, or service keyword (e.g. `/192.168`, `/22`, `/admin`, `/CRIT`) to filter live incidents in real time. Press `Enter` to commit the filter or `Esc` to clear and return.

### Diagnostic attack simulation
Press `s` or launch with `--simulate` to inject realistic diagnostic test attack sequences (SSH brute-force, web vulnerability probing, and horizontal port sweeps) to test alerting sounds, webhooks, MITRE mapping, and auto-ban behavior without needing an external machine.

### GeoIP lookup
Every detected IP is looked up against the [ip-api.com](http://ip-api.com) service. Country, city and ISP are shown in the dashboard and written to the log. Results are cached for the session; failed lookups retry after two minutes.

### Audit logs
Incidents are written to daily log files (`sentinela_YYYY-MM-DD.log`) in the working directory. The format is plain text, one line per event. When an IP is seen again, the hit counter on its log line is updated in place.

### Session report
When you quit, Sentinela prints a summary to the terminal: uptime, total alerts, unique IPs seen, the most active source, the most targeted port, and a breakdown by severity.

---

## Incident severity levels

| Level | Colour | Triggered by |
|---|---|---|
| Critical | Red | Connections to SSH (22, 2222), Telnet (23, 2323), Redis (6379), MongoDB (27017) traps |
| Sweep | Red | ≥ 5 distinct ports from the same IP within 5 seconds |
| Medium | Yellow | Connections to FTP, SMTP, MySQL, PostgreSQL, RDP traps |
| Scan | Magenta | Raw SYN / NULL / FIN / XMAS packet detected |
| Alert | Cyan | Connections to DNS, HTTP, HTTPS or custom traps |

---

## Dashboard

The terminal UI adapts to the available width:

| Terminal width | Columns shown |
|---|---|
| Under 70 columns | Time, Risk, Source, Target |
| 70 – 94 columns | + Location |
| 95 columns and above | + Hits, ISP |

The header shows current network interface IPs, raw scanner status, and system info. An asterisk next to an IP (`192.168.1.1*`) means that address has triggered more than one alert this session.

The UI language switches between Portuguese and English at runtime. It is auto-detected from your `$LANG` / `$LC_ALL` environment variable at startup and can be toggled at any time with `l`.

### Keyboard shortcuts

| Key | Action |
|---|---|
| `q` / `Ctrl+C` | Exit (cleans up any active killswitch and temporary bans) |
| `c` | Open live active network sockets & connections inspector (LISTEN, ESTABLISHED) |
| `Enter` | Open deep forensic inspection modal for selected incident |
| `b` | Surgically ban / unban selected attacker IP (DROP firewall rule) |
| `u` | Add / remove selected IP to/from trusted whitelist (immune to auto-ban) |
| `x` | Toggle automated firewall auto-ban for high-threat IPs (Threat Score ≥ 80) |
| `t` | Cycle visual dashboard themes (Cyber SOC / Matrix / Midnight / High Contrast) |
| `/` | Live interactive search & filter by IP, port or service keyword |
| `o` | Spawn dynamic live honeypot trap on specified TCP port |
| `m` | Executive SOC metrics & forensic telemetry analytics panel |
| `s` | Inject diagnostic test attack simulation sequence into SOC |
| `e` | Export session Threat Intel (JSON, CSV, PCAP, CEF, Syslog, Markdown, and HTML) |
| `a` | Toggle audio bell alarm and desktop notifications |
| `i` | Open / close help modal |
| `w` | Open / close port security audit |
| `l` | Toggle language (PT / EN) |
| `k` | Toggle emergency network killswitch |
| `f` | Cycle severity filter: All → Critical → Medium and above |
| `r` | Restore network (undo killswitch) |
| `↑` / `↓` / `j` / `k` | Scroll incident list |
| `PgUp` / `PgDn` | Scroll 5 lines at a time |
| `Home` / `End` | Jump to top / bottom |
| `Esc` | Close any open modal |

Scrolling works the same way inside the help and port audit modals.

---

## Build from source

**Dependencies:**
- Rust and Cargo 1.70 or later
- On Linux: `libpcap` and `libcap`

```bash
# Fedora / RHEL
sudo dnf install libpcap-devel libcap

# Debian / Ubuntu
sudo apt install libpcap-dev libcap2-bin
```

**Using the included script (recommended):**
```bash
chmod +x run.sh
./run.sh

# With custom trap ports:
./run.sh 22 3306 9200
```

The script builds a release binary, applies `CAP_NET_RAW` automatically, and runs it.

**Manual:**
```bash
cargo build --release
sudo setcap cap_net_raw,cap_net_admin+eip target/release/sentinela
./target/release/sentinela
```

---

## Code structure

| File | Role |
|---|---|
| `src/main.rs` | Entry point, event loop, CLI argument parsing, async coordination |
| `src/models.rs` | Core data types: `Incident`, `PortWarning`, `SeverityFilter`, `Language` |
| `src/network.rs` | Raw packet capture, GeoIP, killswitch, local port scanner, desktop notifications |
| `src/scanner.rs` | Heuristic scan detection (SYN stealth, NULL, FIN, XMAS, port sweeps) |
| `src/traps.rs` | Honeypot TCP listeners, connection handling, alert generation |
| `src/ui.rs` | Ratatui rendering, responsive layout, modals |

The scanner module (`src/scanner.rs`) is Linux-only and compiled conditionally. On other platforms, the rest of the application continues to work through the trap-based detection in `src/traps.rs`.

---

## Notes on permissions

Raw packet capture on Linux requires `CAP_NET_RAW`. The install script and `run.sh` set this capability on the binary automatically using `setcap`. If you run the binary without it, Sentinela will still start and the honeypot traps will still work — only the raw scanner will be inactive, which is shown in the header.

The killswitch also needs `CAP_NET_ADMIN` (or root) to insert `iptables` rules. Without it, it falls back to bringing interfaces down via `ip link`.

---

## Platform support

| Feature | Linux | Windows |
|---|---|---|
| Honeypot traps | ✓ | ✓ |
| Raw scan detection | ✓ | — |
| Auto-Ban firewall rules | ✓ (iptables) | ✓ (netsh) |
| Trusted Whitelisting | ✓ | ✓ |
| MITRE ATT&CK Mapping | ✓ | ✓ |
| Wireshark PCAP export | ✓ | ✓ |
| Live search & Themes | ✓ | ✓ |
| Webhook alerts | ✓ | ✓ |
| Killswitch | ✓ (iptables + rfkill) | ✓ (PowerShell) |
| Desktop notifications | ✓ (notify-send) | ✓ (PowerShell) |
| GeoIP lookup | ✓ | ✓ |
| Audit logs | ✓ | ✓ |

---

## License

MIT — see [LICENSE](LICENSE).

---

*Developed by [teizinh](https://github.com/teizinh). Special thanks to [SirEntr0pyy](https://github.com/SirEntr0pyy) for SSH & mobile optimization ideas.*

## Multi-Platform Builds & CI/CD

Every push to main and tag release runs comprehensive automated tests across Linux, Windows and macOS.
The release workflow packages Linux (x86_64, ARM64), macOS (Intel, Apple Silicon) and Windows x64 binaries, computing verified SHA-256 checksums automatically.

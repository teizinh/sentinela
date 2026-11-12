# Sentinela Hub (sentinela-hub) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `sentinela-hub`, a distributed, native 100% Rust SIEM and multi-host correlation dashboard with an interactive `egui` desktop GUI, embedded SQLite storage, and background HTTP/UDP telemetry ingestion for Sentinela nodes.

**Architecture:** A standalone Rust binary running `tokio` in a background thread for non-blocking HTTP and UDP telemetry ingestion into an embedded SQLite database (`rusqlite`), coupled with an immediate-mode GUI powered by `eframe`/`egui`/`egui_plot` on the main thread for 60 FPS live visualization, filtering, and multi-host attack correlation.

**Tech Stack:**
- Rust 2021 Edition
- GUI: `eframe = "0.28"`, `egui = "0.28"`, `egui_plot = "0.28"`
- Storage: `rusqlite = { version = "0.31", features = ["bundled"] }`
- Async Runtime & Ingestion: `tokio = { version = "1", features = ["full"] }`, `warp` or `axum` or raw `tokio::net::TcpListener`/`UdpSocket` for minimal lightweight ingestion
- Serialization: `serde = "1.0"`, `serde_json = "1.0"`, `chrono = "0.4"`

---

## Global Constraints
- 100% pure Rust code (no Node.js, no JavaScript, no Electron, no external database server).
- Must run natively on Linux (Wayland & X11) and Windows without external C libraries (using SQLite `bundled`).
- Zero UI freezing: all network I/O and SQLite writes must happen asynchronously or off the render loop.
- All unit tests must pass (`cargo test`).

---

## Review Focus
1. **Concurrency Safety:** Ingestion server writing to SQLite concurrently with GUI reading historical logs (mitigated by SQLite WAL mode and cross-thread channels).
2. **Multi-Host Correlation Logic:** Accurate time-window grouping of attacks coming from the same IP attacking 2 or more distinct nodes.
3. **GUI Responsiveness:** Smooth 60 FPS rendering under high-volume alert streams via channel batching.
4. **Resilience & Offline Handling:** Clean error recovery if a node sends malformed JSON or if the port is busy.
5. **Zero Data Loss:** Immediate persistence of incoming incidents to disk SQLite database.

---

## File Structure (`/home/salvadorpontes/sentinela-hub`)
- `Cargo.toml`: Dependencies and release profile.
- `src/main.rs`: Entry point, background tokio runtime initialization, eframe native window launch.
- `src/models.rs`: Core data structures (`AgentNode`, `HubIncident`, `CorrelationAlert`, `Severity`).
- `src/db.rs`: SQLite schema initialization (WAL mode), CRUD operations, queries for incidents and nodes.
- `src/correlation.rs`: Correlation engine detecting coordinated multi-host attacks within a time window.
- `src/server.rs`: Lightweight async ingestion listener receiving incidents from Sentinela agents.
- `src/ui/`:
  - `mod.rs`: Theme styling (Cyber Dark, rounded frames, fonts).
  - `header.rs`: Top metrics bar (Nodes online, Total hits, Correlated attacks, Status badge).
  - `sidebar.rs`: Node list with status dots and IP addresses.
  - `views/incidents.rs`: Live incidents table with interactive search, filters, and action buttons.
  - `views/correlations.rs`: Coordinated multi-host attack alerts view.
  - `views/analytics.rs`: Interactive timeline chart and top attackers list via `egui_plot`.

---

## Tasks

### Task 1: Project Scaffolding & Core Models
- [ ] Initialize cargo project at `/home/salvadorpontes/sentinela-hub`.
- [ ] Configure `Cargo.toml` with `eframe`, `egui`, `egui_plot`, `rusqlite`, `tokio`, `serde`, `serde_json`, `chrono`.
- [ ] Implement `src/models.rs` with `AgentNode`, `HubIncident`, `CorrelationAlert`, `Severity`.
- [ ] Write unit tests for models serialization and deserialization in `src/models.rs`.
- [ ] Verify `cargo test` passes.

### Task 2: Embedded SQLite Storage Engine (`src/db.rs`)
- [ ] Create `Database` struct wrapping `Arc<Mutex<rusqlite::Connection>>`.
- [ ] Initialize schema: `nodes` table, `incidents` table with indices on `timestamp`, `ip`, `node_id`.
- [ ] Enable `PRAGMA journal_mode = WAL` and `PRAGMA synchronous = NORMAL` for high write throughput.
- [ ] Implement `insert_incident`, `register_node`, `get_recent_incidents`, `get_nodes`, `get_top_attackers`.
- [ ] Write unit tests for SQLite CRUD operations in `src/db.rs`.
- [ ] Verify `cargo test` passes.

### Task 3: Multi-Host Attack Correlation Engine (`src/correlation.rs`)
- [ ] Implement `CorrelationEngine` with a configurable sliding time window (e.g. 10 minutes).
- [ ] Group incidents by attacker IP: if `distinct_nodes_targeted >= 2`, generate a `CorrelationAlert`.
- [ ] Calculate aggregate threat score and targeted port list across all target machines.
- [ ] Write unit tests for correlation triggers and window expiration in `src/correlation.rs`.
- [ ] Verify `cargo test` passes.

### Task 4: Lightweight Telemetry Ingestion Server (`src/server.rs`)
- [ ] Implement async HTTP/JSON ingestion listener (e.g. `POST /api/v1/incident`) on port `8765`.
- [ ] Parse JSON incident payloads (matching Sentinela's format).
- [ ] Pipe received incidents into the SQLite database and notify GUI channels.
- [ ] Write unit tests for HTTP ingestion parsing in `src/server.rs`.
- [ ] Verify `cargo test` passes.

### Task 5: Native Cyber GUI Shell & Custom Dark Theme (`src/ui/`)
- [ ] Implement `eframe::App` in `src/app.rs`.
- [ ] Apply custom Cyber SOC visual theme: dark slate background (`#0D1117`), cyan borders, amber key indicators, emerald green status dots.
- [ ] Build top status header with live counters (Nodes, Incidents, Correlated Attacks).
- [ ] Build left sidebar listing registered Sentinela agents with online/offline ping indicators.
- [ ] Test window spawning and layout responsiveness.

### Task 6: Interactive Views (Incidents, Correlations & Analytics)
- [ ] Implement `views/incidents.rs`: interactive table with search bar, severity filter dropdown, and action buttons (`[Banir IP]`, `[Ver Detalhes]`).
- [ ] Implement `views/correlations.rs`: dedicated card view displaying multi-host coordinated attacks with affected node badges.
- [ ] Implement `views/analytics.rs`: interactive `egui_plot` timeline of attacks per minute and bar chart of top offending IPs.
- [ ] Connect SQLite queries and live channel receiver to the GUI state.

### Task 7: Sentinela Agent Integration (`--hub` flag)
- [ ] In `/home/salvadorpontes/sentinela`, add `--hub <URL>` CLI flag and `sentinela.toml` setting.
- [ ] In `sentinela`, stream every detected incident to the Hub URL via non-blocking HTTP POST.
- [ ] Add unit test in `sentinela` verifying hub dispatch logic.
- [ ] Run full integration test: start `sentinela-hub`, run `sentinela --simulate --hub http://127.0.0.1:8765`, and confirm incidents and correlation appear live on the Hub GUI!

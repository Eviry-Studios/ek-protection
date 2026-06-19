# EK-Protection — Architecture v1.0

## Overview

EK-Protection is a modular, terminal-based antivirus daemon for Linux.
It follows a layered architecture where each subsystem is independent
and communicates through the central `EKEngine`.

```
┌─────────────────────────────────────────────────────────────────┐
│               CLI (ekp command) — Typer + Rich                  │
│  auth  logs  monitor  exceptions  quarantine  scan  heuristics  │
│  update  report  ← → IPCClient (Unix socket)                    │
└──────────────────────────┬──────────────────────────────────────┘
                           │ Unix Socket IPC
┌──────────────────────────▼──────────────────────────────────────┐
│                   EKEngine (core/engine.py)                     │
│              Lifecycle manager — start/stop/status              │
├──────┬──────┬──────┬──────┬───────┬───────┬───────┬────────────┤
│auth/ │logs/ │mon./ │exc./ │quar./ │scan./ │heur./ │updater/    │
│bcrypt│SQLite│inotf │white │Fernet │SHA256 │22rules│HTTP+SHA256 │
│sess. │JSONL │psutil│black │vault  │sigDB  │score  │auto 24h    │
├──────┴──────┴──────┴──────┴───────┴───────┴───────┴────────────┤
│          plugins/ (ClamAV + custom Python plugins)              │
│          reports/ (HTML / JSON / TXT)                           │
└─────────────────────────────────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│              config/ (YAML + ConfigManager)                     │
│          /etc/ek-protection/config.yaml — single source         │
└─────────────────────────────────────────────────────────────────┘
```

## Data Flow — Threat Detection

```
File event (inotify/watchdog)
       │
       ▼
  MonitorManager
  FSWatcher + ProcWatcher
       │  FileEvent / ProcessEvent
       ▼
  asyncio.Queue  →  _dispatch_loop  →  plugin.fire_file_event()
       │
       ▼ (auto-scan on new executables — future)
  ScanEngine.scan_file(path)
       │
       ├─── ExceptionManager.check() ──→ SKIPPED (whitelist)
       │                               → THREAT  (blacklist)
       │
       ├─── SignatureDB.lookup(sha256) ──→ THREAT (known hash)
       │
       ├─── Basic heuristics (location, entropy, ELF)
       │
       ├─── HeuristicEngine.analyze(path) ──→ 22 rules → score
       │
       └─── FileScanResult
                │
                ├── is_critical? ──→ QuarantineManager.quarantine_file()
                │                    (auto-quarantine mode)
                │
                └── LogManager.event(SCAN_MATCH / THREAT_DETECTED)
                    PluginManager.fire_threat()
                    Alert → Rich terminal display
```

## Storage Layout

```
/etc/ek-protection/
  config.yaml           — user configuration (YAML)
  auth.hash             — bcrypt password hash (chmod 600, never commit)

/var/lib/ek-protection/
  ek-protection.db      — SQLite: logs, quarantine index, exceptions, events
  signatures.db         — threat signature SHA-256 database
  quarantine/           — encrypted .ekpq files (Fernet AES-128-CBC)
  quarantine/.keys/     — quarantine.key (chmod 600)
  plugins/              — optional Python plugins

/var/log/ek-protection/
  ekp.log               — rotating text log (10MB × 3)
  ekp.jsonl             — structured JSON log (one event per line)
  daemon.log            — daemon stdout/stderr

/run/ek-protection/
  daemon.sock           — Unix socket for CLI ↔ daemon IPC (chmod 660)
  daemon.pid            — PID file
```

## IPC Protocol

```
Request  (CLI → daemon):   {"cmd": "status"}\n
Response (daemon → CLI):   {"ok": true, "data": {...}}\n

Commands:
  ping              → "pong"
  status            → full engine status dict
  stop              → "stopping" (triggers graceful shutdown)
  scan_file path=X  → FileScanResult.to_dict()
  update force=B    → FetchResult summary
  quarantine_list   → [QuarantineEntry.to_dict(), ...]
  log_tail n=20     → [LogEntry.to_dict(), ...]
```

## Subsystem Initialization Order

```
Engine.start():
  1. _init_logs()          — SQLite + rotating file handler
  2. _init_auth()          — bcrypt auth manager
  3. _init_exceptions()    — whitelist/blacklist (loads from config)
  4. _init_heuristics()    — 22-rule engine
  5. _init_quarantine()    — encrypted vault
  6. _init_scanner()       — SHA-256 + signature DB
  7. _init_updater()       — HTTP fetcher + auto-update loop
  8. _init_monitor()       — inotify FSWatcher + psutil ProcWatcher

Engine.stop() (reverse order):
  updater.stop() → monitor.stop() → quarantine.close()
  → exceptions.close() → logs.close()
```

## Patch History

| Patch | Version | Feature |
|-------|---------|---------|
| 1  | 0.1.0 | Base structure, config, CLI skeleton, async engine |
| 2  | 0.2.0 | Authentication (bcrypt, session, lockout) |
| 3  | 0.3.0 | Structured logging (SQLite + JSONL + rotating) |
| 4  | 0.4.0 | Real-time monitoring (inotify + psutil) |
| 5  | 0.5.0 | Exception system (whitelist/blacklist, O(1) cache) |
| 6  | 0.6.0 | Secure quarantine (Fernet vault, auth required) |
| 7  | 0.7.0 | On-demand scanner (SHA-256, signatures, auto-quarantine) |
| 8  | 0.8.0 | Advanced heuristics (22 rules, weighted score) |
| 9  | 0.9.0 | Daemon IPC (Unix socket), systemd, signature updater |
| 10 | 1.0.0 | Reports, plugins, ClamAV integration, stable release |

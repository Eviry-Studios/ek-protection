# Changelog — EK-Protection

All notable changes to this project will be documented in this file.
Format: [Semantic Versioning](https://semver.org/)

---

## [1.0.0] — 2024-06-15

### ✅ Stable Release

#### Added
- **Patch 1** — Base project structure, config system (YAML), CLI skeleton (Typer + Rich), async engine
- **Patch 2** — Authentication: bcrypt (work factor 14), session tokens, lockout, `ekp auth *`
- **Patch 3** — Structured logging: SQLite + JSONL + rotating files, `ekp logs *`
- **Patch 4** — Real-time monitoring: FSWatcher (inotify), ProcWatcher (psutil), async dispatch pipeline
- **Patch 5** — Exception system: whitelist/blacklist by path/hash/process/extension, O(1) cache, `ekp exceptions *`
- **Patch 6** — Secure quarantine: Fernet encryption, vault, restore/delete with auth, `ekp quarantine *`
- **Patch 7** — On-demand scanner: SHA-256 chunked, signature DB, quick/full/paths scan, `ekp scan *`
- **Patch 8** — Advanced heuristics: 22 rules (H001–H022), weighted score, configurable sensitivity, `ekp heuristics *`
- **Patch 9** — Daemon IPC: Unix socket, real-time status, signature updater, systemd unit, `ekp update *`
- **Patch 10** — v1.0 stable: reports (HTML/JSON/TXT), plugin architecture, ClamAV integration, EKP logo

#### Security
- All file operations audit-logged to SQLite
- Quarantine uses AES-128-CBC (Fernet) — files unreadable without key
- Authentication bcrypt work factor 14 (~1s per attempt)
- Constant-time token comparison (`hmac.compare_digest`)
- Signature update checksum verification (SHA-256)
- IPC socket chmod 660 — root-only write access

---

## [0.9.0] — Patch 9

Daemon IPC, Unix socket, systemd notify, signature auto-updater.

## [0.8.0] — Patch 8

22 heuristic rules: reverse shells, fileless malware, C2 beacons, privilege escalation, fork bombs, UPX packing.

## [0.7.0] — Patch 7

SHA-256 scanner, signature database, auto-quarantine for critical threats.

## [0.6.0] — Patch 6

Fernet-encrypted quarantine vault with full audit trail.

## [0.5.0] — Patch 5

Whitelist/blacklist exception system with O(1) hash lookups.

## [0.4.0] — Patch 4

Real-time inotify filesystem monitoring + psutil process watcher.

## [0.3.0] — Patch 3

SQLite + JSONL structured logging with retention and export.

## [0.2.0] — Patch 2

bcrypt authentication, session management, progressive lockout.

## [0.1.0] — Patch 1

Initial project structure, configuration manager, CLI skeleton.

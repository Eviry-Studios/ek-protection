# Changelog — EK-Protection

All notable changes to this project will be documented in this file.
Format: [Semantic Versioning](https://semver.org/)

---

## [Unreleased] — Patch 11 (2026-09-04)

> Not yet tagged as a package version bump — `__version__`/`pyproject.toml`
> still read `1.0.0`. Bumping that touches a hardcoded value in
> `reports/generator.py` and an assertion in `tests/test_patch10.py`, left
> out of this documentation-only fix on purpose.

CLI read commands (`logs`, `quarantine`, `scan`, `exceptions`) migrated to talk
to the running daemon over IPC first, falling back to direct file access only
if the daemon isn't up — closes the long-standing bug where these commands
needed `sudo` to open root-owned SQLite files directly.

#### Added
- IPC streaming mode: `scan quick`/`scan full`/`scan paths` now emit a
  `progress` event per file plus a final `result` event, instead of a single
  request/response.
- `quarantine info`/`quarantine stats` migrated to IPC (last gap in the
  sudo-free CLI).
- Real `manifest.json` + `signatures.jsonl` published for the signature
  updater (previously pointed at a URL with no real payload).

#### Fixed
- Heuristic engine: a rule's `severity` never influenced the aggregated
  `risk_level` — a single "critical" match (reverse shell, fork bomb,
  fileless malware) could still report "low" risk and skip auto-quarantine.
- `monitor.paths` entries that were, or contained, a symlinked directory
  (e.g. `/opt` → `/var/opt`) registered an inotify watch that silently never
  fired.
- `EKP_DATA_DIR` didn't relocate `logs.dir`, breaking the logging subsystem
  when running without root.

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

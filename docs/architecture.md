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

## Roadmap — Próximos Patches (pós-v1.0)

### 🐛 Bug conhecido: comandos CLI ignoram o daemon e abrem o SQLite direto

**Sintoma:** `ekp logs tail`, `ekp quarantine list`, `ekp scan file`, `ekp exceptions list`
e outros comandos de leitura falham com `sqlite3.OperationalError: unable to open
database file` quando rodados **sem sudo**, mesmo com o daemon ativo e respondendo
normalmente a `ekp status`.

**Causa raiz:** Só o `ekp status` e `ekp stop` foram migrados para conversar com o
daemon via `IPCClient` (socket Unix, Patch 9). Todos os outros comandos (`logs`,
`quarantine`, `scan`, `exceptions`, `heuristics`, `update`) ainda instanciam seus
próprios `LogStore`/`QuarantineStore`/`SignatureDB` e abrem os arquivos `.db` em
`/var/lib/ek-protection/` diretamente do processo da CLI. Como esses arquivos
pertencem a `root` (dono do processo do daemon), qualquer usuário sem sudo recebe
"unable to open database file" — não é falha de lógica, é falta de permissão de
disco mesmo.

**Paliativo atual:** prefixar esses comandos com `sudo`.

**Progresso (Patch 11):**
- ✅ `logs_search` — feito (`ekp logs tail`/`search`, 2026-08-23)
- ✅ `exceptions_list` — feito (`ekp exceptions list`, 2026-08-24)
- ✅ `scan_file` — o daemon já implementava desde o Patch 9, só a CLI nunca
  usava; migrado (`ekp scan file`, 2026-08-24)
- ❌ `heuristics_analyze` — **verificado e removido desta lista** (2026-08-24):
  `ekp heuristics analyze` não instancia `LogStore`/`QuarantineStore`/
  `SignatureDB`, roda `HeuristicEngine(cfg)` sem `exc_manager`/`log_manager`,
  nunca toca um arquivo `.db` root-owned — não tem o bug de sudo descrito
  acima, não precisa de IPC.
- 📋 `scan_quick`/`scan_full` ainda pendentes — mesmo bug de sudo dos outros
  (`_build_engine()` em `scan_commands.py` abre `SignatureDB`+`ExceptionManager`
  direto), mas scan longo via IPC precisa de progresso/streaming pelo socket,
  não é só trocar por `client.send()` — fica pra uma rodada futura.
- Fallback já padronizado num helper único (`cli/_ipc_or_direct.py`, 2026-08-23)
  em vez de duplicar a lógica em cada arquivo de comando

### 📋 Outras melhorias planejadas

- **Banco de assinaturas real** — hoje só existem 3 hashes de demonstração.
  Popular com feeds públicos de IOCs (ex: MalwareBazaar, URLhaus) ou focar
  inteiramente na detecção heurística + ClamAV como motor de assinaturas.
- **Auto-scan no monitor** — hoje o monitor só *observa* eventos de arquivo;
  ele não dispara `scan_file()` automaticamente em executáveis novos. Ligar
  `MonitorManager` → `ScanEngine` via callback é trabalho pendente.
- **Symlink `/opt` → `/var/opt` em sistemas atômicos** — confirmar que paths
  resolvidos em runtime (`Path(__file__).resolve()`) não geram inconsistência
  entre `/opt/...` e `/var/opt/...` nos logs e mensagens de erro (cosmético,
  mas confunde no diagnóstico).
- **Updater de assinaturas com manifest real** — hoje aponta para uma URL que
  não existe ainda; criar o `manifest.json` + `signatures.jsonl` no próprio
  repositório como fonte inicial.
- **Testes de integração com daemon real** — a suíte atual (525 testes) cobre
  cada módulo isoladamente com mocks; faltam testes end-to-end que sobem o
  daemon de verdade e validam o IPC completo, pegando bugs como o acima antes
  de chegar em produção.

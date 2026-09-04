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
- ✅ `scan_quick`/`scan_full`/`scan_paths` — feito (2026-08-26). Protocolo IPC
  ganhou um segundo modo (`_STREAMING_COMMANDS` em `daemon.py`): a conexão
  recebe várias linhas JSON (evento `progress` por arquivo + 1 evento `result`
  final com o `ScanReport` completo) em vez do request/response de 1 linha só.
  `IPCClient.send_stream()` consome isso com um callback de progresso.
  `ekp scan quick/full/paths` tentam o daemon primeiro (mesmo padrão dos
  outros comandos Patch 11), caem pro `_build_engine()` local se ele não
  estiver rodando.
- Fallback já padronizado num helper único (`cli/_ipc_or_direct.py`, 2026-08-23)
  em vez de duplicar a lógica em cada arquivo de comando
- ✅ `quarantine_info`/`quarantine_stats` — feito (2026-09-03). `ekp
  quarantine list` (sem `--all`) já tinha sido migrado em 2026-08-22, mas
  `ekp quarantine info <id>` e `ekp quarantine stats` continuavam abrindo
  o SQLite root-owned direto (`_open_mgr`), exigindo sudo mesmo com o
  daemon rodando — último gap real do Patch 11, achado ao revisar
  `quarantine_commands.py` comando a comando. Comandos novos
  `quarantine_info`/`quarantine_stats` no `IPCServer._dispatch`
  (`daemon.py`), CLI migrada pro mesmo padrão "IPC primeiro, cai pro
  acesso direto se o daemon não responder" já usado por `quarantine
  list`. `cmd_restore`/`cmd_delete`/`cmd_purge` ficam de fora de propósito
  — são operações destrutivas/irreversíveis que já exigem autenticação
  própria (`_authenticate`), não fazem parte do bug "comando de leitura
  sem sudo".

### 📋 Outras melhorias planejadas

- ✅ **Motor heurístico avançado nunca era consultado pelo scanner real —
  corrigido (2026-08-29)**. Achado em 3 camadas na mesma rodada, do sintoma
  até a causa raiz:
  1. `HeuristicEngine._calculate_score` só somava `weight` — o `severity`
     de cada regra (usado até então só pra colorir a listagem da CLI) nunca
     influenciava o `risk_level` agregado. Resultado: uma regra "crítico"
     isolada (H006 reverse shell, H011 fork bomb, H015 fileless...) sempre
     saía como "baixo" (peso 10 = 20 pontos, longe do threshold 80).
     Corrigido com um piso de severidade: o `risk_level` final nunca fica
     abaixo da maior severidade entre as regras que dispararam (o score
     numérico continua igual, só o mapeamento pra `risk_level` mudou).
  2. Mesmo com "crítico" correto, `ScanEngine._scan_file_inner` sempre
     forçava `verdict=SUSPICIOUS` pra detecção heurística — `is_critical`
     exige `verdict==THREAT`, então a auto-quarentena (`quarantine.
     auto_quarantine_critical`) nunca disparava pra nenhuma ameaça vinda
     de heurística, só de assinatura conhecida. Corrigido: heurística
     "crítico" agora vira `verdict=THREAT`. `_auto_quarantine` também
     usava sempre `QuarantineReason.SIGNATURE_MATCH` mesmo pra detecção
     heurística — corrigido pra usar `QuarantineReason.HEURISTIC` quando
     `threat_type=="Heuristic"`.
  3. **Causa raiz real, só apareceu ao validar ponta a ponta via monitor
     real** (os 2 achados acima pareciam resolvidos nos testes unitários,
     que sempre injetam `heuristic_engine=` manualmente na construção do
     `ScanEngine`): `EKEngine.start()` chamava `_init_scanner()` **antes**
     de `_init_heuristics()` — `ScanEngine.__init__` recebe
     `heuristic_engine=self.heuristics`, e nesse instante `self.heuristics`
     ainda era `None`. O scanner captura esse `None` permanentemente; o
     motor de 22 regras nunca era consultado por nenhum scan real
     (manual, agendado ou auto-scan) em nenhuma instalação rodando —
     só a checagem base crua (localização/entropia/ELF) importava de
     verdade. Corrigido invertendo a ordem de boot (heuristics antes de
     scanner), com comentário no código explicando por que a ordem
     difere da numeração dos patches.
  **Efeito prático do achado**: até esta rodada, um reverse shell/fork
  bomb/técnica fileless literal dropado num diretório monitorado era
  detectado (aparecia nos logs como SUSPICIOUS) mas **nunca era
  quarentenado automaticamente**, mesmo com `auto_quarantine_critical:
  true` (default). Validado end-to-end com teste novo, sem mock nenhum
  (`tests/test_engine.py::TestAutoScanWiring::
  test_end_to_end_simulated_reverse_shell_auto_quarantined`): dropa um
  script com reverse shell literal (inofensivo, nunca executado) num
  diretório monitorado de verdade e confirma, via inotify real, que ele
  é detectado E removido/quarentenado sozinho. Testes novos também em
  `tests/test_heuristics.py::TestSeverityFloor` (5 casos) e
  `tests/test_scanner.py::test_auto_quarantine_reason_is_heuristic_for_heuristic_threat`.
- ✅ **H018 (Strings de Wallet Crypto) validada via pipeline real —
  confirmado (2026-09-04)**. Teste intenso da tarefa diária: dropper de
  cryptominer simulado (config com endereço de payout) num diretório
  monitorado de verdade. Nunca tinha sido testada fora de unit test com
  `HeuristicContext` construído manualmente — confirmado agora que o
  pipeline completo (inotify → auto-scan → heurística → log) detecta de
  verdade, e que a severidade "alto" isolada corretamente **não** dispara
  auto-quarentena (só "crítico" dispara, comportamento esperado, arquivo
  fica no disco pra revisão manual). Teste novo:
  `tests/test_engine.py::TestAutoScanWiring::
  test_end_to_end_crypto_wallet_string_detected_not_quarantined`.
- **Banco de assinaturas real** — hoje só existem 3 hashes de demonstração.
  Popular com feeds públicos de IOCs (ex: MalwareBazaar, URLhaus) ou focar
  inteiramente na detecção heurística + ClamAV como motor de assinaturas.
- ✅ **Auto-scan no monitor** — feito (2026-08-27). `EKEngine._wire_auto_scan()`
  registra um callback no `MonitorManager` assim que o `ScanEngine` termina
  de iniciar (ordem de boot: monitor primeiro, scanner depois — callback
  precisa ser ligado depois dos dois existirem). Eventos `CREATED`/`MOVED`/
  `EXECUTED` de arquivo com extensão executável (`FileEvent.
  is_executable_extension`) disparam `scan_file()` de verdade via
  `loop.run_in_executor()` (não bloqueia o dispatch loop do monitor).
  `MODIFIED` fica de fora de propósito (evita rescanear o mesmo arquivo
  várias vezes durante uma escrita em partes/download). Controlável via
  `monitor.auto_scan_new_executables` (default `true`). Validado com EICAR
  real via inotify de verdade (não mock) em `tests/test_engine.py::
  TestAutoScanWiring::test_end_to_end_real_eicar_via_fs_watcher`.
- ✅ **Symlink `/opt` → `/var/opt` em sistemas atômicos** — feito (2026-09-02).
  Investigado como suspeita de item cosmético, virou achado real de falha
  silenciosa: `Path(__file__)` não é usado em nenhum lugar sensível a isso
  (só `reports/generator.py` pra achar o `assets/logo.png`), mas o
  `watchdog` (lib usada pelo `FSWatcher`) agenda watches de inotify com a
  flag `IN_DONT_FOLLOW` por padrão — se o path configurado em
  `monitor.paths` for (ou passar por) um symlink de diretório, ex.
  `/opt/ek-protection` num sistema atômico onde `/opt` → `/var/opt`, o
  watch "ativa" sem erro nenhum (`FSWatcher.active_paths` mostra o path
  normal) mas **nunca dispara evento nenhum pra conteúdo criado/modificado
  dentro dele** — monitoramento morto silenciosamente, sem log de aviso.
  Confirmado empiricamente (symlink real em `/tmp`, sem mock) antes de
  mexer no código. Corrigido em `ekprotection/monitor/fs_watcher.py`:
  `FSWatcher.start()` agora agenda o watch no path **resolvido**
  (`Path.resolve()`, senão o inotify nunca vê dentro do diretório), e
  `_EKPEventHandler` reescreve o path de cada evento de volta pro prefixo
  **configurado** originalmente (`_unresolve()`) antes de colocar o
  `FileEvent` na fila — assim heurística (`std_dirs` em
  `_r_no_extension_elf`), logs e exceptions continuam vendo
  `/opt/ek-protection/...` como configurado, nunca o `/var/opt/...` real.
  Teste novo `tests/test_monitor.py::TestFSWatcher::
  test_symlinked_root_still_produces_events_with_original_path` (symlink
  real, sem mock): confirma evento disparado E path reportado com o
  prefixo configurado, não o resolvido.
- ✅ **Updater de assinaturas com manifest real** — feito (2026-08-28).
  `signatures/manifest.json` + `signatures/signatures.jsonl` criados no
  próprio repositório (fonte inicial self-hosted via
  `raw.githubusercontent.com/Eviry-Studios/ek-protection/main/signatures/`,
  a mesma URL que `UpdateManager` já montava por padrão desde o Patch 9 —
  só nunca existiu do lado do servidor). Conteúdo inicial: só o hash real
  do EICAR (`source: ekp-official`) — os 2 hashes fictícios de
  `_DEMO_SIGNATURES` (`demo_trojan_downloader_...`/`demo_coinminer_...`)
  ficam de fora de propósito, são placeholders de pipeline documentados
  como tal no próprio código, não assinaturas reais publicáveis. Item
  maior "banco de assinaturas real via feed de IOCs" (MalwareBazaar/
  URLhaus) continua em aberto, é escopo maior — populariam este mesmo
  `signatures.jsonl`. Validado com teste novo (sem mock nenhum):
  `tests/test_updater.py::TestSignatureFetcherRealManifest` sobe um
  `http.server` local servindo uma cópia de `signatures/`, roda
  `SignatureFetcher.update()` real (HTTP → checksum SHA-256 → import
  JSONL) e confirma o EICAR importado no `SignatureDB`.
- ✅ **Testes de integração com daemon real** — feito (2026-08-25,
  `tests/test_cli_ipc.py`): sobe `ekp start` como subprocesso de verdade
  num ambiente isolado, valida `ekp logs tail`, `ekp exceptions list` e
  `ekp scan file` via socket IPC real (não mock), inclusive o fallback
  pro SQLite direto quando o daemon é derrubado. **Ampliado em 2026-08-26**
  (`TestScanStreamingViaIPC`): mesma cobertura agora pra `ekp scan full`
  (detecção real do EICAR) e `ekp scan paths` (IPC + fallback direto).

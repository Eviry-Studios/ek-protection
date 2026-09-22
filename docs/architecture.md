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
- ✅ **Permissões de chave/hash não eram reforçadas num load posterior —
  corrigido (2026-09-05)**. Tanto `QuarantineVault` (`quarantine.key`,
  decifra todo o conteúdo em quarentena) quanto `AuthManager`
  (`auth.hash`, hash bcrypt da senha) só garantiam `chmod 600` no
  **momento da criação** — se a permissão fosse afrouxada depois por
  qualquer motivo (restore de backup, reinstalação por cima, extração de
  tar/zip sem preservar modo de arquivo), o daemon continuava carregando
  o arquivo normalmente, sem aviso nenhum, deixando a chave mestra do
  vault (ou o hash bcrypt, habilitando brute-force offline apesar do work
  factor 14) legível por qualquer usuário local. Confirmado ao vivo antes
  de corrigir: `chmod 644` manual seguido de `initialize()`/
  `authenticate()` mantinha 644, não reforçava 600. Corrigido com
  `_enforce_key_permissions()`/`_enforce_hash_file_permissions()`,
  chamados a cada load (`_load_key()`/`_read_hash()`), que corrigem o
  modo de volta pra 600 e logam warning se precisaram agir — auto-cura
  de permissão em vez de só confiar no estado inicial. Testes novos sem
  mock: `tests/test_quarantine.py::TestQuarantineVaultInit::
  test_reinitialize_reenforces_loosened_key_permissions` +
  `test_load_key_reenforces_loosened_permissions`,
  `tests/test_auth.py::TestSetup::test_authenticate_reenforces_loosened_permissions`.
- ✅ **H023 (Exfiltração de Segredo/Wallet) — regra nova (2026-09-15)**.
  Teste intenso da tarefa diária: revisão das 22 regras existentes contra
  um cenário de dropper que lê um segredo (chave do vault de quarentena,
  hash de auth, wallet.dat/keystore/id_rsa/mnemonic) e manda pra um host
  externo via `curl -F`/`-d`/`-T`/`wget --post-data` — nenhuma cobria
  isso: H009 ("Acesso a Arquivos Sensíveis") só olha `/etc/shadow` e cia
  (credenciais do SO, não segredos do próprio app nem de wallet), H019
  ("Beacon C2") exige padrão de loop `sleep`+`curl`, não um upload único.
  Nova regra `H023`, severidade "crítico" (mesmo grupo do reverse
  shell/fork bomb — exfiltração da chave mestra do vault ou de uma wallet
  é perda de fundos irreversível, não menos grave que RCE), dispara em
  path sensível + primitivo de upload de rede juntos (nenhum dos dois
  isolado). Validado end-to-end sem mock via inotify real —
  `tests/test_engine.py::TestAutoScanWiring::
  test_end_to_end_secret_exfiltration_auto_quarantined`: script dropado
  detectado E quarentenado sozinho. Unit tests em
  `tests/test_heuristics.py::TestRuleH023SecretExfiltration` (5 casos,
  incluindo falso-positivo negativo pra download simples e upload sem
  segredo). Suite completa 569/569 sem regressão (23 regras agora, era 22).
- ✅ **H019 (Beacon C2) tinha falso-negativo e falso-positivo reais —
  corrigido (2026-09-16)**. Teste intenso da tarefa diária: revisão do
  regex `_RE_C2_BEACON` (`ekprotection/heuristics/rules.py`) contra
  cenários de beacon reais. 2 bugs achados na mesma regra:
  1. **Falso-negativo** — o regex único exigia a ordem exata
     `sleep/usleep ... curl/wget/nc`; o padrão de beacon igualmente comum
     (faz o check-in de rede primeiro, dorme depois, repete em loop —
     ex. `while true; do curl ...; sleep 60; done`) nunca disparava a
     regra, mesmo sendo severidade "crítico" (deveria auto-quarentenar).
  2. **Falso-positivo mais sério** — `nc` no regex não tinha
     word-boundary, então batia como substring de qualquer palavra comum
     (`function`, `sync`, `rsync`, `balance`, `announce`...). Qualquer
     script benigno com um `sleep N` em algum ponto e qualquer uma dessas
     palavras depois disparava H019 como "crítico" e era auto-quarentenado
     de verdade — risco real de falso-positivo destrutivo numa regra de
     severidade máxima.
  Corrigido: `_RE_C2_SLEEP`/`_RE_C2_NET` viraram 2 regexes independentes
  (mesmo padrão de combo já usado em H020/H023), checados sem exigir
  ordem entre si, e `\b` adicionado em `curl|wget|nc` pra não casar
  substring. Testes novos em `tests/test_heuristics.py::
  TestRuleH019C2Beacon` (ordem invertida dispara, `nc`/`sync`/`rsync`
  perto de sleep não dispara mais) e end-to-end sem mock em
  `tests/test_engine.py::TestAutoScanWiring::
  test_end_to_end_c2_beacon_request_then_sleep_auto_quarantined` (inotify
  real, script com loop "request depois sleep" detectado E quarentenado
  sozinho). Suite completa 574/574 sem regressão (569 + 5 novos).
- ✅ **H009 (Acesso a Arquivos Sensíveis) não cobria acesso local a
  credencial/wallet — corrigido (2026-09-17)**. Teste intenso da tarefa
  diária: revisão do gap deixado pela introdução de H023 (09-15) — H023
  só dispara na combinação path-sensível + upload de rede no mesmo
  arquivo; um stager/coletor que só *lê ou copia localmente*
  `wallet.dat`/`id_rsa`/`keystore`/`mnemonic`/`quarantine.key`/`auth.hash`
  (ex. `cp ~/.ssh/id_rsa /tmp/.cache-x/`, sem nenhum `curl`/`wget` no
  mesmo arquivo) não disparava nenhuma das 23 regras — H009 só olhava
  `/etc/shadow`/`/etc/passwd`/`/etc/sudoers` (credenciais de SO). Um
  atacante que separa coleta local de exfiltração em 2 etapas (ex. junta
  tudo num diretório de staging pra retirada manual depois) passava
  batido na 1ª etapa. Corrigido: `_r_sensitive_files` (H009) agora também
  checa `_RE_SECRET_PATHS` (mesma lista de paths já usada por H023),
  sem exigir o primitivo de rede — mantém severidade "alto" (mesmo piso
  de H018), não eleva a "crítico"/auto-quarentena sozinho (H023 continua
  sendo o caminho crítico quando o upload de rede está presente). Unit
  tests novos em `tests/test_heuristics.py::TestRuleH009SensitiveFiles`
  (6 casos: wallet.dat, id_rsa, keystore, mnemonic, quarantine.key, +
  negativo pra "private beach"/"key lime" não casar `private_key`
  por engano). End-to-end sem mock via inotify real:
  `tests/test_engine.py::TestAutoScanWiring::
  test_end_to_end_local_wallet_credential_access_detected_not_quarantined`
  — script de coleta local dropado num diretório monitorado, detectado
  como SUSPICIOUS, sem auto-quarentena. Suite completa 581/581 sem
  regressão (574 + 7 novos).
- ✅ **H014 (ptrace / LD_PRELOAD) exigia binário ELF pra QUALQUER sinal,
  inclusive LD_PRELOAD — corrigido (2026-09-18)**. Teste intenso da
  tarefa diária: revisão de regra crítica nunca validada via pipeline
  real desde que foi escrita. `ptrace()` é syscall nativa (faz sentido
  exigir ELF), mas `LD_PRELOAD` é técnica de env var/config — o vetor
  real mais comum é um **dropper em shell** setando a variável antes de
  lançar um processo alvo (ex. `export LD_PRELOAD=/tmp/.hook.so; exec
  wallet-cli`, hijack de libs pra interceptar chave/senha de uma wallet
  CLI ou bot em memória) ou escrevendo direto em `/etc/ld.so.preload`
  (sequestro persistente de todo processo do sistema, nem precisa
  relançar nada) — nenhum dos dois exige um binário compilado. A regra
  antiga (`if not ctx.is_elf: return None` antes de checar qualquer
  coisa) deixava esse script inteiro passar batido pelas 23 regras,
  justamente o cenário mais ligado ao foco desta tarefa diária
  (proteção de credenciais/criptoativos em memória de processo).
  Corrigido (`ekprotection/heuristics/rules.py`): sinal de `ptrace()`
  continua exigindo ELF; sinal de `LD_PRELOAD`/`ld.so.preload` virou
  independente, dispara em ELF OU script (mesmo padrão de combo
  independente já usado em H019/H023), com regex própria em vez de
  compartilhar `_RE_PTRACE` genérico. Testes novos em
  `tests/test_heuristics.py::TestRuleH014PtracePreload` (+4 casos:
  export em script dispara, escrita em `/etc/ld.so.preload` em script
  dispara, menção solta em texto/log sem ser ELF/script não dispara,
  `ptrace()` como string em script sem LD_PRELOAD não dispara — sinal
  nativo continua isolado do sinal de script). End-to-end sem mock via
  inotify real: `tests/test_engine.py::TestAutoScanWiring::
  test_end_to_end_ld_preload_shell_hijack_auto_quarantined` — launcher
  shell com `export LD_PRELOAD=...` dropado num diretório monitorado de
  verdade, detectado E quarentenado sozinho (severidade "crítico", piso
  de severidade de 08-29 continua valendo). Suite completa **586/586**
  sem regressão (581 + 5 novos: 4 unit + 1 end-to-end). Achado à parte,
  não relacionado a este fix: 1ª rodada da suite completa teve
  `test_created_executable_triggers_scan_file` falhando sob carga
  (passou isolado em 3.26s); reexecução completa confirmou 586/586 —
  flakiness de timing pré-existente sob concorrência de vários testes
  async/inotify reais na mesma suite, não regressão introduzida aqui.
- ✅ **H015 (técnica fileless) só casava `/proc/self/mem` e PID literal —
  corrigido (2026-09-19)**. Teste intenso da tarefa diária: revisão
  linha a linha da regra crítica, nunca validada via pipeline real. A
  regex antiga (`/proc/self/mem|/proc/[0-9]+/mem`) só disparava com o PID
  escrito como número literal, mas um scraper real de memória (ler a
  chave de uma wallet CLI/bot da Exchange rodando na VPS direto de
  `/proc/<pid>/mem`) escreve o PID como **variável** — `dd if=/proc/$PID/mem`,
  `cat /proc/${pid}/mem`, `/proc/$$/mem`, `/proc/$(pgrep wallet-cli)/mem`,
  `open(f"/proc/{pid}/mem")`, `'/proc/%d/mem' % pid`,
  `'/proc/' + str(pid) + '/mem'`, `/proc/thread-self/mem` — e nenhuma
  dessas formas disparava nenhuma das 23 regras (H009 só cobre path de
  credencial, não leitura de memória de processo). Também tinha falso
  positivo por prefixo: `/proc/1234/memory_stats` casava (sem limite de
  palavra depois de `mem`). Corrigido (`ekprotection/heuristics/rules.py`,
  `_RE_MEMFD`): aceita as formas acima e exige que `mem` não seja prefixo
  de outra palavra. Limite conhecido: concatenação só cobre `+` (não
  `os.path.join`/`"".join`) — ficou de fora por ser mais frágil de
  reconhecer por regex sem falso-positivo. Testes novos em
  `tests/test_heuristics.py::TestRuleH015Fileless` (+12 casos: 8 formas de
  PID variável disparam, 4 lookalikes — `/proc/meminfo`,
  `/proc/1234/memory_stats`, `/proc/$PID/status`, `cmdline` — não
  disparam). End-to-end sem mock via inotify real:
  `tests/test_engine.py::TestAutoScanWiring::
  test_end_to_end_proc_pid_mem_scraper_auto_quarantined` — script
  `dd if=/proc/$PID/mem` dropado num diretório monitorado, detectado E
  quarentenado sozinho (severidade "crítico"). Confirmado que os testes
  novos **falham sem o fix** (10 falhas com a regex antiga) e passam com
  ele. Suite completa **599/599** sem regressão (586 + 13 novos: 12 unit
  + 1 end-to-end); a flakiness de timing sinalizada em 09-18
  (`test_created_executable_triggers_scan_file`) não reapareceu.
- ✅ **H010 (comando destrutivo) errava nas duas direções — corrigido
  (2026-09-20)**. Teste intenso da tarefa diária: revisão linha a linha
  da regra crítica. A regex antiga (`rm\s+-[rf]{1,2}\s+/`) foi medida
  contra 48 casos reais antes de mexer: **14 de 28 wipers passavam
  batido** (`--no-preserve-root`, `~`, `$HOME`, `"$HOME"`, `-rfv`,
  `-r -f`, `--recursive --force`, alvo entre aspas, flag depois do alvo,
  `~/.ssh`, `~/.bitcoin`) e **14 de 20 comandos benignos disparavam como
  crítico** (`rm -rf /tmp/build`, `rm -f /tmp/app.pid`,
  `rm -rf /var/cache/...`, `rm -rf /home/x/proj/node_modules`) — e como
  crítico aciona auto-quarentena, o falso-positivo derrubava script de
  limpeza legítimo. Também não tinha word-boundary: `confirm -f /etc/hosts`,
  `perform -r /data`, `form -f /x` casavam como `rm`. O teste antigo
  `test_rm_rf_specific_triggers` afirmava `rm -rf /tmp/safe` como disparo
  — o próprio teste consagrava o falso-positivo; foi invertido.
  Corrigido (`ekprotection/heuristics/rules.py`, `_RE_RM_CMD` +
  `_rm_target_is_critical`): acha `rm` com word-boundary (`/bin/rm`,
  `sudo rm`, `xargs rm` contam), analisa flags em qualquer posição
  (`-r`/`-R`/cluster como `-rfv`/`--recursive`; `--no-preserve-root`
  dispara sozinho) e só dispara se recursivo E o alvo é raiz
  (`/`, `/*`), diretório de sistema (`/etc`, `/usr`, `/var/lib`...),
  `$HOME`/`~`/`/home/<user>`/`/root`, ou chave/wallet
  (`~/.ssh`, `.gnupg`, `.bitcoin`, `.ethereum`, `.electrum`, `.monero`).
  Limites conhecidos: `rm` não-recursivo de arquivo de sistema
  (`rm -f /etc/passwd`) deixa de ser H010 (antes casava por acidente) —
  continua pego por H009 (alto, sem auto-quarentena); variável não
  resolvida (`rm -rf "$DIR/"*`) e outros wipers (`find / -delete`,
  `dd of=/dev/sda`, `shred`, `mkfs`) não são cobertos por esta regra.
  Testes novos: `tests/test_heuristics.py::TestRuleH010RmRf` (26 formas
  destrutivas disparam, 13 limpezas de rotina e 4 palavras terminadas em
  `rm` não disparam) e end-to-end sem mock via inotify real:
  `tests/test_engine.py::TestAutoScanWiring::
  test_end_to_end_wiper_quarantined_routine_cleanup_left_alone` — wiper
  (`rm -rfv $HOME`, `rm -r -f ~/.bitcoin`) detectado E quarentenado; script
  de limpeza benigno no mesmo diretório monitorado não é quarentenado nem
  citado por H010. Confirmado que os testes novos **falham sem o fix**
  (28 unit + 1 e2e). Suite completa **644/644** sem regressão.
  Achado colateral do dia 09-20, **corrigido em 2026-09-21**: H002 (ver
  entrada própria abaixo).
- ✅ **H002 (executável em diretório suspeito) casava por substring, não
  por diretório — corrigido (2026-09-21)**. Achado colateral sinalizado
  em 09-20 (bloco H010 acima), semântica aprovada pelo Hermes no mesmo
  dia: os 4 diretórios (`/tmp`, `/dev/shm`, `/var/tmp`, `/run/user`)
  devem casar como sequência inteira de componentes de path, em qualquer
  profundidade (`/tmp/x.sh` e `/mnt/x/tmp/y.sh` disparam;
  `/home/u/tmpfiles/x.sh` e `/tmp-old/x.sh` não). A implementação antiga
  (`f"/{d.strip('/')}" in ctx.path`) casava por substring, então
  `tmpfiles`/`tmp-old` disparavam como falso-positivo de "executável em
  /tmp" só por conter o texto. Corrigido (`ekprotection/heuristics/rules.py`,
  `_r_exec_in_tmp`): path quebrado em componentes (`ctx.path.split("/")`,
  vazios descartados) e cada diretório suspeito vira uma sequência de
  componentes (`("tmp",)`, `("dev","shm")`, `("var","tmp")`,
  `("run","user")`) buscada como subsequência contígua exata, em qualquer
  posição — o `startswith` antigo já estava certo e não precisou mudar,
  só o ramo por substring. Testes novos em `tests/test_heuristics.py::
  TestRuleH002ExecInTmp` (+6 casos: os 4 diretórios disparando aninhados
  em profundidade arbitrária, e os 2 lookalikes `tmpfiles`/`tmp-old` não
  disparando). Confirmado que os 2 testes de lookalike **falham sem o
  fix** (stash só de `rules.py`). A asserção "H010 não é o motivo" do
  e2e de 09-20 (`test_end_to_end_wiper_quarantined_routine_cleanup_left_alone`)
  continua válida — `tmp_path` do pytest sempre inclui o componente
  exato `tmp`, então H002 segue disparando ali como antes.
- ✅ **H004 (eval/exec dinâmico) só cobria a forma Python — corrigido
  (2026-09-22)**. Achado da rodada diária: a regex antiga
  (`\beval\s*\(|\bexec\s*\(|\bexecve\s*\(`) exige parênteses logo após a
  palavra, o que cobre `eval(...)`/`exec(...)` em Python e a syscall
  `execve()`, mas **não cobre o builtin `eval` de shell**, que não usa
  parênteses — e essa é justamente a forma mais comum de dropper (payload
  base64/hex decodificado numa variável, rodado via `eval $cmd`,
  `eval "$(curl ... )"` ou `` eval `cat payload` ``). Testado ao vivo antes
  do fix: nenhuma das 4 formas disparava. Corrigido
  (`ekprotection/heuristics/rules.py`, `_RE_EVAL_EXEC`): segunda alternativa
  na regex casa `eval` de shell só quando o argumento é claramente dinâmico
  (`$(...)`, `${...}`, `$VAR` ou crase) — `eval "comando literal"` estático
  continua sem disparar, não é o padrão de ataque. `exec` de shell foi
  deixado de fora de propósito: `exec "$@"`/`exec $SHELL` são idiomas
  benignos e muito comuns em entrypoint/wrapper scripts, incluir geraria
  falso-positivo em volume sem ganho real (o vetor perigoso de `exec`
  dinâmico com rede, ex. `/dev/tcp/`, já é coberto por H006). Testes novos
  em `tests/test_heuristics.py::TestRuleH004EvalExec` (+10 casos: 6 formas
  de `eval` de shell disparando — var nua, var entre aspas, command
  substitution com e sem aspas, brace expansion, backtick — e 4 casos que
  não devem disparar — `eval` de string literal, `exec "$@"`, `exec $SHELL`,
  `evaluate(...)` como regressão de word-boundary). Confirmado que as 6
  novas asserções de disparo **falham sem o fix** (stash só de `rules.py`).
  Suite completa **660/660** sem regressão (650 + 10 novos). Próximas
  candidatas: H012 (deleção de histórico) e H013 (ofuscação de shell) —
  ainda não revisadas linha a linha nesta rodada.
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

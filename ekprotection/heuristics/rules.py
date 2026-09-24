"""
ekprotection.heuristics.rules
================================
Definição de regras heurísticas.

Cada regra é um objeto imutável com:
  - id:          identificador único
  - name:        nome legível
  - description: o que ela detecta
  - severity:    impacto se disparar (baixo/médio/alto/crítico)
  - weight:      peso no score composto (1–10)
  - tags:        categorias (script, binary, network, privilege, obfuscation...)
  - match(ctx):  função que recebe HeuristicContext e retorna RuleMatch ou None

As regras são avaliadas pelo HeuristicEngine e combinadas num score
ponderado que resulta num RiskScore final.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing      import Callable, Optional


@dataclass(frozen=True)
class RuleMatch:
    """Resultado positivo de uma regra."""
    rule_id:  str
    detail:   str                  # descrição específica do que foi encontrado
    evidence: Optional[str] = None  # trecho do arquivo ou linha suspeita (truncado)


@dataclass(frozen=True)
class HeuristicRule:
    """Regra heurística imutável."""
    rule_id:     str
    name:        str
    description: str
    severity:    str                   # baixo | médio | alto | crítico
    weight:      int                   # 1–10
    tags:        tuple[str, ...]
    _match_fn:   Callable             = field(compare=False, hash=False)

    def match(self, ctx: "HeuristicContext") -> Optional[RuleMatch]:
        """Aplica a regra ao contexto. Retorna RuleMatch ou None."""
        try:
            return self._match_fn(ctx, self.rule_id)
        except Exception:
            return None


@dataclass
class HeuristicContext:
    """
    Contexto passado a cada regra durante a avaliação.

    Contém todos os dados disponíveis sobre o arquivo sendo analisado.
    Regras usam apenas o que precisam — campos opcionais podem ser None.
    """
    path:           str
    sha256:         Optional[str]   = None
    file_size:      Optional[int]   = None
    entropy:        Optional[float] = None
    is_elf:         bool            = False
    is_script:      bool            = False
    is_executable:  bool            = False
    extension:      str             = ""
    content_sample: Optional[bytes] = None   # primeiros 64KB do arquivo
    strings:        list[str]       = field(default_factory=list)  # strings extraídas
    process_name:   Optional[str]   = None
    process_cmdline: list[str]      = field(default_factory=list)
    uid:            Optional[int]   = None
    mode:           Optional[int]   = None


# ---------------------------------------------------------------------------
# Funções de match das regras
# ---------------------------------------------------------------------------

# Padrões regex compilados uma vez (performance)
_RE_B64_DECODE   = re.compile(rb'base64\s*[-]d|base64_decode|atob\(', re.I)
# H004: forma Python/syscall exige parênteses (`eval(`/`exec(`/`execve(`).
# Mas o builtin `eval` de shell não usa parênteses (`eval $cmd`,
# `eval "$(curl ... )"`, `` eval `payload` `` — justamente a forma mais comum
# de dropper que decodifica payload (base64/hex) numa variável e roda via
# eval dinâmico) — a regex antiga não cobria essa forma. Segunda alternativa
# cobre `eval` de shell só quando o argumento é claramente dinâmico (`$(...)`,
# `${...}`, `$VAR` ou crase), não `eval "comando literal"` estático.
# `exec` de shell foi deixado de fora de propósito: `exec "$@"`/`exec $SHELL`
# são idiomas benignos e comuns (entrypoint/wrapper scripts), causariam
# muito falso-positivo sem ganho real de detecção.
_RE_EVAL_EXEC    = re.compile(
    rb"\beval\s*\(|\bexec\s*\(|\bexecve\s*\("
    rb"|\beval\s+['\"]?(?:\$\(|\$\{|\$[A-Za-z_]|`)",
    re.I,
)
_RE_WGET_CURL    = re.compile(rb'wget\s+|curl\s+|fetch\s+http', re.I)
_RE_CHMOD_X      = re.compile(rb'chmod\s+[+]?[x7][0-9]*|chmod\s+0?[0-7]*[1357]', re.I)
_RE_PIPE_SH      = re.compile(rb'\|\s*(bash|sh|zsh|ash|dash)\b', re.I)
_RE_DEV_TCP      = re.compile(rb'/dev/tcp/', re.I)
_RE_REVERSE_SH   = re.compile(rb'bash\s+-i|nc\s+-[el]|ncat\s+|socat\s+', re.I)
_RE_PRIVESC      = re.compile(rb'sudo\s+-[isSu]|su\s+-[lc]|pkexec\b', re.I)
_RE_CRON_INSTALL = re.compile(rb'crontab\s+-[lu]|/etc/cron|/var/spool/cron', re.I)
_RE_SHADOW_ETC   = re.compile(rb'/etc/shadow|/etc/passwd|/etc/sudoers', re.I)
# H010: acha o comando `rm` (word-boundary: `confirm`/`perform` não contam;
# `/bin/rm`, `sudo rm`, `xargs rm` contam) e captura os argumentos até o fim
# do comando. Flags e alvos são analisados em _r_rm_rf, não na regex.
_RE_RM_CMD       = re.compile(rb'(?<![\w.\-])rm\s+([^;&|\n`<>()]*)', re.I)
_RM_SYSTEM_DIRS  = frozenset({
    "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib32", "/lib64",
    "/media", "/mnt", "/opt", "/proc", "/root", "/sbin", "/srv", "/sys",
    "/usr", "/var",
    "/var/lib", "/var/log", "/usr/bin", "/usr/sbin", "/usr/lib",
    "/usr/local", "/usr/share",
})
_HOME_PREFIX     = r'(?:~|\$HOME|\$\{HOME\}|/home/[^/]+|/root)'
_RE_RM_HOME      = re.compile(r'^(?:~|\$HOME|\$\{HOME\}|/home/[^/]+)$')
_RE_RM_HOME_KEYS = re.compile(
    rf'^{_HOME_PREFIX}/\.(?:ssh|gnupg|bitcoin|ethereum|electrum|monero)$'
)
_RE_C2_SLEEP     = re.compile(rb'\b(?:sleep|usleep)\s+[0-9]+', re.I)
_RE_C2_NET       = re.compile(rb'\b(?:curl|wget|nc)\b', re.I)
_RE_CRYPTO_ADDR  = re.compile(rb'[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[0-9a-fA-F]{40}')
_RE_IP_HARDCODED = re.compile(rb'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
_RE_FORK_BOMB    = re.compile(rb':\(\)\s*\{|:\|\s*:&|forkbomb', re.I | re.S)
# history -c/-w e HISTFILE=/dev/null/unset HIST* eram as únicas formas
# cobertas; malware/dropper real também usa `set +o history` (desliga log
# de histórico sem tocar em HISTFILE), HISTFILE= vazio ("" ou '' também
# desabilita), HISTSIZE=0/HISTFILESIZE=0 (zera antes mesmo de escrever), e
# apagar/truncar o arquivo de histórico direto (rm/shred/truncate ou um
# único `>` de overwrite — `>>` de append fica de fora, não é evasão) em
# qualquer *_history (bash/zsh/sh/python/psql/mysql/irb etc, não só bash).
_RE_HISTORY_DEL  = re.compile(
    rb'history\s+-[cw]|'
    rb'unset\s+HIST|'
    rb'set\s+\+o\s+history|'
    rb'HISTFILE\s*=\s*(/dev/null|["\x27]{2})?\s*(;|\n|$)|'
    rb'HIST(SIZE|FILESIZE)\s*=\s*0\b|'
    rb'(rm|shred|truncate)\s+[^\n;]{0,80}\w*_history\b|'
    rb'(?<!>)>(?!>)\s*[^\n;]{0,80}\w*_history\b',
    re.I,
)
_RE_OBFUSC_SH    = re.compile(rb'\$\{[^}]{40,}\}|\$\([^)]{40,}\)|\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){5,}', re.I)
_RE_PTRACE_CALL  = re.compile(rb'ptrace\s*\(|PTRACE_ATTACH', re.I)
_RE_LD_PRELOAD   = re.compile(rb'LD_PRELOAD\s*=|/etc/ld\.so\.preload', re.I)
# /proc/<pid>/mem em todas as formas em que um scraper/injetor real escreve o
# PID: literal, self/thread-self, variável de shell ($PID, ${pid}, $$, $(pgrep
# x)), placeholder de format string do Python (f"{pid}", %d/%s) ou
# concatenação ('/proc/' + str(pid) + '/mem'). "mem" não pode ser prefixo de
# outra palavra (/proc/<pid>/memory_stats não é a técnica).
_RE_MEMFD        = re.compile(
    rb'memfd_create|'
    rb'/proc/(?:self|thread-self|[0-9]+|\$\$|\$\{?\w+\}?|\{[^{}/\s]*\}|%[sd]|\$\([^)]*\))/mem(?!\w)|'
    rb"""/proc/['"]\s*\+[^\n]{0,80}?\+\s*['"]/mem(?!\w)""",
    re.I,
)
_RE_PACKED_UPX   = re.compile(rb'UPX!|This file is packed')
_RE_SECRET_PATHS = re.compile(
    rb'quarantine\.key|auth\.hash|wallet\.dat|id_rsa|id_ed25519|\.ssh/id_|'
    rb'UTC--|keystore|seed\s*phrase|mnemonic|private[_ ]?key',
    re.I,
)
_RE_EXFIL_NET    = re.compile(
    rb'curl\s+[^\n]*(-d\s|--data|-F\s|--upload-file|-T\s)|'
    rb'wget\s+[^\n]*--post-data',
    re.I,
)


def _r_high_entropy(ctx: HeuristicContext, rid: str) -> Optional[RuleMatch]:
    """Alta entropia em executável (> 7.2) → possible packed/cifrado."""
    if ctx.entropy is None or not (ctx.is_elf or ctx.is_executable):
        return None
    if ctx.entropy > 7.2:
        return RuleMatch(rid, f"entropia {ctx.entropy:.3f} > 7.2 em executável")
    return None


_SUSPICIOUS_EXEC_DIR_SEQS = (("tmp",), ("dev", "shm"), ("var", "tmp"), ("run", "user"))


def _r_exec_in_tmp(ctx: HeuristicContext, rid: str) -> Optional[RuleMatch]:
    """Arquivo executável em /tmp, /dev/shm, /var/tmp ou /run/user, em qualquer profundidade."""
    if not (ctx.is_executable or ctx.is_elf or ctx.is_script):
        return None
    components = [c for c in ctx.path.split("/") if c]
    for seq in _SUSPICIOUS_EXEC_DIR_SEQS:
        n = len(seq)
        for i in range(len(components) - n + 1):
            if tuple(components[i:i + n]) == seq:
                return RuleMatch(rid, f"executável em diretório suspeito: /{'/'.join(seq)}")
    return None


def _r_base64_decode(ctx: HeuristicContext, rid: str) -> Optional[RuleMatch]:
    """Decodificação base64 seguida de execução em script."""
    if not ctx.content_sample:
        return None
    if not (ctx.is_script or ctx.extension in (".sh", ".py", ".pl", ".rb", ".php")):
        return None
    if _RE_B64_DECODE.search(ctx.content_sample):
        return RuleMatch(rid, "decodificação base64 detectada em script")
    return None


def _r_eval_exec(ctx: HeuristicContext, rid: str) -> Optional[RuleMatch]:
    """Uso de eval/exec dinâmico em script."""
    if not ctx.content_sample:
        return None
    m = _RE_EVAL_EXEC.search(ctx.content_sample)
    if m:
        snippet = ctx.content_sample[max(0, m.start()-20):m.end()+20]
        return RuleMatch(rid, "eval/exec dinâmico detectado",
                         evidence=snippet.decode("utf-8", errors="replace")[:80])
    return None


def _r_download_execute(ctx: HeuristicContext, rid: str) -> Optional[RuleMatch]:
    """Download seguido de execução (wget/curl | sh)."""
    if not ctx.content_sample:
        return None
    has_download = bool(_RE_WGET_CURL.search(ctx.content_sample))
    has_pipe_sh  = bool(_RE_PIPE_SH.search(ctx.content_sample))
    if has_download and has_pipe_sh:
        return RuleMatch(rid, "padrão download+execução (wget/curl | sh)")
    return None


def _r_reverse_shell(ctx: HeuristicContext, rid: str) -> Optional[RuleMatch]:
    """Padrões de reverse shell (bash -i, nc -e, socat, /dev/tcp)."""
    if not ctx.content_sample:
        return None
    for pattern, desc in [
        (_RE_DEV_TCP,     "/dev/tcp redirect (reverse shell)"),
        (_RE_REVERSE_SH,  "comando de reverse shell (bash -i / nc / socat)"),
    ]:
        if pattern.search(ctx.content_sample):
            return RuleMatch(rid, desc)
    return None


def _r_privesc(ctx: HeuristicContext, rid: str) -> Optional[RuleMatch]:
    """Tentativa de escalação de privilégios."""
    if not ctx.content_sample:
        return None
    m = _RE_PRIVESC.search(ctx.content_sample)
    if m:
        snippet = ctx.content_sample[max(0, m.start()-10):m.end()+10]
        return RuleMatch(rid, "tentativa de escalação de privilégios",
                         evidence=snippet.decode("utf-8", errors="replace")[:80])
    return None


def _r_cron_persistence(ctx: HeuristicContext, rid: str) -> Optional[RuleMatch]:
    """Instalação de persistência via cron."""
    if not ctx.content_sample:
        return None
    if _RE_CRON_INSTALL.search(ctx.content_sample):
        return RuleMatch(rid, "modificação de cron (possível persistência)")
    return None


def _r_sensitive_files(ctx: HeuristicContext, rid: str) -> Optional[RuleMatch]:
    """/etc/shadow, /etc/passwd, /etc/sudoers no conteúdo, ou acesso local a
    credencial/wallet (mesma lista de paths de H023, mas sem exigir upload de
    rede — cobre stager/coletor local que só lê/copia pra outro lugar do
    disco antes de uma 2ª etapa, achado real de 2026-09-17: acesso local a
    wallet.dat/id_rsa/keystore/mnemonic/quarantine.key/auth.hash não disparava
    nenhuma das 23 regras se não viesse acompanhado de curl/wget no mesmo
    arquivo (H023 exige o combo, isso aqui cobre o acesso isolado)."""
    if not ctx.content_sample:
        return None
    m = _RE_SHADOW_ETC.search(ctx.content_sample)
    if m:
        return RuleMatch(rid, f"acesso a arquivo sensível: {m.group().decode('utf-8', errors='replace')}")
    m = _RE_SECRET_PATHS.search(ctx.content_sample)
    if m:
        return RuleMatch(rid, f"acesso local a credencial/wallet: {m.group().decode('utf-8', errors='replace')}")
    return None


def _rm_target_is_critical(target: str) -> bool:
    """True se o alvo do rm é raiz, diretório de sistema, $HOME ou chave/wallet."""
    t = target.strip("'\"")
    t = re.sub(r'/{2,}', '/', t)
    # `/etc/`, `/etc/*`, `/etc/.*`, `/etc/.` -> `/etc`; `/` e `/*` -> ''
    t = re.sub(r'(?:/(?:\.?\*|\.))+$', '', t)
    t = t.rstrip('/')
    return (
        t == ''
        or t in _RM_SYSTEM_DIRS
        or bool(_RE_RM_HOME.match(t))
        or bool(_RE_RM_HOME_KEYS.match(t))
    )


def _r_rm_rf(ctx: HeuristicContext, rid: str) -> Optional[RuleMatch]:
    """rm recursivo (ou --no-preserve-root) mirando raiz, diretório de
    sistema, $HOME ou chave/wallet. `rm -rf /tmp/build` e `rm -f x.pid`
    são limpeza normal e não disparam."""
    if not ctx.content_sample:
        return None
    for m in _RE_RM_CMD.finditer(ctx.content_sample):
        recursive = no_preserve_root = False
        targets: list[str] = []
        end_of_opts = False
        for tok in m.group(1).decode('utf-8', errors='replace').split():
            if not end_of_opts and tok == '--':
                end_of_opts = True
            elif not end_of_opts and tok.startswith('--'):
                recursive        |= tok == '--recursive'
                no_preserve_root |= tok == '--no-preserve-root'
            elif not end_of_opts and tok.startswith('-') and len(tok) > 1:
                recursive |= any(c in 'rR' for c in tok[1:])
            else:
                targets.append(tok)
        if no_preserve_root:
            return RuleMatch(rid, "comando destrutivo: rm --no-preserve-root")
        if recursive:
            for t in targets:
                if _rm_target_is_critical(t):
                    return RuleMatch(rid, f"comando destrutivo: rm -r em {t}")
    return None


def _r_fork_bomb(ctx: HeuristicContext, rid: str) -> Optional[RuleMatch]:
    """Fork bomb clássica :(){ :|:& };:"""
    if not ctx.content_sample:
        return None
    if _RE_FORK_BOMB.search(ctx.content_sample):
        return RuleMatch(rid, "fork bomb detectada")
    return None


def _r_history_deletion(ctx: HeuristicContext, rid: str) -> Optional[RuleMatch]:
    """Deleção de histórico de comandos (técnica de evasão)."""
    if not ctx.content_sample:
        return None
    if _RE_HISTORY_DEL.search(ctx.content_sample):
        return RuleMatch(rid, "deleção de histórico de comandos (evasão)")
    return None


def _r_obfuscation(ctx: HeuristicContext, rid: str) -> Optional[RuleMatch]:
    """Ofuscação de shell script (variáveis longas, hex escapes)."""
    if not ctx.content_sample:
        return None
    if not ctx.is_script and ctx.extension not in (".sh", ".bash", ".zsh"):
        return None
    if _RE_OBFUSC_SH.search(ctx.content_sample):
        return RuleMatch(rid, "ofuscação de código detectada em script")
    return None


def _r_ptrace_ld_preload(ctx: HeuristicContext, rid: str) -> Optional[RuleMatch]:
    """ptrace() (só ELF, é syscall nativa) ou LD_PRELOAD/ld.so.preload
    (ELF OU script — é técnica de env var/config, não exige binário
    compilado; dropper em shell setando LD_PRELOAD pra sequestrar libs
    de um processo alvo, ex. wallet CLI/bot, é o vetor mais comum)
    → possível rootkit/injector."""
    if not ctx.content_sample:
        return None
    if ctx.is_elf and _RE_PTRACE_CALL.search(ctx.content_sample):
        return RuleMatch(rid, "uso de ptrace() detectado (possível debugger/injector malicioso)")
    is_script_like = ctx.is_script or ctx.extension in (".sh", ".bash", ".zsh")
    if (ctx.is_elf or is_script_like) and _RE_LD_PRELOAD.search(ctx.content_sample):
        return RuleMatch(rid, "LD_PRELOAD/ld.so.preload detectado (possível hijack de biblioteca dinâmica)")
    return None


def _r_memfd_proc(ctx: HeuristicContext, rid: str) -> Optional[RuleMatch]:
    """memfd_create ou acesso a /proc/self/mem → fileless malware."""
    if not ctx.content_sample:
        return None
    if _RE_MEMFD.search(ctx.content_sample):
        return RuleMatch(rid, "técnica fileless: memfd_create ou /proc/self/mem")
    return None


def _r_packed_upx(ctx: HeuristicContext, rid: str) -> Optional[RuleMatch]:
    """Binário ELF comprimido com UPX."""
    if not ctx.content_sample or not ctx.is_elf:
        return None
    if _RE_PACKED_UPX.search(ctx.content_sample):
        return RuleMatch(rid, "binário comprimido com UPX (técnica de evasão)")
    return None


def _r_hardcoded_ip(ctx: HeuristicContext, rid: str) -> Optional[RuleMatch]:
    """IPs hardcoded no binário (possível C2)."""
    if not ctx.content_sample or not ctx.is_elf:
        return None
    ips = _RE_IP_HARDCODED.findall(ctx.content_sample)
    # Filtra IPs locais e de loopback
    external = [
        ip.decode("utf-8", errors="replace") for ip in ips
        if not ip.startswith((b"127.", b"192.168.", b"10.", b"172."))
    ]
    if len(external) >= 2:
        return RuleMatch(rid, f"{len(external)} IPs externos hardcoded",
                         evidence=", ".join(external[:5]))
    return None


def _r_crypto_strings(ctx: HeuristicContext, rid: str) -> Optional[RuleMatch]:
    """Strings de carteiras crypto (possível cryptominer)."""
    if not ctx.content_sample:
        return None
    matches = _RE_CRYPTO_ADDR.findall(ctx.content_sample)
    if matches:
        return RuleMatch(rid, f"{len(matches)} possível(is) endereço(s) de carteira crypto",
                         evidence=matches[0].decode("utf-8", errors="replace")[:40])
    return None


def _r_c2_beacon(ctx: HeuristicContext, rid: str) -> Optional[RuleMatch]:
    """Padrão de beacon C2: sleep() + requisição de rede, em qualquer ordem
    (loops reais de beacon tanto fazem "sleep depois request" quanto
    "request depois sleep" — a versão anterior só cobria a 1a ordem).
    Word-boundary em curl/wget/nc: sem isso "nc" batia como substring de
    qualquer palavra comum (function, sync, balance, announce...),
    gerando falso-positivo crítico (auto-quarentena) em script benigno
    que só por acaso tinha um "sleep N" antes."""
    if not ctx.content_sample:
        return None
    if _RE_C2_SLEEP.search(ctx.content_sample) and _RE_C2_NET.search(ctx.content_sample):
        return RuleMatch(rid, "padrão de beacon C2: sleep + requisição de rede")
    return None


def _r_chmod_plus_x(ctx: HeuristicContext, rid: str) -> Optional[RuleMatch]:
    """chmod +x em script (auto-execução após download)."""
    if not ctx.content_sample:
        return None
    if not (ctx.is_script or ctx.extension in (".sh", ".py", ".pl")):
        return None
    has_chmod = bool(_RE_CHMOD_X.search(ctx.content_sample))
    has_wget  = bool(_RE_WGET_CURL.search(ctx.content_sample))
    if has_chmod and has_wget:
        return RuleMatch(rid, "download + chmod +x (auto-instalação)")
    return None


def _r_hidden_executable(ctx: HeuristicContext, rid: str) -> Optional[RuleMatch]:
    """Arquivo oculto (começa com .) com bit de execução."""
    import os
    name = os.path.basename(ctx.path)
    if name.startswith(".") and ctx.is_executable:
        return RuleMatch(rid, f"arquivo oculto executável: {name}")
    return None


def _r_secret_exfiltration(ctx: HeuristicContext, rid: str) -> Optional[RuleMatch]:
    """Leitura de segredo/chave (própria do EK-Protection ou de wallet)
    combinada com upload de rede (curl -d/-F/-T, wget --post-data) —
    padrão de exfiltração, não coberto por H009 (só /etc/shadow&cia) nem
    por H019 (exige sleep+loop de beacon, não upload único)."""
    if not ctx.content_sample:
        return None
    m = _RE_SECRET_PATHS.search(ctx.content_sample)
    if not m:
        return None
    if not _RE_EXFIL_NET.search(ctx.content_sample):
        return None
    return RuleMatch(
        rid,
        f"leitura de segredo ({m.group().decode('utf-8', errors='replace')}) + upload de rede (exfiltração)",
    )


def _r_no_extension_elf(ctx: HeuristicContext, rid: str) -> Optional[RuleMatch]:
    """Binário ELF sem extensão em local não-padrão."""
    std_dirs = ("/usr/", "/bin/", "/sbin/", "/lib/", "/opt/")
    if not ctx.is_elf:
        return None
    if ctx.extension != "":
        return None
    if any(ctx.path.startswith(d) for d in std_dirs):
        return None
    return RuleMatch(rid, f"binário ELF sem extensão em local não-padrão: {ctx.path}")


# ---------------------------------------------------------------------------
# Catálogo de regras
# ---------------------------------------------------------------------------

ALL_RULES: list[HeuristicRule] = [
    HeuristicRule("H001", "Alta Entropia em Executável",
                  "Executável com entropia de Shannon > 7.2 (packed/cifrado)",
                  "médio", 6, ("binary", "evasion", "packing"),
                  _match_fn=_r_high_entropy),

    HeuristicRule("H002", "Executável em Diretório Suspeito",
                  "Executável em /tmp, /dev/shm, /var/tmp",
                  "alto", 7, ("location", "dropper"),
                  _match_fn=_r_exec_in_tmp),

    HeuristicRule("H003", "Decodificação Base64 em Script",
                  "Script usa base64 decode (técnica de ofuscação)",
                  "médio", 5, ("script", "obfuscation"),
                  _match_fn=_r_base64_decode),

    HeuristicRule("H004", "eval/exec Dinâmico",
                  "Script executa código dinâmico via eval/exec",
                  "médio", 6, ("script", "obfuscation", "code_injection"),
                  _match_fn=_r_eval_exec),

    HeuristicRule("H005", "Download + Execução",
                  "wget/curl com pipe para sh (dropper clássico)",
                  "alto", 8, ("script", "dropper", "network"),
                  _match_fn=_r_download_execute),

    HeuristicRule("H006", "Reverse Shell",
                  "Padrões de reverse shell (bash -i, nc -e, /dev/tcp)",
                  "crítico", 10, ("network", "shell", "backdoor"),
                  _match_fn=_r_reverse_shell),

    HeuristicRule("H007", "Escalação de Privilégios",
                  "Tentativa de sudo -i, su, pkexec",
                  "alto", 7, ("privilege", "escalation"),
                  _match_fn=_r_privesc),

    HeuristicRule("H008", "Persistência via Cron",
                  "Modificação de crontab ou /etc/cron",
                  "alto", 7, ("persistence", "cron"),
                  _match_fn=_r_cron_persistence),

    HeuristicRule("H009", "Acesso a Arquivos Sensíveis",
                  "/etc/shadow, /etc/passwd, /etc/sudoers, ou credencial/wallet "
                  "local (wallet.dat, id_rsa, keystore, mnemonic, quarantine.key, "
                  "auth.hash) sem exigir upload de rede",
                  "alto", 8, ("sensitive", "credential", "wallet"),
                  _match_fn=_r_sensitive_files),

    HeuristicRule("H010", "Comando Destrutivo",
                  "rm -rf em paths do sistema",
                  "crítico", 9, ("destructive", "wiper"),
                  _match_fn=_r_rm_rf),

    HeuristicRule("H011", "Fork Bomb",
                  "Padrão :(){ :|:& } detectado",
                  "crítico", 10, ("dos", "fork_bomb"),
                  _match_fn=_r_fork_bomb),

    HeuristicRule("H012", "Deleção de Histórico",
                  "history -c ou HISTFILE=/dev/null (evasão forense)",
                  "médio", 5, ("evasion", "forensics"),
                  _match_fn=_r_history_deletion),

    HeuristicRule("H013", "Ofuscação de Shell",
                  "Variáveis excessivamente longas ou hex escapes em massa",
                  "médio", 6, ("script", "obfuscation"),
                  _match_fn=_r_obfuscation),

    HeuristicRule("H014", "ptrace / LD_PRELOAD",
                  "ptrace() em binário ELF, ou LD_PRELOAD/ld.so.preload em "
                  "ELF ou script (injeção/rootkit/hijack de biblioteca)",
                  "crítico", 9, ("binary", "script", "rootkit", "injection"),
                  _match_fn=_r_ptrace_ld_preload),

    HeuristicRule("H015", "Técnica Fileless",
                  "memfd_create ou /proc/self/mem (execução sem arquivo)",
                  "crítico", 10, ("binary", "fileless", "evasion"),
                  _match_fn=_r_memfd_proc),

    HeuristicRule("H016", "Binário Comprimido UPX",
                  "ELF comprimido com UPX (técnica de evasão)",
                  "médio", 4, ("binary", "packing", "evasion"),
                  _match_fn=_r_packed_upx),

    HeuristicRule("H017", "IPs Externos Hardcoded",
                  "IPs externos embutidos no binário (possível C2)",
                  "alto", 6, ("network", "c2", "binary"),
                  _match_fn=_r_hardcoded_ip),

    HeuristicRule("H018", "Strings de Wallet Crypto",
                  "Endereços de carteira Bitcoin/Ethereum (cryptominer)",
                  "alto", 7, ("crypto", "miner"),
                  _match_fn=_r_crypto_strings),

    HeuristicRule("H019", "Beacon C2",
                  "Padrão sleep + requisição de rede (beaconing)",
                  "crítico", 9, ("network", "c2", "persistence"),
                  _match_fn=_r_c2_beacon),

    HeuristicRule("H020", "Download + chmod +x",
                  "Script que baixa e torna executável (auto-instalação)",
                  "alto", 8, ("dropper", "script", "persistence"),
                  _match_fn=_r_chmod_plus_x),

    HeuristicRule("H021", "Arquivo Oculto Executável",
                  "Arquivo com nome começando por '.' e bit de execução",
                  "médio", 5, ("evasion", "hidden"),
                  _match_fn=_r_hidden_executable),

    HeuristicRule("H022", "ELF Sem Extensão Fora do Padrão",
                  "Binário ELF sem extensão em diretório não-padrão",
                  "médio", 4, ("binary", "evasion"),
                  _match_fn=_r_no_extension_elf),

    HeuristicRule("H023", "Exfiltração de Segredo/Wallet",
                  "Leitura de chave/segredo (própria ou de wallet) + upload de rede",
                  "crítico", 9, ("crypto", "exfiltration", "credential"),
                  _match_fn=_r_secret_exfiltration),
]

# Indexado por rule_id para lookup rápido
RULES_BY_ID: dict[str, HeuristicRule] = {r.rule_id: r for r in ALL_RULES}

# RULES_BY_ID built above covers H022

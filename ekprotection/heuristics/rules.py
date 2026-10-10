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
import struct
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
# H003: a regex antiga só pegava `base64 -d`, `base64_decode` (PHP) e `atob(`.
# Passavam batido `base64 --decode`, `b64decode` (Python, a forma mais comum
# em dropper), `base64.decodebytes`, `decode_base64` (Perl) e `decode64`
# (Ruby); e casava por substring sem word-boundary (`base64-decoder` em
# comentário, `boatob(`). Agora: flags do CLI (`-d`/`-D`/cluster/`--decode`,
# após outras flags opcionais como `-w 0`) e funções de decode com \b.
_RE_B64_DECODE   = re.compile(
    rb'\bbase64\s+(?:(?:-\S+|\d+)\s+)*?(?:-[a-z]*d[a-z]*|--decode)(?![\w-])'
    rb'|\b(?:urlsafe_|standard_)?b64decode\b'
    rb'|\bbase64\.(?:decodebytes|decodestring)\b'
    rb'|\bbase64_decode\b|\bdecode_base64\b|\b(?:strict_|urlsafe_)?decode64\b'
    rb'|\batob\(',
    re.I)
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
# H020: "wget"/"curl" sem word-boundary casavam por substring em qualquer
# identificador terminado nessas letras seguido de espaço — "libcurl
# bindings for python", "mycurl file.sh --download", "downloadwget
# http://..." disparavam como comando de download real, mesma classe de
# bug já vista em H006 (nc/ncat/socat) e H008 (crontab).
_RE_WGET_CURL    = re.compile(rb'\bwget\s+|\bcurl\s+|\bfetch\s+http', re.I)
# H005: antes exigia curl/wget e `| sh` em QUALQUER ponto do arquivo (sem
# relação entre eles): um `curl` de health-check + um `| sh -c` não
# relacionado disparava (falso positivo), e as formas reais de dropper
# `curl | sudo bash`, `curl | python`, `bash <(curl ...)`, `sh -c "$(curl ...)"`
# e `source <(curl ...)` passavam batido (falso negativo). Agora o downloader
# e o executor precisam estar na MESMA linha, ligados por pipe ou por
# substituição de processo/comando.
_DL = rb'(?:curl|wget|fetch)\b'
_INTERP = (rb'(?:sudo\s+(?:-\S+\s+)*)?(?:/[\w./-]*/)?'
           rb'(?:bash|sh|zsh|ash|dash|python[23]?|perl|ruby|php)\b')
_RE_DL_PIPE_EXEC = re.compile(
    _DL + rb'[^\n;&]*?\|\s*' + _INTERP, re.I)
_RE_DL_SUBST_EXEC = re.compile(
    rb'(?:^|[\s;&|(])(?:bash|sh|zsh|ash|dash|source|\.)\s+(?:-\w+\s+)*'
    rb'["\']?(?:<\(|\$\()\s*' + _DL, re.I | re.M)
# H020: só cobria "chmod +x" literal ou formas octais (755/700/...).
# Formas simbólicas com classe explícita ("chmod u+x", "chmod a+x",
# "chmod go+x"), com múltiplas permissões junto da execução ("chmod
# a+rx"), e com flag antes do modo ("chmod -R +x dir", "chmod -Rv u+x
# dir") — todas idiomas extremamente comuns em script de instalação —
# passavam batido. Flags curtas (-R, -v, -Rv...) agora são toleradas
# antes do modo; a forma simbólica exige "+" seguido de um bloco de
# letras rwxXst que contenha pelo menos um x/X, em qualquer ordem.
_RE_CHMOD_X      = re.compile(
    rb'chmod\s+(?:-[a-zA-Z]+\s+)*'
    rb'(?:[ugoa]*[+][rwxXst]*[xX][rwxXst]*|[x7][0-9]*|0?[0-7]*[1357])',
    re.I,
)
_RE_DEV_TCP      = re.compile(rb'/dev/tcp/', re.I)
# H006: "nc"/"ncat"/"socat" sem word-boundary casavam por substring em
# qualquer palavra terminada nessas letras — `rsync -e ssh ...` (forma
# comum de deploy/backup pra especificar shell remoto) e `rsync -e "ssh
# -p 2222" ...` disparavam via "...nc -e" (rsync termina em "nc").
# Lookbehind negativo evita casar quando "nc"/"ncat"/"socat" é sufixo de
# outra palavra.
_RE_REVERSE_SH   = re.compile(
    rb'bash\s+-i|(?<![\w.\-])nc\s+-[el]|(?<![\w.\-])ncat\s+|(?<![\w.\-])socat\s+',
    re.I)
# H007: cobria só `sudo -i/-s/-S/-u` e `su -l/-c` (com "su" sem
# word-boundary, casando por substring em qualquer palavra terminada em
# "su" — `thisu -lc` disparava). Passavam batido as formas mais comuns de
# troca pra root: `su -`, `su`/`su root` sozinho (sem -l/-c), `sudo su`
# (encadeamento comum), `doas` (alternativa ao sudo em Alpine/BSD/distros
# minimalistas) e o bit setuid via `chmod` (`chmod u+s`/`chmod 4755`,
# T1548.001 — dá privilégio elevado persistente sem precisar de sudo/su
# depois). Lookbehind negativo evita casar "su" como sufixo de palavra.
_RE_PRIVESC      = re.compile(
    rb'sudo\s+-[isSu]|'
    rb'(?<![\w.\-])su\s+-(?:[lc]\b|-login\b)|'
    rb'(?<![\w.\-])su(?:\s+(?:-(?=\s|$)|[A-Za-z_][\w.\-]*\b))?\s*(?=[;&|\n]|$)|'
    rb'pkexec\b|'
    rb'\bdoas\s|'
    rb'chmod\s+(?:-\S+\s+)*(?:[ugoa]*\+s\b|(?<!\d)[4-7][0-7]{3}(?!\d)\b)',
    re.I | re.M)
# H008: `crontab -[lu]` original só cobria listagem (-l) e troca de usuário
# (-u), deixando passar as duas formas mais comuns de instalar persistência:
# `crontab <arquivo>` (sem nenhuma flag) e `crontab -` (lendo do stdin via
# pipe, idioma clássico de dropper: `echo '* * * * * payload' | crontab -`).
# Lookbehind negativo evita casar "crontab" como sufixo de outra palavra
# (ex: "mycrontab -l"). FLAG cobre -l/-u/stdin bare; FILE cobre instalação
# a partir de caminho de arquivo (absoluto, relativo, ~ ou $HOME), com ou
# sem -u <user> antes. `-r`/`-e` ficam de fora de propósito (remoção não é
# persistência; edição interativa não é facilmente scriptável sem o truque
# de EDITOR, fora de escopo desta rodada).
_RE_CRON_FLAG    = re.compile(rb'(?<![\w.\-])crontab\s+-(?:[lu]\b|(?![\w-]))', re.I)
_RE_CRON_FILE    = re.compile(
    rb'(?<![\w.\-])crontab\s+(?:-u\s+\S+\s+)?(?:\.{0,2}/|~|\$\{?HOME\}?)\S*', re.I)
_RE_CRON_INSTALL = re.compile(rb'/etc/cron|/var/spool/cron', re.I)
# H009, rodada 2026-10-03: faltavam /etc/gshadow (hash de senha de GRUPO,
# mesma classe de segredo que /etc/shadow) e /etc/security/opasswd
# (histórico de senhas antigas em hash, usado por PAM pra impedir reuso —
# útil pra quebra offline mesmo sendo "antigo"). Achado novo, testado ao
# vivo (passavam batido antes do fix). `/etc/master.passwd` (BSD) ficou
# de fora de propósito — esta VPS é Linux, não existe esse arquivo aqui.
_RE_SHADOW_ETC   = re.compile(
    rb'/etc/shadow|/etc/passwd|/etc/sudoers|/etc/gshadow|/etc/security/opasswd',
    re.I)
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
# H011, rodada 2026-10-04: a regex acima só cobre a fork bomb clássica com
# a função nomeada ":" (`:(){ :|:& };:`) — trocar o nome da função
# (`a(){ a|a& };a`, `bomb(){ bomb|bomb& };bomb`, ou a variante sem pipe
# `x(){ x & x & };x`) passa batido mesmo sendo o mesmo ataque, é só
# trivialmente renomear pra evadir a detecção de string literal. Backreference
# (\1/\2) amarra o nome capturado nos dois usos dentro do corpo e na chamada
# final, então não precisa listar nomes — qualquer função que se autoinvoca
# em pipe+background (ou duas vezes em background) e é chamada logo após
# definida bate, sem casar substring parcial de nomes diferentes (`deploy`
# vs `deploy_step1`, `a` vs `ab`) graças ao `(?!...)` no fim de cada ramo.
_RE_FORK_BOMB_GENERIC = re.compile(
    rb'([A-Za-z0-9_.:]{1,40})\s*\(\)\s*\{\s*\1\s*\|\s*\1\s*&\s*\}\s*;\s*\1(?![A-Za-z0-9_.:])'
    rb'|([A-Za-z0-9_.:]{1,40})\s*\(\)\s*\{\s*\2\s*&\s*\2\s*&\s*\}\s*;\s*\2(?![A-Za-z0-9_.:])',
    re.I,
)
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
_RE_OBFUSC_SH    = re.compile(
    rb'\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){5,}'                      # hex escapes em sequência
    rb'|(\\[0-7]{3}){6,}'                                        # octal escapes em sequência
    rb'|\b(base64\s+(-d|--decode|-D)|xxd\s+-r|openssl\s+(enc|base64)\s[^|\n]*-d|rev)\b[^|\n]*\|\s*(\S*/)?(ba|z|da|k)?sh\b',  # decoder | shell
    re.I)
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
# H009, rodada 2026-10-03: `id_rsa`/`id_ed25519`/`.ssh/id_` casavam por
# substring sem olhar o que vem depois — `cat ~/.ssh/id_rsa.pub`,
# `ssh-copy-id -i ~/.ssh/id_rsa.pub` e `scp ~/.ssh/id_ed25519.pub
# deploy@host:~/.ssh/authorized_keys` disparavam como "acesso a
# credencial/wallet", mas chave PÚBLICA não é segredo — é o idioma mais
# comum de deploy/onboarding de servidor, dispararia toda hora em uso
# legítimo. Testado ao vivo: confirmado falso positivo nas 2 variantes
# (`id_rsa.pub`, `id_ed25519.pub`) e em qualquer nome dentro de `.ssh/id_*`
# (ex. `id_ecdsa.pub`, chave custom `id_github.pub`). Fix em
# `_r_sensitive_files`: olha o que vem depois do match (nome de arquivo
# completo) e pula se terminar em `.pub` — feito em Python, não regex,
# porque `[\w.-]*(?!\.pub)` sofre do mesmo problema de backtracking já
# visto antes (o quantificador recua até um corte menor que escapa da
# negação, como o lookahead quebrado documentado no H003).
# `/etc/ssh/ssh_host_*_key` (chave privada de host SSH — rouba isso e dá
# pra se passar pelo servidor/fazer MITM) entrou como achado novo (falso
# negativo, testado ao vivo, passava batido); mesma lógica de `.pub`
# evita disparar na chave pública do host (`ssh_host_rsa_key.pub`),
# arquivo rotineiramente lido/distribuído (fingerprint, known_hosts).
_RE_SECRET_PATHS = re.compile(
    rb'quarantine\.key|auth\.hash|wallet\.dat|id_rsa|id_ed25519|\.ssh/id_|'
    rb'/etc/ssh/ssh_host_\w+_key|'
    rb'UTC--|keystore|seed\s*phrase|mnemonic|private[_ ]?key',
    re.I,
)
# Auditoria de performance, rodada 2026-10-06: `[^\n]*` irrestrito antes da
# flag de upload é O(n) por tentativa de match — com "curl"/"wget" repetido
# muitas vezes numa única linha sem "\n" (arquivo adversarial, sem exigir
# shell válido), cada tentativa varre o resto do buffer até falhar, e o
# número de tentativas cresce com o buffer → O(n²) total. Medido ao vivo:
# 64KB→0.405s, 131KB→1.68s (~4x por 2x de tamanho, assinatura quadrática
# clássica); extrapolado pra 4MB (cap candidato a aumentar, ver rodada
# 2026-10-05) dá ~29min por arquivo — de detecção incompleta a vetor de DoS
# contra o próprio monitoramento em tempo real. Das ~19 regras de conteúdo
# auditadas nesta rodada (H003–H020, H023), só esta teve esse padrão
# (confirmado por medição, não só por formato de regex — outras com
# `[^\n]*`/`[^|\n]*` irrestrito, ex. H005/H013, escalaram linear na prática).
# Fix: bound explícito (4096 bytes, generoso pra linha de comando real),
# mesmo padrão já usado em H012/H015 — limita o custo por tentativa a uma
# constante, eliminando o termo quadrático independente do tamanho do buffer.
_RE_EXFIL_NET    = re.compile(
    rb'curl\s+[^\n]{0,4096}(-d\s|--data|-F\s|--upload-file|-T\s)|'
    rb'wget\s+[^\n]{0,4096}--post-data',
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
    if (_RE_DL_PIPE_EXEC.search(ctx.content_sample)
            or _RE_DL_SUBST_EXEC.search(ctx.content_sample)):
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
    if (_RE_CRON_FLAG.search(ctx.content_sample)
            or _RE_CRON_FILE.search(ctx.content_sample)
            or _RE_CRON_INSTALL.search(ctx.content_sample)):
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
    for m in _RE_SECRET_PATHS.finditer(ctx.content_sample):
        # nome de arquivo completo logo após o match (ex. "rsa.pub" depois
        # de ".ssh/id_", ou ".pub" depois de "id_rsa" direto) — se terminar
        # em .pub é chave PÚBLICA, não segredo (ver comentário no regex).
        tail = re.match(rb'[\w.-]*', ctx.content_sample[m.end():]).group()
        if tail.lower().endswith(b'.pub'):
            continue
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
    """Fork bomb clássica :(){ :|:& };: ou renomeada (mesma estrutura com
    outro nome de função, ver H011 em _RE_FORK_BOMB_GENERIC)."""
    if not ctx.content_sample:
        return None
    if _RE_FORK_BOMB.search(ctx.content_sample):
        return RuleMatch(rid, "fork bomb detectada")
    if _RE_FORK_BOMB_GENERIC.search(ctx.content_sample):
        return RuleMatch(rid, "fork bomb detectada (função renomeada)")
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


def _elf_shnum_phnum(content: bytes) -> Optional[tuple[int, int]]:
    """Lê `e_shnum`/`e_phnum` do header ELF (32 ou 64 bits, qualquer
    endianness). Retorna None se não tiver bytes suficientes."""
    if len(content) < 5 or content[:4] != b"\x7fELF":
        return None
    is_64   = content[4] == 2            # EI_CLASS: 1=32-bit, 2=64-bit
    is_be   = len(content) > 5 and content[5] == 2  # EI_DATA: 1=LE, 2=BE
    fmt_end = ">" if is_be else "<"
    if is_64:
        # e_phnum @56 (H), e_shnum @60 (H) — precisa de 62 bytes
        if len(content) < 62:
            return None
        phnum = struct.unpack_from(fmt_end + "H", content, 56)[0]
        shnum = struct.unpack_from(fmt_end + "H", content, 60)[0]
    else:
        # e_phnum @44 (H), e_shnum @48 (H) — precisa de 50 bytes
        if len(content) < 50:
            return None
        phnum = struct.unpack_from(fmt_end + "H", content, 44)[0]
        shnum = struct.unpack_from(fmt_end + "H", content, 48)[0]
    return (shnum, phnum)


def _r_packed_upx(ctx: HeuristicContext, rid: str) -> Optional[RuleMatch]:
    """Binário ELF comprimido com UPX.

    Rodada 2026-10-10: `_RE_PACKED_UPX` só olhava as strings `UPX!`/`This
    file is packed`, que ficam no stub do des-empacotador só pra
    identificação humana — não são usadas pelo loader do kernel pra
    executar o binário. Testado ao vivo: baixar o UPX real (sem root,
    binário estático da release oficial), empacotar `/bin/ls` de verdade
    e sobrescrever as duas strings de assinatura por bytes aleatórios
    (`UPX!`→`XXXX`, `This file is packed`→`XXXXXXXXXXXXXXXXXXXX`) produz
    um binário que **continua executando perfeitamente** (mesmo
    comportamento/saída do original) e evade 100% a regex — evasão
    trivial de 2 patches de bytes, sem precisar entender nada do formato
    UPX além de "apagar a string que o AV procura".

    Como defesa em profundidade, soma-se um sinal estrutural que a
    evasão acima não quebra: o UPX (por padrão, pra reduzir tamanho)
    gera um binário com **zero section headers** (`e_shnum == 0`) e só
    uns poucos program headers (3 no teste ao vivo, contra 11-14 em
    binários normais do sistema). Testado contra 1145 ELFs reais de
    `/usr/bin` e `/usr/lib` desta VPS: nenhum tinha `e_shnum == 0`
    (nem mesmo depois de `strip --strip-all`, que remove símbolos mas
    mantém a tabela de sections) — sinal raro em uso legítimo neste
    ambiente. Limiar de `phnum <= 4` é margem de segurança sobre o 3
    observado, não um valor exato medido contra uma amostra maior.

    **Limitação conhecida, não resolvida hoje**: esse sinal estrutural
    também é, em teoria, evadível — bastaria reescrever `e_shnum`/`e_phnum`
    no header pra um valor não-zero (o loader do kernel Linux não lê a
    tabela de sections pra executar, só os program headers, então um
    valor falso não quebraria a execução). Isso exige entender o formato
    ELF, não só "apagar uma string", mas não é uma barreira alta pra quem
    já está empacotando binário deliberadamente. Não implementei checagem
    de consistência mais profunda (ex. validar se `e_shoff` aponta pra
    dados plausíveis) nesta rodada — registrado como possível próxima
    frente se o Matheus achar que vale o escopo.
    """
    if not ctx.content_sample or not ctx.is_elf:
        return None
    if _RE_PACKED_UPX.search(ctx.content_sample):
        return RuleMatch(rid, "binário comprimido com UPX (técnica de evasão)")
    shnum_phnum = _elf_shnum_phnum(ctx.content_sample)
    if shnum_phnum is not None:
        shnum, phnum = shnum_phnum
        if shnum == 0 and 0 < phnum <= 4:
            return RuleMatch(
                rid,
                "binário ELF sem tabela de section headers e poucos "
                "program headers (indicador estrutural de packing, "
                "ex. UPX com strings de assinatura removidas)",
            )
    return None


def _is_rfc1918_or_loopback(ip: bytes) -> bool:
    """127.0.0.0/8, 10.0.0.0/8, 192.168.0.0/16, ou 172.16.0.0/12 (só o
    2º octeto 16-31 — "172." sozinho pega metade errada: 172.67.x.x
    (Cloudflare) e 172.217.x.x (Google) são faixas PÚBLICAS reais, não
    RFC1918, e C2 hardcoded ali passava batido como "IP local")."""
    if ip.startswith((b"127.", b"10.", b"192.168.")):
        return True
    if ip.startswith(b"172."):
        try:
            second_octet = int(ip.split(b".", 2)[1])
        except (IndexError, ValueError):
            return False
        return 16 <= second_octet <= 31
    return False


def _r_hardcoded_ip(ctx: HeuristicContext, rid: str) -> Optional[RuleMatch]:
    """IPs hardcoded no binário (possível C2)."""
    if not ctx.content_sample or not ctx.is_elf:
        return None
    ips = _RE_IP_HARDCODED.findall(ctx.content_sample)
    # Filtra IPs locais e de loopback
    external = [
        ip.decode("utf-8", errors="replace") for ip in ips
        if not _is_rfc1918_or_loopback(ip)
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


_HIDDEN_EXEC_ALLOWLIST = {".xsession", ".xinitrc", ".Xclients"}


def _is_direct_home_dir(dirname: str) -> bool:
    """``/home/<user>`` ou ``/root``, sem subdiretório — é exatamente onde
    display/session managers (lightdm, gdm, xdm, ``startx``) procuram e
    executam ``.xsession``/``.xinitrc``/``.Xclients`` de verdade. Caminho
    aninhado (ex. ``/home/user/.config/.xsession``) não é onde o DM olha,
    então não ganha a mesma confiança."""
    if dirname == "/root":
        return True
    parts = dirname.split("/")
    return len(parts) == 3 and parts[1] == "home" and parts[2] != ""


def _r_hidden_executable(ctx: HeuristicContext, rid: str) -> Optional[RuleMatch]:
    """Arquivo oculto (começa com .) com bit de execução — exceto os
    scripts de início de sessão X padrão do sistema quando estão direto
    na home do usuário/root. Achado ao vivo: ``/etc/skel/.xsession``
    (shipped por padrão em Debian/Ubuntu, copiado pra TODA conta nova) e
    `/home/hermes/.xsession` têm mode 755 e são shell scripts legítimos —
    display managers os executam diretamente por design, não é evasão
    nem uso incomum. Sem a exceção, qualquer sistema com ambiente desktop
    dispararia essa regra em praticamente toda conta de usuário."""
    import os
    name = os.path.basename(ctx.path)
    if not (name.startswith(".") and ctx.is_executable):
        return None
    dirname = os.path.dirname(ctx.path)
    if name in _HIDDEN_EXEC_ALLOWLIST and _is_direct_home_dir(dirname):
        return None
    return RuleMatch(rid, f"arquivo oculto executável: {name}")


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
                  "/etc/shadow, /etc/passwd, /etc/sudoers, /etc/gshadow, "
                  "/etc/security/opasswd, chave privada de host SSH "
                  "(/etc/ssh/ssh_host_*_key), ou credencial/wallet local "
                  "(wallet.dat, id_rsa, keystore, mnemonic, quarantine.key, "
                  "auth.hash) sem exigir upload de rede — chave PÚBLICA "
                  "(.pub) não dispara",
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

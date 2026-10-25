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

import hashlib
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
    content_sample: Optional[bytes] = None   # primeiro 1 MiB do arquivo (CONTENT_SAMPLE_SIZE)
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
# Bound de 4096 no trecho entre o downloader e o pipe (2026-10-11, mesmo padrão de H012/H015/H023): sem ele, uma linha
# longa com "curl"/"wget" repetidos e sem pipe fazia cada tentativa varrer o resto da linha -> O(n²) medido ao vivo
# (64KB 1,06s, 128KB 4,08s; 1 MiB ~268s com o arquivo inteiro). Só apareceu com anchors misturados numa linha, por isso
# a auditoria de 2026-10-06 (um anchor por vez) não pegou. Pré-requisito para subir CONTENT_SAMPLE_SIZE.
#
# Rodada 2026-10-18: o bound acima tirou o termo quadrático só quando os anchors são esparsos. Com "curl " denso (um a
# cada 5 bytes, sem pipe), cada uma das ~210 mil tentativas ainda varria até 4096 bytes: medido ao vivo 0,93s em 64KB e
# **14,6s em 1 MiB** por arquivo (linear, mas com fator 4096) — DoS do monitor em tempo real igual. Substituído por uma
# varredura única de tokens (downloader / separador / pipe): guarda o fim do downloader mais recente do comando atual e,
# em cada "|", testa o interpretador só ali. Mesma semântica da regex antiga (downloader e "| interp" no mesmo comando,
# gap <= 4096 sem \n ; &) — o downloader mais recente é sempre o melhor candidato, então não precisa tentar os outros.
_DL_PIPE_GAP      = 4096
_RE_DL_PIPE_TOKEN = re.compile(rb'(' + _DL + rb')|[\n;&]+|\|', re.I)
_RE_PIPE_INTERP   = re.compile(rb'\|\s*' + _INTERP, re.I)
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
# H018, rodada 2026-10-22: a regex antiga (`[13][base58]{25,34}` sem
# boundary nem checksum) casava qualquer corrida hex/alfanumérica que
# começasse com 1 ou 3 — build-id, hashes embutidos, tabelas de símbolos.
# Medido: 1381 de 5508 ELFs desta VPS (25%) saíam risco "alto" por H018,
# incluindo /bin/ls. Agora cada família tem boundary alfanumérico dos dois
# lados e, onde o checksum é verificável só com stdlib, ele é verificado:
# BTC legado via Base58Check (sha256d, versão 0x00/0x05) e BTC segwit via
# bech32/bech32m (BIP173/BIP350). ETH não tem checksum verificável sem
# Keccak (EIP-55 só existe em mixed-case), fica só com boundary. Monero
# (o que cryptominer real usa — xmrig) não era coberto: entra pelo formato
# estrutural (95 chars Base58, prefixo 4/8 + [0-9AB]), também sem checksum
# pelo mesmo motivo do Keccak.
_B58_ALPHABET    = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
_B58_INDEX       = {c: i for i, c in enumerate(_B58_ALPHABET)}
_RE_BTC_LEGACY   = re.compile(rb'(?<![0-9A-Za-z])[13][a-km-zA-HJ-NP-Z1-9]{25,34}(?![0-9A-Za-z])')
_RE_BTC_BECH32   = re.compile(rb'(?<![0-9A-Za-z])bc1(?:[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{20}){0,1}[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{39}(?![0-9A-Za-z])', re.I)
_RE_ETH_ADDR     = re.compile(rb'(?<![0-9A-Za-z])0x[0-9a-fA-F]{40}(?![0-9A-Za-z])')
_RE_XMR_ADDR     = re.compile(rb'(?<![0-9A-Za-z])[48][0-9AB][a-km-zA-HJ-NP-Z1-9]{93}(?:[a-km-zA-HJ-NP-Z1-9]{11})?(?![0-9A-Za-z])')
_BECH32_CHARSET  = b'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
_BECH32_CONSTS   = (1, 0x2bc830a3)   # bech32 (v0), bech32m (v1+)
_BECH32_POLY     = (0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)
# XOR dos geradores por valor do topo (5 bits): 1 lookup por char em vez de
# 5 testes de bit — com candidato denso o polymod era o gargalo (1,2s/MiB).
_BECH32_GEN: list[int] = []
for _top in range(32):
    _acc = 0
    for _i, _g in enumerate(_BECH32_POLY):
        if (_top >> _i) & 1:
            _acc ^= _g
    _BECH32_GEN.append(_acc)
del _top, _acc, _i, _g
# H017, rodada 2026-10-24: o `\b` antigo casava 4 arcos no meio de OID
# (`1.3.6.1.5.5.7.3.1` → `1.3.6.1`) e de versão (`1.2.3.4.5`). Agora o
# dotted quad não pode ter ponto colado antes nem `.dígito` depois.
# 2026-10-25: octeto validado em `_is_c2_candidate_ip`, não no regex — a
# alternância por octeto + lookbehind no início tirava o `\b` como âncora e
# custava ~4x o regex antigo por MiB; `\d{1,3}` com `\b` sai mais barato que
# o original. Também fora: nome PTR reverso (`170.0.0.192.in-addr.arpa`, o
# systemd-resolved embute vários) e número de seção (`RFC 8011 section
# 4.1.6.2`, ipptool).
_RE_IP_HARDCODED = re.compile(
    rb'\b(?<!\.)(?<![Ss]ection )\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    rb'(?!\.\d|(?i:\.in-addr\.arpa))'
)
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
# Rodada 2026-10-18: sem âncora no início do nome, o motor tentava os 40
# comprimentos do grupo em CADA byte de qualquer corrida longa de
# [A-Za-z0-9_.:] — blob base64 de 1 MiB (comum em script/instalador
# legítimo) levava 2,0s e "aaaa..." 3,5s por arquivo, medido ao vivo. O
# lookbehind negativo faz o nome só começar onde começa um identificador
# (o que já era o caso de toda fork bomb real), e o custo cai pra ~linear.
_RE_FORK_BOMB_GENERIC = re.compile(
    rb'(?<![A-Za-z0-9_.:])([A-Za-z0-9_.:]{1,40})\s*\(\)\s*\{\s*\1\s*\|\s*\1\s*&\s*\}\s*;\s*\1(?![A-Za-z0-9_.:])'
    rb'|(?<![A-Za-z0-9_.:])([A-Za-z0-9_.:]{1,40})\s*\(\)\s*\{\s*\2\s*&\s*\2\s*&\s*\}\s*;\s*\2(?![A-Za-z0-9_.:])',
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
# H013, rodada 2026-10-12: os dois `[^|\n]*` irrestritos abaixo (gap interno
# do ramo openssl até o "-d", e gap externo compartilhado por todos os ramos
# até o "|") são aninhados — pra cada ocorrência do anchor decoder, o motor
# tenta todo corte possível do gap interno (cada "-d" mais à frente no buffer)
# e, pra cada um, todo corte possível do gap externo (cada "|" mais à frente)
# até esgotar as combinações. Confirmado ao vivo com anchors combinados numa
# linha só (mesmo método que achou o bug do H005 em 2026-10-11, mas a
# auditoria de performance de 2026-10-06 não cobriu esta regra): **20,4s em
# 64KB**, pior que o H005 original (1,06s em 64KB) — backtracking catastrófico
# (crescimento super-linear acelerando: 512B 0,09ms → 32KB 2,47s → 64KB
# timeout >15s), não só O(n²). Com `CONTENT_SAMPLE_SIZE` em 1 MiB, um arquivo
# com "openssl"/"base64 -d" repetidos sem pipe real travaria o monitor em
# tempo real (inotify dispara `analyze()` a cada escrita) — vetor de DoS
# contra o próprio EK-Protection.
#
# Fix: bound nos dois gaps, mas **não** o mesmo valor de 4096 usado em
# H005/H009/H023 — medido ao vivo que, por serem DOIS quantificadores
# aninhados aqui (gap interno × gap externo, não só um), o custo no pior caso
# escala com o produto dos bounds, não com a soma: 4096 deu 24,9s em 1 MiB
# (pior que antes do fix!), 512 deu 0,71s, 256 deu 0,36s. 512 escolhido como
# teto generoso pra qualquer linha real de decoder+pipe+shell (exemplos reais
# nos testes abaixo têm <80 bytes de gap) mantendo o pior caso sub-segundo.
#
# Rodada 2026-10-18: o bound de 512 resolveu o caso de anchors misturados, mas
# não o de anchors DENSOS: "openssl enc -d " repetido (sem pipe) ainda custava
# ~34 cortes do gap interno × 512 do externo por ocorrência — medido ao vivo
# **22,8s em 1 MiB** ("base64 -d " denso 2,0s). O ramo decoder|shell virou uma
# varredura de tokens (separador | ou \n, decoder completo, prefixo openssl,
# "-d"): guarda o fim do decoder mais recente e do prefixo openssl mais recente
# do comando atual; "-d" até 512 bytes depois do prefixo fecha o decoder openssl;
# no "|", confere distância <= 512 e o shell logo depois. Mesma semântica
# (decoder mais recente é sempre o melhor candidato pros dois gaps), O(n).
_RE_OBFUSC_SH    = re.compile(
    rb'\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){5,}'                      # hex escapes em sequência
    rb'|(\\[0-7]{3}){6,}',                                       # octal escapes em sequência
    re.I)
_OBFUSC_GAP      = 512
_RE_OBFUSC_TOKEN = re.compile(
    rb'([|\n])'
    rb'|\b(?:base64\s+(?:-d|--decode|-D)|xxd\s+-r|rev)\b()'
    rb'|\b(openssl\s+(?:enc|base64)\s)'
    rb'|(-d)\b',
    re.I)
_RE_PIPE_SHELL   = re.compile(rb'\|\s*(\S*/)?(ba|z|da|k)?sh\b', re.I)
_RE_PTRACE_CALL  = re.compile(rb'ptrace\s*\(|PTRACE_ATTACH', re.I)
_RE_LD_PRELOAD   = re.compile(rb'LD_PRELOAD\s*=|/etc/ld\.so\.preload', re.I)
# /proc/<pid>/mem em todas as formas em que um scraper/injetor real escreve o
# PID: literal, self/thread-self, variável de shell ($PID, ${pid}, $$, $(pgrep
# x)), placeholder de format string do Python (f"{pid}", %d/%s) ou
# concatenação ('/proc/' + str(pid) + '/mem'). "mem" não pode ser prefixo de
# outra palavra (/proc/<pid>/memory_stats não é a técnica).
#
# Rodada 2026-10-20: o ramo `\$\([^)]*\)` não tinha bound nem parava em nada
# além de ")" — com "/proc/$(" repetido e nenhum ")" no arquivo, cada anchor
# varria o resto do buffer inteiro: O(n²) medido ao vivo (64KB 0,38s, 128KB
# 1,5s, 256KB 6,3s; ~100s extrapolado em 1 MiB) — mesmo vetor de DoS do
# monitor em tempo real de H005/H013. Agora `[^()]*`: o próprio anchor tem
# "(", então a varredura de cada um para no próximo anchor e o total fica
# O(n). Único caso que deixa de casar é "(" solto sem ")" dentro do $(...)
# (ex. `$(echo \( x)`) — não é como um scraper real escreve o PID.
_RE_MEMFD        = re.compile(
    rb'memfd_create|'
    rb'/proc/(?:self|thread-self|[0-9]+|\$\$|\$\{?\w+\}?|\{[^{}/\s]*\}|%[sd]|\$\([^()]*\))/mem(?!\w)|'
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
_RE_FNAME_TAIL   = re.compile(rb'[\w.-]*')
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
#
# Rodada 2026-10-18: igual a H005 — o bound só resolve anchors esparsos. Com
# "curl " denso (sem flag nenhuma), cada tentativa ainda percorria 4096 bytes
# e voltava: medido ao vivo **9,1s em 1 MiB** ("wget " 1,3s). Agora é uma
# varredura de tokens (curl / wget / flag / \n) que guarda o fim do curl e do
# wget mais recentes da linha e compara a distância quando aparece a flag —
# mesma semântica (flag até 4096 bytes depois de `curl\s+`/`wget\s+`, mesma
# linha), O(n).
_EXFIL_GAP         = 4096
_RE_EXFIL_TOKEN    = re.compile(
    rb'(curl\s+)|(wget\s+)|(-d\s|--data|-F\s|--upload-file|-T\s)|(--post-data)|\n',
    re.I,
)


def _exfil_net(buf: bytes) -> bool:
    # Rodada 2026-10-19: a versão de 18/10 zerava curl/wget só no token "\n"
    # isolado — mas "-d\s"/"-F\s"/"-T\s" (e "curl\s+"/"wget\s+") podem
    # CONSUMIR o \n, que aí nunca vira token e a linha nunca era fechada:
    # "wget a -F\n--post-data" disparava (a regex antiga não). Achado por fuzz
    # diferencial contra a regex antiga. Agora guarda a posição do último \n
    # visto dentro de QUALQUER token e exige o downloader depois dele.
    curl_end = wget_end = last_nl = -1
    for m in _RE_EXFIL_TOKEN.finditer(buf):
        if m.group(1) is not None:
            curl_end = m.end()
        elif m.group(2) is not None:
            wget_end = m.end()
        elif m.group(3) is not None:
            if curl_end > last_nl and m.start() - curl_end <= _EXFIL_GAP:
                return True
        elif m.group(4) is not None:
            if wget_end > last_nl and m.start() - wget_end <= _EXFIL_GAP:
                return True
        nl = m.group().rfind(b'\n')
        if nl >= 0:
            last_nl = m.start() + nl
    return False


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


def _dl_pipe_exec(buf: bytes) -> bool:
    """downloader ... | interp no mesmo comando, em O(n) (ver _RE_DL_PIPE_TOKEN)."""
    last_dl_end = -1
    for m in _RE_DL_PIPE_TOKEN.finditer(buf):
        if m.group(1) is not None:
            last_dl_end = m.end()
        elif m.group() != b'|':
            last_dl_end = -1
        elif (last_dl_end >= 0 and m.start() - last_dl_end <= _DL_PIPE_GAP
                and _RE_PIPE_INTERP.match(buf, m.start())):
            return True
    return False


def _r_download_execute(ctx: HeuristicContext, rid: str) -> Optional[RuleMatch]:
    """Download seguido de execução (wget/curl | sh)."""
    if not ctx.content_sample:
        return None
    if (_dl_pipe_exec(ctx.content_sample)
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
    buf = ctx.content_sample
    run_end, run_is_pub = -1, False
    for m in _RE_SECRET_PATHS.finditer(buf):
        # nome de arquivo completo logo após o match (ex. "rsa.pub" depois
        # de ".ssh/id_", ou ".pub" depois de "id_rsa" direto) — se terminar
        # em .pub é chave PÚBLICA, não segredo (ver comentário no regex).
        #
        # Rodada 2026-10-18: a versão anterior fazia `buf[m.end():]` (cópia
        # do resto do buffer) + `[\w.-]*` do zero a CADA match — com
        # "id_rsa.pub" repetido sem separador (uma corrida só de [\w.-] que
        # termina em .pub), O(n²): medido ao vivo **266s em 1 MiB** por
        # arquivo, e ~2s com espaço entre as repetições. Agora a corrida é
        # medida uma vez (match por posição, sem cópia) e reaproveitada pelos
        # matches seguintes que caem dentro dela — mesmo resultado, O(n).
        if m.end() >= run_end:
            run_end = _RE_FNAME_TAIL.match(buf, m.end()).end()
            run_is_pub = buf[max(m.end(), run_end - 4):run_end].lower() == b'.pub'
        if run_is_pub and run_end - m.end() >= 4:
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


def _decoder_pipe_shell(buf: bytes) -> bool:
    """decoder (base64 -d / xxd -r / openssl enc ... -d / rev) | sh, em O(n)."""
    # Rodada 2026-10-19: mesmo bug achado em _exfil_net — "openssl enc\s" e
    # "base64\s+-d" podem consumir o \n, que aí não vira token separador
    # ("rev x openssl enc\n|sh" disparava, a regex antiga não). Achado por
    # fuzz diferencial; agora o \n é rastreado dentro de qualquer token.
    dec_end = ossl_end = last_nl = -1
    for m in _RE_OBFUSC_TOKEN.finditer(buf):
        if m.group(1) == b'|':
            if (dec_end > last_nl
                    and m.start() - dec_end <= _OBFUSC_GAP
                    and _RE_PIPE_SHELL.match(buf, m.start())):
                return True
            dec_end = ossl_end = -1
        elif m.group(2) is not None:
            dec_end = m.end()
        elif m.group(3) is not None:
            ossl_end = m.end()
        elif (m.group(4) is not None and ossl_end > last_nl
                and m.start() - ossl_end <= _OBFUSC_GAP):
            dec_end = m.end()
        nl = m.group().rfind(b'\n')
        if nl >= 0:
            last_nl = m.start() + nl
    return False


def _r_obfuscation(ctx: HeuristicContext, rid: str) -> Optional[RuleMatch]:
    """Ofuscação de shell script (variáveis longas, hex escapes)."""
    if not ctx.content_sample:
        return None
    if not ctx.is_script and ctx.extension not in (".sh", ".bash", ".zsh"):
        return None
    if (_RE_OBFUSC_SH.search(ctx.content_sample)
            or _decoder_pipe_shell(ctx.content_sample)):
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


def _elf_section_table_missing(content: bytes, file_size: Optional[int]) -> bool:
    """True se o ELF não tem tabela de section headers *crível*.

    Rodada 2026-10-21: a checagem antiga era só `e_shnum == 0`. Testado
    ao vivo com UPX 4.2.4 real: reescrever 2 bytes (`e_shnum` = 31) no
    `/bin/ls` empacotado, sem tocar em mais nada, mantém o binário
    executando e evadia o sinal estrutural (o kernel não lê sections).
    Agora `e_shnum > 0` só conta como tabela real se `e_shoff != 0`,
    `e_shentsize` for o tamanho do formato (64/40) e a tabela couber no
    arquivo (quando o tamanho é conhecido). `e_shnum == 0` com `e_shoff`
    != 0 é a numeração estendida do gABI (>= 0xff00 sections, contagem
    real em sh[0].sh_size), não ausência de tabela."""
    if len(content) < 64 or content[:4] != b"\x7fELF":
        return False
    is_64 = content[4] == 2
    e     = ">" if content[5] == 2 else "<"
    if is_64:
        shoff = struct.unpack_from(e + "Q", content, 40)[0]
        shentsize, shnum = struct.unpack_from(e + "HH", content, 58)
        want = 64
    else:
        shoff = struct.unpack_from(e + "I", content, 32)[0]
        shentsize, shnum = struct.unpack_from(e + "HH", content, 46)
        want = 40
    if shnum == 0:
        return shoff == 0
    if shoff == 0 or shentsize != want:
        return True
    return file_size is not None and shoff + shnum * shentsize > file_size


_PT_LOAD, _PT_DYNAMIC, _PT_INTERP = 1, 2, 3


def _elf_packed_load_layout(content: bytes) -> bool:
    """Layout de program headers típico de packer (UPX): nenhum
    PT_INTERP/PT_DYNAMIC, no máximo 2 PT_LOAD, e algum PT_LOAD com
    memsz >= 8x filesz (o espaço onde o stub descomprime o original).

    Rodada 2026-10-21: program headers são o que o kernel usa pra mapear
    e executar — ao contrário de sections/strings, não dá pra forjar sem
    quebrar a execução. Medido ao vivo: 9/9 binários UPX 4.2.4 reais
    (ls PIE, gh e docker-compose Go estáticos, python3, gzip do klibc,
    o próprio upx) batem, 2 PT_LOAD e razão 36x a 19000x. Contra 5040 ELFs
    executáveis/shared reais desta VPS (/usr, /opt, /home, /var/lib):
    zero. Os estáticos legítimos sem PT_DYNAMIC com bss grande (Go: gh,
    docker-compose, esbuild; klibc) têm 3-4 PT_LOAD."""
    if len(content) < 64 or content[:4] != b"\x7fELF":
        return False
    is_64 = content[4] == 2
    e     = ">" if content[5] == 2 else "<"
    if is_64:
        phoff = struct.unpack_from(e + "Q", content, 32)[0]
        phentsize, phnum = struct.unpack_from(e + "HH", content, 54)
        fmt = e + "I4xQQQQQ"     # p_type, (p_flags), p_offset..p_memsz
    else:
        phoff = struct.unpack_from(e + "I", content, 28)[0]
        phentsize, phnum = struct.unpack_from(e + "HH", content, 42)
        fmt = e + "IIIIII"       # p_type, p_offset..p_memsz
    need = struct.calcsize(fmt)
    if phnum == 0 or phnum > 64 or phentsize < need:
        return False
    loads: list[tuple[int, int]] = []
    for i in range(phnum):
        off = phoff + i * phentsize
        if off + need > len(content):
            return False
        p_type, _, _, _, filesz, memsz = struct.unpack_from(fmt, content, off)
        if p_type in (_PT_DYNAMIC, _PT_INTERP):
            return False
        if p_type == _PT_LOAD:
            loads.append((filesz, memsz))
    if not 0 < len(loads) <= 2:
        return False
    return any(memsz > 0 and memsz >= 8 * filesz for filesz, memsz in loads)


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

    Rodada 2026-10-21: limitação acima confirmada ao vivo (2 bytes bastam)
    e fechada em duas camadas — `_elf_section_table_missing` (tabela de
    sections precisa ser coerente) e `_elf_packed_load_layout` (layout de
    PT_LOAD, que o kernel usa e não dá pra forjar sem quebrar a execução).
    Resta evasão por packer que gere 3+ PT_LOAD ou PT_DYNAMIC falso.
    """
    if not ctx.content_sample or not ctx.is_elf:
        return None
    if _RE_PACKED_UPX.search(ctx.content_sample):
        return RuleMatch(rid, "binário comprimido com UPX (técnica de evasão)")
    shnum_phnum = _elf_shnum_phnum(ctx.content_sample)
    if shnum_phnum is not None:
        _, phnum = shnum_phnum
        if (0 < phnum <= 4
                and _elf_section_table_missing(ctx.content_sample, ctx.file_size)):
            return RuleMatch(
                rid,
                "binário ELF sem tabela de section headers e poucos "
                "program headers (indicador estrutural de packing, "
                "ex. UPX com strings de assinatura removidas)",
            )
    if _elf_packed_load_layout(ctx.content_sample):
        return RuleMatch(
            rid,
            "binário ELF com layout de segmentos de packer (sem "
            "PT_INTERP/PT_DYNAMIC, <=2 PT_LOAD, memsz >> filesz) — "
            "indicador estrutural de packing que sobrevive a forjar "
            "sections/strings",
        )
    return None


# Resolvers DNS públicos: malware usa (checagem de conectividade, descobrir
# o IP local), mas não são C2. nmcli/nmtui embutem 8.8.8.8 + 8.8.4.4.
_PUBLIC_RESOLVERS = frozenset({
    b"8.8.8.8", b"8.8.4.4", b"1.1.1.1", b"1.0.0.1", b"9.9.9.9",
    b"149.112.112.112", b"208.67.222.222", b"208.67.220.220",
})
# Root servers DNS (a–m; B tem 3 endereços na história): root hints do
# dirmngr/unbound/bind. 2026-10-25, único H017 restante do dirmngr.
_DNS_ROOT_SERVERS = frozenset({
    b"198.41.0.4", b"170.247.170.2", b"199.9.14.201", b"192.228.79.201",
    b"192.33.4.12", b"199.7.91.13", b"192.203.230.10", b"192.5.5.241",
    b"192.112.36.4", b"198.97.190.53", b"192.36.148.17", b"192.58.128.30",
    b"193.0.14.129", b"199.7.83.42", b"202.12.27.33",
})


def _net(cidr: str) -> tuple[int, int]:
    base, bits = cidr.split("/")
    mask = (0xFFFFFFFF << (32 - int(bits))) & 0xFFFFFFFF
    return int.from_bytes(bytes(int(x) for x in base.split(".")), "big"), mask


# Faixas não-globais/não-unicast do registro IANA (as mesmas que tiram o
# `is_global` do `ipaddress`, + multicast). Máscara de inteiro em vez de
# `ipaddress.IPv4Address`: com 1 MiB de quads únicos o `ipaddress` levava
# 1,4s; isto leva bem menos (ver EK-Protection.md, 2026-10-24).
_NON_GLOBAL_V4 = tuple(_net(c) for c in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
))


def _is_c2_candidate_ip(ip: bytes) -> bool:
    """IP que pode ser C2: global e unicast (tira RFC1918, loopback, 0/8,
    CGNAT, link-local, TEST-NET, multicast, 240/4), fora dos resolvers
    públicos e sem cara de OID/versão.

    Medido em 2026-10-24 nos 5575 ELFs da VPS: H017 disparava em 100, todos
    falso positivo. A maioria era OID de X.509/LDAP/SNMP com 4 arcos, que
    é formalmente um IPv4 válido (`2.5.29.19`, `1.3.6.1`, `1.3.101.112`), e
    versão (`1.2.3.3` do zlib). OID começa com arco 0/1/2 e o 2º arco é
    < 40 pra 0/1 (X.660), por isso `o[0] <= 2 and o[1] < 40` sai. Custo:
    C2 real em 1.0–1.39.x.x / 2.0–2.39.x.x deixa de contar. Final .0/.255
    (rede/broadcast, e versões tipo `13.0.10.0`) também sai."""
    o = [int(x) for x in ip.split(b".")]
    if max(o) > 255:
        return False
    if o[0] <= 2 and o[1] < 40:
        return False
    if o[3] in (0, 255) or ip in _PUBLIC_RESOLVERS or ip in _DNS_ROOT_SERVERS:
        return False
    n = (o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]
    return not any((n & mask) == base for base, mask in _NON_GLOBAL_V4)


def _r_hardcoded_ip(ctx: HeuristicContext, rid: str) -> Optional[RuleMatch]:
    """IPs hardcoded no binário (possível C2). Conta IPs distintos: o
    mesmo IP repetido 5x (era o caso de `1.101.3.4` nos módulos do grub)
    não é evidência de 2 destinos."""
    if not ctx.content_sample or not ctx.is_elf:
        return None
    # Dedup antes de classificar e para no 5º (só 5 vão pra evidência):
    # 1 MiB denso de OID/IP custava 0,5–0,7s validando cada ocorrência.
    seen: set[bytes] = set()
    found: list[str] = []
    for m in _RE_IP_HARDCODED.finditer(ctx.content_sample):
        ip = m.group()
        if ip in seen:
            continue
        seen.add(ip)
        if _is_c2_candidate_ip(ip):
            found.append(ip.decode("ascii"))
            if len(found) == 5:
                break
    external = sorted(found)
    if len(external) >= 2:
        return RuleMatch(rid, f"{len(external)} IPs externos hardcoded",
                         evidence=", ".join(external[:5]))
    return None


def _r_crypto_strings(ctx: HeuristicContext, rid: str) -> Optional[RuleMatch]:
    """Strings de carteiras crypto (possível cryptominer)."""
    if not ctx.content_sample:
        return None
    data = ctx.content_sample
    matches = [m.group() for m in _RE_BTC_LEGACY.finditer(data) if _base58check_ok(m.group())]
    matches += [m.group() for m in _RE_BTC_BECH32.finditer(data) if _bech32_ok(m.group())]
    matches += _RE_ETH_ADDR.findall(data)
    matches += _RE_XMR_ADDR.findall(data)
    if matches:
        return RuleMatch(rid, f"{len(matches)} possível(is) endereço(s) de carteira crypto",
                         evidence=matches[0].decode("utf-8", errors="replace")[:40])
    return None


# Rodada 2026-10-23: H024 (config de cryptominer). O `config.json` do xmrig
# é onde a carteira fica de verdade, e o monitor em tempo real nunca o
# escaneava (só extensões executáveis). Rodar as 23 regras em todo config
# novo não serve: medido contra os 4527 .json/.yaml/.yml/.conf/.toml desta
# VPS, 158 (3,5%) davam suspeito, a maioria H009 (chave "privateKey",
# "keystore", "mnemonic" em config/fixture de repo) e H018 (endereço real
# com checksum válido em fixture de repo cripto). Nenhum era minerador.
# H024 exige as duas coisas no mesmo arquivo: endereço de carteira (mesmo
# matcher do H018, com checksum) + indicador de minerador. Os indicadores
# são específicos de minerador: esquema stratum (protocolo de pool),
# `donate-level` (opção do xmrig, em config e em CLI) e `"algo"` com nome de
# algoritmo de mineração.
_RE_MINER_HINT = re.compile(
    rb'stratum2?\+(?:tcp|ssl|tls)://|'
    rb'["\'-]donate-level["\'=:\s]|'
    rb'"algo"\s*:\s*"(?:rx/|cn/|cn-|randomx|kawpow|ethash|etchash|autolykos|argon2|ghostrider)',
    re.I,
)


def _r_miner_config(ctx: HeuristicContext, rid: str) -> Optional[RuleMatch]:
    """Carteira crypto + indicador de minerador (pool stratum, donate-level,
    algoritmo de mineração) no mesmo arquivo."""
    if not ctx.content_sample:
        return None
    hint = _RE_MINER_HINT.search(ctx.content_sample)
    if not hint:
        return None
    wallet = _r_crypto_strings(ctx, rid)
    if wallet is None:
        return None
    hint_txt = hint.group().decode('utf-8', errors='replace').strip('"\'-=: \t\r\n')
    return RuleMatch(rid, f"carteira + {hint_txt}", evidence=wallet.evidence)


def _base58check_ok(addr: bytes) -> bool:
    """Endereço BTC legado (P2PKH 0x00 / P2SH 0x05) com checksum sha256d
    válido. Chance de corrida aleatória passar: 2^-32 × versão certa."""
    n = 0
    for c in addr:
        n = n * 58 + _B58_INDEX[c]
    pad = len(addr) - len(addr.lstrip(b'1'))
    try:
        raw = b'\x00' * pad + n.to_bytes((n.bit_length() + 7) // 8, 'big')
    except OverflowError:
        return False
    if len(raw) != 25 or raw[0] not in (0x00, 0x05):
        return False
    return hashlib.sha256(hashlib.sha256(raw[:21]).digest()).digest()[:4] == raw[21:]


def _bech32_ok(addr: bytes) -> bool:
    """Endereço BTC segwit (bc1...) com checksum bech32/bech32m válido.
    Mixed-case é inválido pela BIP173."""
    if addr != addr.lower() and addr != addr.upper():
        return False
    addr = addr.lower()
    values = [c >> 5 for c in b'bc'] + [0] + [c & 31 for c in b'bc']
    values += [_BECH32_CHARSET.index(c) for c in addr[3:]]
    chk = 1
    for v in values:
        chk = ((chk & 0x1ffffff) << 5) ^ v ^ _BECH32_GEN[chk >> 25]
    return chk in _BECH32_CONSTS


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


# Áreas graváveis por qualquer usuário, onde dropper cai primeiro (um
# www-data comprometido não escreve em mais nada). H021/H022, 2026-10-24.
_STAGING_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")


def _in_staging_dir(path: str) -> bool:
    return path.startswith(_STAGING_DIRS)


def _hidden_dir_in_staging(path: str) -> Optional[str]:
    """Diretório oculto no caminho de um arquivo em /tmp, /var/tmp ou
    /dev/shm — o padrão de botnet de mineração: Outlaw em
    ``/tmp/.X25-unix/.rsync/c/``, TeamTNT/Kinsing em ``/tmp/.ICE-unix/``
    e ``/dev/shm/.x/``. O nome do arquivo não começa com ponto, então o
    H021 antigo (só basename) não via. Medido 2026-10-24: 1212 executáveis
    sob diretório oculto na VPS (``~/.nvm``, ``~/.cache``, ``~/.local``...),
    **zero** deles em área temporária — por isso só lá."""
    if not _in_staging_dir(path):
        return None
    parts = path.split("/")[:-1]
    for i, part in enumerate(parts):
        if part.startswith(".") and part not in (".", ".."):
            return "/".join(parts[:i + 1])
    return None


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
    if not ctx.is_executable:
        return None
    if not name.startswith("."):
        hidden_dir = _hidden_dir_in_staging(ctx.path)
        if hidden_dir:
            return RuleMatch(
                rid, f"executável dentro de diretório oculto em área "
                     f"temporária: {hidden_dir}/.../{name}")
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
    if not _exfil_net(ctx.content_sample):
        return None
    return RuleMatch(
        rid,
        f"leitura de segredo ({m.group().decode('utf-8', errors='replace')}) + upload de rede (exfiltração)",
    )


_RE_PY_INTERP_NAME = re.compile(r"^python3?(\.\d+)?$")
_NVM_BIN_NAMES      = {"node", "npm", "npx", "corepack"}


def _is_venv_bin_interpreter(path: str, name: str) -> bool:
    """``.../venv/bin/python`` ou ``.../.venv/bin/python3.12`` — toda
    virtualenv Python (via ``venv``/``virtualenv``/``pip``) copia o
    interpretador real pra dentro de ``<venv>/bin/`` sem extensão, mesma
    convenção de nomenclatura do ``/usr/bin/python3`` já excluído pelos
    std_dirs — só muda o diretório onde a cópia mora."""
    import os
    if not _RE_PY_INTERP_NAME.match(name):
        return False
    parent = os.path.dirname(path)
    grandparent = os.path.dirname(parent)
    return (os.path.basename(parent) == "bin"
            and os.path.basename(grandparent).endswith("venv"))


def _is_nvm_bin(path: str, name: str) -> bool:
    """``.../.nvm/versions/node/vX.Y.Z/bin/{node,npm,npx,corepack}`` —
    instalação padrão do nvm, binários reais do Node.js sem extensão."""
    return name in _NVM_BIN_NAMES and "/.nvm/versions/node/" in path


def _is_node_modules_binary(path: str) -> bool:
    """Qualquer binário ELF sem extensão dentro de uma árvore
    ``node_modules/`` — convenção do npm/yarn/pnpm pra pacotes que
    distribuem binário nativo (ex. esbuild), gerenciada pelo próprio
    gerenciador de pacotes, não um local onde se espera um dropper manual."""
    return "/node_modules/" in path


def _is_playwright_cache_binary(path: str) -> bool:
    """``~/.cache/ms-playwright/...`` — binários de browser (Chromium,
    ffmpeg) baixados pelo próprio Playwright, cache fixo e conhecido da
    ferramenta."""
    return "/.cache/ms-playwright/" in path


def _is_update_alternatives_symlink(path: str) -> bool:
    """``/etc/alternatives/<nome>`` — symlinks geridos pelo próprio
    ``update-alternatives`` do Debian/Ubuntu, só graváveis por root."""
    import os
    return os.path.dirname(path) == "/etc/alternatives"


# H022, 2026-10-24: ELF com extensão de texto/imagem/dado é disfarce
# (`/tmp/update.png`, `kdevtmpfsi.log`). Antes qualquer extensão saía da
# regra. Medido nos 5575 ELFs da VPS: nenhum com extensão desta lista; as
# extensões reais de ELF são .so, .so.N, .o, .mod, .node, .cgi, .real, .img.
_MASQUERADE_EXTENSIONS = frozenset({
    ".txt", ".log", ".md", ".csv", ".json", ".yaml", ".yml", ".xml",
    ".html", ".htm", ".css", ".js", ".ini", ".cfg", ".conf", ".toml",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".mp3", ".mp4", ".wav",
    ".zip", ".gz", ".tgz", ".tar", ".bz2", ".xz", ".7z", ".rar",
    ".sh", ".py", ".pl", ".rb", ".php", ".pid", ".lock", ".sql",
})


def _r_no_extension_elf(ctx: HeuristicContext, rid: str) -> Optional[RuleMatch]:
    """Binário ELF sem extensão em local não-padrão.

    Achado ao vivo (escaneados 32278 arquivos candidatos fora dos
    std_dirs nesta VPS real): 131 ELFs sem extensão legítimos, nenhum
    deles um dropper — cópias de interpretador em virtualenv (``.venv/
    bin/python``), binários do nvm (``~/.nvm/versions/node/*/bin/node``),
    binários nativos distribuídos via npm dentro de ``node_modules/``
    (ex. ``esbuild``), cache de browser do Playwright
    (``~/.cache/ms-playwright/``) e symlinks do ``update-alternatives``
    em ``/etc/alternatives/``. Essas 5 convenções, sozinhas, já geravam
    ~130 falsos positivos numa única máquina de desenvolvimento comum —
    cada ``pip venv``/``npm install``/``npx playwright install`` novo
    dispararia a regra via o piso de severidade (H022 isolado força
    risk_level ``médio`` independente do score agregado, ver
    ``_calculate_score``)."""
    import os
    std_dirs = ("/usr/", "/bin/", "/sbin/", "/lib/", "/opt/")
    if not ctx.is_elf:
        return None
    if ctx.extension in _MASQUERADE_EXTENSIONS:
        return RuleMatch(rid, f"binário ELF disfarçado de {ctx.extension}: "
                              f"{ctx.path}")
    if ctx.extension != "":
        return None
    if any(ctx.path.startswith(d) for d in std_dirs):
        return None
    name = os.path.basename(ctx.path)
    # As exceções abaixo são convenção de caminho, e caminho em /tmp o
    # atacante cria com mkdir: `/tmp/node_modules/xmrig`,
    # `/dev/shm/.cache/ms-playwright/kdevtmpfsi` e `/tmp/x/.venv/bin/python3`
    # passavam (2026-10-24). Em área temporária não vale exceção.
    if _in_staging_dir(ctx.path):
        return RuleMatch(rid, f"binário ELF sem extensão em local não-padrão: {ctx.path}")
    if (_is_venv_bin_interpreter(ctx.path, name)
            or _is_nvm_bin(ctx.path, name)
            or _is_node_modules_binary(ctx.path)
            or _is_playwright_cache_binary(ctx.path)
            or _is_update_alternatives_symlink(ctx.path)):
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

    HeuristicRule("H024", "Config de Cryptominer",
                  "Carteira crypto + pool stratum/opção de minerador no mesmo arquivo",
                  "crítico", 9, ("crypto", "miner", "config"),
                  _match_fn=_r_miner_config),
]

# Regras rodadas no auto-scan em tempo real de arquivos de config
# (.json/.yaml/...). Ver comentário de _RE_MINER_HINT.
CONFIG_AUTOSCAN_RULES: frozenset[str] = frozenset({"H024"})

# Indexado por rule_id para lookup rápido
RULES_BY_ID: dict[str, HeuristicRule] = {r.rule_id: r for r in ALL_RULES}

# RULES_BY_ID built above covers H022

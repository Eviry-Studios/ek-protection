"""
ekprotection.monitor.canary
=============================
Arquivos-isca (canary/honeytoken) de credencial e wallet.

Infostealer e invasor manual leem ``~/.ssh/id_*``, keystore, ``wallet.dat``
e seed phrase com ``open()`` + ``read()``. Leitura não gera nenhum evento no
FSWatcher (só escrita/criação/remoção), e as regras de conteúdo (H023 etc.)
só olham o *código* de quem lê, quando ele cai em disco. Um ``cat
~/.ssh/id_ed25519`` numa shell invadida passava sem nada (medido
2026-11-04).

O usuário planta arquivos falsos com nome de segredo em
``monitor.canary_paths``. Ninguém legítimo abre esses arquivos, então
qualquer IN_OPEN neles vira alerta CRITICAL. Não serve pra arquivo de
segredo *real*: a própria wallet/ssh abre o seu arquivo o tempo todo.

Nome da isca: NÃO usar os nomes padrão do cliente ssh (``id_rsa``,
``id_ecdsa``, ``id_ed25519``, ``id_dsa``, ``id_xmss`` e ``*_sk``). O ``ssh``
abre esses arquivos sozinho a cada conexão sem ``IdentitiesOnly`` (``ssh -G``
na VPS, 2026-11-04), então todo ``git push`` alertaria. Stealer faz glob de
``~/.ssh/*``, então ``~/.ssh/id_ed25519_old``, ``~/.ssh/backup_prod.pem``,
``~/wallets/UTC--...--<addr>`` ou ``~/seed-phrase.txt`` pegam igual.

Limites:
  - inotify não diz quem abriu. A atribuição varre ``/proc/*/fd`` logo depois
    do evento (melhor esforço): ``cat`` costuma já ter fechado o arquivo.
  - Cooldown de ``_COOLDOWN_S`` por arquivo: loop que abre o arquivo mil
    vezes gera 1 alerta, não mil.
  - O próprio scanner pula os arquivos-isca (ver ScanEngine), senão um
    ``ekp scan /home`` disparava o alerta.
"""

from __future__ import annotations

import asyncio
import base64
import grp
import json
import logging
import os
import pwd
import secrets
import stat
import time
from pathlib import Path
from typing import Callable, Optional

from watchdog.events import FileOpenedEvent, FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from .events import FileEvent, FileEventKind

logger = logging.getLogger(__name__)

_COOLDOWN_S = 60.0

# Arquivos que o cliente/servidor ssh abre sozinho (``ssh -G``, sshd_config
# padrão). Isca com esse nome alerta a cada ``ssh``/``git push``.
_SSH_AUTO_OPENED = frozenset(
    [f"{k}{suf}" for k in ("id_rsa", "id_ecdsa", "id_ecdsa_sk", "id_ed25519",
                           "id_ed25519_sk", "id_dsa", "id_xmss")
     for suf in ("", ".pub", "-cert.pub")]
    + ["config", "known_hosts", "known_hosts2", "authorized_keys", "authorized_keys2"]
)

CANARY_KINDS = ("ssh", "wallet", "seed", "aws", "generic")

_SEED_WORDS = (
    "abandon", "ability", "absorb", "access", "action", "adjust", "agent", "alarm",
    "anchor", "april", "artist", "audit", "badge", "basket", "beach", "border",
    "bridge", "cabin", "canvas", "carbon", "castle", "cherry", "circle", "coffee",
    "coral", "cousin", "danger", "desert", "dragon", "eagle", "empire", "fabric",
    "garden", "harbor", "island", "jungle", "lemon", "marble", "orbit", "planet",
)


def _readable_by(st: os.stat_result, uid: int) -> bool:
    if uid == 0:
        return True
    if st.st_uid == uid:
        return bool(st.st_mode & stat.S_IRUSR)
    if st.st_mode & stat.S_IRGRP:
        try:
            pw = pwd.getpwuid(uid)
            if st.st_gid == pw.pw_gid or pw.pw_name in grp.getgrgid(st.st_gid).gr_mem:
                return True
        except KeyError:
            pass
    return bool(st.st_mode & stat.S_IROTH)


def canary_issues(path: str | Path) -> list[str]:
    """Problemas que deixam a isca cega ou barulhenta. Vazio = ok.

    O "invasor provável" é o dono do diretório da isca (stealer rodando
    como o usuário daquela home)."""
    p = Path(path).expanduser()
    issues: list[str] = []
    if p.name in _SSH_AUTO_OPENED:
        issues.append(
            f"nome '{p.name}' é aberto sozinho pelo ssh/sshd: alerta a cada conexão "
            "(use algo como backup_prod.pem ou id_ed25519_old)")
    try:
        st = p.stat()
        dir_uid = p.resolve().parent.stat().st_uid
    except OSError:
        return issues
    if not _readable_by(st, dir_uid):
        try:
            who = pwd.getpwuid(dir_uid).pw_name
        except KeyError:
            who = str(dir_uid)
        issues.append(
            f"ilegível por {who} (dono do diretório): abertura falha com EACCES e o "
            f"inotify não gera evento (corrija com `chown {who}: {p} && chmod 600 {p}`)")
    return issues


def bait_content(kind: str) -> str:
    """Conteúdo falso com cara de segredo. Bytes aleatórios, não é chave válida."""
    if kind == "ssh":
        body = secrets.token_bytes(300)
        b64 = base64.b64encode(b"openssh-key-v1\0" + body).decode()
        lines = [b64[i:i + 70] for i in range(0, len(b64), 70)]
        return ("-----BEGIN OPENSSH PRIVATE KEY-----\n" + "\n".join(lines)
                + "\n-----END OPENSSH PRIVATE KEY-----\n")
    if kind == "wallet":
        return json.dumps({
            "address": secrets.token_hex(20),
            "crypto": {
                "cipher": "aes-128-ctr",
                "cipherparams": {"iv": secrets.token_hex(16)},
                "ciphertext": secrets.token_hex(32),
                "kdf": "scrypt",
                "kdfparams": {"dklen": 32, "n": 262144, "p": 1, "r": 8,
                              "salt": secrets.token_hex(32)},
                "mac": secrets.token_hex(32),
            },
            "id": "-".join(secrets.token_hex(n) for n in (4, 2, 2, 2, 6)),
            "version": 3,
        }) + "\n"
    if kind == "seed":
        return " ".join(secrets.choice(_SEED_WORDS) for _ in range(12)) + "\n"
    if kind == "aws":
        return ("[default]\n"
                "aws_access_key_id = AKIA" + secrets.token_hex(8).upper() + "\n"
                "aws_secret_access_key = " + secrets.token_urlsafe(30)[:40] + "\n")
    if kind == "generic":
        return secrets.token_hex(32) + "\n"
    raise ValueError(f"tipo de isca desconhecido: {kind} (use {', '.join(CANARY_KINDS)})")


def create_canary(path: str | Path, kind: str) -> Path:
    """Cria a isca 0600, dona = dono do diretório. Não sobrescreve nada."""
    p = Path(path).expanduser()
    content = bait_content(kind)
    parent_st = p.parent.stat()           # dir tem que existir
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        if os.geteuid() == 0 and parent_st.st_uid != 0:
            os.fchown(fd, parent_st.st_uid, parent_st.st_gid)
        os.write(fd, content.encode())
    except BaseException:
        os.close(fd)
        p.unlink(missing_ok=True)
        raise
    os.close(fd)
    return p


def find_openers(path: str, proc_root: str = "/proc") -> list[str]:
    """PIDs (como ``"nome(pid)"``) com fd aberto apontando pra ``path``.
    Só enxerga processos que o usuário atual pode ler."""
    found: list[str] = []
    own = str(os.getpid())
    try:
        pids = [p for p in os.listdir(proc_root) if p.isdigit() and p != own]
    except OSError:
        return found
    for pid in pids:
        fd_dir = os.path.join(proc_root, pid, "fd")
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue
        for fd in fds:
            try:
                target = os.readlink(os.path.join(fd_dir, fd))
            except OSError:
                continue
            if target == path:
                try:
                    with open(os.path.join(proc_root, pid, "comm")) as f:
                        name = f.read().strip()
                except OSError:
                    name = "?"
                found.append(f"{name}({pid})")
                break
    return found


def resolve_canaries(paths: list[str]) -> dict[str, str]:
    """Path real -> path configurado, só dos arquivos que existem."""
    out: dict[str, str] = {}
    for raw in paths or []:
        p = Path(raw).expanduser()
        if not p.is_file():
            logger.warning("Arquivo-isca não existe (ignorado): %s", raw)
            continue
        for issue in canary_issues(p):
            logger.warning("Arquivo-isca %s: %s", raw, issue)
        out[str(p.resolve())] = str(p)
    return out


class _CanaryHandler(FileSystemEventHandler):
    def __init__(
        self,
        canaries: dict[str, str],
        emit:     Callable[[FileEvent], None],
        clock:    Callable[[], float] = time.monotonic,
        openers:  Callable[[str], list[str]] = find_openers,
    ) -> None:
        super().__init__()
        self._canaries = canaries
        self._emit     = emit
        self._clock    = clock
        self._openers  = openers
        self._last: dict[str, float] = {}

    def on_opened(self, event: FileSystemEvent) -> None:
        self.handle_open(event.src_path)

    def handle_open(self, real_path: str) -> None:
        configured = self._canaries.get(real_path)
        if configured is None:
            return
        now  = self._clock()
        last = self._last.get(real_path)
        if last is not None and now - last < _COOLDOWN_S:
            return
        self._last[real_path] = now
        who = self._openers(real_path)
        detail = ("aberto por " + ", ".join(who)) if who else "processo não identificado"
        self._emit(FileEvent(kind=FileEventKind.ACCESSED, path=configured, detail=detail))


class CanaryWatcher:
    """Observa IN_OPEN nos arquivos-isca e empurra FileEvent ACCESSED na fila."""

    def __init__(
        self,
        paths: list[str],
        queue: asyncio.Queue,
        loop:  asyncio.AbstractEventLoop,
    ) -> None:
        self._canaries = resolve_canaries(paths)
        self._queue    = queue
        self._loop     = loop
        self._observer: Optional[Observer] = None
        # Cooldown por isca, compartilhado entre observers (ver update()).
        self._last: dict[str, float] = {}

    def _emit(self, ev: FileEvent) -> None:
        self._loop.call_soon_threadsafe(self._queue.put_nowait, ev)

    def _build_observer(self, canaries: dict[str, str]) -> Optional[Observer]:
        if not canaries:
            return None
        from watchdog.observers.inotify import InotifyObserver
        observer = InotifyObserver()
        handler = _CanaryHandler(canaries, self._emit)
        handler._last = self._last
        # Watch no dir pai (não recursivo), filtrado só pra IN_OPEN. O
        # handler descarta abertura de qualquer outro arquivo do dir.
        for parent in sorted({os.path.dirname(p) for p in canaries}):
            try:
                observer.schedule(handler, parent, recursive=False,
                                  event_filter=[FileOpenedEvent])
            except OSError as exc:
                logger.error("Não foi possível vigiar arquivos-isca em %s: %s", parent, exc)
        observer.start()
        return observer

    def start(self) -> None:
        self._observer = self._build_observer(self._canaries)
        if self._observer:
            logger.info("CanaryWatcher: %d arquivo(s)-isca vigiado(s).", len(self._canaries))

    def update(self, paths: list[str]) -> dict[str, list[str]]:
        """Troca a lista de iscas sem reiniciar o daemon (SIGHUP / IPC reload).

        O observer novo sobe **antes** de parar o antigo: não há janela em que
        nenhuma isca é vigiada. Abertura no meio da troca pode chegar pelos
        dois, por isso o cooldown (`_last`) é o mesmo dict nos dois handlers.
        """
        new = resolve_canaries(paths)
        old_paths, new_paths = set(self._canaries.values()), set(new.values())
        old_observer = self._observer
        self._observer = self._build_observer(new)
        self._canaries = new
        if old_observer and old_observer.is_alive():
            old_observer.stop()
            old_observer.join(timeout=5)
        for real in list(self._last):
            if real not in new:
                del self._last[real]
        diff = {"added": sorted(new_paths - old_paths), "removed": sorted(old_paths - new_paths)}
        logger.info("CanaryWatcher recarregado: %d isca(s) (+%d, -%d).",
                    len(new), len(diff["added"]), len(diff["removed"]))
        return diff

    def stop(self) -> None:
        if self._observer and self._observer.is_alive():
            self._observer.stop()
            self._observer.join(timeout=5)

    @property
    def is_running(self) -> bool:
        return bool(self._observer and self._observer.is_alive())

    @property
    def paths(self) -> list[str]:
        return sorted(self._canaries.values())

    def status(self) -> dict:
        return {"running": self.is_running, "canaries": self.paths}

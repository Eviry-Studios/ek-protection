"""
ekprotection.monitor.fs_watcher
=================================
Observador de sistema de arquivos baseado em watchdog.

Usa inotify no Linux (via watchdog.observers.inotify) com fallback
para polling caso o inotify não esteja disponível (ex: tmpfs remoto,
sistemas de arquivos sem suporte).

Responsabilidades:
  - Observar múltiplos diretórios configurados
  - Filtrar eventos por padrão de exclusão (glob)
  - Normalizar eventos watchdog → FileEvent
  - Empurrar FileEvent para uma asyncio.Queue thread-safe
  - Suporte a parar e reiniciar de forma limpa
"""

from __future__ import annotations

import asyncio
import fnmatch
import logging
import os
import stat as stat_mod
import warnings
from pathlib import Path
from typing import Callable, Optional

from watchdog.events import (
    FileClosedEvent,
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileMovedEvent,
    FileSystemEvent,
    FileSystemEventHandler,
)
from watchdog.observers import Observer

from .events import FileEvent, FileEventKind

logger = logging.getLogger(__name__)

# Extensões que nunca interessam ao monitor (reduz ruído)
_BORING_EXTENSIONS = {
    ".pyc", ".pyo", ".swp", ".swo", ".swn",
    ".lock", ".pid", ".sock",
    ".log",   # logs são monitorados via LogManager, não via filesystem
}


class _EKPEventHandler(FileSystemEventHandler):
    """
    Handler watchdog que converte eventos raw em FileEvent
    e os coloca numa asyncio.Queue.

    Como o watchdog roda em thread separada, usamos
    loop.call_soon_threadsafe para enfileirar de forma segura.
    """

    def __init__(
        self,
        queue:      asyncio.Queue,
        loop:       asyncio.AbstractEventLoop,
        ignores:    list[str],
        path_remap: Optional[dict[str, str]] = None,
    ) -> None:
        super().__init__()
        self._queue      = queue
        self._loop       = loop
        self._ignores    = ignores   # padrões glob
        # resolved (real) prefix -> prefixo configurado originalmente
        # (ver FSWatcher.start() para o porquê)
        self._path_remap = path_remap or {}

    # ------------------------------------------------------------------
    # Handlers watchdog
    # ------------------------------------------------------------------

    def on_created(self, event: FileSystemEvent) -> None:
        self._push(event.src_path, FileEventKind.CREATED, event.is_directory)

    def on_modified(self, event: FileSystemEvent) -> None:
        self._push(event.src_path, FileEventKind.MODIFIED, event.is_directory)

    def on_attrib(self, event: FileSystemEvent) -> None:
        # watchdog >= 7 entrega IN_ATTRIB (chmod/chown/utime) como
        # FileAttribEvent -> on_attrib. No 6.x o mesmo IN_ATTRIB chegava como
        # FileModifiedEvent -> on_modified. Sem este handler, na VPS (7.1.0) um
        # `chmod +x` depois da escrita (curl -o x && chmod +x x) não gerava
        # re-scan e o H021 ficava cego (2026-11-23). Mantém a semântica do 6.x:
        # vira MODIFIED, que já é o caminho do re-scan pós-chmod (2026-10-27).
        # No watchdog 6 este método nunca é chamado.
        self._push(event.src_path, FileEventKind.MODIFIED, event.is_directory)

    def on_closed(self, event: FileSystemEvent) -> None:
        # IN_CLOSE_WRITE. No IN_CREATE o arquivo ainda está vazio ou pela
        # metade (download lento era escaneado com 1/4 do conteúdo, medido
        # 2026-10-26); é aqui que o conteúdo final existe.
        self._push(event.src_path, FileEventKind.CLOSED, event.is_directory)

    def on_deleted(self, event: FileSystemEvent) -> None:
        self._push(event.src_path, FileEventKind.DELETED, event.is_directory)

    def on_moved(self, event: FileMovedEvent) -> None:  # type: ignore[override]
        self._push(
            event.dest_path,
            FileEventKind.MOVED,
            event.is_directory,
            src_path=event.src_path,
        )

    def _unresolve(self, path: str) -> str:
        """
        Reescreve um path resolvido (real) de volta pro prefixo configurado
        originalmente pelo usuário em ``monitor.paths``.

        Necessário porque ``FSWatcher.start()`` agenda o watch usando o path
        *resolvido* (senão o inotify nunca vê nada dentro de um diretório
        raiz que seja symlink — ver comentário lá). Sem isso, todo o resto do
        sistema (heurística ``std_dirs``, logs, exceptions) passaria a
        enxergar o path real (ex: ``/var/opt/...``) em vez do configurado
        (ex: ``/opt/...``), quebrando comparações de prefixo silenciosamente.
        """
        for resolved_prefix, original_prefix in self._path_remap.items():
            if path == resolved_prefix or path.startswith(resolved_prefix + os.sep):
                return original_prefix + path[len(resolved_prefix):]
        return path

    # ------------------------------------------------------------------
    # Lógica interna
    # ------------------------------------------------------------------

    def _push(
        self,
        path:     str,
        kind:     FileEventKind,
        is_dir:   bool,
        src_path: Optional[str] = None,
    ) -> None:
        """Filtra e enfileira o evento de forma thread-safe."""
        if is_dir:
            return   # diretórios: só eventos de arquivo nos interessam

        path = self._unresolve(path)
        if src_path is not None:
            src_path = self._unresolve(src_path)

        if self._should_ignore(path):
            return

        size: Optional[int] = None
        uid:  Optional[int] = None
        mode: Optional[int] = None

        if kind != FileEventKind.DELETED:
            try:
                st = os.stat(path)
                size = st.st_size
                uid  = st.st_uid
                mode = st.st_mode
            except (OSError, FileNotFoundError):
                pass

        ev = FileEvent(
            kind     = kind,
            path     = path,
            is_dir   = is_dir,
            src_path = src_path,
            size     = size,
            uid      = uid,
            mode     = mode,
        )
        self._loop.call_soon_threadsafe(self._queue.put_nowait, ev)

    def _should_ignore(self, path: str) -> bool:
        name = Path(path).name
        ext  = Path(path).suffix.lower()

        if ext in _BORING_EXTENSIONS:
            return True

        for pattern in self._ignores:
            if fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(name, pattern):
                return True

        return False


# watchdog >= 7 (inotify): quando um diretório novo aparece numa raiz recursiva,
# o InotifyWatchGroup registra a árvore inteira (os.walk) e depois registra de
# novo cada subdiretório quando o IN_CREATE dele chega. O id do callback é o do
# próprio grupo, então ele só é sobrescrito pelo mesmo callback (inofensivo),
# mas o watchdog emite um RuntimeWarning cujo texto inclui o repr de TODOS os
# watches do grupo: na VPS (~1500 watches em /tmp) cada aviso virava uma linha
# de ~48 KB no journal (o limite de linha do journald), 110 vezes em 5 dias
# (EKP-MON #441, semana 1). O filtro é estreito: só essa mensagem, só RuntimeWarning,
# só vindo de módulo do watchdog. Qualquer outro aviso continua aparecendo.
_DUP_CALLBACK_WARNING_RE = r"Callback with id .* already exists for watch"
_WATCHDOG_MODULE_RE = r"watchdog(\..*)?$"


def _install_watchdog_dup_callback_filter() -> None:
    """Silencia o RuntimeWarning benigno de callback duplicado do watchdog 7.x.

    Idempotente sem flag de módulo: confere se o filtro já está em
    ``warnings.filters`` (um ``catch_warnings`` pode ter restaurado a lista
    e apagado o filtro; ``filterwarnings`` empilharia duplicata a cada start).
    """
    for action, msg, cat, mod, _lineno in warnings.filters:
        if (action == "ignore" and cat is RuntimeWarning
                and msg is not None and msg.pattern == _DUP_CALLBACK_WARNING_RE
                and mod is not None and mod.pattern == _WATCHDOG_MODULE_RE):
            return
    warnings.filterwarnings(
        "ignore",
        message=_DUP_CALLBACK_WARNING_RE,
        category=RuntimeWarning,
        module=_WATCHDOG_MODULE_RE,
    )


class FSWatcher:
    """
    Observador de filesystem para o EK-Protection.

    Uso:
        watcher = FSWatcher(paths=["/home", "/tmp"], queue=event_queue, loop=loop)
        watcher.start()
        ...
        watcher.stop()
    """

    def __init__(
        self,
        paths:      list[str],
        queue:      asyncio.Queue,
        loop:       asyncio.AbstractEventLoop,
        recursive:  bool       = True,
        ignores:    list[str]  = None,
    ) -> None:
        self._paths     = paths
        self._queue     = queue
        self._loop      = loop
        self._recursive = recursive
        self._ignores   = ignores or []
        self._observer: Optional[Observer] = None
        self._active_paths: list[str] = []
        self._handler: Optional[_EKPEventHandler] = None

    # ------------------------------------------------------------------
    # Ciclo de vida
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Inicia o Observer e agenda todos os paths configurados."""
        _install_watchdog_dup_callback_filter()
        self._observer = self._create_observer()

        # inotify (watchdog usa IN_DONT_FOLLOW por padrão) não segue symlink
        # na *raiz* watcheada — se o path configurado for (ou passar por) um
        # symlink de diretório (ex: /opt -> /var/opt em sistemas atômicos),
        # o watch "ativa" sem erro mas nunca recebe nenhum evento de dentro
        # dele, silenciosamente. Por isso agendamos o watch no path
        # *resolvido*, e guardamos o mapeamento resolvido->configurado pra
        # reescrever os paths dos eventos de volta (ver
        # _EKPEventHandler._unresolve) — assim o resto do sistema (heurística
        # std_dirs, logs, exceptions) continua vendo o path que o usuário
        # configurou, não o real.
        path_remap: dict[str, str] = {}
        for raw_path in self._paths:
            path = Path(raw_path)
            if not path.exists():
                continue
            resolved = path.resolve()
            if str(resolved) != str(path):
                path_remap[str(resolved)] = str(path)

        handler = _EKPEventHandler(self._queue, self._loop, self._ignores, path_remap)
        self._handler = handler

        for raw_path in self._paths:
            path = Path(raw_path)
            if not path.exists():
                logger.warning("Path de monitoramento não existe (ignorado): %s", path)
                continue
            watch_path = path.resolve()
            if str(watch_path) != str(path):
                logger.info(
                    "Path de monitoramento %s é/contém symlink, watch real em %s",
                    path, watch_path,
                )
            try:
                self._observer.schedule(handler, str(watch_path), recursive=self._recursive)
                self._active_paths.append(str(path))
                logger.info("Monitorando: %s (recursivo=%s)", path, self._recursive)
            except (OSError, PermissionError) as exc:
                logger.error("Não foi possível monitorar %s: %s", path, exc)

        self._observer.start()
        logger.info(
            "FSWatcher iniciado. %d/%d paths ativos.",
            len(self._active_paths), len(self._paths),
        )

    def stop(self) -> None:
        """Para o Observer de forma limpa."""
        if self._observer and self._observer.is_alive():
            self._observer.stop()
            self._observer.join(timeout=5)
            logger.info("FSWatcher encerrado.")

    @property
    def is_running(self) -> bool:
        return bool(self._observer and self._observer.is_alive())

    @property
    def active_paths(self) -> list[str]:
        return list(self._active_paths)

    def sweep_since(self, since: float, max_entries: int = 50_000) -> tuple[list[str], bool]:
        """Arquivos regulares nos paths ativos com ctime >= ``since``.

        Usado depois de um overflow da fila (2026-11-17): eventos que caíram
        não foram auto-escaneados, e um flood de arquivos inofensivos pode ser
        cortina pra um binário malicioso. ctime (não mtime) porque mtime é
        forjável com ``touch -d``. Não segue symlink, respeita os mesmos
        ignores do handler e devolve paths no prefixo configurado.
        Retorna (paths, truncado) — truncado se passou de ``max_entries``
        entradas visitadas.
        """
        found: list[str] = []
        visited = 0
        for raw in self._active_paths:
            root = Path(raw).resolve()
            stack = [str(root)]
            while stack:
                d = stack.pop()
                try:
                    it = os.scandir(d)
                except OSError:
                    continue
                with it:
                    for entry in it:
                        visited += 1
                        if visited > max_entries:
                            return found, True
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                if self._recursive:
                                    stack.append(entry.path)
                                continue
                            if not entry.is_file(follow_symlinks=False):
                                continue
                            st = entry.stat(follow_symlinks=False)
                        except OSError:
                            continue
                        if st.st_ctime < since:
                            continue
                        path = entry.path
                        if self._handler is not None:
                            path = self._handler._unresolve(path)
                            if self._handler._should_ignore(path):
                                continue
                        found.append(path)
        return found, False

    def status(self) -> dict:
        return {
            "running":      self.is_running,
            "active_paths": self._active_paths,
            "total_paths":  len(self._paths),
            "recursive":    self._recursive,
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _create_observer() -> Observer:
        """
        Tenta usar InotifyObserver no Linux para eficiência máxima.
        Fallback para PollingObserver em outros sistemas.
        """
        try:
            from watchdog.observers.inotify import InotifyObserver
            logger.debug("Usando InotifyObserver (inotify nativo).")
            return InotifyObserver()
        except (ImportError, AttributeError):
            logger.debug("InotifyObserver indisponível, usando PollingObserver.")
            return Observer()

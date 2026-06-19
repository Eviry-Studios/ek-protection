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
        queue:   asyncio.Queue,
        loop:    asyncio.AbstractEventLoop,
        ignores: list[str],
    ) -> None:
        super().__init__()
        self._queue   = queue
        self._loop    = loop
        self._ignores = ignores   # padrões glob

    # ------------------------------------------------------------------
    # Handlers watchdog
    # ------------------------------------------------------------------

    def on_created(self, event: FileSystemEvent) -> None:
        self._push(event.src_path, FileEventKind.CREATED, event.is_directory)

    def on_modified(self, event: FileSystemEvent) -> None:
        self._push(event.src_path, FileEventKind.MODIFIED, event.is_directory)

    def on_deleted(self, event: FileSystemEvent) -> None:
        self._push(event.src_path, FileEventKind.DELETED, event.is_directory)

    def on_moved(self, event: FileMovedEvent) -> None:  # type: ignore[override]
        self._push(
            event.dest_path,
            FileEventKind.MOVED,
            event.is_directory,
            src_path=event.src_path,
        )

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

    # ------------------------------------------------------------------
    # Ciclo de vida
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Inicia o Observer e agenda todos os paths configurados."""
        self._observer = self._create_observer()
        handler = _EKPEventHandler(self._queue, self._loop, self._ignores)

        for raw_path in self._paths:
            path = Path(raw_path)
            if not path.exists():
                logger.warning("Path de monitoramento não existe (ignorado): %s", path)
                continue
            try:
                self._observer.schedule(handler, str(path), recursive=self._recursive)
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

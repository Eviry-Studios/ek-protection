"""
ekprotection.monitor.manager
==============================
Gerenciador central do subsistema de monitoramento.

Orquestra:
  - FSWatcher  — eventos de filesystem (inotify)
  - ProcWatcher — eventos de processo (psutil polling)
  - Fila assíncrona de eventos (asyncio.Queue)
  - Loop de despacho de eventos → callbacks registrados
  - Logging de todos os eventos relevantes
  - Integração com o sistema de logs (LogManager)

Arquitetura de eventos:
  FSWatcher (thread)  ──►┐
                         ├──► asyncio.Queue ──► _dispatch_loop ──► callbacks
  ProcWatcher (task)  ──►┘

Callbacks registrados por outros subsistemas (scanner, heuristics, alerts)
recebem MonitorEvent e podem retornar corrotinas.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable, Callable, Optional

from ekprotection.config.manager import ConfigManager
from ekprotection.logs.models import EventType, LogLevel

from .events import (
    FileEvent, FileEventKind,
    ProcessEvent, ProcEventKind,
    MonitorEvent,
)
from .fs_watcher   import FSWatcher
from .proc_watcher import ProcWatcher

logger = logging.getLogger(__name__)

# Tipo de callback: pode ser sync ou async
EventCallback = Callable[[MonitorEvent], Optional[Awaitable[None]]]

# Tamanho máximo da fila — descarta eventos se cheia (evita consumo de memória)
_QUEUE_MAXSIZE = 2048


class MonitorManager:
    """
    Gerenciador de monitoramento em tempo real.

    Uso:
        monitor = MonitorManager(config, log_manager)
        await monitor.start()
        monitor.add_callback(meu_handler)
        ...
        await monitor.stop()
    """

    def __init__(
        self,
        config:      ConfigManager,
        log_manager: Any = None,   # LogManager opcional (evita circular import)
    ) -> None:
        self.config      = config
        self._log        = log_manager
        self._queue:     asyncio.Queue = asyncio.Queue(maxsize=_QUEUE_MAXSIZE)
        self._callbacks: list[EventCallback] = []
        self._fs_watcher:   Optional[FSWatcher]   = None
        self._proc_watcher: Optional[ProcWatcher] = None
        self._dispatch_task: Optional[asyncio.Task] = None
        self._proc_task:     Optional[asyncio.Task] = None
        self._running = False

        # Contadores para status
        self._counters: dict[str, int] = {
            "file_created":   0,
            "file_modified":  0,
            "file_deleted":   0,
            "file_moved":     0,
            "proc_new":       0,
            "proc_suspicious":0,
            "dropped":        0,
        }

    # ------------------------------------------------------------------
    # Ciclo de vida
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Inicia FSWatcher, ProcWatcher e o loop de despacho."""
        if self._running:
            return

        self._running = True
        loop = asyncio.get_running_loop()

        # --- FSWatcher ---
        fs_enabled = self.config.get("monitor.enabled", True)
        if fs_enabled:
            paths     = self.config.get("monitor.paths", [])
            recursive = self.config.get("monitor.recursive", True)
            ignores   = self.config.get("monitor.ignore_patterns", [])

            self._fs_watcher = FSWatcher(
                paths     = paths,
                queue     = self._queue,
                loop      = loop,
                recursive = recursive,
                ignores   = ignores,
            )
            self._fs_watcher.start()

        # --- ProcWatcher ---
        proc_enabled = self.config.get("monitor.enabled", True)
        if proc_enabled:
            interval = self.config.get("monitor.poll_interval_ms", 500) / 1000 * 10
            # poll_interval_ms é para fs; processos usam intervalo maior (5s padrão)
            self._proc_watcher = ProcWatcher(
                queue    = self._queue,
                interval = 5.0,
            )
            self._proc_task = asyncio.create_task(
                self._proc_watcher.run(),
                name="ekp-proc-watcher",
            )

        # --- Loop de despacho ---
        self._dispatch_task = asyncio.create_task(
            self._dispatch_loop(),
            name="ekp-monitor-dispatch",
        )

        logger.info("MonitorManager iniciado.")
        self._log_event(EventType.SYSTEM_START, "Monitor em tempo real iniciado.", LogLevel.INFO)

    async def stop(self) -> None:
        """Para todos os watchers e o loop de despacho de forma limpa."""
        if not self._running:
            return

        self._running = False

        # Para proc watcher
        if self._proc_watcher:
            self._proc_watcher.stop()
        if self._proc_task and not self._proc_task.done():
            self._proc_task.cancel()
            try:
                await self._proc_task
            except asyncio.CancelledError:
                pass

        # Para fs watcher (thread)
        if self._fs_watcher:
            self._fs_watcher.stop()

        # Para dispatch loop
        if self._dispatch_task and not self._dispatch_task.done():
            self._dispatch_task.cancel()
            try:
                await self._dispatch_task
            except asyncio.CancelledError:
                pass

        logger.info("MonitorManager encerrado.")

    # ------------------------------------------------------------------
    # Registro de callbacks
    # ------------------------------------------------------------------

    def add_callback(self, cb: EventCallback) -> None:
        """
        Registra callback a ser chamado para cada evento.
        Patches futuros (scanner, heuristics, alerts) usam isso.
        """
        self._callbacks.append(cb)

    def remove_callback(self, cb: EventCallback) -> None:
        self._callbacks = [c for c in self._callbacks if c is not cb]

    # ------------------------------------------------------------------
    # Loop de despacho
    # ------------------------------------------------------------------

    async def _dispatch_loop(self) -> None:
        """
        Consome eventos da fila e os despacha para todos os callbacks.
        Roda como asyncio.Task — não bloqueia o event loop.
        """
        logger.debug("Dispatch loop iniciado.")
        while self._running:
            try:
                event: MonitorEvent = await asyncio.wait_for(
                    self._queue.get(), timeout=1.0
                )
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

            self._update_counters(event)
            self._log_event_from(event)

            for cb in list(self._callbacks):
                try:
                    result = cb(event)
                    if asyncio.iscoroutine(result):
                        await result
                except Exception as exc:
                    logger.error("Erro em callback de monitor: %s", exc)

            self._queue.task_done()

        logger.debug("Dispatch loop encerrado.")

    # ------------------------------------------------------------------
    # Logging de eventos
    # ------------------------------------------------------------------

    def _log_event_from(self, event: MonitorEvent) -> None:
        """Grava evento de monitoramento nos logs estruturados."""
        if isinstance(event, FileEvent):
            kind_map = {
                FileEventKind.CREATED:  (EventType.FILE_CREATED,  LogLevel.DEBUG),
                FileEventKind.MODIFIED: (EventType.FILE_MODIFIED, LogLevel.DEBUG),
                FileEventKind.DELETED:  (EventType.FILE_DELETED,  LogLevel.DEBUG),
                FileEventKind.MOVED:    (EventType.FILE_MODIFIED, LogLevel.DEBUG),
                FileEventKind.EXECUTED: (EventType.FILE_EXECUTED, LogLevel.INFO),
            }
            etype, level = kind_map.get(event.kind, (EventType.GENERIC, LogLevel.DEBUG))
            msg = f"[{event.kind.name}] {event.path}"
            self._log_event(etype, msg, level, file_path=event.path)

        elif isinstance(event, ProcessEvent):
            if event.kind == ProcEventKind.SUSPICIOUS:
                self._log_event(
                    EventType.PROC_SUSPICIOUS,
                    f"Processo suspeito: {event.name} (PID {event.pid}) — {event.reason}",
                    LogLevel.WARNING,
                    process=event.name,
                )
            # NEW e TERMINATED: apenas debug, muito verboso para INFO
            elif event.kind == ProcEventKind.NEW:
                logger.debug("Processo novo: %s (PID %d)", event.name, event.pid)
            elif event.kind == ProcEventKind.TERMINATED:
                logger.debug("Processo encerrado: %s (PID %d)", event.name, event.pid)

    def _log_event(
        self,
        etype:     EventType,
        message:   str,
        level:     LogLevel,
        **kwargs:  Any,
    ) -> None:
        if self._log is None:
            return
        try:
            self._log.get_source("monitor").event(etype, message, level=level, **kwargs)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Contadores e status
    # ------------------------------------------------------------------

    def _update_counters(self, event: MonitorEvent) -> None:
        if isinstance(event, FileEvent):
            key = {
                FileEventKind.CREATED:  "file_created",
                FileEventKind.MODIFIED: "file_modified",
                FileEventKind.DELETED:  "file_deleted",
                FileEventKind.MOVED:    "file_moved",
                FileEventKind.EXECUTED: "file_created",
            }.get(event.kind)
            if key:
                self._counters[key] = self._counters.get(key, 0) + 1
        elif isinstance(event, ProcessEvent):
            if event.kind == ProcEventKind.NEW:
                self._counters["proc_new"] += 1
            elif event.kind == ProcEventKind.SUSPICIOUS:
                self._counters["proc_suspicious"] += 1

    def status(self) -> dict:
        result: dict[str, Any] = {
            "running":  self._running,
            "counters": dict(self._counters),
            "queue_size": self._queue.qsize(),
        }
        if self._fs_watcher:
            result["fs_watcher"] = self._fs_watcher.status()
        if self._proc_watcher:
            result["proc_watcher"] = self._proc_watcher.status()
        return result

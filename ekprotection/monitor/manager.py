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
  CanaryWatcher (thread) ──► fila própria ──► _canary_loop ──► log CRITICAL + callbacks

As iscas têm fila e loop próprios: na fila comum o alerta esperava atrás de
todo o backlog de FS/auto-scan, e um flood em /tmp (qualquer usuário) atrasava
o alerta em ~1 min ou fazia ele sumir com a fila cheia (2026-11-16).

Callbacks registrados por outros subsistemas (scanner, heuristics, alerts)
recebem MonitorEvent e podem retornar corrotinas.
"""

from __future__ import annotations

import asyncio
import logging
import os
import stat as stat_mod
import time
from collections import OrderedDict
from typing import Any, Awaitable, Callable, Optional

from ekprotection.config.manager import ConfigManager
from ekprotection.logs.models import EventType, LogLevel

from .events import (
    FileEvent, FileEventKind,
    ProcessEvent, ProcEventKind,
    MonitorEvent,
)
from .canary       import CanaryWatcher
from .fs_watcher   import FSWatcher
from .proc_watcher import ProcWatcher

logger = logging.getLogger(__name__)

# Tipo de callback: pode ser sync ou async
EventCallback = Callable[[MonitorEvent], Optional[Awaitable[None]]]

# Tamanho máximo da fila — descarta eventos se cheia (evita consumo de memória)
_QUEUE_MAXSIZE = 2048
# Iscas: cooldown de 60s por isca, então isso nunca enche na prática.
_CANARY_QUEUE_MAXSIZE = 256
# Aviso de fila cheia no máximo 1x a cada N segundos (o flood não vira flood de log).
_DROP_WARN_INTERVAL_S = 60.0
# Recuperação pós-overflow (2026-11-17): paths que caíram ficam guardados (um
# por path, coalescido) e voltam pra fila quando ela esvazia. Passou disso,
# vira varredura dos monitor.paths por ctime desde o 1º descarte.
_PENDING_MAX = 4096
_SWEEP_MAX_ENTRIES = 50_000
# Margem do ctime: o evento chega na fila um pouco depois do arquivo existir.
_SWEEP_MARGIN_S = 5.0


class _DropCountingQueue(asyncio.Queue):
    """asyncio.Queue cujo put_nowait não estoura QueueFull: conta e avisa.

    Os watchers rodam em thread e empurram com
    `loop.call_soon_threadsafe(queue.put_nowait, ev)`. Com a fila cheia o
    QueueFull estourava dentro do callback do loop, ia só pro "Exception in
    callback" do asyncio e o evento sumia sem passar pelo contador `dropped`
    (que ficava 0). `await put()` segue com backpressure normal (só chama
    put_nowait depois que há espaço).
    """

    def __init__(self, maxsize: int, on_drop: Callable[[Any], None]) -> None:
        super().__init__(maxsize=maxsize)
        self._on_drop = on_drop

    def put_nowait(self, item: Any) -> None:
        try:
            super().put_nowait(item)
        except asyncio.QueueFull:
            self._on_drop(item)


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
        self._queue: asyncio.Queue = _DropCountingQueue(_QUEUE_MAXSIZE, self._on_drop)
        self._canary_queue: asyncio.Queue = _DropCountingQueue(
            _CANARY_QUEUE_MAXSIZE, self._on_canary_drop)
        self._canary_task:   Optional[asyncio.Task] = None
        self._drops_unreported = 0
        self._last_drop_warn: Optional[float] = None
        self._clock: Callable[[], float] = time.monotonic
        self._pending: "OrderedDict[str, None]" = OrderedDict()
        self._sweep_needed = False
        self._overflow_since: Optional[float] = None
        self._callbacks: list[EventCallback] = []
        self._fs_watcher:   Optional[FSWatcher]   = None
        self._canary:       Optional[CanaryWatcher] = None
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
            "canary_accessed":0,
            "dropped":        0,
            "canary_dropped": 0,
            "recovered":      0,
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

            canaries = self.config.get("monitor.canary_paths", [])
            if canaries:
                self._canary = CanaryWatcher(canaries, self._canary_queue, loop)
                try:
                    self._canary.start()
                except Exception as exc:
                    logger.error("Erro ao iniciar CanaryWatcher: %s", exc)

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

        # --- Loops de despacho (iscas separadas, ver docstring do módulo) ---
        self._dispatch_task = asyncio.create_task(
            self._dispatch_loop(),
            name="ekp-monitor-dispatch",
        )
        self._canary_task = asyncio.create_task(
            self._dispatch_loop(self._canary_queue),
            name="ekp-monitor-canary",
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
        if self._canary:
            self._canary.stop()

        # Para dispatch loops
        for task in (self._dispatch_task, self._canary_task):
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        logger.info("MonitorManager encerrado.")

    def reload_canaries(self, paths: list[str]) -> dict[str, list[str]]:
        """Aplica nova lista de iscas no watcher que já está rodando."""
        if not self._running or not self.config.get("monitor.enabled", True):
            return {"added": [], "removed": []}
        if self._canary is None:
            self._canary = CanaryWatcher([], self._canary_queue, asyncio.get_running_loop())
        return self._canary.update(paths or [])

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

    async def _dispatch_loop(self, queue: Optional[asyncio.Queue] = None) -> None:
        """
        Consome eventos da fila e os despacha para todos os callbacks.
        Roda como asyncio.Task — não bloqueia o event loop. Uma instância
        pra fila comum e outra pra fila das iscas.
        """
        queue = self._queue if queue is None else queue
        logger.debug("Dispatch loop iniciado.")
        while self._running:
            if (queue is self._queue and queue.qsize() == 0
                    and (self._pending or self._sweep_needed)):
                try:
                    await self._recover_overflow()
                except Exception as exc:
                    logger.error("Erro na recuperação pós-overflow: %s", exc)
            try:
                event: MonitorEvent = await asyncio.wait_for(
                    queue.get(), timeout=1.0
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

            queue.task_done()

        logger.debug("Dispatch loop encerrado.")

    # ------------------------------------------------------------------
    # Fila cheia
    # ------------------------------------------------------------------

    def _on_drop(self, event: Any) -> None:
        """Evento que não coube na fila comum. Roda no thread do loop."""
        self._counters["dropped"] += 1
        if self._overflow_since is None:
            self._overflow_since = time.time() - _SWEEP_MARGIN_S
        if (isinstance(event, FileEvent) and not event.is_dir
                and event.kind != FileEventKind.DELETED):
            if event.path in self._pending or len(self._pending) < _PENDING_MAX:
                self._pending[event.path] = None
            else:
                self._sweep_needed = True
        self._drops_unreported += 1
        now = self._clock()
        if (self._last_drop_warn is not None
                and now - self._last_drop_warn < _DROP_WARN_INTERVAL_S):
            return
        self._last_drop_warn = now
        n, self._drops_unreported = self._drops_unreported, 0
        msg = (f"Fila do monitor cheia ({_QUEUE_MAXSIZE}): {n} evento(s) descartado(s) "
               f"(total {self._counters['dropped']}). Arquivos criados nesse intervalo "
               "não foram auto-escaneados. Flood de arquivos pode ser tentativa de cegar o monitor.")
        logger.warning(msg)
        self._log_event(EventType.MONITOR_OVERFLOW, msg, LogLevel.WARNING)

    @staticmethod
    def _recovery_events(paths: list[str]) -> list[FileEvent]:
        """FileEvent CLOSED pros paths que ainda existem como arquivo regular.
        Roda no executor (stat de milhares de paths)."""
        out: list[FileEvent] = []
        for path in paths:
            try:
                st = os.lstat(path)
            except OSError:
                continue
            if not stat_mod.S_ISREG(st.st_mode):
                continue
            out.append(FileEvent(
                kind=FileEventKind.CLOSED, path=path, size=st.st_size,
                uid=st.st_uid, mode=st.st_mode, detail="overflow-recovery",
            ))
        return out

    async def _recover_overflow(self) -> None:
        """Fila comum esvaziou depois de um overflow: devolve pra ela os
        arquivos cujo evento caiu, pra passarem pelo auto-scan. Sem isso um
        binário escondido num flood de 20 mil arquivos inofensivos nunca era
        escaneado (só contado, 2026-11-16)."""
        loop = asyncio.get_running_loop()
        since = self._overflow_since
        sweep = self._sweep_needed
        paths = list(self._pending)
        self._pending.clear()
        self._sweep_needed = False
        self._overflow_since = None

        truncated = False
        if sweep and self._fs_watcher is not None and since is not None:
            swept, truncated = await loop.run_in_executor(
                None, self._fs_watcher.sweep_since, since, _SWEEP_MAX_ENTRIES)
            paths = list(dict.fromkeys(paths + swept))

        events = await loop.run_in_executor(None, self._recovery_events, paths)
        queued = 0
        for i, ev in enumerate(events):
            if self._queue.full():
                # Não descarta de novo: o resto volta pro pendente e sai na
                # próxima vez que a fila esvaziar.
                for rest in events[i:]:
                    self._pending[rest.path] = None
                if self._overflow_since is None:
                    self._overflow_since = since
                break
            self._queue.put_nowait(ev)
            queued += 1
        self._counters["recovered"] += queued

        msg = (f"Recuperação pós-overflow: {queued} arquivo(s) reenfileirado(s) pro "
               f"auto-scan ({len(paths)} candidato(s)"
               f"{', com varredura dos monitor.paths' if sweep else ''}).")
        if truncated:
            msg += (f" Varredura TRUNCADA em {_SWEEP_MAX_ENTRIES} entradas: rode "
                    "`ekp scan` nos monitor.paths.")
            logger.warning(msg)
            self._log_event(EventType.MONITOR_OVERFLOW, msg, LogLevel.WARNING)
        else:
            logger.info(msg)
            self._log_event(EventType.MONITOR_OVERFLOW, msg, LogLevel.INFO)

    def _on_canary_drop(self, event: Any) -> None:
        self._counters["canary_dropped"] += 1
        path = getattr(event, "path", "?")
        msg = f"Alerta de arquivo-isca PERDIDO (fila das iscas cheia): {path}"
        logger.critical(msg)
        self._log_event(EventType.CANARY_ACCESSED, msg, LogLevel.CRITICAL, file_path=path)

    # ------------------------------------------------------------------
    # Logging de eventos
    # ------------------------------------------------------------------

    def _log_event_from(self, event: MonitorEvent) -> None:
        """Grava evento de monitoramento nos logs estruturados."""
        if isinstance(event, FileEvent) and event.kind == FileEventKind.ACCESSED:
            self._log_event(
                EventType.CANARY_ACCESSED,
                f"Arquivo-isca aberto: {event.path} — {event.detail}",
                LogLevel.CRITICAL,
                file_path=event.path,
            )
        elif isinstance(event, FileEvent):
            kind_map = {
                FileEventKind.CREATED:  (EventType.FILE_CREATED,  LogLevel.DEBUG),
                FileEventKind.MODIFIED: (EventType.FILE_MODIFIED, LogLevel.DEBUG),
                FileEventKind.DELETED:  (EventType.FILE_DELETED,  LogLevel.DEBUG),
                FileEventKind.MOVED:    (EventType.FILE_MODIFIED, LogLevel.DEBUG),
                FileEventKind.EXECUTED: (EventType.FILE_EXECUTED, LogLevel.INFO),
                FileEventKind.CLOSED:   (EventType.FILE_MODIFIED, LogLevel.DEBUG),
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
                FileEventKind.ACCESSED: "canary_accessed",
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
            "canary_queue_size": self._canary_queue.qsize(),
        }
        if self._fs_watcher:
            result["fs_watcher"] = self._fs_watcher.status()
        if self._proc_watcher:
            result["proc_watcher"] = self._proc_watcher.status()
        if self._canary:
            result["canary"] = self._canary.status()
        return result

"""
ekprotection.core.engine
=========================
Motor principal do EK-Protection.

Subsistemas ativos:
  Patch 1: engine skeleton
  Patch 2: auth  (AuthManager)
  Patch 3: logs  (LogManager)
  Patch 4: monitor (MonitorManager)
  Patch 5: exceptions (ExceptionManager)
  Patch 6+: quarantine, scanner, heuristics, updater...
"""

from __future__ import annotations

import asyncio
import logging
import signal
from enum import Enum, auto
from typing import Any

from ekprotection import __version__
from ekprotection.config.manager import ConfigManager

logger = logging.getLogger(__name__)


class EngineState(Enum):
    STOPPED  = auto()
    STARTING = auto()
    RUNNING  = auto()
    STOPPING = auto()
    ERROR    = auto()


class EKEngine:
    def __init__(self, config: ConfigManager) -> None:
        self.config = config
        self.state  = EngineState.STOPPED
        self._subsystems: dict[str, Any]     = {}
        self._tasks:      list[asyncio.Task] = []  # type: ignore[type-arg]
        self._stop_event: asyncio.Event | None = None

        # Referências rápidas
        self.auth:       Any = None
        self.logs:       Any = None
        self.monitor:    Any = None
        self.exceptions:  Any = None
        self.quarantine:  Any = None
        self.scanner:     Any = None
        self.heuristics:  Any = None
        self.updater:     Any = None

    # ------------------------------------------------------------------
    # Ciclo de vida
    # ------------------------------------------------------------------

    async def start(self) -> None:
        if self.state != EngineState.STOPPED:
            raise RuntimeError(f"Engine já está em estado {self.state.name}.")

        self.state = EngineState.STARTING
        logger.info("EK-Protection Engine iniciando...")

        self._stop_event = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, self._handle_signal)

        await self._init_logs()        # Patch 3
        await self._init_auth()        # Patch 2
        await self._init_exceptions()  # Patch 5
        await self._init_monitor()     # Patch 4

        await self._init_quarantine()     # Patch 6
        await self._init_scanner()     # Patch 7
        await self._init_heuristics()  # Patch 8
        await self._init_updater()     # Patch 9

        self.state = EngineState.RUNNING
        self._log_sys("SYSTEM_START", f"EK-Protection v0.5.0 iniciado. PID={self._get_pid()}")
        logger.info("EK-Protection Engine em execução. PID=%d", self._get_pid())

    async def stop(self) -> None:
        if self.state not in (EngineState.RUNNING, EngineState.STARTING):
            return
        self.state = EngineState.STOPPING
        self._log_sys("SYSTEM_STOP", "EK-Protection encerrando.")

        if self.monitor:
            try: await self.monitor.stop()
            except Exception as e: logger.warning("Erro ao parar monitor: %s", e)

        if self.exceptions:
            try: self.exceptions.close()
            except Exception: pass

        if self.updater:
            try: self.updater.stop()
            except Exception: pass

        if self.quarantine:
            try: self.quarantine.close()
            except Exception: pass

        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)

        if self.logs:
            try: self.logs.close()
            except Exception: pass

        if self._stop_event:
            self._stop_event.set()

        self.state = EngineState.STOPPED
        logger.info("EK-Protection Engine encerrado.")

    async def wait(self) -> None:
        if self._stop_event:
            await self._stop_event.wait()

    # ------------------------------------------------------------------
    # Inicializadores de subsistemas
    # ------------------------------------------------------------------

    async def _init_logs(self) -> None:
        from ekprotection.logs.manager import LogManager
        mgr = LogManager(self.config)
        try:
            mgr.open()
            self.logs = mgr
            self.register("logs", mgr)
        except Exception as exc:
            logger.warning("Logs persistentes indisponíveis: %s", exc)

    async def _init_auth(self) -> None:
        from ekprotection.auth.manager import AuthManager
        auth = AuthManager(self.config)
        self.auth = auth
        self.register("auth", auth)
        if not auth.is_configured:
            logger.warning("Autenticação não configurada. Execute: ekp auth setup")

    async def _init_exceptions(self) -> None:
        from ekprotection.exceptions.manager import ExceptionManager
        mgr = ExceptionManager(self.config, self.logs)
        try:
            mgr.open()
            self.exceptions = mgr
            self.register("exceptions", mgr)
            logger.info("ExceptionManager iniciado: %s", mgr.status())
        except Exception as exc:
            logger.error("Erro ao iniciar exceptions: %s", exc)

    async def _init_updater(self) -> None:
        from ekprotection.updater.manager import UpdateManager
        sig_db = self.get_subsystem("sig_db")
        mgr    = UpdateManager(self.config, sig_db=sig_db, log_manager=self.logs)
        mgr.initialize()
        self.updater = mgr
        self.register("updater", mgr)
        logger.debug("UpdateManager registrado.")

    async def _init_heuristics(self) -> None:
        from ekprotection.heuristics.engine import HeuristicEngine
        try:
            heur = HeuristicEngine(self.config, self.exceptions, self.logs)
            self.heuristics = heur
            self.register("heuristics", heur)
            logger.info("HeuristicEngine iniciado: %s", heur.status())
        except Exception as exc:
            logger.error("Erro ao iniciar heuristics: %s", exc)

    async def _init_scanner(self) -> None:
        from ekprotection.scanner.signatures import SignatureDB
        from ekprotection.scanner.engine     import ScanEngine
        import os

        sig_raw  = self.config.get("signatures.db_path",
                                   "/var/lib/ek-protection/signatures.db")
        data_dir = os.environ.get("EKP_DATA_DIR", "")
        if data_dir:
            sig_raw = sig_raw.replace("/var/lib/ek-protection", data_dir)

        try:
            sig_db = SignatureDB(sig_raw)
            sig_db.open()
            engine = ScanEngine(
                self.config,
                sig_db            = sig_db,
                exc_manager       = self.exceptions,
                quar_manager      = self.quarantine,
                log_manager       = self.logs,
                heuristic_engine  = self.heuristics,
            )
            self.scanner = engine
            self.register("scanner", engine)
            self.register("sig_db",  sig_db)
            logger.info("ScanEngine iniciado. Assinaturas: %d", sig_db.count())
        except Exception as exc:
            logger.error("Erro ao iniciar scanner: %s", exc)

    async def _init_quarantine(self) -> None:
        from ekprotection.quarantine.manager import QuarantineManager
        mgr = QuarantineManager(self.config, self.logs, self.auth)
        try:
            mgr.open()
            self.quarantine = mgr
            self.register("quarantine", mgr)
            logger.info("QuarantineManager iniciado.")
        except Exception as exc:
            logger.error("Erro ao iniciar quarantine: %s", exc)

    async def _init_monitor(self) -> None:
        from ekprotection.monitor.manager import MonitorManager
        mon = MonitorManager(self.config, self.logs)
        self.monitor = mon
        self.register("monitor", mon)
        try:
            await mon.start()
        except Exception as exc:
            logger.error("Erro ao iniciar monitor: %s", exc)

    # ------------------------------------------------------------------
    # Utilitários
    # ------------------------------------------------------------------

    def _log_sys(self, attr: str, msg: str) -> None:
        if not self.logs:
            return
        try:
            from ekprotection.logs.models import EventType, LogLevel
            etype = getattr(EventType, attr)
            self.logs.get_source("engine").event(etype, msg, level=LogLevel.INFO)
        except Exception:
            pass

    def register(self, name: str, subsystem: Any) -> None:
        self._subsystems[name] = subsystem
        logger.debug("Subsistema registrado: %s", name)

    def get_subsystem(self, name: str) -> Any:
        return self._subsystems.get(name)

    def _handle_signal(self) -> None:
        logger.info("Sinal de parada recebido.")
        if self._stop_event:
            self._stop_event.set()

    @staticmethod
    def _get_pid() -> int:
        import os
        return os.getpid()

    @property
    def is_running(self) -> bool:
        return self.state == EngineState.RUNNING

    def status(self) -> dict[str, Any]:
        s: dict[str, Any] = {
            "state":      self.state.name,
            "subsystems": list(self._subsystems.keys()),
            "pid":        self._get_pid(),
            "version":    __version__,
        }
        if self.auth:       s["auth"]       = self.auth.status()
        if self.logs:
            try:            s["logs"]       = self.logs.stats()
            except Exception: pass
        if self.monitor:    s["monitor"]    = self.monitor.status()
        if self.exceptions:  s["exceptions"]  = self.exceptions.status()
        if self.quarantine:
            try: s["quarantine"] = self.quarantine.stats()
            except Exception: pass
        if self.scanner:
            sig = self.get_subsystem('sig_db')
            s["scanner"] = {"signatures": sig.count() if sig else 0}
        if self.heuristics: s["heuristics"] = self.heuristics.status()
        if self.updater:    s["updater"]    = self.updater.status()
        return s

"""
ekprotection.logs.manager
==========================
Gerenciador de logs de alto nível do EK-Protection.

Centraliza:
  - API fluente de log (info/warning/error/critical/event)
  - Integração com o logging padrão do Python (handler customizado)
  - Arquivo de log rotacionado
  - Emissão para LogStore (SQLite + JSONL)
  - Interface para o subsistema de alertas
  - Acesso por outros módulos via get_logger()

Uso nos módulos internos:

    from ekprotection.logs import get_logger
    log = get_logger("scanner")
    log.event(EventType.SCAN_MATCH, "Ameaça detectada", file_path="/tmp/mal.sh", level=LogLevel.CRITICAL)

    # Ou simplesmente:
    log.warning("arquivo suspeito encontrado")
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from ekprotection.config.manager import ConfigManager
from .models import EventType, LogEntry, LogLevel, QueryFilter
from .store import LogStore

logger = logging.getLogger(__name__)

# Referência global para acesso de qualquer módulo
_global_log_manager: Optional["LogManager"] = None


def get_logger(source: str = "core") -> "SourceLogger":
    """
    Retorna um SourceLogger para o módulo chamador.
    Se o LogManager global não estiver inicializado, usa um fallback
    que grava apenas no logging padrão do Python.
    """
    if _global_log_manager is not None:
        return _global_log_manager.get_source(source)
    return _FallbackLogger(source)


def set_global(manager: "LogManager") -> None:
    """Registra o LogManager global (chamado pelo Engine)."""
    global _global_log_manager
    _global_log_manager = manager


# ---------------------------------------------------------------------------
# Handler Python logging → LogStore
# ---------------------------------------------------------------------------

class _StoreHandler(logging.Handler):
    """
    Handler que redireciona registros do logging padrão do Python
    para o LogStore do EK-Protection.
    """

    def __init__(self, store: LogStore, source: str = "python") -> None:
        super().__init__()
        self._store  = store
        self._source = source

    def emit(self, record: logging.LogRecord) -> None:
        try:
            level_map = {
                logging.DEBUG:    LogLevel.DEBUG,
                logging.INFO:     LogLevel.INFO,
                logging.WARNING:  LogLevel.WARNING,
                logging.ERROR:    LogLevel.ERROR,
                logging.CRITICAL: LogLevel.CRITICAL,
            }
            level = level_map.get(record.levelno, LogLevel.INFO)
            entry = LogEntry(
                level      = level,
                event_type = EventType.GENERIC,
                message    = self.format(record),
                source     = record.name,
                pid        = os.getpid(),
                timestamp  = datetime.utcfromtimestamp(record.created),
            )
            self._store.write(entry)
        except Exception:
            self.handleError(record)


# ---------------------------------------------------------------------------
# SourceLogger — API de log por módulo
# ---------------------------------------------------------------------------

class SourceLogger:
    """
    Logger vinculado a um módulo específico.
    Obtido via LogManager.get_source("nome") ou get_logger("nome").
    """

    def __init__(self, source: str, manager: "LogManager") -> None:
        self._source  = source
        self._manager = manager

    # Atalhos de nível
    def debug(self, message: str, **extra: Any) -> LogEntry:
        return self.event(EventType.GENERIC, message, level=LogLevel.DEBUG, **extra)

    def info(self, message: str, **extra: Any) -> LogEntry:
        return self.event(EventType.GENERIC, message, level=LogLevel.INFO, **extra)

    def warning(self, message: str, **extra: Any) -> LogEntry:
        return self.event(EventType.GENERIC, message, level=LogLevel.WARNING, **extra)

    def error(self, message: str, **extra: Any) -> LogEntry:
        return self.event(EventType.GENERIC, message, level=LogLevel.ERROR, **extra)

    def critical(self, message: str, **extra: Any) -> LogEntry:
        return self.event(EventType.GENERIC, message, level=LogLevel.CRITICAL, **extra)

    def event(
        self,
        event_type: EventType,
        message:    str,
        *,
        level:      LogLevel      = LogLevel.INFO,
        file_path:  Optional[str] = None,
        sha256:     Optional[str] = None,
        process:    Optional[str] = None,
        **extra:    Any,
    ) -> LogEntry:
        """
        Grava um evento tipado com metadados completos.
        É o método mais importante — todos os outros são atalhos para este.
        """
        entry = LogEntry(
            level      = level,
            event_type = event_type,
            message    = message,
            source     = self._source,
            pid        = os.getpid(),
            file_path  = file_path,
            sha256     = sha256,
            process    = process,
            extra      = extra if extra else {},
        )
        return self._manager._write(entry)


class _FallbackLogger(SourceLogger):
    """
    Logger de fallback usado quando o LogManager ainda não foi iniciado.
    Delega ao logging padrão do Python sem persistir no SQLite.
    """

    def __init__(self, source: str) -> None:
        self._source  = source
        self._manager = None  # type: ignore[assignment]
        self._py_log  = logging.getLogger(source)

    def event(self, event_type: EventType, message: str, *, level: LogLevel = LogLevel.INFO, **kw: Any) -> LogEntry:  # type: ignore[override]
        log_fn = {
            LogLevel.DEBUG:    self._py_log.debug,
            LogLevel.INFO:     self._py_log.info,
            LogLevel.WARNING:  self._py_log.warning,
            LogLevel.ERROR:    self._py_log.error,
            LogLevel.CRITICAL: self._py_log.critical,
        }.get(level, self._py_log.info)
        log_fn("[%s] %s", event_type.value, message)
        return LogEntry(level=level, event_type=event_type, message=message, source=self._source)


# ---------------------------------------------------------------------------
# LogManager principal
# ---------------------------------------------------------------------------

class LogManager:
    """
    Gerenciador central de logs do EK-Protection.

    Inicializado pelo Engine; exposto globalmente via set_global().
    """

    def __init__(self, config: ConfigManager) -> None:
        self.config    = config
        self._store:   Optional[LogStore]   = None
        self._sources: dict[str, SourceLogger] = {}
        self._min_level = LogLevel.from_str(config.get("daemon.log_level", "INFO"))

    # ------------------------------------------------------------------
    # Ciclo de vida
    # ------------------------------------------------------------------

    def open(self) -> "LogManager":
        """Abre o LogStore e configura o handler de arquivo."""
        db_path   = self._resolve("logs.db_path",  "/var/lib/ek-protection/ek-protection.db")
        log_dir   = self._resolve("logs.dir",       "/var/log/ek-protection")
        max_mb    = self.config.get("logs.max_size_mb",   100)
        rotate_n  = self.config.get("logs.rotate_count",   5)
        structured = self.config.get("logs.structured",   True)

        jsonl_path = (log_dir / "ekp.jsonl") if structured else None

        self._store = LogStore(db_path, jsonl_path)
        self._store.open()

        # Configura arquivo de log rotacionado
        log_file = log_dir / "ekp.log"
        log_dir.mkdir(parents=True, exist_ok=True)

        file_handler = logging.handlers.RotatingFileHandler(
            filename    = str(log_file),
            maxBytes    = max_mb * 1024 * 1024,
            backupCount = rotate_n,
            encoding    = "utf-8",
        )
        file_handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))

        root_logger = logging.getLogger()
        root_logger.addHandler(file_handler)

        # Handler que espelha logging padrão → SQLite
        store_handler = _StoreHandler(self._store, source="python")
        store_handler.setLevel(logging.WARNING)  # só WARNING+ vai ao SQLite via este canal
        root_logger.addHandler(store_handler)

        set_global(self)
        logger.info("Sistema de logs iniciado. DB: %s", db_path)
        return self

    def close(self) -> None:
        """Fecha o LogStore e remove referência global."""
        global _global_log_manager
        if self._store:
            self._store.close()
            self._store = None
        if _global_log_manager is self:
            _global_log_manager = None

    # ------------------------------------------------------------------
    # API de acesso
    # ------------------------------------------------------------------

    def get_source(self, source: str) -> SourceLogger:
        if source not in self._sources:
            self._sources[source] = SourceLogger(source, self)
        return self._sources[source]

    def query(self, f: QueryFilter) -> list[LogEntry]:
        assert self._store, "LogManager não está aberto."
        return self._store.query(f)

    def count(self, f: QueryFilter) -> int:
        assert self._store
        return self._store.count(f)

    def stats(self) -> dict:
        assert self._store
        return self._store.stats()

    def purge_old(self) -> int:
        assert self._store
        days = self.config.get("logs.retention_days", 90)
        return self._store.purge_old(days)

    def export_json(self, dest: Path, f: Optional[QueryFilter] = None) -> int:
        assert self._store
        return self._store.export_json(dest, f)

    def export_csv(self, dest: Path, f: Optional[QueryFilter] = None) -> int:
        assert self._store
        return self._store.export_csv(dest, f)

    # ------------------------------------------------------------------
    # Interno
    # ------------------------------------------------------------------

    def _write(self, entry: LogEntry) -> LogEntry:
        """Grava entry se nível >= mínimo configurado."""
        # Espelha no logging padrão do Python sempre
        py_level = entry.level.numeric
        logging.getLogger(entry.source).log(py_level, entry.message)

        # Persiste no SQLite apenas se store estiver aberto e nível suficiente
        if self._store and entry.level.numeric >= self._min_level.numeric:
            return self._store.write(entry)

        return entry

    def _resolve(self, key: str, default: str) -> Path:
        raw = self.config.get(key, default)
        data_dir = os.environ.get("EKP_DATA_DIR", "")
        if data_dir:
            raw = str(raw).replace("/var/lib/ek-protection", data_dir)
        return Path(raw)

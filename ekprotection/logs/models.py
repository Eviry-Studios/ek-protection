"""
ekprotection.logs.models
=========================
Modelos de dados para o sistema de logs.

Define:
  - LogLevel    — níveis de severidade
  - EventType   — categorias de evento
  - LogEntry    — registro imutável de evento
  - QueryFilter — filtros para consulta de logs
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Any


class LogLevel(str, Enum):
    DEBUG    = "DEBUG"
    INFO     = "INFO"
    WARNING  = "WARNING"
    ERROR    = "ERROR"
    CRITICAL = "CRITICAL"

    @property
    def numeric(self) -> int:
        return {
            "DEBUG":    10,
            "INFO":     20,
            "WARNING":  30,
            "ERROR":    40,
            "CRITICAL": 50,
        }[self.value]

    @classmethod
    def from_str(cls, s: str) -> "LogLevel":
        try:
            return cls(s.upper())
        except ValueError:
            return cls.INFO


class EventType(str, Enum):
    # Sistema
    SYSTEM_START   = "system.start"
    SYSTEM_STOP    = "system.stop"
    SYSTEM_ERROR   = "system.error"
    CONFIG_CHANGE  = "config.change"

    # Autenticação
    AUTH_SUCCESS   = "auth.success"
    AUTH_FAILURE   = "auth.failure"
    AUTH_LOCKOUT   = "auth.lockout"
    AUTH_SETUP     = "auth.setup"
    AUTH_CHANGE    = "auth.change"

    # Monitoramento
    FILE_CREATED   = "file.created"
    FILE_MODIFIED  = "file.modified"
    FILE_DELETED   = "file.deleted"
    FILE_EXECUTED  = "file.executed"
    PROC_SUSPICIOUS = "process.suspicious"

    # Ameaças
    THREAT_DETECTED  = "threat.detected"
    THREAT_CRITICAL  = "threat.critical"
    THREAT_IGNORED   = "threat.ignored"

    # Quarentena
    QUARANTINE_ADD    = "quarantine.add"
    QUARANTINE_RESTORE= "quarantine.restore"
    QUARANTINE_DELETE = "quarantine.delete"

    # Scanner
    SCAN_START    = "scan.start"
    SCAN_COMPLETE = "scan.complete"
    SCAN_MATCH    = "scan.match"

    # Atualizações
    UPDATE_START    = "update.start"
    UPDATE_SUCCESS  = "update.success"
    UPDATE_FAILURE  = "update.failure"

    # Exceções
    EXCEPTION_ADD    = "exception.add"
    EXCEPTION_REMOVE = "exception.remove"

    # Genérico
    GENERIC = "generic"


@dataclass(frozen=True)
class LogEntry:
    """
    Registro imutável de um evento do EK-Protection.

    Armazenado no SQLite e serializado para JSONL.
    """
    level:      LogLevel
    event_type: EventType
    message:    str
    timestamp:  datetime          = field(default_factory=datetime.utcnow)
    source:     str               = "core"          # módulo que originou o evento
    pid:        int               = 0
    file_path:  Optional[str]     = None
    sha256:     Optional[str]     = None
    process:    Optional[str]     = None
    extra:      dict[str, Any]    = field(default_factory=dict)
    entry_id:   Optional[int]     = None            # preenchido após gravação no DB

    def to_dict(self) -> dict[str, Any]:
        return {
            "id":         self.entry_id,
            "timestamp":  self.timestamp.isoformat(),
            "level":      self.level.value,
            "event_type": self.event_type.value,
            "message":    self.message,
            "source":     self.source,
            "pid":        self.pid,
            "file_path":  self.file_path,
            "sha256":     self.sha256,
            "process":    self.process,
            "extra":      self.extra,
        }

    def to_json(self) -> str:
        import json
        return json.dumps(self.to_dict(), ensure_ascii=False)


@dataclass
class QueryFilter:
    """
    Filtros para consulta de logs.
    Todos os campos são opcionais — None = sem filtro.
    """
    level:      Optional[LogLevel]    = None
    event_type: Optional[EventType]   = None
    source:     Optional[str]         = None
    since:      Optional[datetime]    = None
    until:      Optional[datetime]    = None
    file_path:  Optional[str]         = None
    search:     Optional[str]         = None    # busca livre no campo message
    limit:      int                   = 100
    offset:     int                   = 0
    order_desc: bool                  = True    # mais recente primeiro


def _parse_dt_str(s: str) -> datetime:
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    raise ValueError(f"Formato de data inválido: {s}. Use YYYY-MM-DD ou YYYY-MM-DDTHH:MM:SS")


def build_query_filter(
    *,
    query:  Optional[str] = None,
    level:  Optional[str] = None,
    event:  Optional[str] = None,
    since:  Optional[str] = None,
    until:  Optional[str] = None,
    path:   Optional[str] = None,
    limit:  int           = 100,
    max_limit: int         = 200,
) -> QueryFilter:
    """
    Constrói um QueryFilter a partir de strings brutas (CLI args ou payload
    IPC) — usado tanto pelo comando direto quanto pelo IPCServer, pra manter
    a mesma lógica de parsing/validação nos dois caminhos.
    Levanta ValueError com mensagem pronta pra exibir se algum campo for
    inválido.
    """
    et = None
    if event:
        try:
            et = EventType(event)
        except ValueError:
            valid = ", ".join(e.value for e in EventType)
            raise ValueError(f"Tipo de evento inválido: {event}. Válidos: {valid}")

    return QueryFilter(
        search     = query,
        level      = LogLevel.from_str(level) if level else None,
        event_type = et,
        since      = _parse_dt_str(since) if since else None,
        until      = _parse_dt_str(until) if until else None,
        file_path  = path,
        limit      = min(limit, max_limit),
        order_desc = True,
    )

"""
ekprotection.monitor.events
============================
Modelos de eventos de filesystem e processo para o monitor.

Define:
  - FileEventKind  — tipo de evento de arquivo (criado, modificado, etc.)
  - ProcEventKind  — tipo de evento de processo (novo, finalizado, suspeito)
  - FileEvent      — evento de arquivo normalizado
  - ProcessEvent   — evento de processo normalizado
  - MonitorEvent   — union dos dois (o que circula na fila do engine)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Optional, Union


class FileEventKind(Enum):
    CREATED  = auto()
    MODIFIED = auto()
    DELETED  = auto()
    MOVED    = auto()
    EXECUTED = auto()   # detectado via modificação de xattr/execve (heurística)


class ProcEventKind(Enum):
    NEW        = auto()   # processo novo detectado
    TERMINATED = auto()   # processo encerrado
    SUSPICIOUS = auto()   # comportamento suspeito em processo existente


@dataclass(frozen=True)
class FileEvent:
    """Evento normalizado de filesystem."""
    kind:       FileEventKind
    path:       str
    timestamp:  datetime          = field(default_factory=datetime.utcnow)
    is_dir:     bool              = False
    src_path:   Optional[str]     = None     # para MOVED: origem
    size:       Optional[int]     = None     # bytes, se disponível
    uid:        Optional[int]     = None     # dono do arquivo
    mode:       Optional[int]     = None     # permissões (stat.st_mode)

    @property
    def extension(self) -> str:
        """Extensão do arquivo em minúsculas, ex: '.sh'"""
        import os
        return os.path.splitext(self.path)[1].lower()

    @property
    def is_executable_extension(self) -> bool:
        return self.extension in {
            ".sh", ".py", ".pl", ".rb", ".php",
            ".elf", ".bin", ".run", ".out",
            "", # sem extensão — pode ser ELF
        }


@dataclass(frozen=True)
class ProcessEvent:
    """Evento normalizado de processo."""
    kind:       ProcEventKind
    pid:        int
    name:       str
    timestamp:  datetime          = field(default_factory=datetime.utcnow)
    cmdline:    list[str]         = field(default_factory=list)
    exe:        Optional[str]     = None
    ppid:       Optional[int]     = None
    username:   Optional[str]     = None
    cpu_pct:    Optional[float]   = None
    mem_pct:    Optional[float]   = None
    reason:     Optional[str]     = None     # para SUSPICIOUS


# Union type que circula na fila interna do monitor
MonitorEvent = Union[FileEvent, ProcessEvent]

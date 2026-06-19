"""
ekprotection.exceptions.models
================================
Modelos de dados para o sistema de exceções.

Define:
  - ExceptionKind  — tipo de exceção (whitelist / blacklist)
  - ExceptionTarget — o que está sendo excluído (path, hash, proc, ext)
  - ExceptionEntry  — registro completo de uma exceção
  - MatchResult     — resultado de verificação (hit, miss, detalhes)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime    import datetime
from enum        import Enum
from typing      import Optional


class ExceptionKind(str, Enum):
    WHITELIST = "whitelist"   # confiável — ignora detecções
    BLACKLIST = "blacklist"   # sempre suspeito — força alerta


class ExceptionTarget(str, Enum):
    PATH      = "path"        # caminho ou glob (ex: /home/user/*, /opt/safe/)
    HASH      = "hash"        # SHA-256 exato do arquivo
    PROCESS   = "process"     # nome do processo (ex: firefox, python3)
    EXTENSION = "extension"   # extensão de arquivo (ex: .iso, .vmdk)


@dataclass(frozen=True)
class ExceptionEntry:
    """
    Registro imutável de uma exceção (whitelist ou blacklist).

    Exemplos:
      ExceptionEntry(kind=WHITELIST, target=PATH,      value="/opt/myapp/*")
      ExceptionEntry(kind=WHITELIST, target=HASH,      value="sha256hex...")
      ExceptionEntry(kind=BLACKLIST, target=PROCESS,   value="cryptominer")
      ExceptionEntry(kind=WHITELIST, target=EXTENSION, value=".iso")
    """
    kind:       ExceptionKind
    target:     ExceptionTarget
    value:      str                        # valor a comparar / glob
    comment:    str          = ""          # nota do usuário
    added_at:   datetime     = field(default_factory=datetime.utcnow)
    added_by:   str          = "user"      # "user" | "auto" | "config"
    entry_id:   Optional[int] = None       # preenchido após gravação no DB

    def to_dict(self) -> dict:
        return {
            "id":       self.entry_id,
            "kind":     self.kind.value,
            "target":   self.target.value,
            "value":    self.value,
            "comment":  self.comment,
            "added_at": self.added_at.isoformat(),
            "added_by": self.added_by,
        }


@dataclass(frozen=True)
class MatchResult:
    """
    Resultado de uma verificação de exceção.

    hit=True  → o item foi encontrado na lista especificada.
    entry     → a ExceptionEntry que gerou o match (ou None).
    """
    hit:   bool
    kind:  Optional[ExceptionKind]   = None
    entry: Optional[ExceptionEntry]  = None

    @classmethod
    def miss(cls) -> "MatchResult":
        return cls(hit=False)

    @classmethod
    def matched(cls, entry: ExceptionEntry) -> "MatchResult":
        return cls(hit=True, kind=entry.kind, entry=entry)

    def is_whitelisted(self) -> bool:
        return self.hit and self.kind == ExceptionKind.WHITELIST

    def is_blacklisted(self) -> bool:
        return self.hit and self.kind == ExceptionKind.BLACKLIST

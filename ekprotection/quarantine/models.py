"""
ekprotection.quarantine.models
================================
Modelos de dados da quarentena.

Define:
  - QuarantineStatus  — estado de um item em quarentena
  - QuarantineReason  — motivo pelo qual foi quarentenado
  - QuarantineEntry   — metadados completos de um item em quarentena
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime    import datetime
from enum        import Enum
from typing      import Optional


class QuarantineStatus(str, Enum):
    ACTIVE    = "active"     # em quarentena, arquivo isolado
    RESTORED  = "restored"   # restaurado pelo usuário
    DELETED   = "deleted"    # excluído permanentemente


class QuarantineReason(str, Enum):
    SIGNATURE_MATCH  = "signature_match"   # hash na blacklist ou DB de assinaturas
    HEURISTIC        = "heuristic"         # comportamento suspeito detectado
    USER_MANUAL      = "user_manual"       # usuário quarentenou manualmente
    AUTO_CRITICAL    = "auto_critical"     # modo crítico automático
    BLACKLIST        = "blacklist"         # na blacklist de exceções


@dataclass(frozen=True)
class QuarantineEntry:
    """
    Metadados completos de um arquivo em quarentena.

    O arquivo físico fica em:
      <quarantine_dir>/<quarantine_id>.ekpq   (cifrado com Fernet)

    Os metadados ficam no SQLite para consulta rápida sem
    precisar decifrar os arquivos.
    """
    original_path:   str
    sha256:          str
    reason:          QuarantineReason
    quarantine_id:   str                      # UUID4 hex — nome do arquivo no vault
    quarantined_at:  datetime                 = field(default_factory=datetime.utcnow)
    status:          QuarantineStatus         = QuarantineStatus.ACTIVE
    file_size:       Optional[int]            = None   # bytes do arquivo original
    threat_type:     Optional[str]            = None   # ex: "Trojan.Agent", "Miner"
    risk_level:      Optional[str]            = None   # baixo | médio | alto | crítico
    process_name:    Optional[str]            = None   # processo que criou/executou
    restored_at:     Optional[datetime]       = None
    restored_to:     Optional[str]            = None   # path de restauração
    comment:         str                      = ""
    entry_id:        Optional[int]            = None   # PK do SQLite

    def to_dict(self) -> dict:
        return {
            "id":             self.entry_id,
            "quarantine_id":  self.quarantine_id,
            "original_path":  self.original_path,
            "sha256":         self.sha256,
            "reason":         self.reason.value,
            "status":         self.status.value,
            "file_size":      self.file_size,
            "threat_type":    self.threat_type,
            "risk_level":     self.risk_level,
            "process_name":   self.process_name,
            "quarantined_at": self.quarantined_at.isoformat(),
            "restored_at":    self.restored_at.isoformat() if self.restored_at else None,
            "restored_to":    self.restored_to,
            "comment":        self.comment,
        }

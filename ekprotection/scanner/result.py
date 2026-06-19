"""
ekprotection.scanner.result
=============================
Modelos de resultado do scanner.

Define:
  - ScanVerdict  — veredicto final de um arquivo
  - FileScanResult — resultado completo de scan de um arquivo
  - ScanReport     — resultado de um scan completo (múltiplos arquivos)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime    import datetime
from enum        import Enum
from typing      import Optional


class ScanVerdict(str, Enum):
    CLEAN       = "clean"        # arquivo seguro
    SUSPICIOUS  = "suspicious"   # comportamento suspeito (heurístico)
    THREAT      = "threat"       # assinatura conhecida
    SKIPPED     = "skipped"      # ignorado (tamanho, permissão, whitelist)
    ERROR       = "error"        # erro ao escanear


@dataclass(frozen=True)
class FileScanResult:
    """Resultado de scan de um arquivo individual."""
    path:          str
    verdict:       ScanVerdict
    sha256:        Optional[str]   = None
    file_size:     Optional[int]   = None
    threat_name:   Optional[str]   = None     # ex: "Trojan.Downloader"
    threat_type:   Optional[str]   = None     # ex: "Trojan"
    risk_level:    Optional[str]   = None     # baixo | médio | alto | crítico
    reason:        Optional[str]   = None     # motivo da detecção
    entropy:       Optional[float] = None     # Shannon entropy
    is_elf:        bool            = False
    is_script:     bool            = False
    scanned_at:    datetime        = field(default_factory=datetime.utcnow)
    scan_ms:       Optional[int]   = None     # tempo de scan em ms
    error_msg:     Optional[str]   = None     # preenchido se verdict=ERROR

    @property
    def is_threat(self) -> bool:
        return self.verdict in (ScanVerdict.THREAT, ScanVerdict.SUSPICIOUS)

    @property
    def is_critical(self) -> bool:
        return self.verdict == ScanVerdict.THREAT and self.risk_level == "crítico"

    def to_dict(self) -> dict:
        return {
            "path":        self.path,
            "verdict":     self.verdict.value,
            "sha256":      self.sha256,
            "file_size":   self.file_size,
            "threat_name": self.threat_name,
            "threat_type": self.threat_type,
            "risk_level":  self.risk_level,
            "reason":      self.reason,
            "entropy":     self.entropy,
            "is_elf":      self.is_elf,
            "is_script":   self.is_script,
            "scanned_at":  self.scanned_at.isoformat(),
            "scan_ms":     self.scan_ms,
            "error_msg":   self.error_msg,
        }


@dataclass
class ScanReport:
    """Relatório agregado de um scan completo."""
    scan_type:   str                       # "quick" | "full" | "file" | "paths"
    started_at:  datetime                  = field(default_factory=datetime.utcnow)
    finished_at: Optional[datetime]        = None
    results:     list[FileScanResult]      = field(default_factory=list)

    # Contadores (preenchidos pelo scanner ao finalizar)
    total_files:    int = 0
    scanned_files:  int = 0
    skipped_files:  int = 0
    threats_found:  int = 0
    errors:         int = 0

    def add(self, result: FileScanResult) -> None:
        self.results.append(result)
        self.total_files   += 1
        if result.verdict   == ScanVerdict.SKIPPED: self.skipped_files += 1
        elif result.verdict == ScanVerdict.ERROR:   self.errors        += 1
        else:
            self.scanned_files += 1
            if result.is_threat:
                self.threats_found += 1

    def finish(self) -> None:
        self.finished_at = datetime.utcnow()

    @property
    def duration_ms(self) -> Optional[int]:
        if self.finished_at:
            return int((self.finished_at - self.started_at).total_seconds() * 1000)
        return None

    @property
    def threats(self) -> list[FileScanResult]:
        return [r for r in self.results if r.is_threat]

    def summary(self) -> dict:
        return {
            "scan_type":    self.scan_type,
            "started_at":   self.started_at.isoformat(),
            "finished_at":  self.finished_at.isoformat() if self.finished_at else None,
            "duration_ms":  self.duration_ms,
            "total_files":  self.total_files,
            "scanned_files":self.scanned_files,
            "skipped_files":self.skipped_files,
            "threats_found":self.threats_found,
            "errors":       self.errors,
        }

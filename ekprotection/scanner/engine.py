"""
ekprotection.scanner.engine
=============================
Motor de scan do EK-Protection.

Responsabilidades:
  - Escanear um arquivo individual (scan_file)
  - Scan sob demanda: rápido (quick), completo (full), paths customizados
  - Pipeline por arquivo:
      1. Verifica whitelist (ExceptionManager) → SKIPPED se confiável
      2. Verifica blacklist → THREAT se forçado
      3. Calcula SHA-256
      4. Consulta SignatureDB → THREAT se hash conhecido
      5. Verifica permissões executáveis e localização suspeita
      6. Calcula entropia → alerta se muito alta em executável
      7. Verifica score heurístico base (extensão, ELF, shebang)
      8. Retorna FileScanResult com veredicto e todos os metadados
  - Para ameaças críticas: integração com QuarantineManager
  - Scan paralelo com ThreadPoolExecutor (threads configurável)
  - Emissão de eventos para LogManager

Heurísticas leves implementadas aqui (Patch 8 aprofunda):
  - Executável em /tmp, /dev/shm, /var/tmp
  - Arquivo sem extensão com bit executável
  - Alta entropia (> 7.2) em executável
  - Script com shebang em local suspeito
"""

from __future__ import annotations

import asyncio
import logging
import os
import stat as stat_mod
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib            import Path
from typing             import Any, Callable, Iterator, Optional

from ekprotection.config.manager    import ConfigManager
from ekprotection.logs.models       import EventType, LogLevel

from .hasher     import sha256_file, is_elf, is_script, file_entropy
from .result     import FileScanResult, ScanReport, ScanVerdict
from .signatures import SignatureDB

logger = logging.getLogger(__name__)

# Diretórios suspeitos para executáveis
_SUSPICIOUS_DIRS = {"/tmp", "/dev/shm", "/var/tmp", "/run/user"}

# Extensões que nunca precisam ser escaneadas
_SKIP_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg",
    ".mp3", ".mp4", ".avi", ".mkv", ".flv", ".wav", ".ogg",
    ".pdf", ".docx", ".xlsx", ".pptx", ".odt", ".ods",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".iso", ".img", ".vmdk",
    ".pyc", ".pyo",
}


class ScanEngine:
    """
    Motor de scanner sob demanda do EK-Protection.

    Inicializado pelo Engine; exposto via engine.scanner.
    """

    def __init__(
        self,
        config:       ConfigManager,
        sig_db:       Optional[SignatureDB]  = None,
        exc_manager:  Any = None,   # ExceptionManager
        quar_manager: Any = None,   # QuarantineManager
        log_manager:  Any = None,   # LogManager
        heuristic_engine: Any = None,  # HeuristicEngine (Patch 8)
    ) -> None:
        self.config       = config
        self._sig_db      = sig_db
        self._exc         = exc_manager
        self._quar        = quar_manager
        self._log         = log_manager
        self._heuristics      = heuristic_engine
        self._threads     = config.get("scanner.threads", 4)
        self._max_size    = config.get("scanner.max_file_size_mb", 512) * 1024 * 1024
        self._entropy_thr = config.get("heuristics.entropy_threshold", 7.2)
        self._auto_quar   = config.get("quarantine.auto_quarantine_critical", True)

    # ------------------------------------------------------------------
    # Scan de arquivo único
    # ------------------------------------------------------------------

    def scan_file(self, path: str | Path) -> FileScanResult:
        """
        Escaneia um arquivo e retorna FileScanResult.
        Nunca lança exceção — erros são capturados no result.

        Esta é a operação central do scanner; todos os outros métodos
        chamam esta função para cada arquivo.
        """
        path    = str(path)
        t_start = time.monotonic()

        try:
            result = self._scan_file_inner(path)
        except Exception as exc:
            result = FileScanResult(
                path      = path,
                verdict   = ScanVerdict.ERROR,
                error_msg = str(exc),
                scan_ms   = int((time.monotonic() - t_start) * 1000),
            )

        # Auto-quarentena para ameaças críticas
        if result.is_critical and self._auto_quar and self._quar:
            self._auto_quarantine(result)

        # Log da detecção
        if result.is_threat:
            self._log_threat(result)

        return result

    def _scan_file_inner(self, path: str) -> FileScanResult:
        p = Path(path)

        # --- Verificações básicas ---
        if not p.exists():
            return FileScanResult(path=path, verdict=ScanVerdict.SKIPPED,
                                  reason="arquivo não existe")
        if not p.is_file():
            return FileScanResult(path=path, verdict=ScanVerdict.SKIPPED,
                                  reason="não é arquivo regular")

        try:
            st        = p.stat()
            file_size = st.st_size
            file_mode = st.st_mode
        except OSError as exc:
            return FileScanResult(path=path, verdict=ScanVerdict.ERROR,
                                  error_msg=f"stat: {exc}")

        # Arquivo muito grande
        if file_size > self._max_size:
            return FileScanResult(path=path, verdict=ScanVerdict.SKIPPED,
                                  file_size=file_size,
                                  reason=f"arquivo muito grande ({file_size // 1024 // 1024}MB)")

        # Extensão ignorada
        ext = p.suffix.lower()
        if ext in _SKIP_EXTENSIONS:
            # Verifica blacklist mesmo para extensões ignoradas
            if self._exc and self._exc.is_blacklisted(path=path):
                pass   # continua o scan
            else:
                return FileScanResult(path=path, verdict=ScanVerdict.SKIPPED,
                                      file_size=file_size,
                                      reason=f"extensão ignorada ({ext})")

        # --- Whitelist / Blacklist por path (antes de calcular hash) ---
        if self._exc:
            bl_path = self._exc.check(path=path)
            if bl_path.is_whitelisted():
                return FileScanResult(path=path, verdict=ScanVerdict.SKIPPED,
                                      file_size=file_size,
                                      reason=f"whitelist: {bl_path.entry.value if bl_path.entry else 'path'}")  # type: ignore[union-attr]

        # --- Calcula hash ---
        t_hash = time.monotonic()
        try:
            sha256 = sha256_file(path)
        except (OSError, PermissionError) as exc:
            return FileScanResult(path=path, verdict=ScanVerdict.ERROR,
                                  file_size=file_size, error_msg=f"hash: {exc}")

        # --- Whitelist / Blacklist por hash ---
        if self._exc:
            hl = self._exc.check(sha256=sha256)
            if hl.is_whitelisted():
                return FileScanResult(path=path, verdict=ScanVerdict.SKIPPED,
                                      sha256=sha256, file_size=file_size,
                                      reason="whitelist: hash confiável")
            if hl.is_blacklisted():
                return FileScanResult(
                    path=path, verdict=ScanVerdict.THREAT,
                    sha256=sha256, file_size=file_size,
                    threat_name="Blacklist.Hash",
                    threat_type="Blacklist",
                    risk_level="crítico",
                    reason="hash na blacklist de exceções",
                )

        # --- Lookup de assinatura ---
        if self._sig_db:
            sig = self._sig_db.lookup(sha256)
            if sig:
                return FileScanResult(
                    path=path, verdict=ScanVerdict.THREAT,
                    sha256=sha256, file_size=file_size,
                    threat_name=sig["name"],
                    threat_type=sig["threat_type"],
                    risk_level=sig["severity"],
                    reason=f"assinatura conhecida: {sig['name']} [{sig['source']}]",
                    scan_ms=int((time.monotonic() - t_hash) * 1000),
                )

        # --- Heurísticas base ---
        elf_file    = is_elf(path)
        script_file = is_script(path)
        is_exec     = bool(file_mode & (stat_mod.S_IXUSR | stat_mod.S_IXGRP | stat_mod.S_IXOTH))
        entropy_val = file_entropy(path) if (elf_file or is_exec) else None

        risk, reason = self._heuristic_check(
            path, ext, file_size, file_mode,
            is_exec, elf_file, script_file, entropy_val,
        )

        verdict = ScanVerdict.SUSPICIOUS if risk else ScanVerdict.CLEAN

        # --- Heurística avançada (Patch 8) ---
        h_result = None
        if self._heuristics:
            try:
                h_result = self._heuristics.analyze(path)
                # Heurística avançada pode elevar o risco
                if h_result.is_suspicious:
                    if h_result.risk_level in ("crítico", "alto") or not risk:
                        risk   = h_result.risk_level
                        reason = h_result.primary_reason or reason
                        # "crítico" vira THREAT (não só SUSPICIOUS) pra
                        # que is_critical/auto-quarentena disparem de
                        # verdade — antes disso, nenhuma detecção
                        # heurística nunca era quarentenada automaticamente
                        # mesmo com quarantine.auto_quarantine_critical=true,
                        # porque is_critical exige verdict==THREAT e este
                        # caminho sempre forçava SUSPICIOUS.
                        verdict = (ScanVerdict.THREAT if h_result.risk_level == "crítico"
                                   else ScanVerdict.SUSPICIOUS)
            except Exception:
                pass

        return FileScanResult(
            path=path, verdict=verdict,
            sha256=sha256, file_size=file_size,
            threat_name="Heuristic.Suspicious" if risk else None,
            threat_type="Heuristic"             if risk else None,
            risk_level=risk,
            reason=reason,
            entropy=entropy_val,
            is_elf=elf_file,
            is_script=script_file,
            scan_ms=int((time.monotonic() - t_hash) * 1000),
        )

    def _heuristic_check(
        self,
        path:        str,
        ext:         str,
        size:        int,
        mode:        int,
        is_exec:     bool,
        elf_file:    bool,
        script_file: bool,
        entropy:     Optional[float],
    ) -> tuple[Optional[str], Optional[str]]:
        """
        Heurísticas base. Retorna (risk_level, reason) ou (None, None).
        Patch 8 aprofunda esta análise.
        """
        reasons: list[str] = []
        risk = "baixo"

        p = Path(path)

        # Executável em diretório suspeito
        for d in _SUSPICIOUS_DIRS:
            if path.startswith(d + "/") or path.startswith(d):
                if is_exec or elf_file or script_file:
                    reasons.append(f"executável em {d}")
                    risk = "alto"
                break

        # Alta entropia em executável
        if entropy is not None and entropy > self._entropy_thr:
            reasons.append(f"alta entropia ({entropy:.2f}) — possível packed/cifrado")
            risk = max(risk, "médio", key=lambda r: {"baixo":0,"médio":1,"alto":2,"crítico":3}.get(r,0))

        # ELF sem extensão em local incomum
        if elf_file and ext == "" and not path.startswith(("/usr", "/bin", "/sbin", "/lib")):
            reasons.append("binário ELF sem extensão em local não-padrão")
            risk = max(risk, "médio", key=lambda r: {"baixo":0,"médio":1,"alto":2,"crítico":3}.get(r,0))

        # Arquivo oculto executável
        if p.name.startswith(".") and is_exec:
            reasons.append("arquivo oculto com bit de execução")
            risk = max(risk, "médio", key=lambda r: {"baixo":0,"médio":1,"alto":2,"crítico":3}.get(r,0))

        if not reasons:
            return None, None

        return risk, "; ".join(reasons)

    # ------------------------------------------------------------------
    # Scans de múltiplos arquivos
    # ------------------------------------------------------------------

    def scan_paths(
        self,
        paths:       list[str],
        recursive:   bool                      = True,
        progress_cb: Optional[Callable[[str], None]] = None,
    ) -> ScanReport:
        """
        Escaneia uma lista de paths (arquivos ou diretórios).
        progress_cb(path) é chamado antes de cada arquivo.
        """
        report = ScanReport(scan_type="paths")
        files  = list(self._iter_files(paths, recursive))

        with ThreadPoolExecutor(max_workers=self._threads) as pool:
            future_to_path = {pool.submit(self.scan_file, f): f for f in files}
            for future in as_completed(future_to_path):
                fpath = future_to_path[future]
                if progress_cb:
                    progress_cb(fpath)
                try:
                    result = future.result()
                except Exception as exc:
                    result = FileScanResult(path=fpath, verdict=ScanVerdict.ERROR,
                                            error_msg=str(exc))
                report.add(result)

        report.finish()
        self._log_scan_complete(report)
        return report

    def scan_quick(self, progress_cb: Optional[Callable[[str], None]] = None) -> ScanReport:
        """Scan rápido: apenas os paths configurados em scanner.quick_scan_paths."""
        paths  = self.config.get("scanner.quick_scan_paths", ["/home", "/tmp", "/var/tmp"])
        report = self.scan_paths(paths, recursive=True, progress_cb=progress_cb)
        report.scan_type = "quick"
        return report

    def scan_full(self, progress_cb: Optional[Callable[[str], None]] = None) -> ScanReport:
        """Scan completo: paths configurados em monitor.paths."""
        paths  = self.config.get("monitor.paths", ["/home", "/tmp"])
        report = self.scan_paths(paths, recursive=True, progress_cb=progress_cb)
        report.scan_type = "full"
        return report

    # ------------------------------------------------------------------
    # Auto-quarentena
    # ------------------------------------------------------------------

    def _auto_quarantine(self, result: FileScanResult) -> None:
        """Quarentena automática para ameaças críticas (modo crítico)."""
        if not self._quar or not result.sha256:
            return
        try:
            from ekprotection.quarantine.models import QuarantineReason
            reason_kind = (QuarantineReason.HEURISTIC if result.threat_type == "Heuristic"
                           else QuarantineReason.SIGNATURE_MATCH)
            self._quar.quarantine_file(
                path         = result.path,
                sha256       = result.sha256,
                reason       = reason_kind,
                threat_type  = result.threat_type,
                risk_level   = result.risk_level,
                comment      = f"Auto-quarentena: {result.threat_name}",
                remove_original = True,
            )
            logger.warning("Auto-quarentena: %s [%s]", result.path, result.threat_name)
        except Exception as exc:
            logger.error("Falha na auto-quarentena de %s: %s", result.path, exc)

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    def _log_threat(self, result: FileScanResult) -> None:
        if not self._log:
            return
        try:
            level  = LogLevel.CRITICAL if result.is_critical else LogLevel.WARNING
            etype  = EventType.SCAN_MATCH
            msg    = (
                f"[{result.verdict.value.upper()}] {result.path} "
                f"— {result.threat_name or 'suspeito'} "
                f"[risco: {result.risk_level or '?'}]"
            )
            self._log.get_source("scanner").event(
                etype, msg, level=level,
                file_path=result.path, sha256=result.sha256,
            )
        except Exception:
            pass

    def _log_scan_complete(self, report: ScanReport) -> None:
        if not self._log:
            return
        try:
            msg = (
                f"Scan {report.scan_type} concluído: "
                f"{report.scanned_files} escaneados, "
                f"{report.threats_found} ameaças, "
                f"{report.errors} erros, "
                f"{report.duration_ms}ms"
            )
            self._log.get_source("scanner").event(
                EventType.SCAN_COMPLETE, msg, level=LogLevel.INFO
            )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Iteração de arquivos
    # ------------------------------------------------------------------

    @staticmethod
    def _iter_files(paths: list[str], recursive: bool) -> Iterator[str]:
        """Itera sobre arquivos regulares nos paths fornecidos."""
        for raw in paths:
            p = Path(raw)
            if p.is_file():
                yield str(p)
            elif p.is_dir():
                if recursive:
                    for child in p.rglob("*"):
                        if child.is_file():
                            try:
                                # Verifica acesso antes de adicionar
                                child.stat()
                                yield str(child)
                            except (OSError, PermissionError):
                                pass
                else:
                    for child in p.iterdir():
                        if child.is_file():
                            yield str(child)

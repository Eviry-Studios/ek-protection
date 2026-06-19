"""
ekprotection.updater.manager
==============================
Gerenciador de atualizações automáticas do EK-Protection.

Responsabilidades:
  - Verificar atualizações de assinaturas periodicamente
  - Integração com LogManager para auditoria
  - Loop assíncrono para atualização automática em background
  - Controle de intervalo e última verificação
"""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timedelta
from pathlib  import Path
from typing   import Any, Optional

from ekprotection.config.manager import ConfigManager
from ekprotection.logs.models    import EventType, LogLevel

from .fetcher import SignatureFetcher, UpdateError, FetchResult

logger = logging.getLogger(__name__)


class UpdateManager:
    """
    Gerenciador de atualizações em background.

    Inicializado pelo Engine; roda como asyncio Task opcional.
    """

    def __init__(
        self,
        config:      ConfigManager,
        sig_db:      Any = None,   # SignatureDB
        log_manager: Any = None,
    ) -> None:
        self.config      = config
        self._sig_db     = sig_db
        self._log        = log_manager
        self._running    = False
        self._last_check: Optional[datetime] = None
        self._fetcher:   Optional[SignatureFetcher] = None

        self._auto_update = config.get("signatures.auto_update",      True)
        self._interval_h  = config.get("signatures.update_interval_hours", 24)
        self._url         = config.get(
            "signatures.update_url",
            "https://raw.githubusercontent.com/Eviry-Studios/ek-protection/main/signatures/",
        )

    # ------------------------------------------------------------------
    # Ciclo de vida
    # ------------------------------------------------------------------

    def initialize(self) -> None:
        """Prepara o fetcher (não inicia o loop automático)."""
        if not self._sig_db:
            logger.warning("UpdateManager: sig_db não disponível.")
            return

        data_dir = os.environ.get("EKP_DATA_DIR", "/var/lib/ek-protection")
        cache    = Path(data_dir)

        manifest_url = self._url.rstrip("/") + "/manifest.json"
        self._fetcher = SignatureFetcher(
            manifest_url = manifest_url,
            sig_db       = self._sig_db,
            cache_dir    = cache,
        )
        logger.debug("UpdateManager inicializado. URL: %s", manifest_url)

    async def run_loop(self) -> None:
        """
        Loop assíncrono de atualização automática.
        Roda como asyncio.Task no daemon.
        """
        if not self._auto_update:
            logger.info("Atualização automática desabilitada.")
            return

        self._running = True
        logger.info(
            "UpdateManager: loop iniciado (intervalo: %dh).", self._interval_h
        )

        while self._running:
            await self._check_and_update()
            # Aguarda o intervalo configurado
            await asyncio.sleep(self._interval_h * 3600)

        logger.info("UpdateManager: loop encerrado.")

    def stop(self) -> None:
        self._running = False

    # ------------------------------------------------------------------
    # Atualização manual (usado pelo CLI)
    # ------------------------------------------------------------------

    def update_now(self, force: bool = False) -> Optional[FetchResult]:
        """
        Executa atualização imediata de assinaturas.
        force=True ignora o intervalo mínimo.
        Retorna FetchResult ou None se não foi possível atualizar.
        """
        if not self._fetcher:
            self.initialize()
        if not self._fetcher:
            logger.error("Fetcher não disponível.")
            return None

        try:
            result = self._fetcher.update()
            self._last_check = datetime.utcnow()
            self._audit(result)
            return result
        except Exception as exc:
            logger.error("Erro na atualização de assinaturas: %s", exc)
            self._log_error(str(exc))
            return None

    def check_available(self) -> tuple[bool, str, str]:
        """Verifica se há atualização disponível."""
        if not self._fetcher:
            self.initialize()
        if not self._fetcher:
            return False, "0.0.0", ""
        return self._fetcher.check_update_available()

    # ------------------------------------------------------------------
    # Interno
    # ------------------------------------------------------------------

    async def _check_and_update(self) -> None:
        """Verifica e atualiza se o intervalo passou."""
        now = datetime.utcnow()
        if self._last_check:
            elapsed_h = (now - self._last_check).total_seconds() / 3600
            if elapsed_h < self._interval_h:
                return

        logger.info("UpdateManager: verificando assinaturas...")
        try:
            loop   = asyncio.get_running_loop()
            result = await loop.run_in_executor(None, self._fetcher.update)  # type: ignore[union-attr]
            self._last_check = now
            self._audit(result)
        except Exception as exc:
            logger.warning("Atualização automática falhou: %s", exc)
            self._log_error(str(exc))

    def _audit(self, result: FetchResult) -> None:
        if not self._log or not result.updated:
            return
        try:
            self._log.get_source("updater").event(
                EventType.UPDATE_SUCCESS,
                f"Assinaturas atualizadas: v{result.version_before} → v{result.version_after} "
                f"(+{result.added} novas)",
                level=LogLevel.INFO,
            )
        except Exception:
            pass

    def _log_error(self, msg: str) -> None:
        if not self._log:
            return
        try:
            self._log.get_source("updater").event(
                EventType.UPDATE_FAILURE,
                f"Falha na atualização: {msg}",
                level=LogLevel.WARNING,
            )
        except Exception:
            pass

    def status(self) -> dict:
        last = self._last_check.isoformat() if self._last_check else "nunca"
        sig_count = 0
        sig_version = "0.0.0"
        if self._sig_db:
            try:
                sig_count   = self._sig_db.count()
                sig_version = self._sig_db.meta().get("version", "0.0.0")
            except Exception:
                pass
        return {
            "auto_update":      self._auto_update,
            "interval_hours":   self._interval_h,
            "last_check":       last,
            "running":          self._running,
            "signatures":       sig_count,
            "sig_version":      sig_version,
            "update_url":       self._url,
        }

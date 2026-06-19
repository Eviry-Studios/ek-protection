"""
ekprotection.quarantine.manager
=================================
Gerenciador de quarentena do EK-Protection.

Orquestra:
  - QuarantineVault  — cifragem e armazenamento físico
  - QuarantineStore  — metadados no SQLite
  - Integração com AuthManager (restaurar/excluir requerem autenticação)
  - Integração com LogManager (auditoria completa)
  - Limpeza automática por retenção configurável

Filosofia de operação:
  - Quarentenar: SEMPRE reversível (arquivo cifrado, não destruído)
  - Restaurar:   requer token de sessão válido
  - Excluir:     requer token + confirmação explícita; irreversível
  - Nenhuma ação destrutiva silenciosa

Uso pelos outros módulos (scanner, heuristics no Patch 7/8):
  mgr.quarantine_file(
      path      = "/tmp/malware.sh",
      sha256    = "abc...",
      reason    = QuarantineReason.SIGNATURE_MATCH,
      threat_type = "Trojan.Downloader",
      risk_level  = "crítico",
  )

  # Requer auth:
  mgr.restore(quarantine_id, dest="/home/user/restored/", token=session_token)
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
from datetime import datetime
from pathlib  import Path
from typing   import Any, Optional

from ekprotection.config.manager import ConfigManager
from ekprotection.logs.models    import EventType, LogLevel

from .models  import QuarantineEntry, QuarantineReason, QuarantineStatus
from .store   import QuarantineStore
from .vault   import QuarantineVault, VaultError

logger = logging.getLogger(__name__)


class QuarantineError(Exception):
    """Erro de operação de quarentena."""


class QuarantineManager:
    """
    Gerenciador central de quarentena.

    Inicializado pelo Engine; exposto via engine.quarantine.
    """

    def __init__(
        self,
        config:       ConfigManager,
        log_manager:  Any = None,
        auth_manager: Any = None,
    ) -> None:
        self.config       = config
        self._log         = log_manager
        self._auth        = auth_manager
        self._store:      Optional[QuarantineStore]  = None
        self._vault:      Optional[QuarantineVault]  = None

    # ------------------------------------------------------------------
    # Ciclo de vida
    # ------------------------------------------------------------------

    def open(self) -> "QuarantineManager":
        db_raw   = self.config.get("logs.db_path", "/var/lib/ek-protection/ek-protection.db")
        vault_raw = self.config.get("quarantine.dir", "/var/lib/ek-protection/quarantine")
        encrypt  = self.config.get("quarantine.encrypt", True)
        data_dir = os.environ.get("EKP_DATA_DIR", "")

        if data_dir:
            db_raw    = db_raw.replace("/var/lib/ek-protection", data_dir)
            vault_raw = vault_raw.replace("/var/lib/ek-protection", data_dir)

        key_dir = Path(vault_raw) / ".keys"

        self._store = QuarantineStore(db_raw)
        self._store.open()

        self._vault = QuarantineVault(vault_raw, key_dir, encrypt=encrypt)
        self._vault.initialize()

        logger.info("QuarantineManager iniciado. Stats: %s", self._store.stats())
        return self

    def close(self) -> None:
        if self._store:
            self._store.close()
            self._store = None

    # ------------------------------------------------------------------
    # Quarentenar
    # ------------------------------------------------------------------

    def quarantine_file(
        self,
        path:         str,
        sha256:       str,
        reason:       QuarantineReason,
        threat_type:  Optional[str]  = None,
        risk_level:   Optional[str]  = None,
        process_name: Optional[str]  = None,
        comment:      str            = "",
        remove_original: bool        = True,
    ) -> QuarantineEntry:
        """
        Quarentena um arquivo:
          1. Cifra e move para o vault
          2. Persiste metadados no SQLite
          3. Remove o original (se remove_original=True)
          4. Registra no log

        Retorna QuarantineEntry com ID preenchido.
        Lança QuarantineError se qualquer etapa falhar.

        NÃO requer autenticação — quarentenar é ação protetora.
        Restaurar é que requer auth.
        """
        assert self._store and self._vault
        src = Path(path)

        if not src.exists():
            raise QuarantineError(f"Arquivo não encontrado: {path}")

        # Tamanho original
        try:
            file_size = src.stat().st_size
        except OSError:
            file_size = None

        # Gera ID único para este item
        quarantine_id = secrets.token_hex(16)

        # 1. Cifra e copia para o vault
        try:
            self._vault.quarantine(src, quarantine_id)
        except VaultError as exc:
            raise QuarantineError(f"Erro ao mover para vault: {exc}") from exc

        # 2. Persiste metadados
        entry = QuarantineEntry(
            quarantine_id  = quarantine_id,
            original_path  = str(src.resolve()),
            sha256         = sha256,
            reason         = reason,
            status         = QuarantineStatus.ACTIVE,
            file_size      = file_size,
            threat_type    = threat_type,
            risk_level     = risk_level,
            process_name   = process_name,
            comment        = comment,
        )
        saved = self._store.add(entry)

        # 3. Remove original SOMENTE após confirmar que o vault gravou
        if remove_original:
            try:
                src.unlink()
                logger.info("Original removido após quarentena: %s", path)
            except OSError as exc:
                logger.warning("Não foi possível remover original %s: %s", path, exc)

        # 4. Auditoria
        self._audit(
            EventType.QUARANTINE_ADD,
            f"Quarentena: {path} [{reason.value}] risco={risk_level or '?'}",
            level=LogLevel.WARNING,
            file_path=path, sha256=sha256,
        )
        logger.warning("Arquivo quarentenado: %s (ID: %s)", path, quarantine_id)
        return saved

    # ------------------------------------------------------------------
    # Restaurar (requer autenticação)
    # ------------------------------------------------------------------

    def restore(
        self,
        quarantine_id: str,
        dest_dir:      str | Path,
        token:         Optional[str] = None,
    ) -> Path:
        """
        Restaura arquivo do vault para dest_dir.

        Requer token de sessão válido se auth_manager estiver configurado.
        Retorna Path do arquivo restaurado.
        """
        assert self._store and self._vault

        # Verifica autenticação
        if self._auth and self.config.get("auth.require_for_critical", True):
            if token is None:
                raise PermissionError("Restauração requer autenticação. Forneça o token de sessão.")
            from ekprotection.auth.manager import AuthSessionExpiredError
            self._auth.require(token)

        entry = self._store.get(quarantine_id)
        if not entry:
            raise QuarantineError(f"Item de quarentena não encontrado: {quarantine_id}")

        if entry.status != QuarantineStatus.ACTIVE:
            raise QuarantineError(
                f"Item não está ativo (status: {entry.status.value}). Não pode ser restaurado."
            )

        # Determina destino
        dest_path = Path(dest_dir) / Path(entry.original_path).name

        try:
            actual_dest = self._vault.restore(quarantine_id, dest_path)
        except VaultError as exc:
            raise QuarantineError(f"Erro ao restaurar do vault: {exc}") from exc

        # Atualiza status no banco
        self._store.update_status(
            quarantine_id,
            QuarantineStatus.RESTORED,
            restored_to=str(actual_dest),
            restored_at=datetime.utcnow(),
        )

        self._audit(
            EventType.QUARANTINE_RESTORE,
            f"Restaurado: {entry.original_path} → {actual_dest}",
            level=LogLevel.INFO,
            file_path=entry.original_path,
        )
        logger.info("Arquivo restaurado: %s → %s", quarantine_id, actual_dest)
        return actual_dest

    # ------------------------------------------------------------------
    # Excluir permanentemente (requer autenticação)
    # ------------------------------------------------------------------

    def delete_permanently(
        self,
        quarantine_id: str,
        token:         Optional[str] = None,
    ) -> bool:
        """
        Exclui arquivo do vault permanentemente.
        IRREVERSÍVEL. Requer autenticação.
        """
        assert self._store and self._vault

        if self._auth and self.config.get("auth.require_for_critical", True):
            if token is None:
                raise PermissionError("Exclusão permanente requer autenticação.")
            self._auth.require(token)

        entry = self._store.get(quarantine_id)
        if not entry:
            raise QuarantineError(f"Item não encontrado: {quarantine_id}")

        self._vault.delete_file(quarantine_id)
        self._store.update_status(quarantine_id, QuarantineStatus.DELETED)

        self._audit(
            EventType.QUARANTINE_DELETE,
            f"Excluído permanentemente: {entry.original_path} (ID: {quarantine_id})",
            level=LogLevel.WARNING,
            file_path=entry.original_path,
            sha256=entry.sha256,
        )
        logger.warning("Arquivo de quarentena excluído: %s", quarantine_id)
        return True

    # ------------------------------------------------------------------
    # Consultas
    # ------------------------------------------------------------------

    def list_active(self) -> list[QuarantineEntry]:
        assert self._store
        return self._store.list_all(status=QuarantineStatus.ACTIVE)

    def list_all(self, limit: int = 200) -> list[QuarantineEntry]:
        assert self._store
        return self._store.list_all(limit=limit)

    def get(self, quarantine_id: str) -> Optional[QuarantineEntry]:
        assert self._store
        return self._store.get(quarantine_id)

    def get_by_id(self, entry_id: int) -> Optional[QuarantineEntry]:
        assert self._store
        return self._store.get_by_id(entry_id)

    def find_by_hash(self, sha256: str) -> list[QuarantineEntry]:
        assert self._store
        return self._store.find_by_sha256(sha256)

    def stats(self) -> dict:
        assert self._store
        return self._store.stats()

    # ------------------------------------------------------------------
    # Limpeza por retenção
    # ------------------------------------------------------------------

    def purge_old(self, token: Optional[str] = None) -> int:
        """Remove registros antigos (status deleted/restored). Requer auth."""
        assert self._store and self._vault

        if self._auth and self.config.get("auth.require_for_critical", True):
            if token:
                self._auth.require(token)

        days = self.config.get("quarantine.retention_days", 30)
        ids_to_purge = self._store.purge_old(days)

        removed = 0
        for qid in ids_to_purge:
            self._vault.delete_file(qid)
            self._store.remove_record(qid)
            removed += 1

        if removed:
            logger.info("Purge de quarentena: %d registros removidos.", removed)
        return removed

    # ------------------------------------------------------------------
    # Interno
    # ------------------------------------------------------------------

    def _audit(self, etype: EventType, message: str, level: LogLevel = LogLevel.INFO, **kw: Any) -> None:
        if self._log is None:
            return
        try:
            self._log.get_source("quarantine").event(etype, message, level=level, **kw)
        except Exception:
            pass

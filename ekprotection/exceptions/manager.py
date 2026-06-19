"""
ekprotection.exceptions.manager
=================================
Gerenciador do sistema de exceções do EK-Protection.

Responsabilidades:
  - Abrir e manter o ExceptionStore
  - Carregar exceções do arquivo YAML de config (seção exceptions.*)
    na primeira inicialização
  - Expor API unificada de check para os outros subsistemas
  - Fornecer método de conveniência para adicionar exceções via CLI
  - Integração com LogManager para auditoria de todas as alterações

Uso pelos outros módulos:

    # Scanner / Heuristics
    result = exc_mgr.check(path=ev.path, sha256=hash_val)
    if result.is_whitelisted():
        return   # ignorar

    # Adicionar exceção interativa
    exc_mgr.add_whitelist_path("/opt/myapp/*", comment="app corporativo")
    exc_mgr.add_whitelist_hash("abc123...", comment="binário auditado")
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing  import Any, Optional

from ekprotection.config.manager import ConfigManager
from ekprotection.logs.models    import EventType, LogLevel

from .models import ExceptionEntry, ExceptionKind, ExceptionTarget, MatchResult
from .store  import ExceptionStore

logger = logging.getLogger(__name__)


class ExceptionManager:
    """
    Gerenciador central de exceções (whitelist / blacklist).

    Inicializado pelo Engine; exposto via engine.exceptions.
    """

    def __init__(
        self,
        config:      ConfigManager,
        log_manager: Any = None,
    ) -> None:
        self.config    = config
        self._log      = log_manager
        self._store:   Optional[ExceptionStore] = None

    # ------------------------------------------------------------------
    # Ciclo de vida
    # ------------------------------------------------------------------

    def open(self) -> "ExceptionManager":
        db_raw   = self.config.get("logs.db_path", "/var/lib/ek-protection/ek-protection.db")
        data_dir = os.environ.get("EKP_DATA_DIR", "")
        if data_dir:
            db_raw = db_raw.replace("/var/lib/ek-protection", data_dir)

        self._store = ExceptionStore(db_raw)
        self._store.open()
        self._load_from_config()
        logger.info(
            "ExceptionManager iniciado. Entradas: %s", self._store.count()
        )
        return self

    def close(self) -> None:
        if self._store:
            self._store.close()
            self._store = None

    # ------------------------------------------------------------------
    # API de verificação — usada por scanner e heuristics
    # ------------------------------------------------------------------

    def check(
        self,
        path:    Optional[str] = None,
        sha256:  Optional[str] = None,
        process: Optional[str] = None,
        ext:     Optional[str] = None,
    ) -> MatchResult:
        """
        Verifica se o item está em qualquer lista de exceção.
        Retorna MatchResult com hit, kind e a entry que causou o match.

        Chamada pelo scanner ANTES de qualquer análise para curto-circuitar
        arquivos confiáveis e forçar alertas em blacklistados.
        """
        assert self._store, "ExceptionManager não está aberto."
        return self._store.check_all(path=path, sha256=sha256, process=process, ext=ext)

    def is_whitelisted(self, **kwargs: Any) -> bool:
        return self.check(**kwargs).is_whitelisted()

    def is_blacklisted(self, **kwargs: Any) -> bool:
        return self.check(**kwargs).is_blacklisted()

    # ------------------------------------------------------------------
    # API de adição — usada pela CLI e pelo modo crítico do scanner
    # ------------------------------------------------------------------

    def add_whitelist_path(self, path: str, comment: str = "") -> ExceptionEntry:
        return self._add(ExceptionKind.WHITELIST, ExceptionTarget.PATH, path, comment)

    def add_whitelist_hash(self, sha256: str, comment: str = "") -> ExceptionEntry:
        return self._add(ExceptionKind.WHITELIST, ExceptionTarget.HASH, sha256.lower(), comment)

    def add_whitelist_process(self, name: str, comment: str = "") -> ExceptionEntry:
        return self._add(ExceptionKind.WHITELIST, ExceptionTarget.PROCESS, name, comment)

    def add_whitelist_extension(self, ext: str, comment: str = "") -> ExceptionEntry:
        e = ext if ext.startswith(".") else f".{ext}"
        return self._add(ExceptionKind.WHITELIST, ExceptionTarget.EXTENSION, e.lower(), comment)

    def add_blacklist_path(self, path: str, comment: str = "") -> ExceptionEntry:
        return self._add(ExceptionKind.BLACKLIST, ExceptionTarget.PATH, path, comment)

    def add_blacklist_hash(self, sha256: str, comment: str = "") -> ExceptionEntry:
        return self._add(ExceptionKind.BLACKLIST, ExceptionTarget.HASH, sha256.lower(), comment)

    def remove(self, entry_id: int) -> bool:
        assert self._store
        ok = self._store.remove(entry_id)
        if ok:
            self._audit(EventType.EXCEPTION_REMOVE, f"Exceção removida: ID {entry_id}")
        return ok

    def remove_by_value(
        self,
        kind:   ExceptionKind,
        target: ExceptionTarget,
        value:  str,
    ) -> bool:
        assert self._store
        ok = self._store.remove_by_value(kind, target, value)
        if ok:
            self._audit(
                EventType.EXCEPTION_REMOVE,
                f"Exceção removida: [{kind.value}/{target.value}] {value}",
            )
        return ok

    # ------------------------------------------------------------------
    # Listagem e exportação
    # ------------------------------------------------------------------

    def list_all(
        self,
        kind:   Optional[ExceptionKind]   = None,
        target: Optional[ExceptionTarget] = None,
    ) -> list[ExceptionEntry]:
        assert self._store
        return self._store.list_all(kind=kind, target=target)

    def count(self) -> dict[str, int]:
        assert self._store
        return self._store.count()

    def export_json(self, dest: Path) -> int:
        assert self._store
        return self._store.export_json(dest)

    def import_json(self, src: Path, overwrite: bool = False) -> tuple[int, int]:
        assert self._store
        added, ignored = self._store.import_json(src, overwrite)
        self._audit(
            EventType.EXCEPTION_ADD,
            f"Importação JSON: {added} adicionadas, {ignored} ignoradas.",
        )
        return added, ignored

    def status(self) -> dict:
        counts = self.count()
        return {
            "whitelist": counts.get("whitelist", 0),
            "blacklist": counts.get("blacklist", 0),
            "total":     sum(counts.values()),
        }

    # ------------------------------------------------------------------
    # Carregamento inicial do YAML de config
    # ------------------------------------------------------------------

    def _load_from_config(self) -> None:
        """
        Lê a seção exceptions.* do config.yaml e popula o store
        se ainda não existirem entradas equivalentes.
        Permite que o administrador pré-configure exceções no YAML.
        """
        assert self._store

        cfg_paths  = self.config.get("exceptions.paths",      [])
        cfg_hashes = self.config.get("exceptions.hashes",     [])
        cfg_procs  = self.config.get("exceptions.processes",  [])
        cfg_exts   = self.config.get("exceptions.extensions", [])

        for p in cfg_paths:
            self._try_add(ExceptionKind.WHITELIST, ExceptionTarget.PATH, p, "config.yaml")
        for h in cfg_hashes:
            self._try_add(ExceptionKind.WHITELIST, ExceptionTarget.HASH, h.lower(), "config.yaml")
        for proc in cfg_procs:
            self._try_add(ExceptionKind.WHITELIST, ExceptionTarget.PROCESS, proc, "config.yaml")
        for ext in cfg_exts:
            e = ext if ext.startswith(".") else f".{ext}"
            self._try_add(ExceptionKind.WHITELIST, ExceptionTarget.EXTENSION, e.lower(), "config.yaml")

    def _try_add(
        self,
        kind:    ExceptionKind,
        target:  ExceptionTarget,
        value:   str,
        comment: str,
    ) -> None:
        """Adiciona silenciosamente; ignora se já existir."""
        try:
            self._store.add(ExceptionEntry(  # type: ignore[union-attr]
                kind=kind, target=target, value=value,
                comment=comment, added_by="config",
            ))
        except ValueError:
            pass   # já existe — ok

    # ------------------------------------------------------------------
    # Internos
    # ------------------------------------------------------------------

    def _add(
        self,
        kind:    ExceptionKind,
        target:  ExceptionTarget,
        value:   str,
        comment: str,
    ) -> ExceptionEntry:
        assert self._store
        entry = ExceptionEntry(
            kind=kind, target=target, value=value,
            comment=comment, added_by="user",
        )
        saved = self._store.add(entry)
        self._audit(
            EventType.EXCEPTION_ADD,
            f"Exceção adicionada: [{kind.value}/{target.value}] {value}",
        )
        return saved

    def _audit(self, etype: EventType, message: str) -> None:
        if self._log is None:
            return
        try:
            self._log.get_source("exceptions").event(
                etype, message, level=LogLevel.INFO
            )
        except Exception:
            pass

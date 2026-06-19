"""
ekprotection.exceptions.store
==============================
Persistência de exceções em SQLite.

Usa a mesma base de dados do sistema de logs para manter
tudo em um único arquivo, com tabela separada.

Features:
  - CRUD completo de ExceptionEntry
  - Cache em memória (dict) para lookups O(1) em hot-path
  - Thread-safe (mesmo lock pattern do LogStore)
  - Import/export JSON para backup e compartilhamento
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from datetime import datetime
from pathlib  import Path
from typing   import Optional

from .models import ExceptionEntry, ExceptionKind, ExceptionTarget, MatchResult

logger = logging.getLogger(__name__)

SCHEMA = """
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS exceptions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT    NOT NULL,
    target      TEXT    NOT NULL,
    value       TEXT    NOT NULL,
    comment     TEXT    NOT NULL DEFAULT '',
    added_at    TEXT    NOT NULL,
    added_by    TEXT    NOT NULL DEFAULT 'user',
    UNIQUE(kind, target, value)
);

CREATE INDEX IF NOT EXISTS idx_exc_kind_target ON exceptions (kind, target);
"""


class ExceptionStore:
    """
    Armazenamento persistente de exceções com cache em memória.

    O cache é reconstruído ao abrir e atualizado em cada escrita,
    garantindo lookups rápidos sem round-trips ao banco em hot-path.
    """

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = Path(db_path)
        self._lock    = threading.Lock()
        self._conn:   Optional[sqlite3.Connection] = None

        # Cache: (kind, target, value) → ExceptionEntry
        self._cache:  dict[tuple, ExceptionEntry] = {}

    # ------------------------------------------------------------------
    # Ciclo de vida
    # ------------------------------------------------------------------

    def open(self) -> "ExceptionStore":
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            str(self._db_path),
            check_same_thread=False,
            isolation_level=None,
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._rebuild_cache()
        logger.debug("ExceptionStore aberto: %s (%d entradas)", self._db_path, len(self._cache))
        return self

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> "ExceptionStore":
        return self.open()

    def __exit__(self, *_: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def add(self, entry: ExceptionEntry) -> ExceptionEntry:
        """
        Adiciona uma exceção. Lança ValueError se já existir.
        Retorna o entry com entry_id preenchido.
        """
        assert self._conn
        with self._lock:
            try:
                cur = self._conn.execute(
                    """INSERT INTO exceptions
                       (kind, target, value, comment, added_at, added_by)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        entry.kind.value, entry.target.value,
                        entry.value, entry.comment,
                        entry.added_at.isoformat(), entry.added_by,
                    ),
                )
                row_id = cur.lastrowid
            except sqlite3.IntegrityError:
                raise ValueError(
                    f"Exceção já existe: {entry.kind.value}/{entry.target.value}/{entry.value}"
                )

        saved = ExceptionEntry(
            kind=entry.kind, target=entry.target, value=entry.value,
            comment=entry.comment, added_at=entry.added_at,
            added_by=entry.added_by, entry_id=row_id,
        )
        self._cache[(entry.kind.value, entry.target.value, entry.value)] = saved
        logger.info("Exceção adicionada: [%s/%s] %s", entry.kind.value, entry.target.value, entry.value)
        return saved

    def remove(self, entry_id: int) -> bool:
        """Remove pelo ID. Retorna True se removeu, False se não encontrou."""
        assert self._conn
        # Localiza no cache para remover
        to_remove = None
        for key, e in self._cache.items():
            if e.entry_id == entry_id:
                to_remove = key
                break

        with self._lock:
            cur = self._conn.execute("DELETE FROM exceptions WHERE id = ?", (entry_id,))
            deleted = cur.rowcount > 0

        if deleted and to_remove:
            self._cache.pop(to_remove, None)
            logger.info("Exceção removida: ID %d", entry_id)
        return deleted

    def remove_by_value(
        self,
        kind:   ExceptionKind,
        target: ExceptionTarget,
        value:  str,
    ) -> bool:
        """Remove pela tripla (kind, target, value)."""
        assert self._conn
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM exceptions WHERE kind=? AND target=? AND value=?",
                (kind.value, target.value, value),
            )
            deleted = cur.rowcount > 0
        if deleted:
            self._cache.pop((kind.value, target.value, value), None)
            logger.info("Exceção removida: %s/%s/%s", kind.value, target.value, value)
        return deleted

    def list_all(
        self,
        kind:   Optional[ExceptionKind]   = None,
        target: Optional[ExceptionTarget] = None,
    ) -> list[ExceptionEntry]:
        """Lista exceções com filtro opcional por kind e/ou target."""
        assert self._conn
        conditions, params = [], []
        if kind:
            conditions.append("kind = ?")
            params.append(kind.value)
        if target:
            conditions.append("target = ?")
            params.append(target.value)

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        rows = self._conn.execute(
            f"SELECT * FROM exceptions {where} ORDER BY added_at DESC",
            params,
        ).fetchall()
        return [self._row_to_entry(r) for r in rows]

    def get_by_id(self, entry_id: int) -> Optional[ExceptionEntry]:
        assert self._conn
        row = self._conn.execute(
            "SELECT * FROM exceptions WHERE id = ?", (entry_id,)
        ).fetchone()
        return self._row_to_entry(row) if row else None

    def count(self) -> dict[str, int]:
        """Retorna contagem por kind."""
        assert self._conn
        rows = self._conn.execute(
            "SELECT kind, COUNT(*) as n FROM exceptions GROUP BY kind"
        ).fetchall()
        return {r["kind"]: r["n"] for r in rows}

    # ------------------------------------------------------------------
    # Lookup em hot-path (O(1) via cache)
    # ------------------------------------------------------------------

    def is_whitelisted_hash(self, sha256: str) -> MatchResult:
        key = (ExceptionKind.WHITELIST.value, ExceptionTarget.HASH.value, sha256.lower())
        e   = self._cache.get(key)
        return MatchResult.matched(e) if e else MatchResult.miss()

    def is_blacklisted_hash(self, sha256: str) -> MatchResult:
        key = (ExceptionKind.BLACKLIST.value, ExceptionTarget.HASH.value, sha256.lower())
        e   = self._cache.get(key)
        return MatchResult.matched(e) if e else MatchResult.miss()

    def is_whitelisted_process(self, name: str) -> MatchResult:
        key = (ExceptionKind.WHITELIST.value, ExceptionTarget.PROCESS.value, name)
        e   = self._cache.get(key)
        return MatchResult.matched(e) if e else MatchResult.miss()

    def is_whitelisted_extension(self, ext: str) -> MatchResult:
        """ext deve incluir o ponto: '.iso'"""
        key = (ExceptionKind.WHITELIST.value, ExceptionTarget.EXTENSION.value, ext.lower())
        e   = self._cache.get(key)
        return MatchResult.matched(e) if e else MatchResult.miss()

    def check_path(self, path: str, kind: ExceptionKind) -> MatchResult:
        """
        Verifica se `path` bate com alguma entrada PATH do kind especificado.
        Suporta glob (fnmatch) e prefixo de diretório.
        Cache de paths é varrido linearmente (lista pequena em prática).
        """
        import fnmatch
        target_val = ExceptionTarget.PATH.value
        for (k, t, v), entry in self._cache.items():
            if k != kind.value or t != target_val:
                continue
            # Match exato
            if path == v:
                return MatchResult.matched(entry)
            # Glob
            if fnmatch.fnmatch(path, v):
                return MatchResult.matched(entry)
            # Prefixo de diretório (v termina com /)
            if v.endswith("/") and path.startswith(v):
                return MatchResult.matched(entry)
        return MatchResult.miss()

    def is_whitelisted_path(self, path: str) -> MatchResult:
        return self.check_path(path, ExceptionKind.WHITELIST)

    def is_blacklisted_path(self, path: str) -> MatchResult:
        return self.check_path(path, ExceptionKind.BLACKLIST)

    def check_all(
        self,
        path:    Optional[str] = None,
        sha256:  Optional[str] = None,
        process: Optional[str] = None,
        ext:     Optional[str] = None,
    ) -> MatchResult:
        """
        Verificação unificada: checa hash → path → processo → extensão.
        Blacklist tem precedência sobre whitelist.
        Retorna o primeiro match encontrado, ou MatchResult.miss().

        Ordem de verificação (da mais específica para menos):
          1. Hash blacklist (certeza de ameaça)
          2. Hash whitelist (certeza de segurança)
          3. Path blacklist
          4. Path whitelist
          5. Process whitelist
          6. Extension whitelist
        """
        # 1. Hash blacklist
        if sha256:
            r = self.is_blacklisted_hash(sha256)
            if r.hit: return r

        # 2. Hash whitelist
        if sha256:
            r = self.is_whitelisted_hash(sha256)
            if r.hit: return r

        # 3. Path blacklist
        if path:
            r = self.is_blacklisted_path(path)
            if r.hit: return r

        # 4. Path whitelist
        if path:
            r = self.is_whitelisted_path(path)
            if r.hit: return r

        # 5. Process whitelist
        if process:
            r = self.is_whitelisted_process(process)
            if r.hit: return r

        # 6. Extension whitelist
        if ext:
            r = self.is_whitelisted_extension(ext)
            if r.hit: return r

        return MatchResult.miss()

    # ------------------------------------------------------------------
    # Import / Export
    # ------------------------------------------------------------------

    def export_json(self, dest: Path) -> int:
        entries = self.list_all()
        dest.write_text(
            json.dumps([e.to_dict() for e in entries], ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return len(entries)

    def import_json(self, src: Path, overwrite: bool = False) -> tuple[int, int]:
        """
        Importa exceções de JSON.
        Retorna (adicionadas, ignoradas).
        """
        data = json.loads(src.read_text(encoding="utf-8"))
        added = ignored = 0
        for item in data:
            entry = ExceptionEntry(
                kind    = ExceptionKind(item["kind"]),
                target  = ExceptionTarget(item["target"]),
                value   = item["value"],
                comment = item.get("comment", ""),
                added_by= item.get("added_by", "import"),
            )
            try:
                self.add(entry)
                added += 1
            except ValueError:
                if overwrite:
                    self.remove_by_value(entry.kind, entry.target, entry.value)
                    self.add(entry)
                    added += 1
                else:
                    ignored += 1
        return added, ignored

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _rebuild_cache(self) -> None:
        assert self._conn
        rows = self._conn.execute("SELECT * FROM exceptions").fetchall()
        self._cache = {
            (r["kind"], r["target"], r["value"]): self._row_to_entry(r)
            for r in rows
        }

    @staticmethod
    def _row_to_entry(row: sqlite3.Row) -> ExceptionEntry:
        return ExceptionEntry(
            entry_id = row["id"],
            kind     = ExceptionKind(row["kind"]),
            target   = ExceptionTarget(row["target"]),
            value    = row["value"],
            comment  = row["comment"] or "",
            added_at = datetime.fromisoformat(row["added_at"]),
            added_by = row["added_by"],
        )

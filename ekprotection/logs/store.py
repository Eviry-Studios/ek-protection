"""
ekprotection.logs.store
========================
Camada de persistência de logs: SQLite + JSONL.

Responsabilidades:
  - Criar e migrar o schema do banco
  - Gravar LogEntry de forma thread-safe
  - Consultar entradas com QueryFilter
  - Rotacionar/limpar logs antigos
  - Exportar para CSV/JSON

Design:
  - Uma única conexão SQLite com WAL mode (leituras simultâneas)
  - Threading lock para escritas concorrentes
  - JSONL append-only como backup legível por humanos
  - Índices em timestamp, level e event_type para queries rápidas
"""

from __future__ import annotations

import csv
import io
import json
import logging
import os
import sqlite3
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterator, Optional

from .models import EventType, LogEntry, LogLevel, QueryFilter

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Schema SQL
# ---------------------------------------------------------------------------

SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS log_entries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL,
    level       TEXT    NOT NULL,
    event_type  TEXT    NOT NULL,
    message     TEXT    NOT NULL,
    source      TEXT    NOT NULL DEFAULT 'core',
    pid         INTEGER NOT NULL DEFAULT 0,
    file_path   TEXT,
    sha256      TEXT,
    process     TEXT,
    extra       TEXT    NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_timestamp  ON log_entries (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_level      ON log_entries (level);
CREATE INDEX IF NOT EXISTS idx_event_type ON log_entries (event_type);
CREATE INDEX IF NOT EXISTS idx_file_path  ON log_entries (file_path)
    WHERE file_path IS NOT NULL;

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);
INSERT OR IGNORE INTO schema_version (version) VALUES (1);
"""


class LogStore:
    """
    Armazenamento persistente de logs com SQLite + JSONL.

    Thread-safe: múltiplas threads podem chamar write() simultaneamente.
    """

    def __init__(
        self,
        db_path: str | Path,
        jsonl_path: Optional[str | Path] = None,
    ) -> None:
        self._db_path   = Path(db_path)
        self._jsonl_path = Path(jsonl_path) if jsonl_path else None
        self._lock      = threading.Lock()
        self._conn:     Optional[sqlite3.Connection] = None
        self._jsonl_fh: Optional[io.TextIOWrapper]   = None

    # ------------------------------------------------------------------
    # Ciclo de vida
    # ------------------------------------------------------------------

    def open(self) -> "LogStore":
        """Abre/cria o banco e o arquivo JSONL."""
        self._db_path.parent.mkdir(parents=True, exist_ok=True)

        self._conn = sqlite3.connect(
            str(self._db_path),
            check_same_thread=False,
            isolation_level=None,   # autocommit — gerenciamos transações manualmente
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        logger.debug("LogStore aberto: %s", self._db_path)

        if self._jsonl_path:
            self._jsonl_path.parent.mkdir(parents=True, exist_ok=True)
            self._jsonl_fh = open(self._jsonl_path, "a", encoding="utf-8")

        return self

    def close(self) -> None:
        """Fecha conexões de forma limpa."""
        if self._jsonl_fh:
            self._jsonl_fh.flush()
            self._jsonl_fh.close()
            self._jsonl_fh = None
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> "LogStore":
        return self.open()

    def __exit__(self, *_: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Escrita
    # ------------------------------------------------------------------

    def write(self, entry: LogEntry) -> LogEntry:
        """
        Persiste um LogEntry no SQLite (e opcionalmente no JSONL).
        Retorna o entry com entry_id preenchido.
        Thread-safe.
        """
        assert self._conn is not None, "LogStore não está aberto."

        with self._lock:
            cursor = self._conn.execute(
                """
                INSERT INTO log_entries
                    (timestamp, level, event_type, message, source,
                     pid, file_path, sha256, process, extra)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.timestamp.isoformat(),
                    entry.level.value,
                    entry.event_type.value,
                    entry.message,
                    entry.source,
                    entry.pid,
                    entry.file_path,
                    entry.sha256,
                    entry.process,
                    json.dumps(entry.extra, ensure_ascii=False),
                ),
            )
            row_id = cursor.lastrowid

            if self._jsonl_fh:
                self._jsonl_fh.write(entry.to_json() + "\n")
                self._jsonl_fh.flush()

        # Retorna entry imutável com ID preenchido
        return LogEntry(
            level=entry.level,
            event_type=entry.event_type,
            message=entry.message,
            timestamp=entry.timestamp,
            source=entry.source,
            pid=entry.pid,
            file_path=entry.file_path,
            sha256=entry.sha256,
            process=entry.process,
            extra=entry.extra,
            entry_id=row_id,
        )

    # ------------------------------------------------------------------
    # Consulta
    # ------------------------------------------------------------------

    def query(self, f: QueryFilter) -> list[LogEntry]:
        """Retorna lista de LogEntry de acordo com o filtro."""
        assert self._conn is not None
        sql, params = self._build_query(f)
        rows = self._conn.execute(sql, params).fetchall()
        return [self._row_to_entry(r) for r in rows]

    def count(self, f: QueryFilter) -> int:
        """Conta entradas que correspondem ao filtro (sem LIMIT/OFFSET)."""
        assert self._conn is not None
        f_count = QueryFilter(
            level=f.level, event_type=f.event_type, source=f.source,
            since=f.since, until=f.until, file_path=f.file_path,
            search=f.search, limit=10**9, offset=0,
        )
        sql, params = self._build_query(f_count, count_only=True)
        row = self._conn.execute(sql, params).fetchone()
        return row[0] if row else 0

    def iter_all(self, batch_size: int = 500) -> Iterator[LogEntry]:
        """Iterador sobre todos os registros em batches (para exportação)."""
        assert self._conn is not None
        offset = 0
        while True:
            rows = self._conn.execute(
                "SELECT * FROM log_entries ORDER BY id ASC LIMIT ? OFFSET ?",
                (batch_size, offset),
            ).fetchall()
            if not rows:
                break
            for r in rows:
                yield self._row_to_entry(r)
            offset += batch_size

    # ------------------------------------------------------------------
    # Manutenção
    # ------------------------------------------------------------------

    def purge_old(self, retention_days: int) -> int:
        """
        Remove entradas mais antigas que retention_days.
        Retorna quantidade de registros removidos.
        """
        assert self._conn is not None
        cutoff = (datetime.utcnow() - timedelta(days=retention_days)).isoformat()
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM log_entries WHERE timestamp < ?", (cutoff,)
            )
            removed = cursor.rowcount
        if removed:
            self._conn.execute("VACUUM")
            logger.info("Purge: %d registros removidos (retenção: %dd)", removed, retention_days)
        return removed

    def stats(self) -> dict:
        """Estatísticas rápidas do banco."""
        assert self._conn is not None
        total = self._conn.execute("SELECT COUNT(*) FROM log_entries").fetchone()[0]
        by_level = {
            row["level"]: row["cnt"]
            for row in self._conn.execute(
                "SELECT level, COUNT(*) as cnt FROM log_entries GROUP BY level"
            ).fetchall()
        }
        oldest = self._conn.execute(
            "SELECT MIN(timestamp) FROM log_entries"
        ).fetchone()[0]
        newest = self._conn.execute(
            "SELECT MAX(timestamp) FROM log_entries"
        ).fetchone()[0]
        db_size = self._db_path.stat().st_size if self._db_path.exists() else 0
        return {
            "total_entries": total,
            "by_level":      by_level,
            "oldest":        oldest,
            "newest":        newest,
            "db_size_bytes": db_size,
            "db_path":       str(self._db_path),
        }

    # ------------------------------------------------------------------
    # Exportação
    # ------------------------------------------------------------------

    def export_json(self, dest: Path, f: Optional[QueryFilter] = None) -> int:
        """Exporta para JSON. Retorna nº de entradas exportadas."""
        entries = self.query(f or QueryFilter(limit=10**6)) if f else list(self.iter_all())
        data = [e.to_dict() for e in entries]
        dest.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        return len(data)

    def export_csv(self, dest: Path, f: Optional[QueryFilter] = None) -> int:
        """Exporta para CSV. Retorna nº de entradas exportadas."""
        entries = self.query(f or QueryFilter(limit=10**6)) if f else list(self.iter_all())
        if not entries:
            dest.write_text("", encoding="utf-8")
            return 0

        fieldnames = ["id", "timestamp", "level", "event_type", "message",
                      "source", "pid", "file_path", "sha256", "process", "extra"]
        with dest.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for e in entries:
                row = e.to_dict()
                row["extra"] = json.dumps(row.get("extra", {}))
                writer.writerow(row)
        return len(entries)

    # ------------------------------------------------------------------
    # Helpers privados
    # ------------------------------------------------------------------

    def _build_query(
        self,
        f: QueryFilter,
        count_only: bool = False,
    ) -> tuple[str, list]:
        conditions: list[str] = []
        params: list = []

        if f.level:
            conditions.append("level = ?")
            params.append(f.level.value)
        if f.event_type:
            conditions.append("event_type = ?")
            params.append(f.event_type.value)
        if f.source:
            conditions.append("source = ?")
            params.append(f.source)
        if f.since:
            conditions.append("timestamp >= ?")
            params.append(f.since.isoformat())
        if f.until:
            conditions.append("timestamp <= ?")
            params.append(f.until.isoformat())
        if f.file_path:
            conditions.append("file_path LIKE ?")
            params.append(f"%{f.file_path}%")
        if f.search:
            conditions.append("message LIKE ?")
            params.append(f"%{f.search}%")

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        if count_only:
            return f"SELECT COUNT(*) FROM log_entries {where}", params

        order = "DESC" if f.order_desc else "ASC"
        sql = (
            f"SELECT * FROM log_entries {where} "
            f"ORDER BY timestamp {order} "
            f"LIMIT ? OFFSET ?"
        )
        params.extend([f.limit, f.offset])
        return sql, params

    @staticmethod
    def _row_to_entry(row: sqlite3.Row) -> LogEntry:
        extra = {}
        try:
            extra = json.loads(row["extra"] or "{}")
        except (json.JSONDecodeError, TypeError):
            pass

        return LogEntry(
            entry_id   = row["id"],
            timestamp  = datetime.fromisoformat(row["timestamp"]),
            level      = LogLevel.from_str(row["level"]),
            event_type = EventType(row["event_type"]),
            message    = row["message"],
            source     = row["source"],
            pid        = row["pid"],
            file_path  = row["file_path"],
            sha256     = row["sha256"],
            process    = row["process"],
            extra      = extra,
        )

"""
ekprotection.quarantine.store
===============================
Persistência de metadados da quarentena em SQLite.

Armazena apenas metadados; os arquivos físicos ficam no vault.
Tabela separada na mesma DB compartilhada do projeto.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from datetime import datetime, timedelta
from pathlib  import Path
from typing   import Optional

from .models import QuarantineEntry, QuarantineReason, QuarantineStatus

logger = logging.getLogger(__name__)

SCHEMA = """
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS quarantine (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    quarantine_id   TEXT    NOT NULL UNIQUE,
    original_path   TEXT    NOT NULL,
    sha256          TEXT    NOT NULL,
    reason          TEXT    NOT NULL,
    status          TEXT    NOT NULL DEFAULT 'active',
    file_size       INTEGER,
    threat_type     TEXT,
    risk_level      TEXT,
    process_name    TEXT,
    quarantined_at  TEXT    NOT NULL,
    restored_at     TEXT,
    restored_to     TEXT,
    comment         TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_quar_status ON quarantine (status);
CREATE INDEX IF NOT EXISTS idx_quar_sha256 ON quarantine (sha256);
CREATE INDEX IF NOT EXISTS idx_quar_at     ON quarantine (quarantined_at DESC);
"""


class QuarantineStore:
    """Metadados da quarentena em SQLite."""

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = Path(db_path)
        self._lock    = threading.Lock()
        self._conn:   Optional[sqlite3.Connection] = None

    def open(self) -> "QuarantineStore":
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            str(self._db_path),
            check_same_thread=False,
            isolation_level=None,
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        return self

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> "QuarantineStore":
        return self.open()

    def __exit__(self, *_: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Escrita
    # ------------------------------------------------------------------

    def add(self, entry: QuarantineEntry) -> QuarantineEntry:
        assert self._conn
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO quarantine
                   (quarantine_id, original_path, sha256, reason, status,
                    file_size, threat_type, risk_level, process_name,
                    quarantined_at, comment)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    entry.quarantine_id, entry.original_path, entry.sha256,
                    entry.reason.value, entry.status.value,
                    entry.file_size, entry.threat_type, entry.risk_level,
                    entry.process_name, entry.quarantined_at.isoformat(),
                    entry.comment,
                ),
            )
            row_id = cur.lastrowid

        return QuarantineEntry(
            quarantine_id  = entry.quarantine_id,
            original_path  = entry.original_path,
            sha256         = entry.sha256,
            reason         = entry.reason,
            status         = entry.status,
            file_size      = entry.file_size,
            threat_type    = entry.threat_type,
            risk_level     = entry.risk_level,
            process_name   = entry.process_name,
            quarantined_at = entry.quarantined_at,
            comment        = entry.comment,
            entry_id       = row_id,
        )

    def update_status(
        self,
        quarantine_id: str,
        status:        QuarantineStatus,
        restored_to:   Optional[str]     = None,
        restored_at:   Optional[datetime] = None,
    ) -> bool:
        assert self._conn
        with self._lock:
            cur = self._conn.execute(
                """UPDATE quarantine SET status=?, restored_to=?, restored_at=?
                   WHERE quarantine_id=?""",
                (
                    status.value,
                    restored_to,
                    restored_at.isoformat() if restored_at else None,
                    quarantine_id,
                ),
            )
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Consulta
    # ------------------------------------------------------------------

    def get(self, quarantine_id: str) -> Optional[QuarantineEntry]:
        assert self._conn
        row = self._conn.execute(
            "SELECT * FROM quarantine WHERE quarantine_id=?", (quarantine_id,)
        ).fetchone()
        return self._row(row) if row else None

    def get_by_id(self, entry_id: int) -> Optional[QuarantineEntry]:
        assert self._conn
        row = self._conn.execute(
            "SELECT * FROM quarantine WHERE id=?", (entry_id,)
        ).fetchone()
        return self._row(row) if row else None

    def list_all(
        self,
        status: Optional[QuarantineStatus] = None,
        limit:  int = 200,
    ) -> list[QuarantineEntry]:
        assert self._conn
        if status:
            rows = self._conn.execute(
                "SELECT * FROM quarantine WHERE status=? ORDER BY quarantined_at DESC LIMIT ?",
                (status.value, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM quarantine ORDER BY quarantined_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._row(r) for r in rows]

    def find_by_sha256(self, sha256: str) -> list[QuarantineEntry]:
        assert self._conn
        rows = self._conn.execute(
            "SELECT * FROM quarantine WHERE sha256=? ORDER BY quarantined_at DESC",
            (sha256,),
        ).fetchall()
        return [self._row(r) for r in rows]

    def stats(self) -> dict:
        assert self._conn
        total   = self._conn.execute("SELECT COUNT(*) FROM quarantine").fetchone()[0]
        active  = self._conn.execute(
            "SELECT COUNT(*) FROM quarantine WHERE status='active'"
        ).fetchone()[0]
        by_reason = {
            r["reason"]: r["cnt"]
            for r in self._conn.execute(
                "SELECT reason, COUNT(*) as cnt FROM quarantine GROUP BY reason"
            ).fetchall()
        }
        total_bytes = self._conn.execute(
            "SELECT COALESCE(SUM(file_size),0) FROM quarantine WHERE status='active'"
        ).fetchone()[0]
        return {
            "total":        total,
            "active":       active,
            "restored":     total - active,
            "by_reason":    by_reason,
            "total_bytes":  total_bytes,
        }

    def purge_old(self, retention_days: int) -> list[str]:
        """
        Retorna lista de quarantine_ids com status DELETED e mais antigos que
        retention_days. Não remove do banco — o manager remove o arquivo físico
        primeiro, depois chama remove_record().
        """
        assert self._conn
        cutoff = (datetime.utcnow() - timedelta(days=retention_days)).isoformat()
        rows = self._conn.execute(
            """SELECT quarantine_id FROM quarantine
               WHERE status IN ('deleted','restored') AND quarantined_at < ?""",
            (cutoff,),
        ).fetchall()
        return [r["quarantine_id"] for r in rows]

    def remove_record(self, quarantine_id: str) -> bool:
        assert self._conn
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM quarantine WHERE quarantine_id=?", (quarantine_id,)
            )
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Helper
    # ------------------------------------------------------------------

    @staticmethod
    def _row(row: sqlite3.Row) -> QuarantineEntry:
        return QuarantineEntry(
            entry_id       = row["id"],
            quarantine_id  = row["quarantine_id"],
            original_path  = row["original_path"],
            sha256         = row["sha256"],
            reason         = QuarantineReason(row["reason"]),
            status         = QuarantineStatus(row["status"]),
            file_size      = row["file_size"],
            threat_type    = row["threat_type"],
            risk_level     = row["risk_level"],
            process_name   = row["process_name"],
            quarantined_at = datetime.fromisoformat(row["quarantined_at"]),
            restored_at    = datetime.fromisoformat(row["restored_at"]) if row["restored_at"] else None,
            restored_to    = row["restored_to"],
            comment        = row["comment"] or "",
        )

"""
ekprotection.scanner.signatures
==================================
Banco de assinaturas de ameaças.

Estrutura:
  - Tabela SQLite `signatures` com hash SHA-256 de arquivos maliciosos
  - Tabela `signature_meta` com metadados da base (versão, data)
  - API para lookup O(1) por hash

Fontes de assinaturas (Patch 9 implementará o download automático):
  - Arquivo JSON/JSONL baixado do repositório
  - Import manual de listas de IOCs

Por ora, inclui um conjunto mínimo de hashes de teste/demo para
validar a pipeline de detecção end-to-end.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from datetime import datetime
from pathlib  import Path
from typing   import Optional

logger = logging.getLogger(__name__)

SCHEMA = """
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS signatures (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256      TEXT    NOT NULL UNIQUE,
    name        TEXT    NOT NULL,
    threat_type TEXT    NOT NULL DEFAULT 'Generic.Malware',
    severity    TEXT    NOT NULL DEFAULT 'alto',
    source      TEXT    NOT NULL DEFAULT 'ekp-community',
    added_at    TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sig_sha256 ON signatures (sha256);

CREATE TABLE IF NOT EXISTS signature_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT OR IGNORE INTO signature_meta (key, value)
    VALUES ('version', '0.0.0'), ('updated_at', ''), ('count', '0');
"""

# Assinaturas de demonstração (hashes fictícios para validar a pipeline)
# Em produção, substituídas por hashes reais via Patch 9
_DEMO_SIGNATURES = [
    {
        # SHA-256 real do arquivo de teste EICAR padrão da indústria
        # (string pública, inofensiva, feita especificamente pra ser
        # detectada por antivírus — não é malware de verdade).
        "sha256":      "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        "name":        "EICAR.Test.File",
        "threat_type": "Test.Signature",
        "severity":    "baixo",
        "source":      "ekp-demo",
    },
    {
        "sha256":      "demo_trojan_downloader_sha256_placeholder_000000000000000000002",
        "name":        "Trojan.Downloader.Demo",
        "threat_type": "Trojan.Downloader",
        "severity":    "crítico",
        "source":      "ekp-demo",
    },
    {
        "sha256":      "demo_coinminer_sha256_placeholder_00000000000000000000000003",
        "name":        "CoinMiner.XMR.Demo",
        "threat_type": "CoinMiner",
        "severity":    "alto",
        "source":      "ekp-demo",
    },
]


class SignatureDB:
    """
    Banco de assinaturas SHA-256 para o scanner.

    Thread-safe: múltiplas threads podem chamar lookup() simultaneamente
    (WAL mode permite leituras concorrentes no SQLite).
    """

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = Path(db_path)
        self._lock    = threading.Lock()
        self._conn:   Optional[sqlite3.Connection] = None

    def open(self) -> "SignatureDB":
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            str(self._db_path),
            check_same_thread=False,
            isolation_level=None,
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._seed_demo()
        logger.debug(
            "SignatureDB aberta: %s (%d assinaturas)", self._db_path, self.count()
        )
        return self

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> "SignatureDB":
        return self.open()

    def __exit__(self, *_: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Lookup principal
    # ------------------------------------------------------------------

    def lookup(self, sha256: str) -> Optional[dict]:
        """
        Verifica se o hash está na base de assinaturas.
        Retorna dicionário com metadados da ameaça, ou None se não encontrado.
        Lookup O(1) via índice SQLite.
        """
        assert self._conn
        row = self._conn.execute(
            "SELECT * FROM signatures WHERE sha256 = ?", (sha256.lower(),)
        ).fetchone()
        if row is None:
            return None
        return {
            "sha256":      row["sha256"],
            "name":        row["name"],
            "threat_type": row["threat_type"],
            "severity":    row["severity"],
            "source":      row["source"],
            "added_at":    row["added_at"],
        }

    def is_known_threat(self, sha256: str) -> bool:
        return self.lookup(sha256) is not None

    # ------------------------------------------------------------------
    # Manutenção
    # ------------------------------------------------------------------

    def add(self, sha256: str, name: str, threat_type: str = "Generic.Malware",
            severity: str = "alto", source: str = "manual") -> bool:
        """Adiciona assinatura. Retorna True se adicionou, False se já existia."""
        assert self._conn
        try:
            with self._lock:
                self._conn.execute(
                    """INSERT INTO signatures (sha256, name, threat_type, severity, source, added_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (sha256.lower(), name, threat_type, severity, source,
                     datetime.utcnow().isoformat()),
                )
            self._update_count()
            return True
        except sqlite3.IntegrityError:
            return False

    def remove(self, sha256: str) -> bool:
        assert self._conn
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM signatures WHERE sha256 = ?", (sha256.lower(),)
            )
        if cur.rowcount:
            self._update_count()
            return True
        return False

    def count(self) -> int:
        assert self._conn
        return self._conn.execute("SELECT COUNT(*) FROM signatures").fetchone()[0]

    def meta(self) -> dict:
        assert self._conn
        rows = self._conn.execute("SELECT key, value FROM signature_meta").fetchall()
        return {r["key"]: r["value"] for r in rows}

    def import_jsonl(self, path: Path) -> tuple[int, int]:
        """
        Importa assinaturas de arquivo JSONL (uma por linha).
        Retorna (adicionadas, duplicatas).
        """
        added = dupes = 0
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                    ok   = self.add(
                        sha256      = item["sha256"],
                        name        = item.get("name", "Unknown"),
                        threat_type = item.get("threat_type", "Generic.Malware"),
                        severity    = item.get("severity", "alto"),
                        source      = item.get("source", "import"),
                    )
                    if ok: added += 1
                    else:  dupes += 1
                except (json.JSONDecodeError, KeyError):
                    pass
        logger.info("SignatureDB import: %d adicionadas, %d duplicatas.", added, dupes)
        return added, dupes

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _seed_demo(self) -> None:
        """Popula assinaturas de demonstração se a base estiver vazia."""
        if self.count() > 0:
            return
        for sig in _DEMO_SIGNATURES:
            self.add(**sig)
        logger.debug("Assinaturas de demonstração carregadas: %d", len(_DEMO_SIGNATURES))

    def _update_count(self) -> None:
        assert self._conn
        n = self.count()
        self._conn.execute(
            "UPDATE signature_meta SET value=? WHERE key='count'", (str(n),)
        )

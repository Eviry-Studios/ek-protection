"""
tests/test_quarantine.py
=========================
Testes do sistema de quarentena (Patch 6).

Cobre:
  - QuarantineEntry: criação, to_dict, imutabilidade
  - QuarantineVault: initialize, quarantine, restore, delete,
                     magic validation, corruption handling,
                     modo sem criptografia
  - QuarantineStore: CRUD completo, update_status, find_by_sha256,
                     stats, purge_old, remove_record
  - QuarantineManager: open/close, quarantine_file, restore (auth),
                       delete_permanently (auth), list, stats, purge
"""

from __future__ import annotations

import os
import secrets
from datetime import datetime, timedelta
from pathlib  import Path
from typing   import Generator
from unittest.mock import MagicMock, patch

import pytest

from ekprotection.config.manager       import ConfigManager
from ekprotection.quarantine.models    import (
    QuarantineEntry, QuarantineReason, QuarantineStatus,
)
from ekprotection.quarantine.vault     import (
    QuarantineVault, VaultError, VaultKeyError, VaultCorruptedError, MAGIC,
)
from ekprotection.quarantine.store     import QuarantineStore
from ekprotection.quarantine.manager   import QuarantineManager, QuarantineError


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_file(tmp_path: Path) -> Path:
    """Arquivo temporário com conteúdo aleatório."""
    f = tmp_path / "test_malware.sh"
    f.write_bytes(secrets.token_bytes(512))
    return f


@pytest.fixture
def vault(tmp_path: Path) -> QuarantineVault:
    v = QuarantineVault(
        vault_dir = tmp_path / "vault",
        key_dir   = tmp_path / "keys",
        encrypt   = True,
    )
    v.initialize()
    return v


@pytest.fixture
def vault_noenc(tmp_path: Path) -> QuarantineVault:
    """Vault sem criptografia para testes mais rápidos."""
    v = QuarantineVault(
        vault_dir = tmp_path / "vault_plain",
        key_dir   = tmp_path / "keys_plain",
        encrypt   = False,
    )
    v.initialize()
    return v


@pytest.fixture
def store(tmp_path: Path) -> Generator[QuarantineStore, None, None]:
    s = QuarantineStore(tmp_path / "quar.db")
    s.open()
    yield s
    s.close()


@pytest.fixture
def cfg(tmp_path: Path) -> ConfigManager:
    os.environ["EKP_DATA_DIR"] = str(tmp_path)
    m = ConfigManager(tmp_path / "config.yaml")
    m.load()
    m.set("logs.db_path",            str(tmp_path / "test.db"))
    m.set("quarantine.dir",          str(tmp_path / "quarantine"))
    m.set("quarantine.encrypt",      False)   # sem cripto nos testes de manager
    m.set("quarantine.retention_days", 30)
    m.set("auth.require_for_critical", False)   # sem auth nos testes básicos
    yield m
    os.environ.pop("EKP_DATA_DIR", None)


@pytest.fixture
def mgr(cfg: ConfigManager) -> Generator[QuarantineManager, None, None]:
    m = QuarantineManager(cfg)
    m.open()
    yield m
    m.close()


def _entry(
    path:   str  = "/tmp/evil.sh",
    sha256: str  = "aabbccdd" * 8,
    reason: QuarantineReason = QuarantineReason.USER_MANUAL,
    qid:    str  = None,
) -> QuarantineEntry:
    return QuarantineEntry(
        quarantine_id = qid or secrets.token_hex(16),
        original_path = path,
        sha256        = sha256,
        reason        = reason,
    )


# ---------------------------------------------------------------------------
# Testes: QuarantineEntry
# ---------------------------------------------------------------------------

class TestQuarantineEntry:
    def test_basic_creation(self) -> None:
        e = _entry()
        assert e.status         == QuarantineStatus.ACTIVE
        assert e.entry_id       is None
        assert isinstance(e.quarantined_at, datetime)

    def test_to_dict_keys(self) -> None:
        e = _entry()
        d = e.to_dict()
        for key in ("id", "quarantine_id", "original_path", "sha256",
                    "reason", "status", "quarantined_at"):
            assert key in d

    def test_to_dict_values(self) -> None:
        e = _entry(path="/home/user/bad.sh", reason=QuarantineReason.SIGNATURE_MATCH)
        d = e.to_dict()
        assert d["original_path"] == "/home/user/bad.sh"
        assert d["reason"]        == "signature_match"
        assert d["status"]        == "active"

    def test_immutable(self) -> None:
        e = _entry()
        with pytest.raises((AttributeError, TypeError)):
            e.original_path = "/changed"  # type: ignore[misc]

    def test_all_reasons_constructable(self) -> None:
        for reason in QuarantineReason:
            e = _entry(reason=reason)
            assert e.reason == reason

    def test_all_statuses_constructable(self) -> None:
        for status in QuarantineStatus:
            e = QuarantineEntry(
                quarantine_id="x", original_path="/x",
                sha256="y", reason=QuarantineReason.USER_MANUAL,
                status=status,
            )
            assert e.status == status


# ---------------------------------------------------------------------------
# Testes: QuarantineVault
# ---------------------------------------------------------------------------

class TestQuarantineVaultInit:
    def test_initialize_creates_dirs(self, tmp_path: Path) -> None:
        v = QuarantineVault(tmp_path / "v", tmp_path / "k")
        v.initialize()
        assert (tmp_path / "v").exists()
        assert (tmp_path / "k").exists()

    def test_initialize_creates_key_file(self, tmp_path: Path) -> None:
        v = QuarantineVault(tmp_path / "v", tmp_path / "k")
        v.initialize()
        key_file = tmp_path / "k" / "quarantine.key"
        assert key_file.exists()
        assert key_file.stat().st_size > 0

    def test_initialize_idempotent(self, tmp_path: Path) -> None:
        v = QuarantineVault(tmp_path / "v", tmp_path / "k")
        v.initialize()
        v.initialize()   # segunda chamada não deve lançar ou sobrescrever chave
        assert (tmp_path / "k" / "quarantine.key").exists()

    def test_load_key_missing_raises(self, tmp_path: Path) -> None:
        v = QuarantineVault(tmp_path / "v", tmp_path / "k")
        with pytest.raises(VaultKeyError):
            v._load_key()


class TestQuarantineVaultOperations:
    def test_quarantine_creates_ekpq_file(self, vault: QuarantineVault, tmp_file: Path) -> None:
        qid  = secrets.token_hex(16)
        dest = vault.quarantine(tmp_file, qid)
        assert dest.exists()
        assert dest.suffix == ".ekpq"

    def test_quarantine_file_starts_with_magic(self, vault: QuarantineVault, tmp_file: Path) -> None:
        qid  = secrets.token_hex(16)
        dest = vault.quarantine(tmp_file, qid)
        assert dest.read_bytes().startswith(MAGIC)

    def test_quarantine_encrypted_content_differs(self, vault: QuarantineVault, tmp_file: Path) -> None:
        original = tmp_file.read_bytes()
        qid      = secrets.token_hex(16)
        dest     = vault.quarantine(tmp_file, qid)
        assert dest.read_bytes()[len(MAGIC):] != original

    def test_quarantine_does_not_remove_original(self, vault: QuarantineVault, tmp_file: Path) -> None:
        qid = secrets.token_hex(16)
        vault.quarantine(tmp_file, qid)
        assert tmp_file.exists()   # vault.quarantine nunca remove — manager decide

    def test_restore_recovers_exact_content(self, vault: QuarantineVault, tmp_file: Path, tmp_path: Path) -> None:
        original = tmp_file.read_bytes()
        qid = secrets.token_hex(16)
        vault.quarantine(tmp_file, qid)
        restored = vault.restore(qid, tmp_path / "restored_file")
        assert restored.read_bytes() == original

    def test_restore_nonexistent_raises(self, vault: QuarantineVault, tmp_path: Path) -> None:
        with pytest.raises(VaultError, match="não encontrado"):
            vault.restore("nonexistent_id", tmp_path / "out")

    def test_delete_removes_file(self, vault: QuarantineVault, tmp_file: Path) -> None:
        qid  = secrets.token_hex(16)
        dest = vault.quarantine(tmp_file, qid)
        assert vault.delete_file(qid) is True
        assert not dest.exists()

    def test_delete_missing_returns_false(self, vault: QuarantineVault) -> None:
        assert vault.delete_file("nonexistent") is False

    def test_file_exists(self, vault: QuarantineVault, tmp_file: Path) -> None:
        qid = secrets.token_hex(16)
        assert not vault.file_exists(qid)
        vault.quarantine(tmp_file, qid)
        assert vault.file_exists(qid)

    def test_corrupted_magic_raises(self, vault: QuarantineVault, tmp_file: Path, tmp_path: Path) -> None:
        qid  = secrets.token_hex(16)
        dest = vault.quarantine(tmp_file, qid)
        # Sobrescreve magic com lixo
        bad  = b"XXXX" + dest.read_bytes()[4:]
        dest.write_bytes(bad)
        with pytest.raises(VaultCorruptedError):
            vault.restore(qid, tmp_path / "out")

    def test_no_encrypt_roundtrip(self, vault_noenc: QuarantineVault, tmp_file: Path, tmp_path: Path) -> None:
        original = tmp_file.read_bytes()
        qid = secrets.token_hex(16)
        vault_noenc.quarantine(tmp_file, qid)
        restored = vault_noenc.restore(qid, tmp_path / "plain_out")
        assert restored.read_bytes() == original

    def test_quarantine_missing_file_raises(self, vault: QuarantineVault, tmp_path: Path) -> None:
        with pytest.raises(VaultError, match="não encontrado"):
            vault.quarantine("/nonexistent/path/file.sh", "someid")


# ---------------------------------------------------------------------------
# Testes: QuarantineStore
# ---------------------------------------------------------------------------

class TestQuarantineStore:
    def test_add_returns_entry_with_id(self, store: QuarantineStore) -> None:
        e = store.add(_entry())
        assert e.entry_id is not None
        assert e.entry_id >= 1

    def test_add_persists_all_fields(self, store: QuarantineStore) -> None:
        original = _entry(
            path   = "/home/user/evil.sh",
            sha256 = "cafebabe" * 8,
            reason = QuarantineReason.HEURISTIC,
        )
        saved   = store.add(original)
        fetched = store.get(saved.quarantine_id)
        assert fetched is not None
        assert fetched.original_path == "/home/user/evil.sh"
        assert fetched.sha256        == "cafebabe" * 8
        assert fetched.reason        == QuarantineReason.HEURISTIC
        assert fetched.status        == QuarantineStatus.ACTIVE

    def test_get_by_id(self, store: QuarantineStore) -> None:
        e = store.add(_entry())
        fetched = store.get_by_id(e.entry_id)  # type: ignore[arg-type]
        assert fetched is not None
        assert fetched.quarantine_id == e.quarantine_id

    def test_get_missing_returns_none(self, store: QuarantineStore) -> None:
        assert store.get("nonexistent_id") is None

    def test_update_status_to_restored(self, store: QuarantineStore) -> None:
        e  = store.add(_entry())
        ok = store.update_status(
            e.quarantine_id,
            QuarantineStatus.RESTORED,
            restored_to="/home/user/safe/",
            restored_at=datetime.utcnow(),
        )
        assert ok is True
        updated = store.get(e.quarantine_id)
        assert updated is not None
        assert updated.status      == QuarantineStatus.RESTORED
        assert updated.restored_to == "/home/user/safe/"
        assert updated.restored_at is not None

    def test_update_status_nonexistent_returns_false(self, store: QuarantineStore) -> None:
        ok = store.update_status("nope", QuarantineStatus.DELETED)
        assert ok is False

    def test_list_all_empty(self, store: QuarantineStore) -> None:
        assert store.list_all() == []

    def test_list_all_returns_all(self, store: QuarantineStore) -> None:
        for i in range(5):
            store.add(_entry(path=f"/tmp/evil{i}.sh"))
        assert len(store.list_all()) == 5

    def test_list_filter_by_status(self, store: QuarantineStore) -> None:
        e1 = store.add(_entry(path="/tmp/a.sh"))
        e2 = store.add(_entry(path="/tmp/b.sh"))
        store.update_status(e1.quarantine_id, QuarantineStatus.RESTORED)
        active = store.list_all(status=QuarantineStatus.ACTIVE)
        assert len(active) == 1
        assert active[0].quarantine_id == e2.quarantine_id

    def test_find_by_sha256(self, store: QuarantineStore) -> None:
        sha = "deaddead" * 8
        store.add(_entry(sha256=sha, path="/tmp/a.sh"))
        store.add(_entry(sha256=sha, path="/tmp/b.sh"))
        store.add(_entry(sha256="other" * 10, path="/tmp/c.sh"))
        results = store.find_by_sha256(sha)
        assert len(results) == 2
        assert all(r.sha256 == sha for r in results)

    def test_stats_counts(self, store: QuarantineStore) -> None:
        e1 = store.add(_entry(path="/tmp/a.sh"))
        e2 = store.add(_entry(path="/tmp/b.sh", reason=QuarantineReason.HEURISTIC))
        store.update_status(e1.quarantine_id, QuarantineStatus.RESTORED)
        s = store.stats()
        assert s["total"]    == 2
        assert s["active"]   == 1
        assert s["restored"] == 1

    def test_purge_old_returns_ids(self, store: QuarantineStore) -> None:
        e = store.add(_entry())
        store.update_status(e.quarantine_id, QuarantineStatus.DELETED)
        # Simula entrada antiga retroagindo no banco
        old_ts = (datetime.utcnow() - timedelta(days=60)).isoformat()
        store._conn.execute(
            "UPDATE quarantine SET quarantined_at=? WHERE quarantine_id=?",
            (old_ts, e.quarantine_id),
        )
        ids = store.purge_old(30)
        assert e.quarantine_id in ids

    def test_remove_record(self, store: QuarantineStore) -> None:
        e = store.add(_entry())
        assert store.remove_record(e.quarantine_id) is True
        assert store.get(e.quarantine_id) is None


# ---------------------------------------------------------------------------
# Testes: QuarantineManager
# ---------------------------------------------------------------------------

class TestQuarantineManager:
    def test_open_close(self, mgr: QuarantineManager) -> None:
        assert mgr._store is not None
        assert mgr._vault is not None

    def test_quarantine_file(self, mgr: QuarantineManager, tmp_file: Path) -> None:
        entry = mgr.quarantine_file(
            path         = str(tmp_file),
            sha256       = "aabbccdd" * 8,
            reason       = QuarantineReason.USER_MANUAL,
            remove_original = False,
        )
        assert entry.entry_id       is not None
        assert entry.quarantine_id  != ""
        assert entry.status         == QuarantineStatus.ACTIVE
        assert entry.original_path  == str(tmp_file.resolve())

    def test_quarantine_removes_original_when_requested(
        self, mgr: QuarantineManager, tmp_file: Path
    ) -> None:
        mgr.quarantine_file(
            path   = str(tmp_file),
            sha256 = "abc" * 20,
            reason = QuarantineReason.USER_MANUAL,
            remove_original = True,
        )
        assert not tmp_file.exists()

    def test_quarantine_missing_file_raises(self, mgr: QuarantineManager) -> None:
        with pytest.raises(QuarantineError, match="não encontrado"):
            mgr.quarantine_file(
                path   = "/nonexistent/file.sh",
                sha256 = "xyz",
                reason = QuarantineReason.USER_MANUAL,
            )

    def test_quarantine_and_restore(self, mgr: QuarantineManager, tmp_file: Path, tmp_path: Path) -> None:
        original_bytes = tmp_file.read_bytes()
        entry = mgr.quarantine_file(
            path    = str(tmp_file),
            sha256  = "abc" * 20,
            reason  = QuarantineReason.USER_MANUAL,
            remove_original = False,
        )
        restored = mgr.restore(entry.quarantine_id, dest_dir=str(tmp_path / "restored"))
        assert restored.read_bytes() == original_bytes

    def test_restore_updates_status(self, mgr: QuarantineManager, tmp_file: Path, tmp_path: Path) -> None:
        entry = mgr.quarantine_file(
            path    = str(tmp_file),
            sha256  = "abc" * 20,
            reason  = QuarantineReason.USER_MANUAL,
            remove_original = False,
        )
        mgr.restore(entry.quarantine_id, dest_dir=str(tmp_path / "r"))
        updated = mgr.get(entry.quarantine_id)
        assert updated is not None
        assert updated.status == QuarantineStatus.RESTORED

    def test_restore_nonexistent_raises(self, mgr: QuarantineManager, tmp_path: Path) -> None:
        with pytest.raises(QuarantineError):
            mgr.restore("nonexistent_id", dest_dir=str(tmp_path))

    def test_restore_non_active_raises(self, mgr: QuarantineManager, tmp_file: Path, tmp_path: Path) -> None:
        entry = mgr.quarantine_file(
            path    = str(tmp_file),
            sha256  = "abc" * 20,
            reason  = QuarantineReason.USER_MANUAL,
            remove_original = False,
        )
        mgr.restore(entry.quarantine_id, dest_dir=str(tmp_path / "r1"))
        with pytest.raises(QuarantineError, match="não está ativo"):
            mgr.restore(entry.quarantine_id, dest_dir=str(tmp_path / "r2"))

    def test_delete_permanently(self, mgr: QuarantineManager, tmp_file: Path) -> None:
        entry = mgr.quarantine_file(
            path    = str(tmp_file),
            sha256  = "abc" * 20,
            reason  = QuarantineReason.USER_MANUAL,
            remove_original = False,
        )
        mgr.delete_permanently(entry.quarantine_id)
        updated = mgr.get(entry.quarantine_id)
        assert updated is not None
        assert updated.status == QuarantineStatus.DELETED
        assert not mgr._vault.file_exists(entry.quarantine_id)  # type: ignore[union-attr]

    def test_delete_nonexistent_raises(self, mgr: QuarantineManager) -> None:
        with pytest.raises(QuarantineError):
            mgr.delete_permanently("nonexistent_id")

    def test_list_active(self, mgr: QuarantineManager, tmp_file: Path, tmp_path: Path) -> None:
        e1 = mgr.quarantine_file(str(tmp_file), "a"*64, QuarantineReason.USER_MANUAL, remove_original=False)
        f2 = tmp_path / "b.sh"; f2.write_bytes(b"content2")
        e2 = mgr.quarantine_file(str(f2),    "b"*64, QuarantineReason.USER_MANUAL, remove_original=False)
        mgr.restore(e1.quarantine_id, dest_dir=str(tmp_path / "r"))
        active = mgr.list_active()
        assert len(active) == 1
        assert active[0].quarantine_id == e2.quarantine_id

    def test_find_by_hash(self, mgr: QuarantineManager, tmp_file: Path, tmp_path: Path) -> None:
        sha = "cafecafe" * 8
        mgr.quarantine_file(str(tmp_file), sha, QuarantineReason.SIGNATURE_MATCH, remove_original=False)
        f2 = tmp_path / "c.sh"; f2.write_bytes(b"other")
        mgr.quarantine_file(str(f2), sha, QuarantineReason.HEURISTIC, remove_original=False)
        results = mgr.find_by_hash(sha)
        assert len(results) == 2

    def test_stats(self, mgr: QuarantineManager, tmp_file: Path) -> None:
        mgr.quarantine_file(str(tmp_file), "x"*64, QuarantineReason.USER_MANUAL, remove_original=False)
        s = mgr.stats()
        assert s["active"] >= 1
        assert s["total"]  >= 1

    def test_quarantine_with_auth_required(self, cfg: ConfigManager, tmp_file: Path, tmp_path: Path) -> None:
        """Quando auth está habilitado, restore sem token deve falhar."""
        cfg.set("auth.require_for_critical", True)

        mock_auth = MagicMock()
        from ekprotection.auth.manager import AuthSessionExpiredError
        mock_auth.require.side_effect = AuthSessionExpiredError("sem sessão")

        m = QuarantineManager(cfg, auth_manager=mock_auth)
        m.open()
        entry = m.quarantine_file(
            str(tmp_file), "abc"*20, QuarantineReason.USER_MANUAL, remove_original=False
        )
        with pytest.raises(PermissionError):
            m.restore(entry.quarantine_id, dest_dir=str(tmp_path / "r"), token=None)
        m.close()

    def test_quarantine_with_valid_token(self, cfg: ConfigManager, tmp_file: Path, tmp_path: Path) -> None:
        """Com token válido, restore deve funcionar mesmo com auth habilitado."""
        cfg.set("auth.require_for_critical", True)

        mock_auth = MagicMock()
        mock_auth.require.return_value = None   # não lança = autenticado

        m = QuarantineManager(cfg, auth_manager=mock_auth)
        m.open()
        entry = m.quarantine_file(
            str(tmp_file), "abc"*20, QuarantineReason.USER_MANUAL, remove_original=False
        )
        restored = m.restore(entry.quarantine_id, dest_dir=str(tmp_path / "r"), token="valid_token")
        assert restored.exists()
        mock_auth.require.assert_called_once_with("valid_token")
        m.close()

    def test_purge_old_removes_restored_entries(
        self, mgr: QuarantineManager, tmp_file: Path, tmp_path: Path
    ) -> None:
        entry = mgr.quarantine_file(
            str(tmp_file), "abc"*20, QuarantineReason.USER_MANUAL, remove_original=False
        )
        mgr.restore(entry.quarantine_id, dest_dir=str(tmp_path / "r"))

        # Retroage o timestamp para simular entrada antiga
        mgr._store._conn.execute(  # type: ignore[union-attr]
            "UPDATE quarantine SET quarantined_at=? WHERE quarantine_id=?",
            ((datetime.utcnow() - timedelta(days=60)).isoformat(), entry.quarantine_id),
        )
        removed = mgr.purge_old()
        assert removed == 1

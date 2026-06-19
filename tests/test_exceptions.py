"""
tests/test_exceptions.py
=========================
Testes do sistema de exceções (Patch 5).

Cobre:
  - ExceptionEntry: criação, imutabilidade, to_dict
  - MatchResult: miss, matched, is_whitelisted, is_blacklisted
  - ExceptionStore: CRUD, cache, check_all (ordem de precedência),
                    glob/prefixo, export/import JSON, thread-safety
  - ExceptionManager: open/close, add_* helpers, check, remove,
                      _load_from_config, auditoria via log_manager
"""

from __future__ import annotations

import json
import threading
from datetime import datetime
from pathlib  import Path
from typing   import Generator
from unittest.mock import MagicMock, patch

import pytest

from ekprotection.config.manager      import ConfigManager
from ekprotection.exceptions.models   import (
    ExceptionEntry, ExceptionKind, ExceptionTarget, MatchResult,
)
from ekprotection.exceptions.store    import ExceptionStore
from ekprotection.exceptions.manager  import ExceptionManager


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def store(tmp_path: Path) -> Generator[ExceptionStore, None, None]:
    s = ExceptionStore(tmp_path / "exc.db")
    s.open()
    yield s
    s.close()


@pytest.fixture
def cfg(tmp_path: Path) -> ConfigManager:
    import os
    os.environ["EKP_DATA_DIR"] = str(tmp_path)
    m = ConfigManager(tmp_path / "config.yaml")
    m.load()
    m.set("logs.db_path", str(tmp_path / "test.db"))
    m.set("exceptions.paths",      [])
    m.set("exceptions.hashes",     [])
    m.set("exceptions.processes",  [])
    m.set("exceptions.extensions", [])
    yield m
    os.environ.pop("EKP_DATA_DIR", None)


@pytest.fixture
def mgr(cfg: ConfigManager) -> Generator[ExceptionManager, None, None]:
    m = ExceptionManager(cfg)
    m.open()
    yield m
    m.close()


def _entry(
    kind:    ExceptionKind   = ExceptionKind.WHITELIST,
    target:  ExceptionTarget = ExceptionTarget.PATH,
    value:   str             = "/tmp/safe",
    comment: str             = "test",
) -> ExceptionEntry:
    return ExceptionEntry(kind=kind, target=target, value=value, comment=comment)


# ---------------------------------------------------------------------------
# Testes: ExceptionEntry
# ---------------------------------------------------------------------------

class TestExceptionEntry:
    def test_basic_creation(self) -> None:
        e = _entry()
        assert e.kind    == ExceptionKind.WHITELIST
        assert e.target  == ExceptionTarget.PATH
        assert e.value   == "/tmp/safe"
        assert e.comment == "test"
        assert e.entry_id is None

    def test_default_timestamp_is_recent(self) -> None:
        before = datetime.utcnow()
        e = _entry()
        after  = datetime.utcnow()
        assert before <= e.added_at <= after

    def test_immutable(self) -> None:
        e = _entry()
        with pytest.raises((AttributeError, TypeError)):
            e.value = "changed"  # type: ignore[misc]

    def test_to_dict_has_all_keys(self) -> None:
        e = _entry()
        d = e.to_dict()
        for key in ("id", "kind", "target", "value", "comment", "added_at", "added_by"):
            assert key in d

    def test_to_dict_values(self) -> None:
        e = _entry(kind=ExceptionKind.BLACKLIST, target=ExceptionTarget.HASH, value="abc123")
        d = e.to_dict()
        assert d["kind"]   == "blacklist"
        assert d["target"] == "hash"
        assert d["value"]  == "abc123"


# ---------------------------------------------------------------------------
# Testes: MatchResult
# ---------------------------------------------------------------------------

class TestMatchResult:
    def test_miss(self) -> None:
        r = MatchResult.miss()
        assert r.hit  is False
        assert r.kind is None
        assert r.entry is None

    def test_matched_whitelist(self) -> None:
        e = _entry(kind=ExceptionKind.WHITELIST)
        r = MatchResult.matched(e)
        assert r.hit             is True
        assert r.kind            == ExceptionKind.WHITELIST
        assert r.is_whitelisted() is True
        assert r.is_blacklisted() is False

    def test_matched_blacklist(self) -> None:
        e = _entry(kind=ExceptionKind.BLACKLIST)
        r = MatchResult.matched(e)
        assert r.is_blacklisted() is True
        assert r.is_whitelisted() is False

    def test_miss_not_whitelisted_not_blacklisted(self) -> None:
        r = MatchResult.miss()
        assert r.is_whitelisted() is False
        assert r.is_blacklisted() is False


# ---------------------------------------------------------------------------
# Testes: ExceptionStore — CRUD
# ---------------------------------------------------------------------------

class TestExceptionStoreCRUD:
    def test_add_returns_entry_with_id(self, store: ExceptionStore) -> None:
        e = store.add(_entry())
        assert e.entry_id is not None
        assert e.entry_id >= 1

    def test_add_persists_all_fields(self, store: ExceptionStore) -> None:
        original = ExceptionEntry(
            kind    = ExceptionKind.BLACKLIST,
            target  = ExceptionTarget.HASH,
            value   = "deadbeef" * 8,
            comment = "malware known",
            added_by= "security_team",
        )
        saved = store.add(original)
        fetched = store.get_by_id(saved.entry_id)  # type: ignore[arg-type]
        assert fetched is not None
        assert fetched.kind    == ExceptionKind.BLACKLIST
        assert fetched.target  == ExceptionTarget.HASH
        assert fetched.value   == "deadbeef" * 8
        assert fetched.comment == "malware known"
        assert fetched.added_by == "security_team"

    def test_add_duplicate_raises(self, store: ExceptionStore) -> None:
        store.add(_entry())
        with pytest.raises(ValueError, match="já existe"):
            store.add(_entry())

    def test_remove_by_id_returns_true(self, store: ExceptionStore) -> None:
        e = store.add(_entry())
        assert store.remove(e.entry_id) is True  # type: ignore[arg-type]

    def test_remove_by_id_missing_returns_false(self, store: ExceptionStore) -> None:
        assert store.remove(99999) is False

    def test_remove_clears_cache(self, store: ExceptionStore) -> None:
        e = store.add(_entry(value="/tmp/todelete"))
        store.remove(e.entry_id)  # type: ignore[arg-type]
        # Verificação via is_whitelisted_path deve ser miss
        r = store.is_whitelisted_path("/tmp/todelete")
        assert r.hit is False

    def test_remove_by_value(self, store: ExceptionStore) -> None:
        store.add(_entry(value="/home/safe"))
        ok = store.remove_by_value(ExceptionKind.WHITELIST, ExceptionTarget.PATH, "/home/safe")
        assert ok is True

    def test_remove_by_value_missing_returns_false(self, store: ExceptionStore) -> None:
        ok = store.remove_by_value(ExceptionKind.WHITELIST, ExceptionTarget.PATH, "/nonexistent")
        assert ok is False

    def test_list_all_empty(self, store: ExceptionStore) -> None:
        assert store.list_all() == []

    def test_list_all_returns_all(self, store: ExceptionStore) -> None:
        store.add(_entry(value="/a", kind=ExceptionKind.WHITELIST))
        store.add(_entry(value="/b", kind=ExceptionKind.BLACKLIST))
        assert len(store.list_all()) == 2

    def test_list_filter_by_kind(self, store: ExceptionStore) -> None:
        store.add(_entry(value="/a", kind=ExceptionKind.WHITELIST))
        store.add(_entry(value="/b", kind=ExceptionKind.BLACKLIST))
        wl = store.list_all(kind=ExceptionKind.WHITELIST)
        assert all(e.kind == ExceptionKind.WHITELIST for e in wl)
        assert len(wl) == 1

    def test_list_filter_by_target(self, store: ExceptionStore) -> None:
        store.add(_entry(target=ExceptionTarget.PATH,  value="/x"))
        store.add(_entry(target=ExceptionTarget.HASH,  value="abc123hash"))
        paths = store.list_all(target=ExceptionTarget.PATH)
        assert all(e.target == ExceptionTarget.PATH for e in paths)

    def test_count_by_kind(self, store: ExceptionStore) -> None:
        store.add(_entry(value="/a", kind=ExceptionKind.WHITELIST))
        store.add(_entry(value="/b", kind=ExceptionKind.WHITELIST))
        store.add(_entry(value="/c", kind=ExceptionKind.BLACKLIST))
        c = store.count()
        assert c["whitelist"] == 2
        assert c["blacklist"] == 1


# ---------------------------------------------------------------------------
# Testes: ExceptionStore — Lookups O(1)
# ---------------------------------------------------------------------------

class TestExceptionStoreLookup:
    def test_whitelisted_hash_hit(self, store: ExceptionStore) -> None:
        store.add(_entry(target=ExceptionTarget.HASH, value="aabbccdd"))
        r = store.is_whitelisted_hash("aabbccdd")
        assert r.is_whitelisted()

    def test_whitelisted_hash_miss(self, store: ExceptionStore) -> None:
        r = store.is_whitelisted_hash("notthere")
        assert not r.hit

    def test_hash_lookup_case_insensitive(self, store: ExceptionStore) -> None:
        store.add(_entry(target=ExceptionTarget.HASH, value="aabbccdd"))
        r = store.is_whitelisted_hash("AABBCCDD")
        assert r.is_whitelisted()

    def test_blacklisted_hash(self, store: ExceptionStore) -> None:
        store.add(_entry(kind=ExceptionKind.BLACKLIST, target=ExceptionTarget.HASH, value="deadbeef"))
        r = store.is_blacklisted_hash("deadbeef")
        assert r.is_blacklisted()

    def test_whitelisted_process(self, store: ExceptionStore) -> None:
        store.add(_entry(target=ExceptionTarget.PROCESS, value="firefox"))
        r = store.is_whitelisted_process("firefox")
        assert r.is_whitelisted()

    def test_process_miss(self, store: ExceptionStore) -> None:
        r = store.is_whitelisted_process("cryptominer")
        assert not r.hit

    def test_whitelisted_extension(self, store: ExceptionStore) -> None:
        store.add(_entry(target=ExceptionTarget.EXTENSION, value=".iso"))
        r = store.is_whitelisted_extension(".iso")
        assert r.is_whitelisted()

    def test_extension_case_insensitive(self, store: ExceptionStore) -> None:
        store.add(_entry(target=ExceptionTarget.EXTENSION, value=".iso"))
        r = store.is_whitelisted_extension(".ISO")
        assert r.is_whitelisted()


# ---------------------------------------------------------------------------
# Testes: ExceptionStore — Path matching (glob / prefixo)
# ---------------------------------------------------------------------------

class TestExceptionStorePathMatching:
    def test_exact_path_match(self, store: ExceptionStore) -> None:
        store.add(_entry(value="/opt/safe/app"))
        r = store.is_whitelisted_path("/opt/safe/app")
        assert r.is_whitelisted()

    def test_glob_path_match(self, store: ExceptionStore) -> None:
        store.add(_entry(value="/opt/safe/*"))
        r = store.is_whitelisted_path("/opt/safe/anything.sh")
        assert r.is_whitelisted()

    def test_glob_no_match(self, store: ExceptionStore) -> None:
        store.add(_entry(value="/opt/safe/*"))
        r = store.is_whitelisted_path("/tmp/evil.sh")
        assert not r.hit

    def test_directory_prefix_match(self, store: ExceptionStore) -> None:
        store.add(_entry(value="/opt/myapp/"))
        r = store.is_whitelisted_path("/opt/myapp/bin/runner")
        assert r.is_whitelisted()

    def test_directory_prefix_no_partial(self, store: ExceptionStore) -> None:
        store.add(_entry(value="/opt/myapp/"))
        r = store.is_whitelisted_path("/opt/myapp_evil/bin")
        assert not r.hit   # prefixo exige barra final

    def test_blacklisted_path_glob(self, store: ExceptionStore) -> None:
        store.add(_entry(kind=ExceptionKind.BLACKLIST, value="/tmp/*"))
        r = store.is_blacklisted_path("/tmp/malware.sh")
        assert r.is_blacklisted()


# ---------------------------------------------------------------------------
# Testes: ExceptionStore — check_all (precedência)
# ---------------------------------------------------------------------------

class TestExceptionStoreCheckAll:
    def test_blacklist_hash_takes_precedence_over_whitelist_path(
        self, store: ExceptionStore
    ) -> None:
        store.add(_entry(kind=ExceptionKind.WHITELIST, target=ExceptionTarget.PATH,  value="/safe/*"))
        store.add(_entry(kind=ExceptionKind.BLACKLIST, target=ExceptionTarget.HASH,  value="evil_hash"))
        r = store.check_all(path="/safe/file.sh", sha256="evil_hash")
        assert r.is_blacklisted()   # blacklist_hash vence

    def test_whitelist_hash_over_path_blacklist(self, store: ExceptionStore) -> None:
        store.add(_entry(kind=ExceptionKind.BLACKLIST, target=ExceptionTarget.PATH, value="/tmp/*"))
        store.add(_entry(kind=ExceptionKind.WHITELIST, target=ExceptionTarget.HASH, value="trusted_hash"))
        r = store.check_all(path="/tmp/safe.sh", sha256="trusted_hash")
        assert r.is_whitelisted()   # whitelist_hash vence path_blacklist

    def test_path_whitelist_matches(self, store: ExceptionStore) -> None:
        store.add(_entry(kind=ExceptionKind.WHITELIST, target=ExceptionTarget.PATH, value="/safe/*"))
        r = store.check_all(path="/safe/app.sh")
        assert r.is_whitelisted()

    def test_process_whitelist(self, store: ExceptionStore) -> None:
        store.add(_entry(target=ExceptionTarget.PROCESS, value="trusted_app"))
        r = store.check_all(process="trusted_app")
        assert r.is_whitelisted()

    def test_extension_whitelist(self, store: ExceptionStore) -> None:
        store.add(_entry(target=ExceptionTarget.EXTENSION, value=".iso"))
        r = store.check_all(path="/mnt/disk.iso", ext=".iso")
        assert r.is_whitelisted()

    def test_complete_miss(self, store: ExceptionStore) -> None:
        r = store.check_all(path="/tmp/unknown.sh", sha256="badhash", process="evil")
        assert not r.hit

    def test_none_arguments_no_crash(self, store: ExceptionStore) -> None:
        r = store.check_all()
        assert not r.hit


# ---------------------------------------------------------------------------
# Testes: ExceptionStore — Export / Import JSON
# ---------------------------------------------------------------------------

class TestExceptionStoreExportImport:
    def test_export_json(self, store: ExceptionStore, tmp_path: Path) -> None:
        store.add(_entry(value="/a"))
        store.add(_entry(value="/b"))
        dest = tmp_path / "out.json"
        n = store.export_json(dest)
        assert n == 2
        data = json.loads(dest.read_text())
        values = [d["value"] for d in data]
        assert "/a" in values and "/b" in values

    def test_import_json(self, tmp_path: Path) -> None:
        # Cria JSON manualmente
        data = [{"kind": "whitelist", "target": "path", "value": "/import/path", "comment": "imp"}]
        src  = tmp_path / "import.json"
        src.write_text(json.dumps(data))

        with ExceptionStore(tmp_path / "fresh.db") as s:
            added, ignored = s.import_json(src)
            assert added   == 1
            assert ignored == 0
            r = s.is_whitelisted_path("/import/path")
            assert r.is_whitelisted()

    def test_import_duplicate_ignored(self, store: ExceptionStore, tmp_path: Path) -> None:
        store.add(_entry(value="/dup"))
        dest = tmp_path / "out.json"
        store.export_json(dest)
        added, ignored = store.import_json(dest)
        assert added   == 0
        assert ignored == 1

    def test_import_overwrite(self, store: ExceptionStore, tmp_path: Path) -> None:
        store.add(_entry(value="/dup"))
        dest = tmp_path / "out.json"
        store.export_json(dest)
        added, ignored = store.import_json(dest, overwrite=True)
        assert added   == 1
        assert ignored == 0


# ---------------------------------------------------------------------------
# Testes: thread-safety
# ---------------------------------------------------------------------------

class TestExceptionStoreThreadSafety:
    def test_concurrent_adds(self, store: ExceptionStore) -> None:
        errors: list[Exception] = []

        def add_bunch(start: int) -> None:
            for i in range(start, start + 10):
                try:
                    store.add(_entry(value=f"/path/thread/{i}"))
                except Exception as exc:
                    errors.append(exc)

        threads = [threading.Thread(target=add_bunch, args=(i * 10,)) for i in range(5)]
        for t in threads: t.start()
        for t in threads: t.join()

        assert errors == []
        assert len(store.list_all()) == 50


# ---------------------------------------------------------------------------
# Testes: ExceptionManager
# ---------------------------------------------------------------------------

class TestExceptionManager:
    def test_open_close(self, mgr: ExceptionManager) -> None:
        assert mgr._store is not None

    def test_add_whitelist_path(self, mgr: ExceptionManager) -> None:
        e = mgr.add_whitelist_path("/opt/safe", comment="app")
        assert e.entry_id is not None
        assert e.kind   == ExceptionKind.WHITELIST
        assert e.target == ExceptionTarget.PATH

    def test_add_whitelist_hash(self, mgr: ExceptionManager) -> None:
        e = mgr.add_whitelist_hash("abc123def456", "auditado")
        assert e.value == "abc123def456"

    def test_add_whitelist_hash_lowercased(self, mgr: ExceptionManager) -> None:
        e = mgr.add_whitelist_hash("UPPERCASE123")
        assert e.value == "uppercase123"

    def test_add_whitelist_process(self, mgr: ExceptionManager) -> None:
        e = mgr.add_whitelist_process("firefox")
        assert e.target == ExceptionTarget.PROCESS

    def test_add_whitelist_extension_adds_dot(self, mgr: ExceptionManager) -> None:
        e = mgr.add_whitelist_extension("iso")   # sem ponto
        assert e.value == ".iso"

    def test_add_whitelist_extension_with_dot(self, mgr: ExceptionManager) -> None:
        e = mgr.add_whitelist_extension(".vmdk")
        assert e.value == ".vmdk"

    def test_add_blacklist_path(self, mgr: ExceptionManager) -> None:
        e = mgr.add_blacklist_path("/tmp/*")
        assert e.kind == ExceptionKind.BLACKLIST

    def test_add_blacklist_hash(self, mgr: ExceptionManager) -> None:
        e = mgr.add_blacklist_hash("malware_sha256")
        assert e.kind   == ExceptionKind.BLACKLIST
        assert e.target == ExceptionTarget.HASH

    def test_check_whitelisted(self, mgr: ExceptionManager) -> None:
        mgr.add_whitelist_path("/safe/*")
        r = mgr.check(path="/safe/app.sh")
        assert r.is_whitelisted()

    def test_check_miss(self, mgr: ExceptionManager) -> None:
        r = mgr.check(path="/unknown/path.sh")
        assert not r.hit

    def test_is_whitelisted_convenience(self, mgr: ExceptionManager) -> None:
        mgr.add_whitelist_extension(".iso")
        assert mgr.is_whitelisted(ext=".iso") is True
        assert mgr.is_whitelisted(ext=".sh")  is False

    def test_is_blacklisted_convenience(self, mgr: ExceptionManager) -> None:
        mgr.add_blacklist_hash("evilhash123")
        assert mgr.is_blacklisted(sha256="evilhash123") is True
        assert mgr.is_blacklisted(sha256="safehash")    is False

    def test_remove_by_id(self, mgr: ExceptionManager) -> None:
        e = mgr.add_whitelist_path("/tmp/x")
        assert mgr.remove(e.entry_id) is True   # type: ignore[arg-type]
        assert not mgr.check(path="/tmp/x").hit

    def test_status_counts(self, mgr: ExceptionManager) -> None:
        mgr.add_whitelist_path("/a")
        mgr.add_whitelist_path("/b")
        mgr.add_blacklist_hash("h1")
        s = mgr.status()
        assert s["whitelist"] == 2
        assert s["blacklist"] == 1
        assert s["total"]     == 3

    def test_load_from_config(self, cfg: ConfigManager) -> None:
        cfg.set("exceptions.paths",      ["/opt/myapp/*"])
        cfg.set("exceptions.extensions", [".iso", ".vmdk"])
        cfg.set("exceptions.processes",  ["safe_proc"])

        m = ExceptionManager(cfg)
        m.open()
        try:
            assert m.is_whitelisted(path="/opt/myapp/bin")
            assert m.is_whitelisted(ext=".iso")
            assert m.is_whitelisted(ext=".vmdk")
            assert m.is_whitelisted(process="safe_proc")
        finally:
            m.close()

    def test_load_from_config_no_duplicates_on_reopen(self, cfg: ConfigManager) -> None:
        cfg.set("exceptions.paths", ["/stable/path"])
        m1 = ExceptionManager(cfg)
        m1.open()
        m1.close()
        # Reabre — não deve lançar ValueError por duplicata
        m2 = ExceptionManager(cfg)
        m2.open()
        m2.close()

    def test_audit_with_log_manager(self, cfg: ConfigManager) -> None:
        """Garante que _audit não estoura quando log_manager está presente."""
        from ekprotection.logs.manager import LogManager
        import os
        tmp = Path(cfg.config_path).parent
        cfg.set("logs.db_path", str(tmp / "audit.db"))
        cfg.set("logs.dir",     str(tmp / "logs"))

        log_mgr = LogManager(cfg)
        log_mgr.open()

        m = ExceptionManager(cfg, log_mgr)
        m.open()
        m.add_whitelist_path("/audited/path", "auditado")   # dispara _audit
        m.close()
        log_mgr.close()

    def test_export_import_roundtrip(self, mgr: ExceptionManager, tmp_path: Path) -> None:
        mgr.add_whitelist_path("/roundtrip/path")
        mgr.add_blacklist_hash("roundtrip_hash_abc")

        dest = tmp_path / "backup.json"
        n = mgr.export_json(dest)
        assert n >= 2

        # Importa num manager limpo
        cfg2 = ConfigManager(tmp_path / "cfg2.yaml")
        cfg2.load()
        cfg2.set("logs.db_path",         str(tmp_path / "fresh.db"))
        cfg2.set("exceptions.paths",     [])
        cfg2.set("exceptions.hashes",    [])
        cfg2.set("exceptions.processes", [])
        cfg2.set("exceptions.extensions",[])

        m2 = ExceptionManager(cfg2)
        m2.open()
        added, _ = m2.import_json(dest)
        assert added >= 2
        assert m2.is_whitelisted(path="/roundtrip/path")
        assert m2.is_blacklisted(sha256="roundtrip_hash_abc")
        m2.close()

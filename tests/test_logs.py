"""
tests/test_logs.py
===================
Testes do sistema de logs (Patch 3).

Cobre:
  - LogEntry: criação, serialização JSON, imutabilidade
  - LogLevel: ordenação numérica, from_str
  - EventType: valores e conversão
  - QueryFilter: construção
  - LogStore: open/close, write, query com filtros, count,
              export JSON/CSV, purge, stats, thread-safety
  - LogManager: open/close, get_source, SourceLogger API,
                get_logger fallback, _write com nível mínimo
"""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Generator

import pytest

from ekprotection.config.manager import ConfigManager
from ekprotection.logs.models import EventType, LogEntry, LogLevel, QueryFilter
from ekprotection.logs.store  import LogStore
from ekprotection.logs.manager import LogManager, get_logger, set_global


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def cfg(tmp_path: Path) -> ConfigManager:
    manager = ConfigManager(tmp_path / "config.yaml")
    manager.load()
    # Redireciona caminhos para tmp
    import os
    os.environ["EKP_DATA_DIR"] = str(tmp_path)
    manager.set("logs.db_path",  str(tmp_path / "test.db"))
    manager.set("logs.dir",      str(tmp_path / "logs"))
    manager.set("logs.structured", True)
    yield manager
    os.environ.pop("EKP_DATA_DIR", None)


@pytest.fixture
def store(tmp_path: Path) -> Generator[LogStore, None, None]:
    s = LogStore(
        db_path   = tmp_path / "test.db",
        jsonl_path= tmp_path / "test.jsonl",
    )
    s.open()
    yield s
    s.close()


@pytest.fixture
def log_mgr(cfg: ConfigManager, tmp_path: Path) -> Generator[LogManager, None, None]:
    cfg.set("logs.db_path",  str(tmp_path / "mgr.db"))
    cfg.set("logs.dir",      str(tmp_path / "logs"))
    cfg.set("daemon.log_level", "DEBUG")
    m = LogManager(cfg)
    m.open()
    yield m
    m.close()


def _make_entry(
    msg:   str        = "teste",
    level: LogLevel   = LogLevel.INFO,
    etype: EventType  = EventType.GENERIC,
    source: str       = "test",
    **kw,
) -> LogEntry:
    return LogEntry(level=level, event_type=etype, message=msg, source=source, **kw)


# ---------------------------------------------------------------------------
# Testes: LogLevel
# ---------------------------------------------------------------------------

class TestLogLevel:
    def test_numeric_ordering(self) -> None:
        assert LogLevel.DEBUG.numeric < LogLevel.INFO.numeric
        assert LogLevel.INFO.numeric  < LogLevel.WARNING.numeric
        assert LogLevel.WARNING.numeric < LogLevel.ERROR.numeric
        assert LogLevel.ERROR.numeric < LogLevel.CRITICAL.numeric

    def test_from_str_valid(self) -> None:
        assert LogLevel.from_str("warning") == LogLevel.WARNING
        assert LogLevel.from_str("CRITICAL") == LogLevel.CRITICAL

    def test_from_str_invalid_fallback(self) -> None:
        assert LogLevel.from_str("INVALID") == LogLevel.INFO

    def test_value_is_string(self) -> None:
        assert LogLevel.INFO.value == "INFO"


# ---------------------------------------------------------------------------
# Testes: LogEntry
# ---------------------------------------------------------------------------

class TestLogEntry:
    def test_default_timestamp_is_utc(self) -> None:
        before = datetime.utcnow()
        e = _make_entry()
        after = datetime.utcnow()
        assert before <= e.timestamp <= after

    def test_to_dict_has_all_fields(self) -> None:
        e = _make_entry("mensagem", file_path="/tmp/x.sh", sha256="abc123")
        d = e.to_dict()
        assert d["message"]   == "mensagem"
        assert d["file_path"] == "/tmp/x.sh"
        assert d["sha256"]    == "abc123"
        assert "timestamp" in d
        assert "level"     in d
        assert "event_type" in d

    def test_to_json_is_valid_json(self) -> None:
        e = _make_entry("json test", extra={"key": "value"})
        parsed = json.loads(e.to_json())
        assert parsed["message"] == "json test"
        assert parsed["extra"]["key"] == "value"

    def test_entry_is_immutable(self) -> None:
        e = _make_entry()
        with pytest.raises((AttributeError, TypeError)):
            e.message = "modificado"  # type: ignore[misc]

    def test_entry_without_optional_fields(self) -> None:
        e = _make_entry()
        assert e.file_path is None
        assert e.sha256    is None
        assert e.process   is None
        assert e.entry_id  is None


# ---------------------------------------------------------------------------
# Testes: LogStore — escrita e leitura
# ---------------------------------------------------------------------------

class TestLogStoreWrite:
    def test_write_returns_entry_with_id(self, store: LogStore) -> None:
        e = store.write(_make_entry("primeiro"))
        assert e.entry_id is not None
        assert e.entry_id >= 1

    def test_ids_are_sequential(self, store: LogStore) -> None:
        ids = [store.write(_make_entry(f"msg {i}")).entry_id for i in range(5)]
        assert ids == sorted(ids)
        assert len(set(ids)) == 5

    def test_written_entry_is_queryable(self, store: LogStore) -> None:
        store.write(_make_entry("buscável", level=LogLevel.ERROR))
        results = store.query(QueryFilter(level=LogLevel.ERROR))
        assert any(e.message == "buscável" for e in results)

    def test_all_fields_persisted(self, store: LogStore) -> None:
        original = LogEntry(
            level      = LogLevel.CRITICAL,
            event_type = EventType.THREAT_DETECTED,
            message    = "ameaça detectada",
            source     = "scanner",
            pid        = 1234,
            file_path  = "/tmp/mal.sh",
            sha256     = "deadbeef" * 8,
            process    = "python3",
            extra      = {"risk": "alto"},
        )
        stored = store.write(original)
        results = store.query(QueryFilter(limit=1))
        e = results[0]
        assert e.level      == LogLevel.CRITICAL
        assert e.event_type == EventType.THREAT_DETECTED
        assert e.message    == "ameaça detectada"
        assert e.source     == "scanner"
        assert e.pid        == 1234
        assert e.file_path  == "/tmp/mal.sh"
        assert e.sha256     == "deadbeef" * 8
        assert e.process    == "python3"
        assert e.extra      == {"risk": "alto"}

    def test_jsonl_written(self, tmp_path: Path) -> None:
        jsonl = tmp_path / "test.jsonl"
        with LogStore(tmp_path / "db.db", jsonl) as s:
            s.write(_make_entry("jsonl test"))
        lines = jsonl.read_text().strip().split("\n")
        assert len(lines) == 1
        parsed = json.loads(lines[0])
        assert parsed["message"] == "jsonl test"


# ---------------------------------------------------------------------------
# Testes: LogStore — QueryFilter
# ---------------------------------------------------------------------------

class TestLogStoreQuery:
    def _populate(self, store: LogStore) -> None:
        store.write(_make_entry("debug msg",    level=LogLevel.DEBUG,    etype=EventType.GENERIC))
        store.write(_make_entry("info msg",     level=LogLevel.INFO,     etype=EventType.FILE_CREATED))
        store.write(_make_entry("warning msg",  level=LogLevel.WARNING,  etype=EventType.THREAT_DETECTED))
        store.write(_make_entry("error msg",    level=LogLevel.ERROR,    etype=EventType.SYSTEM_ERROR,   source="monitor"))
        store.write(_make_entry("critical msg", level=LogLevel.CRITICAL, etype=EventType.THREAT_CRITICAL, file_path="/tmp/x"))

    def test_filter_by_level(self, store: LogStore) -> None:
        self._populate(store)
        results = store.query(QueryFilter(level=LogLevel.ERROR))
        assert all(e.level == LogLevel.ERROR for e in results)

    def test_filter_by_event_type(self, store: LogStore) -> None:
        self._populate(store)
        results = store.query(QueryFilter(event_type=EventType.THREAT_DETECTED))
        assert all(e.event_type == EventType.THREAT_DETECTED for e in results)

    def test_filter_by_source(self, store: LogStore) -> None:
        self._populate(store)
        results = store.query(QueryFilter(source="monitor"))
        assert all(e.source == "monitor" for e in results)

    def test_filter_by_file_path(self, store: LogStore) -> None:
        self._populate(store)
        results = store.query(QueryFilter(file_path="/tmp"))
        assert all(e.file_path and "/tmp" in e.file_path for e in results)

    def test_filter_by_search(self, store: LogStore) -> None:
        self._populate(store)
        results = store.query(QueryFilter(search="warning"))
        assert all("warning" in e.message for e in results)

    def test_filter_by_since(self, store: LogStore) -> None:
        self._populate(store)
        future = datetime.utcnow() + timedelta(hours=1)
        results = store.query(QueryFilter(since=future))
        assert results == []

    def test_limit_respected(self, store: LogStore) -> None:
        self._populate(store)
        results = store.query(QueryFilter(limit=2))
        assert len(results) <= 2

    def test_order_desc(self, store: LogStore) -> None:
        for i in range(5):
            store.write(_make_entry(f"msg {i}"))
        results = store.query(QueryFilter(order_desc=True, limit=5))
        timestamps = [e.timestamp for e in results]
        assert timestamps == sorted(timestamps, reverse=True)

    def test_count_without_limit(self, store: LogStore) -> None:
        self._populate(store)
        total = store.count(QueryFilter(limit=1))  # limit não afeta count
        assert total == 5

    def test_empty_query_returns_all(self, store: LogStore) -> None:
        self._populate(store)
        results = store.query(QueryFilter(limit=100))
        assert len(results) == 5


# ---------------------------------------------------------------------------
# Testes: LogStore — manutenção
# ---------------------------------------------------------------------------

class TestLogStoreMaintenance:
    def test_purge_removes_old_entries(self, store: LogStore, tmp_path: Path) -> None:
        # Cria entrada com timestamp antigo diretamente no DB
        old_ts = (datetime.utcnow() - timedelta(days=100)).isoformat()
        store._conn.execute(
            "INSERT INTO log_entries (timestamp, level, event_type, message, source, pid, extra) "
            "VALUES (?, 'INFO', 'generic', 'antiga', 'test', 0, '{}')",
            (old_ts,),
        )
        store.write(_make_entry("recente"))
        removed = store.purge_old(30)
        assert removed == 1
        remaining = store.query(QueryFilter(limit=100))
        assert all(e.message != "antiga" for e in remaining)

    def test_purge_keeps_recent(self, store: LogStore) -> None:
        store.write(_make_entry("recente"))
        removed = store.purge_old(30)
        assert removed == 0

    def test_stats_returns_correct_total(self, store: LogStore) -> None:
        for _ in range(7):
            store.write(_make_entry())
        s = store.stats()
        assert s["total_entries"] == 7

    def test_stats_by_level(self, store: LogStore) -> None:
        store.write(_make_entry(level=LogLevel.WARNING))
        store.write(_make_entry(level=LogLevel.WARNING))
        store.write(_make_entry(level=LogLevel.ERROR))
        s = store.stats()
        assert s["by_level"].get("WARNING", 0) == 2
        assert s["by_level"].get("ERROR",   0) == 1


# ---------------------------------------------------------------------------
# Testes: LogStore — exportação
# ---------------------------------------------------------------------------

class TestLogStoreExport:
    def test_export_json(self, store: LogStore, tmp_path: Path) -> None:
        store.write(_make_entry("export test"))
        dest = tmp_path / "out.json"
        count = store.export_json(dest)
        assert count == 1
        data = json.loads(dest.read_text())
        assert data[0]["message"] == "export test"

    def test_export_csv(self, store: LogStore, tmp_path: Path) -> None:
        store.write(_make_entry("csv test"))
        dest = tmp_path / "out.csv"
        count = store.export_csv(dest)
        assert count == 1
        content = dest.read_text()
        assert "csv test" in content
        assert "timestamp" in content   # header

    def test_export_empty_csv(self, store: LogStore, tmp_path: Path) -> None:
        dest = tmp_path / "empty.csv"
        count = store.export_csv(dest)
        assert count == 0

    def test_export_with_filter(self, store: LogStore, tmp_path: Path) -> None:
        store.write(_make_entry("a", level=LogLevel.INFO))
        store.write(_make_entry("b", level=LogLevel.ERROR))
        dest = tmp_path / "filtered.json"
        f = QueryFilter(level=LogLevel.ERROR, limit=100)
        count = store.export_json(dest, f)
        assert count == 1
        data = json.loads(dest.read_text())
        assert data[0]["level"] == "ERROR"


# ---------------------------------------------------------------------------
# Testes: thread-safety
# ---------------------------------------------------------------------------

class TestLogStoreThreadSafety:
    def test_concurrent_writes(self, store: LogStore) -> None:
        """100 threads escrevem simultaneamente — nenhuma deve falhar."""
        errors: list[Exception] = []

        def write_n(n: int) -> None:
            try:
                for i in range(n):
                    store.write(_make_entry(f"thread entry {i}"))
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=write_n, args=(10,)) for _ in range(10)]
        for t in threads: t.start()
        for t in threads: t.join()

        assert errors == [], f"Erros: {errors}"
        total = store.count(QueryFilter())
        assert total == 100


# ---------------------------------------------------------------------------
# Testes: LogManager
# ---------------------------------------------------------------------------

class TestLogManager:
    def test_open_close(self, log_mgr: LogManager) -> None:
        assert log_mgr._store is not None

    def test_get_source_returns_logger(self, log_mgr: LogManager) -> None:
        from ekprotection.logs.manager import SourceLogger
        sl = log_mgr.get_source("test_module")
        assert isinstance(sl, SourceLogger)

    def test_same_source_returns_same_instance(self, log_mgr: LogManager) -> None:
        a = log_mgr.get_source("mod")
        b = log_mgr.get_source("mod")
        assert a is b

    def test_info_persists_entry(self, log_mgr: LogManager) -> None:
        log_mgr.get_source("test").info("mensagem info")
        results = log_mgr.query(QueryFilter(search="mensagem info", limit=5))
        assert any(e.message == "mensagem info" for e in results)

    def test_event_with_metadata(self, log_mgr: LogManager) -> None:
        log_mgr.get_source("scanner").event(
            EventType.THREAT_DETECTED,
            "malware encontrado",
            level     = LogLevel.CRITICAL,
            file_path = "/tmp/bad.sh",
            sha256    = "aabbcc",
        )
        results = log_mgr.query(QueryFilter(
            event_type = EventType.THREAT_DETECTED,
            limit = 5,
        ))
        assert len(results) >= 1
        e = results[0]
        assert e.file_path == "/tmp/bad.sh"
        assert e.sha256    == "aabbcc"
        assert e.level     == LogLevel.CRITICAL

    def test_min_level_filters_debug(self, cfg: ConfigManager, tmp_path: Path) -> None:
        cfg.set("daemon.log_level", "WARNING")
        cfg.set("logs.db_path", str(tmp_path / "filter.db"))
        mgr = LogManager(cfg)
        mgr.open()
        mgr.get_source("t").debug("não deve persistir")
        mgr.get_source("t").warning("deve persistir")
        results = mgr.query(QueryFilter(limit=10))
        mgr.close()
        messages = [e.message for e in results]
        assert "não deve persistir" not in messages
        assert "deve persistir" in messages

    def test_stats(self, log_mgr: LogManager) -> None:
        log_mgr.get_source("t").info("a")
        log_mgr.get_source("t").error("b")
        s = log_mgr.stats()
        assert s["total_entries"] >= 2

    def test_purge(self, log_mgr: LogManager) -> None:
        # Nenhum log tem mais de 1 dia, purge não remove nada
        log_mgr.get_source("t").info("recente")
        removed = log_mgr.purge_old()
        assert removed == 0


# ---------------------------------------------------------------------------
# Testes: get_logger (global / fallback)
# ---------------------------------------------------------------------------

class TestGetLogger:
    def test_fallback_logger_before_global(self) -> None:
        from ekprotection.logs import manager as lm
        original = lm._global_log_manager
        lm._global_log_manager = None
        try:
            log = get_logger("fallback_test")
            # Não deve lançar
            log.info("mensagem fallback")
        finally:
            lm._global_log_manager = original

    def test_get_logger_uses_global(self, log_mgr: LogManager) -> None:
        set_global(log_mgr)
        log = get_logger("global_test")
        log.warning("via global")
        results = log_mgr.query(QueryFilter(search="via global", limit=5))
        assert any(e.message == "via global" for e in results)

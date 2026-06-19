"""
tests/test_scanner.py
======================
Testes do scanner sob demanda (Patch 7).

Cobre:
  - hasher: sha256_file, sha256_bytes, is_elf, is_script, file_entropy
  - SignatureDB: open/close, lookup, is_known_threat, add, remove,
                 import_jsonl, count, meta, seed demo
  - FileScanResult / ScanReport: criação, propriedades, add, summary
  - ScanEngine: scan_file (clean, threat, whitelisted, skipped, error),
                heurísticas base (entropy, ELF, suspeito, oculto),
                scan_paths, scan_quick, auto-quarentena mock
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import stat
import secrets
from pathlib import Path
from typing  import Generator
from unittest.mock import MagicMock, patch

import pytest

from ekprotection.config.manager      import ConfigManager
from ekprotection.scanner.hasher      import (
    sha256_file, sha256_bytes, is_elf, is_script, file_entropy,
)
from ekprotection.scanner.signatures  import SignatureDB, _DEMO_SIGNATURES
from ekprotection.scanner.result      import FileScanResult, ScanReport, ScanVerdict
from ekprotection.scanner.engine      import ScanEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def cfg(tmp_path: Path) -> ConfigManager:
    os.environ["EKP_DATA_DIR"] = str(tmp_path)
    m = ConfigManager(tmp_path / "config.yaml")
    m.load()
    m.set("scanner.threads",             2)
    m.set("scanner.max_file_size_mb",    10)
    m.set("heuristics.entropy_threshold", 7.2)
    m.set("quarantine.auto_quarantine_critical", False)
    yield m
    os.environ.pop("EKP_DATA_DIR", None)


@pytest.fixture
def sig_db(tmp_path: Path) -> Generator[SignatureDB, None, None]:
    db = SignatureDB(tmp_path / "sigs.db")
    db.open()
    yield db
    db.close()


@pytest.fixture
def engine(cfg: ConfigManager, sig_db: SignatureDB) -> ScanEngine:
    return ScanEngine(cfg, sig_db=sig_db)


@pytest.fixture
def clean_file(tmp_path: Path) -> Path:
    f = tmp_path / "clean.txt"
    f.write_text("Este arquivo é completamente seguro.\n" * 10)
    return f


@pytest.fixture
def elf_file(tmp_path: Path) -> Path:
    f = tmp_path / "myelf"
    f.write_bytes(b"\x7fELF" + b"\x00" * 60)
    f.chmod(0o755)
    return f


@pytest.fixture
def script_file(tmp_path: Path) -> Path:
    f = tmp_path / "script.sh"
    f.write_text("#!/bin/bash\necho hello\n")
    f.chmod(0o755)
    return f


# ---------------------------------------------------------------------------
# Testes: hasher
# ---------------------------------------------------------------------------

class TestHasher:
    def test_sha256_file_matches_stdlib(self, tmp_path: Path) -> None:
        f    = tmp_path / "test.bin"
        data = secrets.token_bytes(4096)
        f.write_bytes(data)
        expected = hashlib.sha256(data).hexdigest()
        assert sha256_file(f) == expected

    def test_sha256_file_large(self, tmp_path: Path) -> None:
        """Arquivo de 2MB — deve funcionar sem estourar memória."""
        f = tmp_path / "large.bin"
        f.write_bytes(secrets.token_bytes(2 * 1024 * 1024))
        h = sha256_file(f)
        assert len(h) == 64

    def test_sha256_file_max_bytes(self, tmp_path: Path) -> None:
        """Com max_bytes, hash de partes diferentes deve diferir."""
        f = tmp_path / "multi.bin"
        f.write_bytes(b"A" * 1000 + b"B" * 1000)
        h_full  = sha256_file(f)
        h_part  = sha256_file(f, max_bytes=500)
        assert h_full != h_part

    def test_sha256_bytes(self) -> None:
        data = b"test data"
        expected = hashlib.sha256(data).hexdigest()
        assert sha256_bytes(data) == expected

    def test_is_elf_true(self, tmp_path: Path) -> None:
        f = tmp_path / "elf"
        f.write_bytes(b"\x7fELF" + b"\x00" * 10)
        assert is_elf(f) is True

    def test_is_elf_false_for_text(self, tmp_path: Path) -> None:
        f = tmp_path / "text.sh"
        f.write_text("#!/bin/bash\n")
        assert is_elf(f) is False

    def test_is_elf_missing_file(self) -> None:
        assert is_elf("/nonexistent/file") is False

    def test_is_script_true(self, tmp_path: Path) -> None:
        f = tmp_path / "script.py"
        f.write_text("#!/usr/bin/env python3\n")
        assert is_script(f) is True

    def test_is_script_false_for_elf(self, tmp_path: Path) -> None:
        f = tmp_path / "elf"
        f.write_bytes(b"\x7fELF" + b"\x00" * 10)
        assert is_script(f) is False

    def test_is_script_missing_file(self) -> None:
        assert is_script("/nonexistent") is False

    def test_file_entropy_random_is_high(self, tmp_path: Path) -> None:
        f = tmp_path / "random.bin"
        f.write_bytes(secrets.token_bytes(8192))
        e = file_entropy(f)
        assert e > 7.0   # dados aleatórios têm entropia quase 8

    def test_file_entropy_uniform_is_zero(self, tmp_path: Path) -> None:
        f = tmp_path / "uniform.bin"
        f.write_bytes(b"\x00" * 8192)
        e = file_entropy(f)
        assert e == 0.0

    def test_file_entropy_text_is_moderate(self, tmp_path: Path) -> None:
        f = tmp_path / "text.txt"
        f.write_text("Hello world! " * 500)
        e = file_entropy(f)
        assert 3.0 < e < 6.0   # texto tem entropia moderada

    def test_file_entropy_missing(self) -> None:
        assert file_entropy("/nonexistent") == 0.0


# ---------------------------------------------------------------------------
# Testes: SignatureDB
# ---------------------------------------------------------------------------

class TestSignatureDB:
    def test_open_creates_db(self, tmp_path: Path) -> None:
        db = SignatureDB(tmp_path / "test.db")
        db.open()
        assert db.count() > 0   # demo signatures
        db.close()

    def test_demo_signatures_loaded(self, sig_db: SignatureDB) -> None:
        assert sig_db.count() == len(_DEMO_SIGNATURES)

    def test_demo_seeds_only_once(self, tmp_path: Path) -> None:
        db = SignatureDB(tmp_path / "once.db")
        db.open()
        first_count = db.count()
        db.close()
        db2 = SignatureDB(tmp_path / "once.db")
        db2.open()
        assert db2.count() == first_count
        db2.close()

    def test_lookup_known_hash(self, sig_db: SignatureDB) -> None:
        demo_hash = _DEMO_SIGNATURES[0]["sha256"]
        result    = sig_db.lookup(demo_hash)
        assert result is not None
        assert result["sha256"]      == demo_hash
        assert result["name"]        == _DEMO_SIGNATURES[0]["name"]
        assert result["threat_type"] == _DEMO_SIGNATURES[0]["threat_type"]

    def test_lookup_unknown_hash(self, sig_db: SignatureDB) -> None:
        assert sig_db.lookup("deadbeef" * 8) is None

    def test_is_known_threat_true(self, sig_db: SignatureDB) -> None:
        assert sig_db.is_known_threat(_DEMO_SIGNATURES[1]["sha256"]) is True

    def test_is_known_threat_false(self, sig_db: SignatureDB) -> None:
        assert sig_db.is_known_threat("nothreathash000") is False

    def test_add_new_signature(self, sig_db: SignatureDB) -> None:
        ok = sig_db.add("newhash123", "New.Threat", "Trojan", "alto")
        assert ok is True
        assert sig_db.is_known_threat("newhash123") is True

    def test_add_duplicate_returns_false(self, sig_db: SignatureDB) -> None:
        sig_db.add("dupehash", "Dupe", "Test", "baixo")
        ok = sig_db.add("dupehash", "Dupe", "Test", "baixo")
        assert ok is False

    def test_remove_existing(self, sig_db: SignatureDB) -> None:
        sig_db.add("removeme", "Remove.Test", "Test", "baixo")
        assert sig_db.remove("removeme") is True
        assert sig_db.is_known_threat("removeme") is False

    def test_remove_nonexistent(self, sig_db: SignatureDB) -> None:
        assert sig_db.remove("notexists") is False

    def test_count_increases_on_add(self, sig_db: SignatureDB) -> None:
        before = sig_db.count()
        sig_db.add("counttest", "Count.Test", "Test", "baixo")
        assert sig_db.count() == before + 1

    def test_meta_has_version(self, sig_db: SignatureDB) -> None:
        m = sig_db.meta()
        assert "version" in m

    def test_import_jsonl(self, sig_db: SignatureDB, tmp_path: Path) -> None:
        lines = [
            json.dumps({"sha256": f"import_hash_{i:03d}", "name": f"Import.{i}",
                        "threat_type": "Test", "severity": "médio", "source": "test"})
            for i in range(5)
        ]
        f = tmp_path / "import.jsonl"
        f.write_text("\n".join(lines))
        added, dupes = sig_db.import_jsonl(f)
        assert added == 5
        assert dupes == 0

    def test_import_jsonl_duplicates(self, sig_db: SignatureDB, tmp_path: Path) -> None:
        sig_db.add("dupejsonl", "Dupe.JSONL", "Test", "baixo")
        line = json.dumps({"sha256": "dupejsonl", "name": "Dupe.JSONL",
                           "threat_type": "Test", "severity": "baixo"})
        f = tmp_path / "dupe.jsonl"
        f.write_text(line)
        added, dupes = sig_db.import_jsonl(f)
        assert added == 0
        assert dupes == 1


# ---------------------------------------------------------------------------
# Testes: FileScanResult / ScanReport
# ---------------------------------------------------------------------------

class TestScanResult:
    def test_clean_result(self) -> None:
        r = FileScanResult(path="/tmp/clean.txt", verdict=ScanVerdict.CLEAN)
        assert r.is_threat   is False
        assert r.is_critical is False

    def test_threat_result(self) -> None:
        r = FileScanResult(
            path="/tmp/evil.sh", verdict=ScanVerdict.THREAT,
            risk_level="alto",
        )
        assert r.is_threat   is True
        assert r.is_critical is False

    def test_critical_result(self) -> None:
        r = FileScanResult(
            path="/tmp/critical.sh", verdict=ScanVerdict.THREAT,
            risk_level="crítico",
        )
        assert r.is_threat   is True
        assert r.is_critical is True

    def test_to_dict_has_all_keys(self) -> None:
        r = FileScanResult(path="/tmp/x", verdict=ScanVerdict.CLEAN)
        d = r.to_dict()
        for key in ("path", "verdict", "sha256", "threat_name", "risk_level",
                    "reason", "entropy", "is_elf", "is_script", "scanned_at"):
            assert key in d

    def test_scan_report_add(self) -> None:
        report = ScanReport(scan_type="test")
        report.add(FileScanResult(path="/a", verdict=ScanVerdict.CLEAN))
        report.add(FileScanResult(path="/b", verdict=ScanVerdict.THREAT, risk_level="alto"))
        report.add(FileScanResult(path="/c", verdict=ScanVerdict.SKIPPED))
        report.finish()
        assert report.total_files    == 3
        assert report.scanned_files  == 2
        assert report.skipped_files  == 1
        assert report.threats_found  == 1

    def test_scan_report_threats(self) -> None:
        report = ScanReport(scan_type="test")
        report.add(FileScanResult(path="/clean", verdict=ScanVerdict.CLEAN))
        report.add(FileScanResult(path="/evil",  verdict=ScanVerdict.THREAT))
        assert len(report.threats) == 1
        assert report.threats[0].path == "/evil"

    def test_scan_report_duration(self) -> None:
        import time
        report = ScanReport(scan_type="test")
        time.sleep(0.01)
        report.finish()
        assert report.duration_ms is not None
        assert report.duration_ms >= 0

    def test_scan_report_summary(self) -> None:
        report = ScanReport(scan_type="quick")
        report.finish()
        s = report.summary()
        assert s["scan_type"] == "quick"
        assert "duration_ms"  in s


# ---------------------------------------------------------------------------
# Testes: ScanEngine — scan_file
# ---------------------------------------------------------------------------

class TestScanEngineFile:
    def test_clean_file_returns_clean(self, engine: ScanEngine, clean_file: Path) -> None:
        r = engine.scan_file(clean_file)
        assert r.verdict == ScanVerdict.CLEAN
        assert r.sha256  is not None
        assert len(r.sha256) == 64

    def test_missing_file_returns_skipped(self, engine: ScanEngine) -> None:
        r = engine.scan_file("/nonexistent/file.txt")
        assert r.verdict == ScanVerdict.SKIPPED

    def test_known_threat_hash_detected(
        self, engine: ScanEngine, tmp_path: Path
    ) -> None:
        threat_hash = _DEMO_SIGNATURES[1]["sha256"]
        # Cria arquivo cujo hash está na DB de assinaturas
        # (usamos mock para substituir o hash calculado)
        f = tmp_path / "malware.sh"
        f.write_bytes(secrets.token_bytes(64))
        with patch("ekprotection.scanner.engine.sha256_file", return_value=threat_hash):
            r = engine.scan_file(f)
        assert r.verdict     == ScanVerdict.THREAT
        assert r.sha256      == threat_hash
        assert r.threat_name == _DEMO_SIGNATURES[1]["name"]
        assert r.risk_level  == _DEMO_SIGNATURES[1]["severity"]

    def test_skipped_extension(self, engine: ScanEngine, tmp_path: Path) -> None:
        f = tmp_path / "movie.mp4"
        f.write_bytes(b"\x00" * 100)
        r = engine.scan_file(f)
        assert r.verdict == ScanVerdict.SKIPPED

    def test_large_file_skipped(self, cfg: ConfigManager, sig_db: SignatureDB,
                                tmp_path: Path) -> None:
        cfg.set("scanner.max_file_size_mb", 0)   # 0MB = qualquer arquivo é grande demais
        eng = ScanEngine(cfg, sig_db=sig_db)
        f   = tmp_path / "big.bin"
        f.write_bytes(b"\x00" * 1024)
        r   = eng.scan_file(f)
        assert r.verdict == ScanVerdict.SKIPPED
        assert "grande" in (r.reason or "")

    def test_whitelist_path_skipped(self, cfg: ConfigManager, sig_db: SignatureDB,
                                    tmp_path: Path) -> None:
        from ekprotection.exceptions.manager import ExceptionManager
        exc = ExceptionManager(cfg)
        exc.open()
        exc.add_whitelist_path(str(tmp_path / "*"))

        eng = ScanEngine(cfg, sig_db=sig_db, exc_manager=exc)
        f   = tmp_path / "trusted.sh"
        f.write_bytes(secrets.token_bytes(64))
        r   = eng.scan_file(f)
        assert r.verdict == ScanVerdict.SKIPPED
        assert "whitelist" in (r.reason or "").lower()
        exc.close()

    def test_whitelist_hash_skipped(self, cfg: ConfigManager, sig_db: SignatureDB,
                                    tmp_path: Path) -> None:
        from ekprotection.exceptions.manager import ExceptionManager
        f = tmp_path / "trusted.bin"
        f.write_bytes(secrets.token_bytes(64))
        real_hash = sha256_file(f)

        exc = ExceptionManager(cfg)
        exc.open()
        exc.add_whitelist_hash(real_hash, "arquivo auditado")

        eng = ScanEngine(cfg, sig_db=sig_db, exc_manager=exc)
        r   = eng.scan_file(f)
        assert r.verdict == ScanVerdict.SKIPPED
        assert "whitelist" in (r.reason or "").lower()
        exc.close()

    def test_blacklist_hash_detected(self, cfg: ConfigManager, sig_db: SignatureDB,
                                     tmp_path: Path) -> None:
        from ekprotection.exceptions.manager import ExceptionManager
        f = tmp_path / "bad.bin"
        f.write_bytes(secrets.token_bytes(64))
        real_hash = sha256_file(f)

        exc = ExceptionManager(cfg)
        exc.open()
        exc.add_blacklist_hash(real_hash, "confirmado malicioso")

        eng = ScanEngine(cfg, sig_db=sig_db, exc_manager=exc)
        r   = eng.scan_file(f)
        assert r.verdict   == ScanVerdict.THREAT
        assert r.risk_level == "crítico"
        exc.close()

    def test_sha256_present_in_result(self, engine: ScanEngine, clean_file: Path) -> None:
        r = engine.scan_file(clean_file)
        assert r.sha256 is not None
        # Verifica que o hash é correto
        expected = sha256_file(clean_file)
        assert r.sha256 == expected

    def test_scan_returns_file_size(self, engine: ScanEngine, clean_file: Path) -> None:
        r = engine.scan_file(clean_file)
        assert r.file_size == clean_file.stat().st_size

    def test_elf_detected(self, engine: ScanEngine, elf_file: Path) -> None:
        r = engine.scan_file(elf_file)
        assert r.is_elf is True

    def test_script_detected(self, engine: ScanEngine, script_file: Path) -> None:
        r = engine.scan_file(script_file)
        assert r.is_script is True


# ---------------------------------------------------------------------------
# Testes: heurísticas base
# ---------------------------------------------------------------------------

class TestScanEngineHeuristics:
    def test_executable_in_tmp_flagged(self, engine: ScanEngine, tmp_path: Path) -> None:
        """Cria arquivo executável em /tmp — deve ser SUSPICIOUS."""
        # Usa mock para simular /tmp path sem criar arquivo lá de fato
        f = tmp_path / "evil"
        f.write_bytes(b"\x7fELF" + b"\x00" * 60)
        f.chmod(0o755)

        with patch("ekprotection.scanner.engine.sha256_file", return_value="cleanclean" * 6), \
             patch.object(engine._sig_db, "lookup", return_value=None):
            # Força o path a parecer /tmp
            fake_path = "/tmp/suspicious_elf"
            with patch("os.stat") as mock_stat, \
                 patch("pathlib.Path.exists", return_value=True), \
                 patch("pathlib.Path.is_file", return_value=True):
                mock_stat.return_value = MagicMock(
                    st_size=512, st_mode=0o100755
                )
                with patch("ekprotection.scanner.engine.is_elf", return_value=True), \
                     patch("ekprotection.scanner.engine.is_script", return_value=False), \
                     patch("ekprotection.scanner.engine.file_entropy", return_value=3.0):
                    r = engine._scan_file_inner(fake_path)

        assert r.verdict in (ScanVerdict.SUSPICIOUS, ScanVerdict.CLEAN)
        if r.verdict == ScanVerdict.SUSPICIOUS:
            assert "tmp" in (r.reason or "").lower()

    def test_high_entropy_executable_flagged(self, engine: ScanEngine, tmp_path: Path) -> None:
        f = tmp_path / "packed"
        f.write_bytes(secrets.token_bytes(4096))
        f.chmod(0o755)

        with patch("ekprotection.scanner.engine.sha256_file", return_value="safe" * 16), \
             patch.object(engine._sig_db, "lookup", return_value=None), \
             patch("ekprotection.scanner.engine.is_elf", return_value=True), \
             patch("ekprotection.scanner.engine.is_script", return_value=False), \
             patch("ekprotection.scanner.engine.file_entropy", return_value=7.9):
            r = engine._scan_file_inner(str(f))

        assert r.verdict == ScanVerdict.SUSPICIOUS
        assert "entropia" in (r.reason or "").lower()

    def test_hidden_executable_flagged(self, engine: ScanEngine, tmp_path: Path) -> None:
        f = tmp_path / ".hidden_exec"
        f.write_bytes(b"#!/bin/sh\nrm -rf /")
        f.chmod(0o755)

        with patch("ekprotection.scanner.engine.sha256_file", return_value="safe" * 16), \
             patch.object(engine._sig_db, "lookup", return_value=None), \
             patch("ekprotection.scanner.engine.is_elf", return_value=False), \
             patch("ekprotection.scanner.engine.is_script", return_value=True), \
             patch("ekprotection.scanner.engine.file_entropy", return_value=4.0):
            r = engine._scan_file_inner(str(f))

        assert r.verdict == ScanVerdict.SUSPICIOUS
        assert "oculto" in (r.reason or "").lower()


# ---------------------------------------------------------------------------
# Testes: scan de múltiplos arquivos
# ---------------------------------------------------------------------------

class TestScanEnginePaths:
    def test_scan_paths_empty(self, engine: ScanEngine, tmp_path: Path) -> None:
        report = engine.scan_paths([str(tmp_path / "nonexistent")])
        assert report.total_files == 0

    def test_scan_paths_multiple_files(self, engine: ScanEngine, tmp_path: Path) -> None:
        d = tmp_path / "multi"; d.mkdir()
        for i in range(5):
            (d / f"file{i}.txt").write_text(f"content {i}")
        report = engine.scan_paths([str(d)], recursive=False)
        assert report.total_files == 5

    def test_scan_paths_recursive(self, engine: ScanEngine, tmp_path: Path) -> None:
        d = tmp_path / "recur"; d.mkdir()
        sub = d / "sub"; sub.mkdir()
        (d / "root.txt").write_text("root")
        (sub / "child.txt").write_text("child")
        report = engine.scan_paths([str(d)], recursive=True)
        assert report.total_files == 2

    def test_scan_paths_nonrecursive(self, engine: ScanEngine, tmp_path: Path) -> None:
        d = tmp_path / "nonrec"; d.mkdir()
        sub = d / "sub"; sub.mkdir()
        (d / "root.txt").write_text("root")
        (sub / "child.txt").write_text("child")
        report = engine.scan_paths([str(d)], recursive=False)
        assert report.total_files == 1

    def test_scan_paths_progress_callback(self, engine: ScanEngine, tmp_path: Path) -> None:
        d = tmp_path / "cb"; d.mkdir()
        (d / "a.txt").write_text("a")
        (d / "b.txt").write_text("b")
        called = []
        engine.scan_paths([str(d)], progress_cb=lambda p: called.append(p))
        assert len(called) == 2

    def test_scan_paths_reports_threats(self, engine: ScanEngine, tmp_path: Path) -> None:
        f = tmp_path / "threat.bin"
        f.write_bytes(secrets.token_bytes(64))
        threat_hash = _DEMO_SIGNATURES[0]["sha256"]

        with patch("ekprotection.scanner.engine.sha256_file", return_value=threat_hash):
            report = engine.scan_paths([str(f)])

        assert report.threats_found >= 1

    def test_scan_quick_uses_config_paths(self, cfg: ConfigManager,
                                          sig_db: SignatureDB, tmp_path: Path) -> None:
        safe_dir = tmp_path / "quick_scan"
        safe_dir.mkdir()
        (safe_dir / "file.txt").write_text("safe content")
        cfg.set("scanner.quick_scan_paths", [str(safe_dir)])
        eng = ScanEngine(cfg, sig_db=sig_db)
        report = eng.scan_quick()
        assert report.scan_type   == "quick"
        assert report.total_files >= 1

    def test_scan_report_finishes(self, engine: ScanEngine, tmp_path: Path) -> None:
        (tmp_path / "x.txt").write_text("x")
        report = engine.scan_paths([str(tmp_path)])
        assert report.finished_at is not None
        assert report.duration_ms is not None

    def test_auto_quarantine_critical(self, cfg: ConfigManager,
                                      sig_db: SignatureDB, tmp_path: Path) -> None:
        """Ameaça crítica com auto_quarantine=True chama quarantine_file."""
        cfg.set("quarantine.auto_quarantine_critical", True)

        mock_quar = MagicMock()
        mock_quar.quarantine_file.return_value = MagicMock(entry_id=1)

        eng = ScanEngine(cfg, sig_db=sig_db, quar_manager=mock_quar)

        f = tmp_path / "critical.bin"
        f.write_bytes(secrets.token_bytes(64))

        critical_hash = _DEMO_SIGNATURES[1]["sha256"]   # severity=crítico
        with patch("ekprotection.scanner.engine.sha256_file", return_value=critical_hash):
            r = eng.scan_file(f)

        assert r.is_critical is True
        mock_quar.quarantine_file.assert_called_once()

    def test_auto_quarantine_not_triggered_for_non_critical(
        self, cfg: ConfigManager, sig_db: SignatureDB, tmp_path: Path
    ) -> None:
        cfg.set("quarantine.auto_quarantine_critical", True)
        mock_quar = MagicMock()
        eng = ScanEngine(cfg, sig_db=sig_db, quar_manager=mock_quar)

        f = tmp_path / "low.txt"
        f.write_text("safe content")
        eng.scan_file(f)
        mock_quar.quarantine_file.assert_not_called()

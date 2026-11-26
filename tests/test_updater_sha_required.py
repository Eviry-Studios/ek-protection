"""
tests/test_updater_sha_required.py
==================================
Task #578 (EKP-SHA): o fetcher RECUSA manifest sem sha256 válido.

Antes: `if expected_sha:` em fetcher.py pulava a verificação quando o manifest
não trazia `sha256` (ou trazia vazio), e qualquer arquivo baixado era importado.
Agora:
  - sha256 ausente / vazio / não-string / formato != 64 hex -> ManifestError,
    levantado ANTES de baixar o signatures.jsonl; banco intocado.
  - sha256 com formato certo e valor errado -> ChecksumError; banco intocado,
    temporário apagado.
  - sha256 certo (inclusive maiúsculo / com espaço nas pontas) -> importa.
  - UpdateManager.update_now registra o motivo no log e devolve None.
  - Fim a fim via HTTP local real: manifest sem sha256 não chega a pedir o
    signatures.jsonl ao servidor.
"""

from __future__ import annotations

import functools
import hashlib
import json
import logging
import os
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Generator
from unittest.mock import patch

import pytest

from ekprotection.config.manager    import ConfigManager
from ekprotection.scanner.signatures import SignatureDB
from ekprotection.updater.fetcher   import ChecksumError, ManifestError, SignatureFetcher
from ekprotection.updater.manager   import UpdateManager

NEW_HASH = "ab" * 32  # sha256 de "amostra" fictícia que só o feed novo traz
JSONL = (json.dumps({"sha256": NEW_HASH, "name": "Test.FeedNovo",
                     "type": "trojan", "severity": "high"}) + "\n").encode()
JSONL_SHA = hashlib.sha256(JSONL).hexdigest()
OLD_VERSION = "2026.01.01"


@pytest.fixture
def tmp_dir(tmp_path: Path) -> Generator[Path, None, None]:
    os.environ["EKP_DATA_DIR"] = str(tmp_path)
    yield tmp_path
    os.environ.pop("EKP_DATA_DIR", None)


@pytest.fixture
def sig_db(tmp_dir: Path) -> Generator[SignatureDB, None, None]:
    db = SignatureDB(tmp_dir / "sigs.db")
    db.open()
    db._conn.execute("UPDATE signature_meta SET value=? WHERE key='version'", (OLD_VERSION,))
    yield db
    db.close()


def _fetcher(sig_db: SignatureDB, tmp_dir: Path, url: str = "http://test.local/m.json") -> SignatureFetcher:
    return SignatureFetcher(manifest_url=url, sig_db=sig_db, cache_dir=tmp_dir, timeout=5)


def _manifest(**over) -> dict:
    m = {"version": "2026.11.25", "updated_at": "2026-11-25T03:00:00Z",
         "signatures_url": "http://test.local/sigs.jsonl", "sha256": JSONL_SHA}
    m.update(over)
    return {k: v for k, v in m.items() if v is not _DROP}


_DROP = object()


def _fake_download(tmp_dir: Path, calls: list):
    def dl(url: str) -> Path:
        calls.append(url)
        p = tmp_dir / ".sig_download.tmp"
        p.write_bytes(JSONL)
        return p
    return dl


def _assert_db_untouched(sig_db: SignatureDB, count_before: int) -> None:
    assert sig_db.meta()["version"] == OLD_VERSION
    assert sig_db.lookup(NEW_HASH) is None
    assert sig_db.count() == count_before


# --- recusa antes do download ------------------------------------------------

@pytest.mark.parametrize("sha", [
    _DROP,                 # chave ausente (o caso do FEED.md §1.4)
    "",                    # vazio
    None,                  # null no JSON
    "   ",                 # só espaço
    123,                   # tipo errado
    ["a" * 64],            # tipo errado
    "a" * 63,              # curto
    "a" * 65,              # longo
    "g" * 64,              # não-hex
    "md5:" + "a" * 60,     # prefixo de algoritmo não suportado
], ids=["ausente", "vazio", "null", "espacos", "int", "lista",
        "63hex", "65hex", "nao_hex", "prefixo"])
def test_manifest_without_valid_sha_is_refused_before_download(
    sig_db: SignatureDB, tmp_dir: Path, sha,
) -> None:
    before = sig_db.count()
    calls: list = []
    f = _fetcher(sig_db, tmp_dir)
    with patch.object(f, "_fetch_manifest", return_value=_manifest(sha256=sha)), \
         patch.object(f, "_download_file", side_effect=_fake_download(tmp_dir, calls)):
        with pytest.raises(ManifestError, match="sha256"):
            f.update()
    assert calls == [], "não pode baixar o arquivo de assinaturas sem checksum"
    _assert_db_untouched(sig_db, before)


def test_wrong_sha_raises_checksum_error_and_keeps_db(sig_db: SignatureDB, tmp_dir: Path) -> None:
    before = sig_db.count()
    calls: list = []
    f = _fetcher(sig_db, tmp_dir)
    wrong = hashlib.sha256(b"outro conteudo").hexdigest()
    with patch.object(f, "_fetch_manifest", return_value=_manifest(sha256=wrong)), \
         patch.object(f, "_download_file", side_effect=_fake_download(tmp_dir, calls)):
        with pytest.raises(ChecksumError):
            f.update()
    assert len(calls) == 1
    assert not (tmp_dir / ".sig_download.tmp").exists()
    _assert_db_untouched(sig_db, before)


@pytest.mark.parametrize("sha", [JSONL_SHA, JSONL_SHA.upper(), f"  {JSONL_SHA}\n"],
                         ids=["minusculo", "maiusculo", "com_espaco"])
def test_right_sha_imports(sig_db: SignatureDB, tmp_dir: Path, sha: str) -> None:
    calls: list = []
    f = _fetcher(sig_db, tmp_dir)
    with patch.object(f, "_fetch_manifest", return_value=_manifest(sha256=sha)), \
         patch.object(f, "_download_file", side_effect=_fake_download(tmp_dir, calls)):
        r = f.update()
    assert r.updated is True and r.added == 1
    assert sig_db.meta()["version"] == "2026.11.25"
    assert sig_db.lookup(NEW_HASH) is not None


def test_same_version_without_sha_is_noop_not_error(sig_db: SignatureDB, tmp_dir: Path) -> None:
    """Versão igual não aplica nada, então não precisa (nem deve) falhar."""
    f = _fetcher(sig_db, tmp_dir)
    with patch.object(f, "_fetch_manifest", return_value=_manifest(version=OLD_VERSION, sha256=_DROP)):
        r = f.update()
    assert r.updated is False


def test_update_manager_logs_clear_reason(
    sig_db: SignatureDB, tmp_dir: Path, caplog: pytest.LogCaptureFixture,
) -> None:
    cfg = ConfigManager(tmp_dir / "config.yaml")
    cfg.load()
    cfg.set("signatures.auto_update", False)
    mgr = UpdateManager(cfg, sig_db=sig_db)
    mgr.initialize()
    before = sig_db.count()
    with patch.object(mgr._fetcher, "_fetch_manifest", return_value=_manifest(sha256=_DROP)), \
         caplog.at_level(logging.ERROR, logger="ekprotection.updater.manager"):
        assert mgr.update_now() is None
    msgs = " | ".join(r.getMessage() for r in caplog.records)
    assert "sem 'sha256'" in msgs and "recusada" in msgs
    _assert_db_untouched(sig_db, before)


# --- fim a fim, HTTP local real ------------------------------------------------

class _LoggingHandler(SimpleHTTPRequestHandler):
    requests: list

    def log_message(self, *a) -> None:  # silencia stderr
        pass

    def do_GET(self) -> None:
        type(self).requests.append(self.path)
        super().do_GET()


@pytest.fixture
def feed_server(tmp_path_factory: pytest.TempPathFactory):
    mirror = tmp_path_factory.mktemp("feed_sem_sha")
    (mirror / "signatures.jsonl").write_bytes(JSONL)
    handler_cls = type("H", (_LoggingHandler,), {"requests": []})
    server = ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(handler_cls, directory=str(mirror)))
    base = f"http://127.0.0.1:{server.server_port}"
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        yield base, mirror, handler_cls.requests
    finally:
        server.shutdown()
        t.join(timeout=5)


def test_e2e_http_manifest_without_sha_never_fetches_signatures(
    sig_db: SignatureDB, tmp_dir: Path, feed_server,
) -> None:
    base, mirror, reqs = feed_server
    m = _manifest(signatures_url=f"{base}/signatures.jsonl", sha256=_DROP)
    (mirror / "manifest.json").write_text(json.dumps(m), encoding="utf-8")
    before = sig_db.count()
    with pytest.raises(ManifestError, match="sha256"):
        _fetcher(sig_db, tmp_dir, f"{base}/manifest.json").update()
    assert reqs == ["/manifest.json"]
    _assert_db_untouched(sig_db, before)

    # Controle: o mesmo servidor com o sha256 certo importa (prova que o
    # teste acima falhou pelo motivo certo, não por servidor quebrado).
    m["sha256"] = JSONL_SHA
    (mirror / "manifest.json").write_text(json.dumps(m), encoding="utf-8")
    r = _fetcher(sig_db, tmp_dir, f"{base}/manifest.json").update()
    assert r.updated is True and sig_db.lookup(NEW_HASH) is not None
    assert reqs == ["/manifest.json", "/manifest.json", "/signatures.jsonl"]

"""
tests/test_updater.py
======================
Testes do sistema de atualização e daemon IPC (Patch 9).

Cobre:
  - FetchResult: criação, repr
  - SignatureFetcher: _sha256_file, _current_version, check_available (mock HTTP),
                     update (mock HTTP — sucesso, versão igual, checksum inválido,
                     manifest inválido)
  - UpdateManager: initialize, update_now, check_available, status, stop
  - IPCServer: start/stop, _dispatch (status, ping, stop, scan_file, log_tail,
               quarantine_list, comando desconhecido)
  - IPCClient: send (mock socket), is_alive
  - Daemonização: _write_pid, _remove_pid, _notify_systemd
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import tempfile
import threading
import time
from pathlib import Path
from typing  import Generator
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest

from ekprotection.config.manager       import ConfigManager
from ekprotection.scanner.signatures   import SignatureDB
from ekprotection.updater.fetcher      import (
    SignatureFetcher, FetchResult,
    UpdateError, ChecksumError, ManifestError,
)
from ekprotection.updater.manager      import UpdateManager
from ekprotection.daemon               import (
    IPCServer, IPCClient,
    _write_pid, _remove_pid, _notify_systemd,
    _ok, _err,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_dir(tmp_path: Path) -> Path:
    os.environ["EKP_DATA_DIR"] = str(tmp_path)
    yield tmp_path
    os.environ.pop("EKP_DATA_DIR", None)


@pytest.fixture
def cfg(tmp_dir: Path) -> ConfigManager:
    m = ConfigManager(tmp_dir / "config.yaml")
    m.load()
    m.set("logs.db_path",            str(tmp_dir / "test.db"))
    m.set("signatures.db_path",      str(tmp_dir / "sigs.db"))
    m.set("signatures.auto_update",  False)
    return m


@pytest.fixture
def sig_db(tmp_dir: Path) -> Generator[SignatureDB, None, None]:
    db = SignatureDB(tmp_dir / "sigs.db")
    db.open()
    yield db
    db.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_jsonl(entries: list[dict]) -> bytes:
    return b"\n".join(json.dumps(e).encode() for e in entries) + b"\n"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Testes: FetchResult
# ---------------------------------------------------------------------------

class TestFetchResult:
    def test_creation(self) -> None:
        r = FetchResult(
            updated=True, version_before="1.0", version_after="2.0",
            added=50, duplicates=5, message="ok",
        )
        assert r.updated        is True
        assert r.version_before == "1.0"
        assert r.version_after  == "2.0"
        assert r.added          == 50
        assert r.duplicates     == 5

    def test_repr(self) -> None:
        r = FetchResult(True, "1.0", "2.0", added=10)
        assert "1.0" in repr(r)
        assert "2.0" in repr(r)

    def test_not_updated(self) -> None:
        r = FetchResult(False, "1.0", "1.0")
        assert r.updated     is False
        assert r.added       == 0
        assert r.duplicates  == 0


# ---------------------------------------------------------------------------
# Testes: SignatureFetcher
# ---------------------------------------------------------------------------

class TestSignatureFetcherHelpers:
    def test_sha256_file(self, tmp_dir: Path) -> None:
        data = b"test content for hashing"
        f    = tmp_dir / "test.bin"
        f.write_bytes(data)
        expected = hashlib.sha256(data).hexdigest()
        fetcher  = SignatureFetcher("http://x.com/manifest.json", MagicMock(), tmp_dir)
        assert fetcher._sha256_file(f) == expected

    def test_current_version_from_db(self, sig_db: SignatureDB, tmp_dir: Path) -> None:
        sig_db._conn.execute(
            "UPDATE signature_meta SET value='2024.01.01' WHERE key='version'"
        )
        fetcher = SignatureFetcher("http://x.com/manifest.json", sig_db, tmp_dir)
        assert fetcher._current_version() == "2024.01.01"

    def test_current_version_default(self, tmp_dir: Path) -> None:
        mock_db = MagicMock()
        mock_db.meta.return_value = {}
        fetcher = SignatureFetcher("http://x.com/manifest.json", mock_db, tmp_dir)
        assert fetcher._current_version() == "0.0.0"


class TestSignatureFetcherUpdate:
    def _make_fetcher(self, sig_db: SignatureDB, tmp_dir: Path) -> SignatureFetcher:
        return SignatureFetcher(
            manifest_url = "http://test.local/manifest.json",
            sig_db       = sig_db,
            cache_dir    = tmp_dir,
            timeout      = 5,
        )

    def test_already_up_to_date(self, sig_db: SignatureDB, tmp_dir: Path) -> None:
        """Versão local == remota → FetchResult(updated=False)."""
        sig_db._conn.execute(
            "UPDATE signature_meta SET value='2024.06.01' WHERE key='version'"
        )
        fetcher  = self._make_fetcher(sig_db, tmp_dir)
        manifest = json.dumps({"version": "2024.06.01", "sha256": "", "signatures_url": ""})

        with patch.object(fetcher, "_fetch_manifest", return_value=json.loads(manifest)):
            result = fetcher.update()

        assert result.updated is False
        assert result.version_after == "2024.06.01"

    def test_successful_update(self, sig_db: SignatureDB, tmp_dir: Path) -> None:
        """Baixa JSONL, verifica checksum e importa assinaturas."""
        entries = [
            {"sha256": f"hash_{i:040x}", "name": f"Test.{i}",
             "threat_type": "Test", "severity": "baixo", "source": "test"}
            for i in range(5)
        ]
        jsonl_data = _make_jsonl(entries)
        sha256     = _sha256(jsonl_data)
        manifest   = {
            "version":        "2024.06.15",
            "updated_at":     "2024-06-15T00:00:00Z",
            "signatures_url": "http://test.local/signatures.jsonl",
            "sha256":         sha256,
            "count":          5,
        }

        fetcher = self._make_fetcher(sig_db, tmp_dir)

        def fake_download(url: str) -> Path:
            p = tmp_dir / ".sig_download.tmp"
            p.write_bytes(jsonl_data)
            return p

        with patch.object(fetcher, "_fetch_manifest", return_value=manifest), \
             patch.object(fetcher, "_download_file",  side_effect=fake_download):
            result = fetcher.update()

        assert result.updated        is True
        assert result.version_after  == "2024.06.15"
        assert result.added          == 5
        assert sig_db.meta()["version"] == "2024.06.15"

    def test_checksum_failure_raises(self, sig_db: SignatureDB, tmp_dir: Path) -> None:
        """Checksum incorreto → ChecksumError."""
        manifest = {
            "version":        "2024.06.20",
            "signatures_url": "http://test.local/sigs.jsonl",
            "sha256":         "wrong_checksum_000000000000000000000000000000000",
        }
        fetcher = self._make_fetcher(sig_db, tmp_dir)

        def fake_download(url: str) -> Path:
            p = tmp_dir / ".sig_download.tmp"
            p.write_bytes(b"some data")
            return p

        with patch.object(fetcher, "_fetch_manifest", return_value=manifest), \
             patch.object(fetcher, "_download_file",  side_effect=fake_download):
            with pytest.raises(ChecksumError):
                fetcher.update()

    def test_manifest_missing_version_raises(self, sig_db: SignatureDB, tmp_dir: Path) -> None:
        fetcher = self._make_fetcher(sig_db, tmp_dir)
        with patch.object(fetcher, "_fetch_manifest", return_value={"no_version": True}):
            with pytest.raises(ManifestError, match="version"):
                fetcher.update()

    def test_manifest_missing_signatures_url_raises(self, sig_db: SignatureDB, tmp_dir: Path) -> None:
        sig_db._conn.execute(
            "UPDATE signature_meta SET value='old' WHERE key='version'"
        )
        fetcher = self._make_fetcher(sig_db, tmp_dir)
        with patch.object(fetcher, "_fetch_manifest", return_value={"version": "new"}):
            with pytest.raises(ManifestError, match="signatures_url"):
                fetcher.update()

    def test_network_error_raises(self, sig_db: SignatureDB, tmp_dir: Path) -> None:
        fetcher = self._make_fetcher(sig_db, tmp_dir)
        with patch.object(fetcher, "_http_get", side_effect=UpdateError("network down")):
            with pytest.raises(ManifestError):
                fetcher.update()

    def test_check_available_newer_version(self, sig_db: SignatureDB, tmp_dir: Path) -> None:
        fetcher = self._make_fetcher(sig_db, tmp_dir)
        with patch.object(fetcher, "_fetch_manifest", return_value={"version": "9999.01.01"}):
            available, local, remote = fetcher.check_update_available()
        assert available is True
        assert remote == "9999.01.01"

    def test_check_available_same_version(self, sig_db: SignatureDB, tmp_dir: Path) -> None:
        sig_db._conn.execute(
            "UPDATE signature_meta SET value='1.0.0' WHERE key='version'"
        )
        fetcher = self._make_fetcher(sig_db, tmp_dir)
        with patch.object(fetcher, "_fetch_manifest", return_value={"version": "1.0.0"}):
            available, local, remote = fetcher.check_update_available()
        assert available is False

    def test_check_available_network_error(self, sig_db: SignatureDB, tmp_dir: Path) -> None:
        fetcher = self._make_fetcher(sig_db, tmp_dir)
        with patch.object(fetcher, "_http_get", side_effect=Exception("offline")):
            available, local, remote = fetcher.check_update_available()
        assert available is False
        assert remote    == ""


# ---------------------------------------------------------------------------
# Testes: manifest/signatures reais do repositório, via HTTP local de verdade
# (nenhum mock — valida que signatures/manifest.json + signatures/
# signatures.jsonl publicados no repo são consumíveis pelo fetcher real,
# o mesmo caminho que `raw.githubusercontent.com/.../main/signatures/`
# serve em produção).
# ---------------------------------------------------------------------------

REPO_ROOT     = Path(__file__).parent.parent
SIGNATURES_DIR = REPO_ROOT / "signatures"


@pytest.fixture
def real_signatures_server(tmp_path_factory: pytest.TempPathFactory) -> Generator[str, None, None]:
    """
    Sobe um servidor HTTP local servindo uma cópia de signatures/ do
    próprio repo. `signatures.jsonl` é servido byte-a-byte igual ao real;
    `manifest.json` é uma cópia do real com `signatures_url` reapontado
    pro servidor local (em produção aponta pro raw.githubusercontent.com
    absoluto, que este teste não pode/deve chamar de verdade) — versão e
    sha256 continuam os mesmos publicados no repo.
    """
    import functools
    import shutil
    from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler

    mirror = tmp_path_factory.mktemp("signatures_mirror")
    shutil.copy(SIGNATURES_DIR / "signatures.jsonl", mirror / "signatures.jsonl")
    manifest = json.loads((SIGNATURES_DIR / "manifest.json").read_bytes())

    handler = functools.partial(SimpleHTTPRequestHandler, directory=str(mirror))
    server  = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    manifest["signatures_url"] = f"http://127.0.0.1:{server.server_port}/signatures.jsonl"
    (mirror / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)


class TestSignatureFetcherRealManifest:
    def test_manifest_and_signatures_files_exist(self) -> None:
        assert (SIGNATURES_DIR / "manifest.json").is_file()
        assert (SIGNATURES_DIR / "signatures.jsonl").is_file()

    def test_manifest_sha256_matches_signatures_file(self) -> None:
        manifest = json.loads((SIGNATURES_DIR / "manifest.json").read_bytes())
        actual   = _sha256((SIGNATURES_DIR / "signatures.jsonl").read_bytes())
        assert manifest["sha256"] == actual

    def test_update_pulls_real_manifest_over_http(
        self, sig_db: SignatureDB, tmp_dir: Path, real_signatures_server: str,
    ) -> None:
        """Fim a fim, sem mock: HTTP real -> checksum real -> import real."""
        fetcher = SignatureFetcher(
            manifest_url = f"{real_signatures_server}/manifest.json",
            sig_db       = sig_db,
            cache_dir    = tmp_dir,
            timeout      = 5,
        )
        result = fetcher.update()

        assert result.updated is True
        # sig_db já vem com o EICAR via _seed_demo() (SignatureDB.open());
        # o import real do JSONL baixado bate nele e conta como duplicata
        # -- confirma que o parse/checksum/import de verdade rodou mesmo
        # assim (added=0 só quando o import falha silenciosamente).
        assert result.added + result.duplicates == 1
        entry = sig_db.lookup(
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        )
        assert entry is not None
        assert entry["name"] == "EICAR.Test.File"

        # Segunda chamada, mesma versão local == remota -> não reimporta.
        result2 = fetcher.update()
        assert result2.updated is False


# ---------------------------------------------------------------------------
# Testes: UpdateManager
# ---------------------------------------------------------------------------

class TestUpdateManager:
    def test_initialize(self, cfg: ConfigManager, sig_db: SignatureDB) -> None:
        mgr = UpdateManager(cfg, sig_db=sig_db)
        mgr.initialize()
        assert mgr._fetcher is not None

    def test_status_fields(self, cfg: ConfigManager, sig_db: SignatureDB) -> None:
        mgr = UpdateManager(cfg, sig_db=sig_db)
        mgr.initialize()
        s = mgr.status()
        for key in ("auto_update", "interval_hours", "last_check",
                    "running", "signatures", "sig_version", "update_url"):
            assert key in s

    def test_update_now_success(self, cfg: ConfigManager, sig_db: SignatureDB) -> None:
        mgr = UpdateManager(cfg, sig_db=sig_db)
        mgr.initialize()

        mock_result = FetchResult(True, "0.0.0", "2024.01.01", added=10)
        with patch.object(mgr._fetcher, "update", return_value=mock_result):
            result = mgr.update_now()

        assert result is not None
        assert result.updated is True
        assert mgr._last_check is not None

    def test_update_now_failure_returns_none(self, cfg: ConfigManager, sig_db: SignatureDB) -> None:
        mgr = UpdateManager(cfg, sig_db=sig_db)
        mgr.initialize()
        with patch.object(mgr._fetcher, "update", side_effect=UpdateError("offline")):
            result = mgr.update_now()
        assert result is None

    def test_update_now_no_sig_db(self, cfg: ConfigManager) -> None:
        mgr = UpdateManager(cfg, sig_db=None)
        result = mgr.update_now()
        assert result is None

    def test_check_available(self, cfg: ConfigManager, sig_db: SignatureDB) -> None:
        mgr = UpdateManager(cfg, sig_db=sig_db)
        mgr.initialize()
        with patch.object(mgr._fetcher, "check_update_available",
                          return_value=(True, "0.0.0", "1.0.0")):
            avail, local, remote = mgr.check_available()
        assert avail  is True
        assert remote == "1.0.0"

    def test_stop(self, cfg: ConfigManager, sig_db: SignatureDB) -> None:
        mgr = UpdateManager(cfg, sig_db=sig_db)
        mgr._running = True
        mgr.stop()
        assert mgr._running is False

    @pytest.mark.asyncio
    async def test_run_loop_disabled(self, cfg: ConfigManager, sig_db: SignatureDB) -> None:
        cfg.set("signatures.auto_update", False)
        mgr = UpdateManager(cfg, sig_db=sig_db)
        mgr.initialize()
        # Should return immediately without iterating
        await asyncio.wait_for(mgr.run_loop(), timeout=2.0)

    def test_audit_with_log_manager(self, cfg: ConfigManager, sig_db: SignatureDB) -> None:
        mock_log = MagicMock()
        mock_src = MagicMock()
        mock_log.get_source.return_value = mock_src

        mgr = UpdateManager(cfg, sig_db=sig_db, log_manager=mock_log)
        mgr.initialize()

        result = FetchResult(True, "0.0.0", "1.0.0", added=5)
        mgr._audit(result)
        mock_src.event.assert_called_once()


# ---------------------------------------------------------------------------
# Testes: IPC helpers
# ---------------------------------------------------------------------------

class TestIPCHelpers:
    def test_ok_message(self) -> None:
        msg = _ok({"state": "RUNNING"})
        parsed = json.loads(msg.decode().strip())
        assert parsed["ok"]             is True
        assert parsed["data"]["state"]  == "RUNNING"

    def test_err_message(self) -> None:
        msg = _err("something failed")
        parsed = json.loads(msg.decode().strip())
        assert parsed["ok"]    is False
        assert "failed" in parsed["error"]

    def test_write_pid(self, tmp_dir: Path) -> None:
        pid_file = str(tmp_dir / "test.pid")
        _write_pid(pid_file)
        assert Path(pid_file).read_text().strip() == str(os.getpid())

    def test_remove_pid(self, tmp_dir: Path) -> None:
        pid_file = str(tmp_dir / "remove.pid")
        Path(pid_file).write_text("123")
        _remove_pid(pid_file)
        assert not Path(pid_file).exists()

    def test_remove_pid_missing_ok(self, tmp_dir: Path) -> None:
        _remove_pid(str(tmp_dir / "nonexistent.pid"))   # não deve lançar

    def test_notify_systemd_no_socket(self) -> None:
        # Sem NOTIFY_SOCKET — deve ser silencioso
        os.environ.pop("NOTIFY_SOCKET", None)
        _notify_systemd("READY=1\n")   # não deve lançar


# ---------------------------------------------------------------------------
# Testes: IPCServer dispatch
# ---------------------------------------------------------------------------

class TestIPCServerDispatch:
    """Testes do dispatcher IPC sem socket real (testa lógica pura)."""

    def _make_server(self) -> IPCServer:
        mock_engine = MagicMock()
        mock_engine.status.return_value = {"state": "RUNNING", "version": "0.9.0"}
        mock_engine._stop_event = asyncio.Event()
        return IPCServer("/tmp/test_ekp_ipc.sock", mock_engine)

    @pytest.mark.asyncio
    async def test_dispatch_ping(self) -> None:
        server = self._make_server()
        resp   = await server._dispatch({"cmd": "ping"})
        parsed = json.loads(resp.decode().strip())
        assert parsed["ok"]   is True
        assert parsed["data"] == "pong"

    @pytest.mark.asyncio
    async def test_dispatch_status(self) -> None:
        server = self._make_server()
        resp   = await server._dispatch({"cmd": "status"})
        parsed = json.loads(resp.decode().strip())
        assert parsed["ok"]              is True
        assert parsed["data"]["state"]   == "RUNNING"

    @pytest.mark.asyncio
    async def test_dispatch_unknown_command(self) -> None:
        server = self._make_server()
        resp   = await server._dispatch({"cmd": "nonexistent_cmd"})
        parsed = json.loads(resp.decode().strip())
        assert parsed["ok"] is False
        assert "desconhecido" in parsed["error"]

    @pytest.mark.asyncio
    async def test_dispatch_stop(self) -> None:
        server = self._make_server()
        resp   = await server._dispatch({"cmd": "stop"})
        parsed = json.loads(resp.decode().strip())
        assert parsed["ok"]   is True
        assert parsed["data"] == "stopping"

    @pytest.mark.asyncio
    async def test_dispatch_scan_file_no_scanner(self) -> None:
        server = self._make_server()
        server._engine.get_subsystem.return_value = None
        resp   = await server._dispatch({"cmd": "scan_file", "path": "/tmp/x.sh"})
        parsed = json.loads(resp.decode().strip())
        assert parsed["ok"] is False

    @pytest.mark.asyncio
    async def test_dispatch_scan_file_missing_path(self) -> None:
        server = self._make_server()
        resp   = await server._dispatch({"cmd": "scan_file"})  # no path
        parsed = json.loads(resp.decode().strip())
        assert parsed["ok"] is False
        assert "path" in parsed["error"]

    @pytest.mark.asyncio
    async def test_dispatch_scan_file_success(self) -> None:
        server  = self._make_server()
        mock_scanner = MagicMock()
        mock_result  = MagicMock()
        mock_result.to_dict.return_value = {"verdict": "clean", "path": "/tmp/x.sh"}
        mock_scanner.scan_file.return_value = mock_result
        server._engine.get_subsystem.return_value = mock_scanner

        resp   = await server._dispatch({"cmd": "scan_file", "path": "/tmp/x.sh"})
        parsed = json.loads(resp.decode().strip())
        assert parsed["ok"]               is True
        assert parsed["data"]["verdict"]  == "clean"

    @pytest.mark.asyncio
    async def test_dispatch_log_tail_no_logs(self) -> None:
        server = self._make_server()
        server._engine.logs = None
        resp   = await server._dispatch({"cmd": "log_tail"})
        parsed = json.loads(resp.decode().strip())
        assert parsed["ok"] is False

    @pytest.mark.asyncio
    async def test_dispatch_log_tail_success(self) -> None:
        server   = self._make_server()
        mock_log = MagicMock()
        mock_entry = MagicMock()
        mock_entry.to_dict.return_value = {"message": "test", "level": "INFO"}
        mock_log.query.return_value = [mock_entry]
        server._engine.logs = mock_log

        resp   = await server._dispatch({"cmd": "log_tail", "n": 5})
        parsed = json.loads(resp.decode().strip())
        assert parsed["ok"]          is True
        assert len(parsed["data"])   == 1
        assert parsed["data"][0]["message"] == "test"

    @pytest.mark.asyncio
    async def test_dispatch_quarantine_list_no_quar(self) -> None:
        server = self._make_server()
        server._engine.quarantine = None
        resp   = await server._dispatch({"cmd": "quarantine_list"})
        parsed = json.loads(resp.decode().strip())
        assert parsed["ok"] is False

    @pytest.mark.asyncio
    async def test_dispatch_quarantine_list_success(self) -> None:
        server   = self._make_server()
        mock_quar = MagicMock()
        mock_entry = MagicMock()
        mock_entry.to_dict.return_value = {"quarantine_id": "abc", "status": "active"}
        mock_quar.list_active.return_value = [mock_entry]
        server._engine.quarantine = mock_quar

        resp   = await server._dispatch({"cmd": "quarantine_list"})
        parsed = json.loads(resp.decode().strip())
        assert parsed["ok"]        is True
        assert len(parsed["data"]) == 1

    @pytest.mark.asyncio
    async def test_dispatch_quarantine_info_no_quar(self) -> None:
        server = self._make_server()
        server._engine.quarantine = None
        resp   = await server._dispatch({"cmd": "quarantine_info", "entry_id": 1})
        parsed = json.loads(resp.decode().strip())
        assert parsed["ok"] is False

    @pytest.mark.asyncio
    async def test_dispatch_quarantine_info_missing_entry_id(self) -> None:
        server = self._make_server()
        server._engine.quarantine = MagicMock()
        resp   = await server._dispatch({"cmd": "quarantine_info"})
        parsed = json.loads(resp.decode().strip())
        assert parsed["ok"] is False
        assert "entry_id" in parsed["error"]

    @pytest.mark.asyncio
    async def test_dispatch_quarantine_info_not_found(self) -> None:
        server    = self._make_server()
        mock_quar = MagicMock()
        mock_quar.get_by_id.return_value = None
        server._engine.quarantine = mock_quar

        resp   = await server._dispatch({"cmd": "quarantine_info", "entry_id": 99})
        parsed = json.loads(resp.decode().strip())
        assert parsed["ok"] is False

    @pytest.mark.asyncio
    async def test_dispatch_quarantine_info_success(self) -> None:
        server     = self._make_server()
        mock_quar  = MagicMock()
        mock_entry = MagicMock()
        mock_entry.to_dict.return_value = {"id": 7, "quarantine_id": "abc", "status": "active"}
        mock_quar.get_by_id.return_value = mock_entry
        server._engine.quarantine = mock_quar

        resp   = await server._dispatch({"cmd": "quarantine_info", "entry_id": 7})
        parsed = json.loads(resp.decode().strip())
        assert parsed["ok"]             is True
        assert parsed["data"]["id"]     == 7
        mock_quar.get_by_id.assert_called_once_with(7)

    @pytest.mark.asyncio
    async def test_dispatch_quarantine_stats_no_quar(self) -> None:
        server = self._make_server()
        server._engine.quarantine = None
        resp   = await server._dispatch({"cmd": "quarantine_stats"})
        parsed = json.loads(resp.decode().strip())
        assert parsed["ok"] is False

    @pytest.mark.asyncio
    async def test_dispatch_quarantine_stats_success(self) -> None:
        server    = self._make_server()
        mock_quar = MagicMock()
        mock_quar.stats.return_value = {"active": 2, "restored": 1, "total": 3}
        server._engine.quarantine = mock_quar

        resp   = await server._dispatch({"cmd": "quarantine_stats"})
        parsed = json.loads(resp.decode().strip())
        assert parsed["ok"]              is True
        assert parsed["data"]["active"]  == 2


# ---------------------------------------------------------------------------
# Testes: IPCServer start/stop com socket real
# ---------------------------------------------------------------------------

class TestIPCServerSocket:
    @pytest.mark.asyncio
    async def test_server_starts_and_stops(self, tmp_dir: Path) -> None:
        sock_path = str(tmp_dir / "test_ipc.sock")
        mock_engine = MagicMock()
        mock_engine.status.return_value = {"state": "RUNNING"}
        mock_engine._stop_event = asyncio.Event()

        server = IPCServer(sock_path, mock_engine)
        await server.start()
        assert Path(sock_path).exists()
        await server.stop()
        assert not Path(sock_path).exists()

    @pytest.mark.asyncio
    async def test_server_handles_real_client(self, tmp_dir: Path) -> None:
        sock_path = str(tmp_dir / "live_ipc.sock")
        mock_engine = MagicMock()
        mock_engine.status.return_value = {"state": "RUNNING", "version": "0.9.0"}
        mock_engine._stop_event = asyncio.Event()

        server = IPCServer(sock_path, mock_engine)
        await server.start()

        # Conecta como cliente
        reader, writer = await asyncio.open_unix_connection(sock_path)
        writer.write(b'{"cmd": "ping"}\n')
        await writer.drain()

        response = await asyncio.wait_for(reader.readline(), timeout=5.0)
        parsed   = json.loads(response.decode().strip())
        writer.close()
        await writer.wait_closed()

        await server.stop()

        assert parsed["ok"]   is True
        assert parsed["data"] == "pong"

    @pytest.mark.asyncio
    async def test_server_handles_invalid_json(self, tmp_dir: Path) -> None:
        sock_path = str(tmp_dir / "invalid_ipc.sock")
        mock_engine = MagicMock()
        mock_engine._stop_event = asyncio.Event()

        server = IPCServer(sock_path, mock_engine)
        await server.start()

        reader, writer = await asyncio.open_unix_connection(sock_path)
        writer.write(b"NOT JSON AT ALL\n")
        await writer.drain()

        response = await asyncio.wait_for(reader.readline(), timeout=5.0)
        parsed   = json.loads(response.decode().strip())
        writer.close()
        await writer.wait_closed()

        await server.stop()

        assert parsed["ok"] is False
        assert "JSON" in parsed["error"]


# ---------------------------------------------------------------------------
# Testes: IPCClient
# ---------------------------------------------------------------------------

class TestIPCClient:
    def test_is_alive_when_ping_succeeds(self, tmp_dir: Path) -> None:
        client = IPCClient(str(tmp_dir / "test.sock"))
        with patch.object(client, "send", return_value={"ok": True, "data": "pong"}):
            assert client.is_alive() is True

    def test_is_alive_when_connection_fails(self, tmp_dir: Path) -> None:
        client = IPCClient(str(tmp_dir / "nonexistent.sock"))
        assert client.is_alive() is False

    def test_is_alive_when_response_not_pong(self, tmp_dir: Path) -> None:
        client = IPCClient(str(tmp_dir / "test.sock"))
        with patch.object(client, "send", return_value={"ok": True, "data": "something_else"}):
            assert client.is_alive() is False

    def test_send_connection_refused(self, tmp_dir: Path) -> None:
        client = IPCClient(str(tmp_dir / "missing.sock"))
        with pytest.raises(ConnectionError):
            client.send("status")

    @pytest.mark.asyncio
    async def test_send_to_live_server(self, tmp_dir: Path) -> None:
        """Testa send() real contra IPCServer."""
        sock_path = str(tmp_dir / "client_test.sock")

        mock_engine = MagicMock()
        mock_engine.status.return_value = {"state": "RUNNING"}
        mock_engine._stop_event = asyncio.Event()

        server = IPCServer(sock_path, mock_engine)
        await server.start()

        # Executa send() em thread separada (é síncrono)
        loop   = asyncio.get_running_loop()
        client = IPCClient(sock_path, timeout=5.0)
        result = await loop.run_in_executor(None, client.send, "status")

        await server.stop()

        assert result["ok"]             is True
        assert result["data"]["state"]  == "RUNNING"

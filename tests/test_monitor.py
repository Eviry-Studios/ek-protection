"""
tests/test_monitor.py
======================
Testes do subsistema de monitoramento (Patch 4).

Cobre:
  - FileEvent: criação, propriedades, extensão, is_executable_extension
  - ProcessEvent: criação, campos opcionais
  - FSWatcher: start/stop, status, filtragem de extensões chatas,
               padrões ignore, enfileiramento correto de eventos
  - ProcWatcher: snapshot, detecção de novos/encerrados, suspeitos
  - MonitorManager: start/stop, callbacks sync e async, contadores,
                    dispatcher, log_event_from
"""

from __future__ import annotations

import asyncio
import os
import time
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Generator, List
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest

from ekprotection.config.manager     import ConfigManager
from ekprotection.monitor.events     import (
    FileEvent, FileEventKind,
    ProcessEvent, ProcEventKind,
)
from ekprotection.monitor.fs_watcher import FSWatcher, _EKPEventHandler
from ekprotection.monitor.proc_watcher import ProcWatcher, _SUSPICIOUS_EXEC_DIRS
from ekprotection.monitor.manager    import MonitorManager


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def cfg(tmp_path: Path) -> ConfigManager:
    manager = ConfigManager(tmp_path / "config.yaml")
    manager.load()
    manager.set("monitor.paths", [str(tmp_path)])
    manager.set("monitor.recursive", True)
    manager.set("monitor.ignore_patterns", [])
    return manager


@pytest.fixture
def event_queue() -> asyncio.Queue:
    return asyncio.Queue()


# ---------------------------------------------------------------------------
# Testes: FileEvent
# ---------------------------------------------------------------------------

class TestFileEvent:
    def test_basic_creation(self) -> None:
        ev = FileEvent(kind=FileEventKind.CREATED, path="/tmp/test.sh")
        assert ev.kind == FileEventKind.CREATED
        assert ev.path == "/tmp/test.sh"
        assert isinstance(ev.timestamp, datetime)

    def test_extension_lowercase(self) -> None:
        ev = FileEvent(kind=FileEventKind.CREATED, path="/tmp/FILE.SH")
        assert ev.extension == ".sh"

    def test_extension_no_ext(self) -> None:
        ev = FileEvent(kind=FileEventKind.CREATED, path="/tmp/myelf")
        assert ev.extension == ""

    def test_is_executable_extension_true(self) -> None:
        for ext in [".sh", ".py", ".pl", ".rb", ".elf", ""]:
            ev = FileEvent(kind=FileEventKind.CREATED, path=f"/tmp/file{ext}")
            assert ev.is_executable_extension, f"Expected True for {ext}"

    def test_is_executable_extension_false(self) -> None:
        for ext in [".txt", ".jpg", ".pdf", ".mp3", ".zip"]:
            ev = FileEvent(kind=FileEventKind.CREATED, path=f"/tmp/file{ext}")
            assert not ev.is_executable_extension, f"Expected False for {ext}"

    def test_immutable(self) -> None:
        ev = FileEvent(kind=FileEventKind.CREATED, path="/tmp/x")
        with pytest.raises((AttributeError, TypeError)):
            ev.path = "/tmp/y"  # type: ignore[misc]

    def test_optional_fields_default_none(self) -> None:
        ev = FileEvent(kind=FileEventKind.CREATED, path="/tmp/x")
        assert ev.size     is None
        assert ev.uid      is None
        assert ev.mode     is None
        assert ev.src_path is None

    def test_all_kinds_constructable(self) -> None:
        for kind in FileEventKind:
            ev = FileEvent(kind=kind, path="/tmp/x")
            assert ev.kind == kind


# ---------------------------------------------------------------------------
# Testes: ProcessEvent
# ---------------------------------------------------------------------------

class TestProcessEvent:
    def test_basic_creation(self) -> None:
        ev = ProcessEvent(kind=ProcEventKind.NEW, pid=1234, name="python3")
        assert ev.pid  == 1234
        assert ev.name == "python3"
        assert ev.kind == ProcEventKind.NEW

    def test_suspicious_has_reason(self) -> None:
        ev = ProcessEvent(
            kind=ProcEventKind.SUSPICIOUS, pid=999,
            name="badproc", reason="executável em /tmp",
        )
        assert ev.reason == "executável em /tmp"

    def test_cmdline_defaults_empty(self) -> None:
        ev = ProcessEvent(kind=ProcEventKind.NEW, pid=1, name="init")
        assert ev.cmdline == []

    def test_immutable(self) -> None:
        ev = ProcessEvent(kind=ProcEventKind.NEW, pid=1, name="x")
        with pytest.raises((AttributeError, TypeError)):
            ev.pid = 2  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Testes: _EKPEventHandler (handler interno do watchdog)
# ---------------------------------------------------------------------------

class TestEKPEventHandler:
    def _make_handler(self, ignores: list[str] = None) -> tuple[_EKPEventHandler, list]:
        loop    = asyncio.new_event_loop()
        queue   = asyncio.Queue()
        received: list[FileEvent] = []

        # Captura put_nowait sem rodar event loop real
        def fake_threadsafe(cb):
            try:
                item = queue.get_nowait() if not queue.empty() else None
            except Exception:
                pass
            # Executa o callback diretamente (estamos em teste síncrono)
            cb()

        with patch.object(loop, 'call_soon_threadsafe',
                          side_effect=lambda cb: received.append(cb.__closure__[0].cell_contents
                                                                  if cb.__closure__ else None)):
            handler = _EKPEventHandler(queue, loop, ignores or [])

        loop.close()
        return handler, received

    def test_boring_extension_ignored(self) -> None:
        """Arquivos .pyc, .log etc. devem ser ignorados."""
        loop  = asyncio.new_event_loop()
        queue = asyncio.Queue()
        handler = _EKPEventHandler(queue, loop, [])

        calls: list = []
        loop.call_soon_threadsafe = lambda cb: calls.append(cb)  # type: ignore

        # Simula evento de arquivo .pyc
        from watchdog.events import FileCreatedEvent
        ev = FileCreatedEvent("/tmp/something.pyc")
        handler.on_created(ev)
        assert calls == [], ".pyc deve ser ignorado"
        loop.close()

    def test_glob_pattern_ignored(self) -> None:
        loop  = asyncio.new_event_loop()
        queue = asyncio.Queue()
        handler = _EKPEventHandler(queue, loop, ["*.log", ".git/*"])
        calls: list = []
        loop.call_soon_threadsafe = lambda cb: calls.append(cb)

        from watchdog.events import FileCreatedEvent
        handler.on_created(FileCreatedEvent("/var/log/app.log"))
        assert calls == [], "*.log deve ser ignorado"
        loop.close()

    def test_directory_events_ignored(self) -> None:
        loop  = asyncio.new_event_loop()
        queue = asyncio.Queue()
        handler = _EKPEventHandler(queue, loop, [])
        calls: list = []
        loop.call_soon_threadsafe = lambda cb: calls.append(cb)

        from watchdog.events import DirCreatedEvent
        ev = DirCreatedEvent("/tmp/newdir")
        handler.on_created(ev)
        assert calls == [], "Evento de diretório deve ser ignorado"
        loop.close()

    def test_normal_file_enqueued(self) -> None:
        loop  = asyncio.new_event_loop()
        queue: asyncio.Queue = asyncio.Queue()
        handler = _EKPEventHandler(queue, loop, [])

        enqueued: list = []
        # call_soon_threadsafe recebe (callback, *args)
        loop.call_soon_threadsafe = lambda cb, *args: (cb(*args), enqueued.append(True))  # type: ignore

        from watchdog.events import FileCreatedEvent
        with patch("os.stat") as mock_stat:
            mock_stat.return_value = MagicMock(st_size=1024, st_uid=1000, st_mode=0o644)
            handler.on_created(FileCreatedEvent("/tmp/test.sh"))

        assert len(enqueued) == 1
        loop.close()


# ---------------------------------------------------------------------------
# Testes: FSWatcher
# ---------------------------------------------------------------------------

class TestFSWatcher:
    def test_status_not_running(self, tmp_path: Path, event_queue: asyncio.Queue) -> None:
        loop    = asyncio.new_event_loop()
        watcher = FSWatcher([str(tmp_path)], event_queue, loop)
        assert not watcher.is_running
        loop.close()

    def test_status_has_fields(self, tmp_path: Path, event_queue: asyncio.Queue) -> None:
        loop    = asyncio.new_event_loop()
        watcher = FSWatcher([str(tmp_path)], event_queue, loop)
        s = watcher.status()
        assert "running"      in s
        assert "active_paths" in s
        assert "total_paths"  in s
        assert "recursive"    in s
        loop.close()

    def test_nonexistent_path_skipped(self, event_queue: asyncio.Queue) -> None:
        loop    = asyncio.new_event_loop()
        watcher = FSWatcher(["/nonexistent/path/xyz"], event_queue, loop)
        watcher.start()
        assert watcher.active_paths == []
        watcher.stop()
        loop.close()

    def test_start_stop_valid_path(self, tmp_path: Path, event_queue: asyncio.Queue) -> None:
        loop    = asyncio.new_event_loop()
        watcher = FSWatcher([str(tmp_path)], event_queue, loop)
        watcher.start()
        assert watcher.is_running
        assert str(tmp_path) in watcher.active_paths
        watcher.stop()
        loop.close()

    def test_file_creation_produces_event(self, tmp_path: Path) -> None:
        """Integração: criar arquivo → evento na fila."""
        async def _run() -> list:
            queue: asyncio.Queue = asyncio.Queue()
            loop  = asyncio.get_running_loop()
            watcher = FSWatcher([str(tmp_path)], queue, loop, recursive=False)
            watcher.start()
            await asyncio.sleep(0.3)   # deixa observer inicializar

            # Cria arquivo
            test_file = tmp_path / "canary.sh"
            test_file.write_text("#!/bin/bash\necho hello")

            # Aguarda evento (timeout 3s)
            events: list[FileEvent] = []
            try:
                ev = await asyncio.wait_for(queue.get(), timeout=3.0)
                events.append(ev)
            except asyncio.TimeoutError:
                pass
            finally:
                watcher.stop()
            return events

        events = asyncio.run(_run())
        assert len(events) >= 1
        assert any(ev.path.endswith("canary.sh") for ev in events)
        assert any(ev.kind in (FileEventKind.CREATED, FileEventKind.MODIFIED) for ev in events)

    def test_file_deletion_produces_event(self, tmp_path: Path) -> None:
        async def _run() -> list:
            # Cria arquivo antes de iniciar watcher
            test_file = tmp_path / "todelete.txt"
            test_file.write_text("conteudo")

            queue: asyncio.Queue = asyncio.Queue()
            loop  = asyncio.get_running_loop()
            watcher = FSWatcher([str(tmp_path)], queue, loop, recursive=False)
            watcher.start()
            await asyncio.sleep(0.3)

            test_file.unlink()

            events: list = []
            try:
                while True:
                    ev = await asyncio.wait_for(queue.get(), timeout=2.0)
                    events.append(ev)
            except asyncio.TimeoutError:
                pass
            finally:
                watcher.stop()
            return events

        events = asyncio.run(_run())
        assert any(
            isinstance(ev, FileEvent) and ev.kind == FileEventKind.DELETED
            for ev in events
        )

    def test_symlinked_root_still_produces_events_with_original_path(
        self, tmp_path: Path,
    ) -> None:
        """
        Regressão (2026-09-02): se o path de `monitor.paths` é (ou contém)
        um symlink de diretório — caso real em sistemas atômicos, onde
        `/opt` é symlink pra `/var/opt` — o watchdog agenda o watch de
        inotify com IN_DONT_FOLLOW por padrão. Sem tratamento, isso faz o
        watch "ativar" sem erro nenhum mas nunca disparar evento algum pra
        conteúdo dentro do diretório: falha silenciosa de monitoramento.

        `FSWatcher.start()` agora resolve o path real pra agendar o watch
        (inotify precisa disso pra enxergar dentro do diretório), e reescreve
        o path de cada evento de volta pro prefixo configurado — o resto do
        sistema (heurística `std_dirs`, logs) nunca vê o path resolvido.
        """
        real_dir = tmp_path / "var_opt_target"
        real_dir.mkdir()
        link_dir = tmp_path / "opt_link"
        link_dir.symlink_to(real_dir, target_is_directory=True)

        async def _run() -> list:
            queue: asyncio.Queue = asyncio.Queue()
            loop  = asyncio.get_running_loop()
            watcher = FSWatcher([str(link_dir)], queue, loop, recursive=False)
            watcher.start()
            await asyncio.sleep(0.3)

            test_file = link_dir / "canary_via_symlink.sh"
            test_file.write_text("#!/bin/bash\necho hello")

            events: list[FileEvent] = []
            try:
                while True:
                    ev = await asyncio.wait_for(queue.get(), timeout=2.0)
                    events.append(ev)
            except asyncio.TimeoutError:
                pass
            finally:
                watcher.stop()
            return events

        events = asyncio.run(_run())
        assert len(events) >= 1, "nenhum evento recebido: watch de root symlinkado ficou mudo"
        assert any(ev.path.startswith(str(link_dir)) for ev in events), (
            "path do evento não usa o prefixo configurado (deveria começar "
            f"com {link_dir}, não com o path real resolvido)"
        )
        assert not any(ev.path.startswith(str(real_dir)) for ev in events), (
            "path do evento vazou o path real resolvido em vez do configurado"
        )


# ---------------------------------------------------------------------------
# Testes: ProcWatcher
# ---------------------------------------------------------------------------

class TestProcWatcher:
    def test_stop_sets_flag(self, event_queue: asyncio.Queue) -> None:
        pw = ProcWatcher(event_queue, interval=1.0)
        pw._running = True
        pw.stop()
        assert pw._running is False

    def test_status(self, event_queue: asyncio.Queue) -> None:
        pw = ProcWatcher(event_queue, interval=5.0)
        s  = pw.status()
        assert "running"      in s
        assert "interval_s"   in s
        assert "tracked_pids" in s

    def test_new_process_detected(self, event_queue: asyncio.Queue) -> None:
        """Simula aparecimento de novo processo no snapshot."""
        async def _run() -> list[ProcessEvent]:
            pw = ProcWatcher(event_queue, interval=0.05)
            # Snapshot inicial sem o PID 99999
            pw._snapshot = {1: "systemd", 2: "kthreadd"}

            # Próximo tick terá PID novo
            fake_current = {1: "systemd", 2: "kthreadd", 99999: "evil"}

            import psutil
            with patch.object(pw, "_current_pids", return_value=fake_current), \
                 patch.object(pw, "_build_proc_event", side_effect=lambda pid, kind:
                    ProcessEvent(kind=kind, pid=pid, name=fake_current.get(pid, "?"))):
                await pw._tick()

            results = []
            while not event_queue.empty():
                results.append(await event_queue.get())
            return results

        events = asyncio.run(_run())
        new_evs = [e for e in events if isinstance(e, ProcessEvent) and e.kind == ProcEventKind.NEW]
        assert any(e.pid == 99999 for e in new_evs)

    def test_terminated_process_detected(self, event_queue: asyncio.Queue) -> None:
        async def _run() -> list[ProcessEvent]:
            pw = ProcWatcher(event_queue, interval=0.05)
            pw._snapshot = {1: "systemd", 5000: "dying_proc"}
            fake_current = {1: "systemd"}   # 5000 sumiu

            with patch.object(pw, "_current_pids", return_value=fake_current), \
                 patch.object(pw, "_check_suspicious", return_value=None):
                await pw._tick()

            results = []
            while not event_queue.empty():
                results.append(await event_queue.get())
            return results

        events = asyncio.run(_run())
        term_evs = [e for e in events
                    if isinstance(e, ProcessEvent) and e.kind == ProcEventKind.TERMINATED]
        assert any(e.pid == 5000 for e in term_evs)

    def test_suspicious_executable_in_tmp(self, event_queue: asyncio.Queue) -> None:
        async def _run() -> ProcessEvent | None:
            import psutil
            pw = ProcWatcher(event_queue, interval=1.0)
            pw._trusted = set()   # Nenhum processo confiável

            mock_proc = MagicMock(spec=psutil.Process)
            mock_proc.name.return_value = "suspicious"
            mock_proc.exe.return_value  = "/tmp/backdoor"
            mock_proc.cpu_percent.return_value = 0.0
            mock_proc.net_connections.return_value = []

            with patch("psutil.Process", return_value=mock_proc):
                return await pw._check_suspicious(9999)

        result = asyncio.run(_run())
        assert result is not None
        assert result.kind == ProcEventKind.SUSPICIOUS
        assert "/tmp" in (result.reason or "")

    def test_trusted_process_not_flagged(self, event_queue: asyncio.Queue) -> None:
        async def _run() -> ProcessEvent | None:
            import psutil
            pw = ProcWatcher(event_queue, interval=1.0)

            mock_proc = MagicMock(spec=psutil.Process)
            mock_proc.name.return_value = "systemd"   # sempre confiável

            with patch("psutil.Process", return_value=mock_proc):
                return await pw._check_suspicious(1)

        result = asyncio.run(_run())
        assert result is None


# ---------------------------------------------------------------------------
# Testes: MonitorManager
# ---------------------------------------------------------------------------

class TestMonitorManager:
    @pytest.fixture
    def monitor(self, cfg: ConfigManager) -> MonitorManager:
        return MonitorManager(cfg, log_manager=None)

    @pytest.mark.asyncio
    async def test_start_stop(self, monitor: MonitorManager) -> None:
        await monitor.start()
        assert monitor._running
        await monitor.stop()
        assert not monitor._running

    @pytest.mark.asyncio
    async def test_double_start_is_noop(self, monitor: MonitorManager) -> None:
        await monitor.start()
        await monitor.start()   # não deve lançar
        await monitor.stop()

    @pytest.mark.asyncio
    async def test_sync_callback_called(self, monitor: MonitorManager, tmp_path: Path) -> None:
        received: list = []

        def my_callback(event):
            received.append(event)

        await monitor.start()
        monitor.add_callback(my_callback)

        # Injeta evento diretamente na fila
        ev = FileEvent(kind=FileEventKind.CREATED, path="/tmp/test.sh")
        await monitor._queue.put(ev)
        await asyncio.sleep(0.2)   # deixa dispatcher processar

        await monitor.stop()
        assert len(received) >= 1
        assert received[0] is ev

    @pytest.mark.asyncio
    async def test_async_callback_called(self, monitor: MonitorManager) -> None:
        received: list = []

        async def my_async_callback(event):
            received.append(event)

        await monitor.start()
        monitor.add_callback(my_async_callback)

        ev = FileEvent(kind=FileEventKind.MODIFIED, path="/tmp/foo.py")
        await monitor._queue.put(ev)
        await asyncio.sleep(0.2)

        await monitor.stop()
        assert len(received) >= 1

    @pytest.mark.asyncio
    async def test_callback_exception_does_not_crash(self, monitor: MonitorManager) -> None:
        def bad_callback(event):
            raise RuntimeError("callback explodiu")

        await monitor.start()
        monitor.add_callback(bad_callback)

        ev = FileEvent(kind=FileEventKind.CREATED, path="/tmp/x.sh")
        await monitor._queue.put(ev)
        await asyncio.sleep(0.2)

        # Engine ainda está rodando
        assert monitor._running
        await monitor.stop()

    @pytest.mark.asyncio
    async def test_remove_callback(self, monitor: MonitorManager) -> None:
        received: list = []

        def cb(event):
            received.append(event)

        await monitor.start()
        monitor.add_callback(cb)
        monitor.remove_callback(cb)

        ev = FileEvent(kind=FileEventKind.CREATED, path="/tmp/x.sh")
        await monitor._queue.put(ev)
        await asyncio.sleep(0.2)

        await monitor.stop()
        assert received == []

    def test_status_fields(self, monitor: MonitorManager) -> None:
        s = monitor.status()
        assert "running"   in s
        assert "counters"  in s
        assert "queue_size" in s

    @pytest.mark.asyncio
    async def test_counters_updated(self, monitor: MonitorManager) -> None:
        await monitor.start()

        events = [
            FileEvent(kind=FileEventKind.CREATED,  path="/tmp/a.sh"),
            FileEvent(kind=FileEventKind.MODIFIED, path="/tmp/b.py"),
            FileEvent(kind=FileEventKind.DELETED,  path="/tmp/c.txt"),
        ]
        for ev in events:
            await monitor._queue.put(ev)
        await asyncio.sleep(0.3)

        await monitor.stop()
        c = monitor._counters
        assert c["file_created"]  >= 1
        assert c["file_modified"] >= 1
        assert c["file_deleted"]  >= 1

    @pytest.mark.asyncio
    async def test_proc_suspicious_counter(self, monitor: MonitorManager) -> None:
        await monitor.start()

        ev = ProcessEvent(
            kind=ProcEventKind.SUSPICIOUS, pid=666,
            name="evil", reason="em /tmp",
        )
        await monitor._queue.put(ev)
        await asyncio.sleep(0.2)

        await monitor.stop()
        assert monitor._counters["proc_suspicious"] >= 1

    def test_log_event_from_file(self, monitor: MonitorManager) -> None:
        """_log_event_from não deve lançar quando log_manager=None."""
        ev = FileEvent(kind=FileEventKind.CREATED, path="/tmp/x.sh")
        monitor._log_event_from(ev)   # não deve lançar

    def test_log_event_from_proc(self, monitor: MonitorManager) -> None:
        ev = ProcessEvent(
            kind=ProcEventKind.SUSPICIOUS, pid=1,
            name="evil", reason="teste",
        )
        monitor._log_event_from(ev)   # não deve lançar

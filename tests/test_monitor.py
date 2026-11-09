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


@pytest.fixture(autouse=True)
def _no_real_maps(request: pytest.FixtureRequest) -> Generator[None, None, None]:
    """Testes com PID falso (mock) não podem ler /proc/<pid>/maps real: o PID
    pode existir no host. Quem precisa do /proc de verdade marca `real_maps`."""
    if request.node.get_closest_marker("real_maps"):
        yield
        return
    with patch.object(ProcWatcher, "_read_maps", staticmethod(lambda pid: "")):
        yield


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
            mock_proc.exe.return_value  = "/usr/lib/systemd/systemd"
            mock_proc.create_time.return_value = 1.0
            mock_proc.cmdline.return_value = ["/sbin/init"]

            with patch("psutil.Process", return_value=mock_proc):
                return await pw._check_suspicious(1)

        result = asyncio.run(_run())
        assert result is None


def _mock_proc(name: str, exe: str, cmdline: list[str], ctime: float = 1.0) -> MagicMock:
    import psutil
    m = MagicMock(spec=psutil.Process)
    m.name.return_value = name
    m.exe.return_value = exe
    m.cmdline.return_value = cmdline
    m.create_time.return_value = ctime
    m.cpu_percent.return_value = 0.0
    m.net_connections.return_value = []
    m.ppid.return_value = 1
    m.username.return_value = "x"
    m.memory_percent.return_value = 0.0
    return m


_XMR = "48" + "A" * 93
_BTC = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"


class TestProcWatcherTrustedNameAndMiner:
    """Rodada 2026-10-28: nome confiável (comm = basename do executável) não
    dispensa mais exe em dir suspeito nem minerador na cmdline."""

    def _check(self, queue: asyncio.Queue, proc: MagicMock, pid: int = 4242,
               pw: ProcWatcher | None = None) -> ProcessEvent | None:
        pw = pw or ProcWatcher(queue, interval=1.0)
        with patch("psutil.Process", return_value=proc):
            return asyncio.run(pw._check_suspicious(pid))

    @pytest.mark.parametrize("name", ["bash", "kworker", "sshd", "systemd"])
    def test_trusted_name_in_tmp_flagged(self, event_queue: asyncio.Queue, name: str) -> None:
        ev = self._check(event_queue, _mock_proc(name, f"/tmp/.x/{name}", [name]))
        assert ev is not None and "/tmp" in (ev.reason or "")

    def test_trusted_name_miner_cmdline_flagged(self, event_queue: asyncio.Queue) -> None:
        argv = ["sshd", "-o", "stratum+tcp://pool.example.com:3333", "--donate-level", "1"]
        ev = self._check(event_queue, _mock_proc("sshd", "/usr/bin/python3", argv))
        assert ev is not None and "minerador" in (ev.reason or "")

    @pytest.mark.parametrize("argv", [
        ["kdevtmpfsi", "-o", "pool.minexmr.com:443", "-u", _BTC, "-k", "--tls"],
        ["xmrig", "--url=10.0.0.5:3333", "--algo=rx/0"],
        ["x", "-o", "stratum+ssl://p.example.org:443"],
        ["x", "-a", "kawpow", "-u", _XMR],
    ])
    def test_miner_cmdline_flagged(self, event_queue: asyncio.Queue, argv: list[str]) -> None:
        ev = self._check(event_queue, _mock_proc("x", "/usr/local/bin/x", argv))
        assert ev is not None and "minerador" in (ev.reason or "")

    @pytest.mark.parametrize("argv", [
        ["grep", "-r", "stratum+tcp://", "/etc"],
        ["curl", "-o", "a.example.com:80", "http://x"],
        ["gcc", "-o", "main", "main.c"],
        ["ssh", "-o", "Port=22", "host"],
        ["geth", "--etherbase", "0x" + "ab" * 20],
        ["vim", "notes-donate-level.txt"],
    ])
    def test_single_or_no_signal_not_flagged(self, event_queue: asyncio.Queue,
                                             argv: list[str]) -> None:
        assert self._check(event_queue, _mock_proc("x", "/usr/bin/x", argv)) is None

    def test_cmdline_cached_per_create_time(self, event_queue: asyncio.Queue) -> None:
        pw = ProcWatcher(event_queue, interval=1.0)
        proc = _mock_proc("x", "/usr/bin/x", ["x"])
        self._check(event_queue, proc, pw=pw)
        self._check(event_queue, proc, pw=pw)
        assert proc.cmdline.call_count == 1
        # PID reusado por outro processo (create_time diferente) relê a cmdline.
        # O watcher guarda o Process entre ticks (2026-10-29); psutil real dá
        # is_running() False quando o create_time do PID mudou.
        proc.is_running.return_value = False
        proc2 = _mock_proc("x", "/usr/bin/x",
                           ["x", "-o", "stratum+tcp://p.example.com:1", "--donate-level", "0"],
                           ctime=2.0)
        ev = self._check(event_queue, proc2, pw=pw)
        assert pw._miner_cache[4242][0] == 2.0
        assert ev is not None and "minerador" in (ev.reason or "")

    def test_cache_pruned_on_terminate(self, event_queue: asyncio.Queue) -> None:
        pw = ProcWatcher(event_queue, interval=1.0)
        pw._snapshot = {1: "systemd", 4242: "x"}
        pw._miner_cache = {4242: (1.0, [])}
        with patch.object(pw, "_current_pids", return_value={1: "systemd"}), \
             patch.object(pw, "_check_suspicious", return_value=None):
            asyncio.run(pw._tick())
        assert 4242 not in pw._miner_cache

    def test_end_to_end_real_process(self, event_queue: asyncio.Queue,
                                     tmp_path: Path) -> None:
        """Processo real e inofensivo (python dormindo) via symlink chamado
        `sshd` fora de /tmp, com argv de xmrig. Antes do fix: None."""
        import subprocess, sys
        link = tmp_path / "sshd"
        link.symlink_to(os.path.realpath(sys.executable))
        miner = subprocess.Popen([str(link), "-c", "import time; time.sleep(30)",
                                  "-o", "stratum+tcp://pool.example.com:3333",
                                  "-u", _XMR, "--donate-level", "1"])
        benign = subprocess.Popen([str(link), "-c", "import time; time.sleep(30)",
                                   "grep", "stratum+tcp://"])
        try:
            time.sleep(0.3)
            pw = ProcWatcher(event_queue, interval=1.0)
            ev = asyncio.run(pw._check_suspicious(miner.pid))
            assert ev is not None and ev.name == "sshd"
            assert "minerador" in (ev.reason or "")
            assert asyncio.run(pw._check_suspicious(benign.pid)) is None
        finally:
            for p in (miner, benign):
                p.kill(); p.wait()


# ---------------------------------------------------------------------------
# Testes: MonitorManager
# ---------------------------------------------------------------------------

class TestProcWatcherCpuAndTrustedExe:
    """Rodada 2026-10-29: cpu_percent(None) num psutil.Process novo sempre dá
    0.0, e o watcher criava um objeto por tick, então a checagem de CPU nunca
    disparou. E nome confiável embutido agora exige exe de sistema."""

    def _ticks(self, queue: asyncio.Queue, proc: MagicMock, n: int,
               pw: ProcWatcher | None = None, pid: int = 4343) -> list:
        pw = pw or ProcWatcher(queue, interval=1.0)
        with patch("psutil.Process", return_value=proc):
            return [asyncio.run(pw._check_suspicious(pid)) for _ in range(n)]

    def _busy(self, name: str, exe: str | None) -> MagicMock:
        import psutil
        m = _mock_proc(name, exe or "", [name])
        if exe is None:
            m.exe.side_effect = psutil.AccessDenied(4343)
        m.cpu_percent.return_value = 99.0
        return m

    def test_process_object_reused_between_ticks(self, event_queue: asyncio.Queue) -> None:
        pw = ProcWatcher(event_queue, interval=1.0)
        proc = _mock_proc("x", "/usr/local/bin/x", ["x"])
        with patch("psutil.Process", return_value=proc) as ctor:
            for _ in range(3):
                asyncio.run(pw._check_suspicious(4343))
        assert ctor.call_count == 1

    def test_untrusted_high_cpu_flagged_on_second_tick(self, event_queue: asyncio.Queue) -> None:
        evs = self._ticks(event_queue, self._busy("x", "/usr/local/bin/x"), 3)
        assert evs[0] is None
        assert evs[1] is not None and "CPU alta" in (evs[1].reason or "")
        assert evs[1].cpu_pct == 99.0

    def test_cpu_percent_called_once_per_tick(self, event_queue: asyncio.Queue) -> None:
        proc = self._busy("x", "/usr/local/bin/x")
        self._ticks(event_queue, proc, 3)
        assert proc.cpu_percent.call_count == 3

    @pytest.mark.parametrize("name,exe", [
        ("bash", "/home/u/.cache/bash"),
        ("sshd", "/opt/x/sshd"),
        ("kworker", "/var/lib/kworker"),
        ("bash", "/usr/binx/bash"),
    ])
    def test_trusted_name_outside_system_dirs_loses_trust(
        self, event_queue: asyncio.Queue, name: str, exe: str
    ) -> None:
        evs = self._ticks(event_queue, self._busy(name, exe), 2)
        assert evs[1] is not None and "CPU alta" in (evs[1].reason or "")

    @pytest.mark.parametrize("name,exe", [
        ("bash", "/usr/bin/bash"),
        ("sshd", "/usr/sbin/sshd"),
        ("systemd", "/usr/lib/systemd/systemd"),
        ("bash", "/usr/bin/bash (deleted)"),   # binário trocado por upgrade
        ("kworker", ""),                        # thread de kernel
        ("sshd", None),                         # AccessDenied: mantém confiança
    ])
    def test_trusted_name_with_system_exe_keeps_trust(
        self, event_queue: asyncio.Queue, name: str, exe: str | None
    ) -> None:
        assert self._ticks(event_queue, self._busy(name, exe), 3) == [None] * 3

    def test_user_trusted_name_keeps_trust_by_name(self, event_queue: asyncio.Queue) -> None:
        pw = ProcWatcher(event_queue, interval=1.0, trusted={"myapp"})
        evs = self._ticks(event_queue, self._busy("myapp", "/opt/myapp/myapp"), 3, pw=pw)
        assert evs == [None] * 3

    def test_pid_reuse_gets_new_object_and_resets_count(self, event_queue: asyncio.Queue) -> None:
        pw = ProcWatcher(event_queue, interval=1.0)
        old, new = self._busy("x", "/usr/local/bin/x"), self._busy("x", "/usr/local/bin/x")
        self._ticks(event_queue, old, 1, pw=pw)
        assert pw._cpu_high[4343] == 1
        old.is_running.return_value = False   # create_time mudou
        with patch("psutil.Process", return_value=new):
            ev = asyncio.run(pw._check_suspicious(4343))
        assert ev is None and pw._procs[4343] is new and pw._cpu_high[4343] == 1

    def test_gone_pid_pruned(self, event_queue: asyncio.Queue) -> None:
        pw = ProcWatcher(event_queue, interval=1.0)
        self._ticks(event_queue, self._busy("x", "/usr/local/bin/x"), 1, pw=pw)
        pw._snapshot = {4343: "x"}
        with patch.object(ProcWatcher, "_current_pids", return_value={}):
            asyncio.run(pw._tick())
        assert 4343 not in pw._procs and 4343 not in pw._cpu_high

    def test_e2e_real_busy_process_flagged(self, event_queue: asyncio.Queue) -> None:
        import subprocess, sys, time
        p = subprocess.Popen([sys.executable, "-I", "-c", "while True: pass"])
        try:
            time.sleep(0.3)
            pw = ProcWatcher(event_queue, interval=1.0)
            reasons = []
            for _ in range(5):
                ev = asyncio.run(pw._check_suspicious(p.pid))
                reasons.append(ev.reason if ev else "")
                time.sleep(1.0)
            assert any("CPU alta" in r for r in reasons), reasons
        finally:
            p.kill()
            p.wait()


class TestProcWatcherAlertDedup:
    """Rodada 2026-10-30: o mesmo motivo repetia o WARNING a cada tick (CPU
    alta num build de 1h dava ~720). Agora alerta 1x por (processo, tipo de
    motivo) e de novo só se aparecer tipo novo ou o motivo sumir e voltar."""

    def _proc(self, name: str = "x", exe: str = "/usr/local/bin/x",
              cpu: float = 99.0, cmdline: list[str] | None = None) -> MagicMock:
        m = _mock_proc(name, exe, cmdline or [name])
        m.cpu_percent.return_value = cpu
        return m

    def _ticks(self, pw: ProcWatcher, proc: MagicMock, n: int, pid: int = 4444) -> list:
        with patch("psutil.Process", return_value=proc):
            return [asyncio.run(pw._check_suspicious(pid)) for _ in range(n)]

    def test_sustained_cpu_alerts_once(self, event_queue: asyncio.Queue) -> None:
        pw = ProcWatcher(event_queue, interval=1.0)
        evs = self._ticks(pw, self._proc(), 10)
        assert [e is not None for e in evs] == [False, True] + [False] * 8

    def test_exe_in_tmp_alerts_once(self, event_queue: asyncio.Queue) -> None:
        pw = ProcWatcher(event_queue, interval=1.0)
        evs = self._ticks(pw, self._proc(exe="/tmp/evil", cpu=0.0), 5)
        assert evs[0] is not None and "/tmp" in evs[0].reason
        assert evs[1:] == [None] * 4

    def test_new_reason_kind_realerts_with_all_reasons(self, event_queue: asyncio.Queue) -> None:
        pw = ProcWatcher(event_queue, interval=1.0)
        proc = self._proc(exe="/tmp/evil", cpu=0.0)
        first = self._ticks(pw, proc, 2)
        assert first[0] is not None and first[1] is None
        proc.cpu_percent.return_value = 99.0
        evs = self._ticks(pw, proc, 3)
        assert evs[0] is None                     # 1º ciclo de CPU alta
        assert evs[1] is not None
        assert "/tmp" in evs[1].reason and "CPU alta" in evs[1].reason
        assert evs[2] is None

    def test_cpu_value_change_alone_does_not_realert(self, event_queue: asyncio.Queue) -> None:
        pw = ProcWatcher(event_queue, interval=1.0)
        proc = self._proc(cpu=85.0)
        self._ticks(pw, proc, 2)
        proc.cpu_percent.return_value = 150.0
        assert self._ticks(pw, proc, 3) == [None] * 3

    def test_condition_clears_then_returns_realerts(self, event_queue: asyncio.Queue) -> None:
        pw = ProcWatcher(event_queue, interval=1.0)
        proc = self._proc()
        assert self._ticks(pw, proc, 2)[1] is not None
        proc.cpu_percent.return_value = 1.0
        assert self._ticks(pw, proc, 1) == [None]
        assert 4444 not in pw._alerted
        proc.cpu_percent.return_value = 99.0
        evs = self._ticks(pw, proc, 2)
        assert evs[0] is None and evs[1] is not None

    def test_reason_dropping_out_does_not_realert(self, event_queue: asyncio.Queue) -> None:
        pw = ProcWatcher(event_queue, interval=1.0)
        proc = self._proc(exe="/tmp/evil")
        evs = self._ticks(pw, proc, 2)
        assert evs[1] is not None and "CPU alta" in evs[1].reason
        proc.cpu_percent.return_value = 1.0      # só o /tmp continua
        assert self._ticks(pw, proc, 3) == [None] * 3

    def test_pid_reuse_realerts(self, event_queue: asyncio.Queue) -> None:
        pw = ProcWatcher(event_queue, interval=1.0)
        old, new = self._proc(exe="/tmp/a", cpu=0.0), self._proc(exe="/tmp/b", cpu=0.0)
        assert self._ticks(pw, old, 1)[0] is not None
        old.is_running.return_value = False      # create_time mudou
        assert self._ticks(pw, new, 1)[0] is not None

    def test_gone_pid_pruned_from_alerted(self, event_queue: asyncio.Queue) -> None:
        pw = ProcWatcher(event_queue, interval=1.0)
        self._ticks(pw, self._proc(exe="/tmp/evil", cpu=0.0), 1)
        assert 4444 in pw._alerted
        pw._snapshot = {4444: "x"}
        with patch.object(ProcWatcher, "_current_pids", return_value={}):
            asyncio.run(pw._tick())
        assert 4444 not in pw._alerted

    def test_dedup_is_per_pid(self, event_queue: asyncio.Queue) -> None:
        pw = ProcWatcher(event_queue, interval=1.0)
        a, b = self._proc(exe="/tmp/a", cpu=0.0), self._proc(exe="/tmp/b", cpu=0.0)
        assert self._ticks(pw, a, 1, pid=1)[0] is not None
        assert self._ticks(pw, b, 1, pid=2)[0] is not None

    def test_e2e_real_busy_process_alerts_once(self, event_queue: asyncio.Queue) -> None:
        import subprocess, sys, time
        p = subprocess.Popen([sys.executable, "-I", "-c", "while True: pass"])
        try:
            time.sleep(0.3)
            pw = ProcWatcher(event_queue, interval=1.0)
            evs = []
            for _ in range(6):
                evs.append(asyncio.run(pw._check_suspicious(p.pid)))
                time.sleep(1.0)
            cpu_alerts = [e for e in evs if e and "CPU alta" in (e.reason or "")]
            assert len(cpu_alerts) == 1, [e.reason if e else None for e in evs]
        finally:
            p.kill()
            p.wait()


class TestProcWatcherMemfdAndDirBoundary:
    """Rodada 2026-10-31: processo carregado via memfd_create + execve
    (malware fileless) tinha exe `/memfd:<nome>` e passava sem alerta; o
    `/proc/self/fd` da lista nunca casava porque `proc.exe()` já vem
    resolvido. E `exe.startswith("/tmp")` casava `/tmpfoo`."""

    def _check(self, pw: ProcWatcher, proc: MagicMock, pid: int = 5555):
        with patch("psutil.Process", return_value=proc):
            return asyncio.run(pw._check_suspicious(pid))

    @pytest.mark.parametrize("exe", ["/memfd:kworkerz", "/memfd: (deleted)", "/memfd:x (deleted)"])
    def test_memfd_exe_alerts(self, event_queue: asyncio.Queue, exe: str) -> None:
        pw = ProcWatcher(event_queue, interval=1.0)
        ev = self._check(pw, _mock_proc("3", exe, ["kworkerz", "60"]))
        assert ev is not None and "sem arquivo" in ev.reason and exe in ev.reason

    def test_memfd_exe_with_trusted_name_still_alerts(self, event_queue: asyncio.Queue) -> None:
        pw = ProcWatcher(event_queue, interval=1.0)
        ev = self._check(pw, _mock_proc("sshd", "/memfd:sshd", ["sshd"]))
        assert ev is not None and "sem arquivo" in ev.reason

    def test_memfd_alerts_once(self, event_queue: asyncio.Queue) -> None:
        pw = ProcWatcher(event_queue, interval=1.0)
        proc = _mock_proc("3", "/memfd:x", ["x"])
        evs = [self._check(pw, proc) for _ in range(4)]
        assert evs[0] is not None and evs[1:] == [None] * 3

    @pytest.mark.parametrize("exe", ["/tmpfoo/x", "/run/username/x", "/var/tmpx/y", "/dev/shmem/z"])
    def test_prefix_without_boundary_not_flagged(self, event_queue: asyncio.Queue, exe: str) -> None:
        pw = ProcWatcher(event_queue, interval=1.0)
        assert self._check(pw, _mock_proc("x", exe, ["x"])) is None

    @pytest.mark.parametrize("exe", ["/tmp/x", "/tmp/a/b (deleted)", "/run/user/1000/x", "/dev/shm/.x/y"])
    def test_real_suspicious_dirs_still_flagged(self, event_queue: asyncio.Queue, exe: str) -> None:
        pw = ProcWatcher(event_queue, interval=1.0)
        ev = self._check(pw, _mock_proc("x", exe, ["x"]))
        assert ev is not None and "executável em" in ev.reason

    def test_e2e_real_memfd_process_alerts(self, event_queue: asyncio.Queue) -> None:
        import subprocess, sys, time
        loader = (
            "import os\n"
            "fd = os.memfd_create('ekp-test', 0)\n"
            "os.write(fd, open('/bin/sleep', 'rb').read())\n"
            "os.execv(f'/proc/self/fd/{fd}', ['ekp-test', '30'])\n"
        )
        p = subprocess.Popen([sys.executable, "-I", "-c", loader])
        try:
            time.sleep(0.5)
            pw = ProcWatcher(event_queue, interval=1.0)
            ev = asyncio.run(pw._check_suspicious(p.pid))
            assert ev is not None and "/memfd:ekp-test" in ev.reason
        finally:
            p.kill()
            p.wait()


_LD = "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"


class TestProcWatcherLoaderExec:
    """Rodada 2026-11-01: `ld.so /tmp/x` tem exe = loader (dir de sistema) e
    o programa real só aparece na cmdline; passava sem alerta, inclusive com
    arquivo sem +x (fura /tmp noexec)."""

    def _check(self, pw: ProcWatcher, proc: MagicMock, pid: int = 6666):
        with patch("psutil.Process", return_value=proc):
            return asyncio.run(pw._check_suspicious(pid))

    @pytest.mark.parametrize("exe,cmdline", [
        (_LD, ["/lib64/ld-linux-x86-64.so.2", "/tmp/x", "60"]),
        (_LD, ["ld", "--library-path", "/opt/lib", "/dev/shm/.m/xmr"]),
        (_LD, ["ld", "--argv0", "kworker", "--inhibit-cache", "/var/tmp/y"]),
        ("/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1", ["ld", "/run/user/1000/z"]),
        ("/lib/ld-musl-x86_64.so.1", ["ld", "/tmp/a/../b"]),
    ])
    def test_loader_running_suspicious_dir_alerts(self, event_queue: asyncio.Queue,
                                                  exe: str, cmdline: list[str]) -> None:
        pw = ProcWatcher(event_queue, interval=1.0)
        ev = self._check(pw, _mock_proc(os.path.basename(exe), exe, cmdline))
        assert ev is not None and "loader" in ev.reason

    def test_relative_target_resolved_against_cwd(self, event_queue: asyncio.Queue) -> None:
        pw = ProcWatcher(event_queue, interval=1.0)
        proc = _mock_proc("ld-linux-x86-64.so.2", _LD, ["ld", "./x"])
        proc.cwd.return_value = "/dev/shm"
        ev = self._check(pw, proc)
        assert ev is not None and "/dev/shm/x" in ev.reason

    def test_proc_fd_target_alerts(self, event_queue: asyncio.Queue) -> None:
        pw = ProcWatcher(event_queue, interval=1.0)
        ev = self._check(pw, _mock_proc("ld-linux-x86-64.so.2", _LD, ["ld", "/proc/self/fd/3"]))
        assert ev is not None and "descritor" in ev.reason

    @pytest.mark.parametrize("cmdline", [
        ["ld", "/usr/bin/ls"],                       # programa de sistema
        ["ld", "--list", "/tmp/x"],                  # ldd: só inspeciona
        ["ld", "--verify", "/tmp/x"],
        ["ld", "--library-path", "/tmp/lib", "/usr/bin/ls"],  # arg de opção não é o alvo
        ["ld", "/tmpfoo/x"],                         # fronteira de path
        ["ld"],
    ])
    def test_loader_benign_not_flagged(self, event_queue: asyncio.Queue, cmdline: list[str]) -> None:
        pw = ProcWatcher(event_queue, interval=1.0)
        assert self._check(pw, _mock_proc("ld-linux-x86-64.so.2", _LD, cmdline)) is None

    def test_non_loader_exe_ignores_cmdline_path(self, event_queue: asyncio.Queue) -> None:
        pw = ProcWatcher(event_queue, interval=1.0)
        assert self._check(pw, _mock_proc("cat", "/usr/bin/cat", ["cat", "/tmp/x"])) is None

    def test_loader_alerts_once(self, event_queue: asyncio.Queue) -> None:
        pw = ProcWatcher(event_queue, interval=1.0)
        proc = _mock_proc("ld-linux-x86-64.so.2", _LD, ["ld", "/tmp/x"])
        evs = [self._check(pw, proc) for _ in range(3)]
        assert evs[0] is not None and evs[1:] == [None] * 2

    def test_e2e_real_loader_exec_alerts(self, event_queue: asyncio.Queue) -> None:
        import shutil, subprocess, tempfile, time
        ld = "/lib64/ld-linux-x86-64.so.2"
        if not os.path.exists(ld):
            pytest.skip("sem loader x86_64")
        d = tempfile.mkdtemp(dir="/tmp")
        payload = os.path.join(d, "ekp-test")
        shutil.copy("/bin/sleep", payload)
        os.chmod(payload, 0o644)
        p = subprocess.Popen([ld, payload, "30"])
        try:
            time.sleep(0.5)
            pw = ProcWatcher(event_queue, interval=1.0)
            ev = asyncio.run(pw._check_suspicious(p.pid))
            assert ev is not None and payload in ev.reason
        finally:
            p.kill()
            p.wait()
            shutil.rmtree(d)


_LIBZ = "/usr/lib/x86_64-linux-gnu/libz.so.1"


def _maps(*paths: str, perms: str = "r-xp") -> str:
    """maps sintético: libc de sistema, anônimo, [vdso] e os `paths` dados."""
    lines = [
        "7f00-7f10 r-xp 00000000 08:01 11 /usr/lib/x86_64-linux-gnu/libc.so.6",
        "7f10-7f20 rw-p 00000000 00:00 0 ",
        "7f20-7f30 r-xp 00000000 00:00 0 [vdso]",
    ]
    lines += [f"7f40-7f50 {perms} 00000000 08:01 99 {p}" for p in paths]
    return "\n".join(lines) + "\n"


class TestProcWatcherMappedLib:
    """Rodada 2026-11-02: `LD_PRELOAD=/tmp/x.so` (ou dlopen de /tmp) injeta
    código num binário de sistema sem mudar exe nem cmdline; passava sem
    alerta. Agora /proc/<pid>/maps é lido (com cache) atrás de mapeamento
    executável de arquivo em dir suspeito."""

    def _check(self, pw: ProcWatcher, proc: MagicMock, maps: str | MagicMock,
               pid: int = 7777):
        reader = maps if isinstance(maps, MagicMock) else MagicMock(return_value=maps)
        with patch("psutil.Process", return_value=proc), \
             patch.object(ProcWatcher, "_read_maps", staticmethod(reader)):
            return asyncio.run(pw._check_suspicious(pid))

    @pytest.mark.parametrize("path", [
        "/tmp/libkworker.so",
        "/dev/shm/.x/hook.so",
        "/var/tmp/a.so (deleted)",          # apagado depois do preload
        "/run/user/1000/inj.so",
    ])
    def test_exec_mapping_in_suspicious_dir_alerts(self, event_queue: asyncio.Queue,
                                                   path: str) -> None:
        pw = ProcWatcher(event_queue, interval=1.0)
        ev = self._check(pw, _mock_proc("sleep", "/usr/bin/sleep", ["sleep", "60"]), _maps(path))
        assert ev is not None and "biblioteca executável mapeada" in ev.reason
        assert path.replace(" (deleted)", "") + ")" in ev.reason

    def test_trusted_name_still_alerts(self, event_queue: asyncio.Queue) -> None:
        pw = ProcWatcher(event_queue, interval=1.0)
        ev = self._check(pw, _mock_proc("sshd", "/usr/sbin/sshd", ["sshd"]), _maps("/tmp/pam.so"))
        assert ev is not None and "/tmp/pam.so" in ev.reason

    @pytest.mark.parametrize("maps", [
        _maps(),                                        # só sistema/anônimo
        _maps("/tmp/dados.bin", perms="r--p"),          # mmap de dado, sem exec
        _maps("/tmp/cache.db", perms="rw-s"),
        _maps("/tmpfoo/x.so"),                          # fronteira de path
        _maps("/home/u/.local/lib/x.so"),
        "",                                             # sem permissão / thread de kernel
    ])
    def test_benign_maps_not_flagged(self, event_queue: asyncio.Queue, maps: str) -> None:
        pw = ProcWatcher(event_queue, interval=1.0)
        assert self._check(pw, _mock_proc("sleep", "/usr/bin/sleep", ["sleep"]), maps) is None

    def test_exe_in_tmp_reports_exe_dir_only(self, event_queue: asyncio.Queue) -> None:
        pw = ProcWatcher(event_queue, interval=1.0)
        reader = MagicMock(return_value=_maps("/tmp/x", "/tmp/y.so"))
        ev = self._check(pw, _mock_proc("x", "/tmp/x", ["/tmp/x"]), reader)
        assert ev is not None and "executável em /tmp" in ev.reason
        assert "mapeada" not in ev.reason
        reader.assert_not_called()   # mesmo incidente: nem lê maps

    def test_loader_exec_reports_loader_only(self, event_queue: asyncio.Queue) -> None:
        pw = ProcWatcher(event_queue, interval=1.0)
        reader = MagicMock(return_value=_maps("/tmp/x"))
        proc = _mock_proc("ld-linux-x86-64.so.2", _LD, ["ld", "/tmp/x"])
        ev = self._check(pw, proc, reader)
        assert ev is not None and "loader" in ev.reason and "mapeada" not in ev.reason
        reader.assert_not_called()

    def test_maps_cached_within_rescan_window(self, event_queue: asyncio.Queue) -> None:
        from ekprotection.monitor import proc_watcher as pwm
        pw = ProcWatcher(event_queue, interval=1.0)
        reader = MagicMock(return_value=_maps())
        proc = _mock_proc("sleep", "/usr/bin/sleep", ["sleep"])
        for _ in range(pwm._MAPS_RESCAN_TICKS):   # ticks 1..N: só a 1ª lê
            pw._tick_no += 1
            self._check(pw, proc, reader)
        assert reader.call_count == 1
        pw._tick_no += 1
        self._check(pw, proc, reader)
        assert reader.call_count == 2

    def test_late_dlopen_caught_on_rescan_and_alerts_once(self, event_queue: asyncio.Queue) -> None:
        from ekprotection.monitor import proc_watcher as pwm
        pw = ProcWatcher(event_queue, interval=1.0)
        reader = MagicMock(return_value=_maps())
        proc = _mock_proc("python3", "/usr/bin/python3", ["python3", "app.py"])
        assert self._check(pw, proc, reader) is None
        reader.return_value = _maps("/dev/shm/stage2.so")
        evs = []
        for _ in range(2 * pwm._MAPS_RESCAN_TICKS):
            pw._tick_no += 1
            evs.append(self._check(pw, proc, reader))
        hits = [e for e in evs if e is not None]
        assert len(hits) == 1 and "/dev/shm/stage2.so" in hits[0].reason

    def test_new_create_time_rereads_maps(self, event_queue: asyncio.Queue) -> None:
        pw = ProcWatcher(event_queue, interval=1.0)
        reader = MagicMock(return_value=_maps())
        old = _mock_proc("sleep", "/usr/bin/sleep", ["sleep"], ctime=1.0)
        self._check(pw, old, reader)
        old.is_running.return_value = False   # PID reusado por outro processo
        reader.return_value = _maps("/tmp/x.so")
        ev = self._check(pw, _mock_proc("sleep", "/usr/bin/sleep", ["sleep"], ctime=2.0), reader)
        assert reader.call_count == 2 and ev is not None

    def test_terminated_clears_maps_cache(self, event_queue: asyncio.Queue) -> None:
        pw = ProcWatcher(event_queue, interval=1.0)
        pw._snapshot = {7777: "sleep"}
        pw._maps_cache[7777] = (1.0, 0, None)
        with patch.object(ProcWatcher, "_current_pids", staticmethod(lambda: {})):
            asyncio.run(pw._tick())
        assert 7777 not in pw._maps_cache

    @pytest.mark.real_maps
    def test_e2e_real_ld_preload_alerts(self, event_queue: asyncio.Queue) -> None:
        import shutil, subprocess
        if not os.path.exists(_LIBZ):
            pytest.skip("sem libz x86_64")
        d = tempfile.mkdtemp(dir="/tmp")
        lib = os.path.join(d, "libekp-test.so")
        shutil.copy(_LIBZ, lib)   # .so inofensiva, só pra ficar mapeada
        p = subprocess.Popen(["/bin/sleep", "30"], env={**os.environ, "LD_PRELOAD": lib})
        try:
            time.sleep(0.5)
            pw = ProcWatcher(event_queue, interval=1.0)
            ev = asyncio.run(pw._check_suspicious(p.pid))
            assert ev is not None and lib in ev.reason
        finally:
            p.kill()
            p.wait()
            shutil.rmtree(d)


_CORECLR = "/usr/share/dotnet/shared/Microsoft.NETCore.App/8.0.0/libcoreclr.so"


class TestProcWatcherMemfdLib:
    """Rodada 2026-11-03: `.so` carregada de memfd (`LD_PRELOAD=/proc/self/fd/N`
    ou dlopen de memfd) passava sem alerta: aparece em maps como
    `/memfd:<nome> (deleted)` executável, fora de qualquer dir suspeito. O
    memfd `doublemapper` do JIT do .NET só é aceito com libcoreclr.so de
    arquivo real mapeada no mesmo processo."""

    _check = TestProcWatcherMappedLib._check

    @pytest.mark.parametrize("path", [
        "/memfd:kworker (deleted)",
        "/memfd:kworker",                       # kernel sem o sufixo
        "/memfd: (deleted)",                    # nome vazio
        "/memfd:libc.so.6 (deleted)",           # nome imitando lib de sistema
    ])
    def test_exec_memfd_mapping_alerts(self, event_queue: asyncio.Queue, path: str) -> None:
        pw = ProcWatcher(event_queue, interval=1.0)
        ev = self._check(pw, _mock_proc("sleep", "/usr/bin/sleep", ["sleep", "60"]), _maps(path))
        assert ev is not None and "mapeada de memfd" in ev.reason
        assert path.replace(" (deleted)", "") + ")" in ev.reason

    def test_trusted_name_still_alerts(self, event_queue: asyncio.Queue) -> None:
        pw = ProcWatcher(event_queue, interval=1.0)
        ev = self._check(pw, _mock_proc("sshd", "/usr/sbin/sshd", ["sshd"]), _maps("/memfd:x (deleted)"))
        assert ev is not None and "/memfd:x" in ev.reason

    def test_dotnet_doublemapper_with_runtime_not_flagged(self, event_queue: asyncio.Queue) -> None:
        pw = ProcWatcher(event_queue, interval=1.0)
        maps = _maps(_CORECLR, "/memfd:doublemapper (deleted)")
        assert self._check(pw, _mock_proc("dotnet", "/usr/share/dotnet/dotnet", ["dotnet", "app.dll"]), maps) is None

    def test_runtime_listed_after_doublemapper_not_flagged(self, event_queue: asyncio.Queue) -> None:
        pw = ProcWatcher(event_queue, interval=1.0)
        maps = _maps("/memfd:doublemapper (deleted)", _CORECLR)
        assert self._check(pw, _mock_proc("app", "/opt/app/app", ["app"]), maps) is None

    @pytest.mark.parametrize("maps", [
        _maps("/memfd:doublemapper (deleted)"),                          # sem runtime .NET
        _maps("/tmp/x/libcoreclr.so", "/memfd:doublemapper (deleted)"),  # runtime falso em /tmp
        _maps("/memfd:libcoreclr.so (deleted)", "/memfd:doublemapper (deleted)"),
    ])
    def test_doublemapper_without_real_runtime_alerts(self, event_queue: asyncio.Queue, maps: str) -> None:
        pw = ProcWatcher(event_queue, interval=1.0)
        ev = self._check(pw, _mock_proc("sleep", "/usr/bin/sleep", ["sleep"]), maps)
        assert ev is not None and "mapeada de" in ev.reason

    def test_dotnet_runtime_does_not_hide_other_memfd(self, event_queue: asyncio.Queue) -> None:
        pw = ProcWatcher(event_queue, interval=1.0)
        maps = _maps(_CORECLR, "/memfd:doublemapper (deleted)", "/memfd:stage2 (deleted)")
        ev = self._check(pw, _mock_proc("dotnet", "/usr/share/dotnet/dotnet", ["dotnet"]), maps)
        assert ev is not None and "/memfd:stage2" in ev.reason

    @pytest.mark.parametrize("maps", [
        _maps("/memfd:pulseaudio (deleted)", perms="rw-s"),   # memória compartilhada, sem exec
        _maps("/memfd:wayland-cursor (deleted)", perms="r--p"),
        _maps("/home/u/memfd:x.so"),                          # só contém o texto
    ])
    def test_non_exec_memfd_not_flagged(self, event_queue: asyncio.Queue, maps: str) -> None:
        pw = ProcWatcher(event_queue, interval=1.0)
        assert self._check(pw, _mock_proc("sleep", "/usr/bin/sleep", ["sleep"]), maps) is None

    def test_memfd_exe_reports_memfd_only(self, event_queue: asyncio.Queue) -> None:
        pw = ProcWatcher(event_queue, interval=1.0)
        reader = MagicMock(return_value=_maps("/memfd:x (deleted)", "/memfd:y (deleted)"))
        ev = self._check(pw, _mock_proc("x", "/memfd:x (deleted)", ["x"]), reader)
        assert ev is not None and "executável sem arquivo" in ev.reason
        assert "mapeada" not in ev.reason
        reader.assert_not_called()

    def test_late_memfd_dlopen_caught_on_rescan_and_alerts_once(self, event_queue: asyncio.Queue) -> None:
        from ekprotection.monitor import proc_watcher as pwm
        pw = ProcWatcher(event_queue, interval=1.0)
        reader = MagicMock(return_value=_maps())
        proc = _mock_proc("python3", "/usr/bin/python3", ["python3", "app.py"])
        assert self._check(pw, proc, reader) is None
        reader.return_value = _maps("/memfd:stage2 (deleted)")
        evs = []
        for _ in range(2 * pwm._MAPS_RESCAN_TICKS):
            pw._tick_no += 1
            evs.append(self._check(pw, proc, reader))
        hits = [e for e in evs if e is not None]
        assert len(hits) == 1 and "/memfd:stage2" in hits[0].reason

    @pytest.mark.real_maps
    def test_e2e_real_memfd_preload_alerts(self, event_queue: asyncio.Queue) -> None:
        import subprocess
        if not os.path.exists(_LIBZ) or not hasattr(os, "memfd_create"):
            pytest.skip("sem libz x86_64 ou memfd_create")
        fd = os.memfd_create("ekp-test", 0)
        try:
            with open(_LIBZ, "rb") as f:
                os.write(fd, f.read())   # .so inofensiva, só pra ficar mapeada
            p = subprocess.Popen(["/bin/sleep", "30"], pass_fds=(fd,),
                                 env={**os.environ, "LD_PRELOAD": f"/proc/self/fd/{fd}"})
            try:
                time.sleep(0.5)
                pw = ProcWatcher(event_queue, interval=1.0)
                ev = asyncio.run(pw._check_suspicious(p.pid))
                assert ev is not None and "/memfd:ekp-test" in ev.reason
            finally:
                p.kill()
                p.wait()
        finally:
            os.close(fd)


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


# ---------------------------------------------------------------------------
# Testes: arquivos-isca (canary) — 2026-11-04
# ---------------------------------------------------------------------------

from ekprotection.monitor.canary import (  # noqa: E402
    CanaryWatcher, _CanaryHandler, find_openers, resolve_canaries,
)


class TestCanary:
    """Leitura de chave/wallet não gerava evento nenhum (só escrita gera).
    `cat ~/.ssh/id_ed25519` passava limpo (medido 2026-11-04)."""

    @staticmethod
    def _decoy(tmp_path: Path, name: str = "id_ed25519") -> str:
        p = tmp_path / name
        p.write_text("FAKE-DECOY\n")
        return str(p)

    @staticmethod
    def _handler(canaries: dict[str, str], clock=None, openers=None):
        out: list[FileEvent] = []
        t = [0.0]
        h = _CanaryHandler(
            canaries, out.append,
            clock=clock or (lambda: t[0]),
            openers=openers or (lambda p: []),
        )
        return h, out, t

    def test_resolve_skips_missing_and_dir(self, tmp_path: Path) -> None:
        key = self._decoy(tmp_path)
        (tmp_path / "d").mkdir()
        got = resolve_canaries([key, str(tmp_path / "nope"), str(tmp_path / "d")])
        assert got == {str(Path(key).resolve()): key}

    def test_resolve_symlink_maps_back_to_configured(self, tmp_path: Path) -> None:
        real = self._decoy(tmp_path, "real.dat")
        link = tmp_path / "wallet.dat"
        link.symlink_to(real)
        assert resolve_canaries([str(link)]) == {str(Path(real).resolve()): str(link)}

    def test_open_of_canary_emits_accessed(self) -> None:
        h, out, _ = self._handler({"/r/id": "/c/id"}, openers=lambda p: ["cat(42)"])
        h.handle_open("/r/id")
        assert len(out) == 1
        assert out[0].kind == FileEventKind.ACCESSED
        assert out[0].path == "/c/id"
        assert out[0].detail == "aberto por cat(42)"

    def test_unknown_opener_detail(self) -> None:
        h, out, _ = self._handler({"/r/id": "/r/id"})
        h.handle_open("/r/id")
        assert out[0].detail == "processo não identificado"

    def test_other_file_in_same_dir_ignored(self) -> None:
        h, out, _ = self._handler({"/r/.ssh/id_ed25519": "/r/.ssh/id_ed25519"})
        h.handle_open("/r/.ssh/known_hosts")
        h.handle_open("/r/.ssh/id_ed25519.pub")
        assert out == []

    def test_cooldown_per_file(self) -> None:
        h, out, t = self._handler({"/a": "/a", "/b": "/b"})
        for _ in range(100):
            h.handle_open("/a")
        h.handle_open("/b")
        assert [e.path for e in out] == ["/a", "/b"]
        t[0] = 59.9
        h.handle_open("/a")
        assert len(out) == 2
        t[0] = 60.0
        h.handle_open("/a")
        assert [e.path for e in out] == ["/a", "/b", "/a"]

    def test_find_openers_sees_held_fd(self, tmp_path: Path) -> None:
        import subprocess, sys
        key = self._decoy(tmp_path)
        p = subprocess.Popen([sys.executable, "-c",
                              f"f=open({key!r}); import sys; sys.stdin.read()"],
                             stdin=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 5
            found: list[str] = []
            while time.monotonic() < deadline and not found:
                found = find_openers(key)
                time.sleep(0.05)
            assert f"({p.pid})" in " ".join(found)
        finally:
            p.stdin.close(); p.wait(timeout=5)

    def test_find_openers_skips_self(self, tmp_path: Path) -> None:
        key = self._decoy(tmp_path)
        with open(key):
            assert all(f"({os.getpid()})" not in o for o in find_openers(key))

    def test_watcher_without_canaries_does_not_start(self, event_queue) -> None:
        w = CanaryWatcher([], event_queue, asyncio.new_event_loop())
        w.start()
        assert not w.is_running
        assert w.status() == {"running": False, "canaries": []}

    @pytest.mark.asyncio
    async def test_e2e_cat_of_decoy_key_alerts_once(self, tmp_path: Path) -> None:
        import subprocess
        key = self._decoy(tmp_path)
        other = self._decoy(tmp_path, "known_hosts")
        q: asyncio.Queue = asyncio.Queue()
        w = CanaryWatcher([key], q, asyncio.get_running_loop())
        w.start()
        try:
            await asyncio.sleep(0.3)
            subprocess.run(["cat", other], stdout=subprocess.DEVNULL, check=True)
            for _ in range(3):
                subprocess.run(["cat", key], stdout=subprocess.DEVNULL, check=True)
            await asyncio.sleep(0.8)
        finally:
            w.stop()
        evs = []
        while not q.empty():
            evs.append(q.get_nowait())
        assert [(e.kind, e.path) for e in evs] == [(FileEventKind.ACCESSED, key)]

    @pytest.mark.asyncio
    async def test_e2e_stat_and_write_do_not_alert(self, tmp_path: Path) -> None:
        """Só open() conta. stat/ls (indexador, `find`) não abrem o arquivo."""
        key = self._decoy(tmp_path)
        q: asyncio.Queue = asyncio.Queue()
        w = CanaryWatcher([key], q, asyncio.get_running_loop())
        w.start()
        try:
            await asyncio.sleep(0.3)
            os.stat(key); os.listdir(tmp_path); os.access(key, os.R_OK)
            await asyncio.sleep(0.5)
        finally:
            w.stop()
        assert q.empty()

    @pytest.mark.asyncio
    async def test_manager_wires_canary_and_logs_critical(self, cfg: ConfigManager, tmp_path: Path) -> None:
        import subprocess
        from ekprotection.logs.models import EventType, LogLevel
        key = self._decoy(tmp_path)
        cfg.set("monitor.canary_paths", [key])
        log = MagicMock()
        mon = MonitorManager(cfg, log)
        seen: list = []
        mon.add_callback(seen.append)
        with patch.object(ProcWatcher, "run", AsyncMock()):
            await mon.start()
            try:
                await asyncio.sleep(0.3)
                subprocess.run(["cat", key], stdout=subprocess.DEVNULL, check=True)
                await asyncio.sleep(1.5)
                st = mon.status()
            finally:
                await mon.stop()
        acc = [e for e in seen if isinstance(e, FileEvent) and e.kind == FileEventKind.ACCESSED]
        assert len(acc) == 1
        assert st["counters"]["canary_accessed"] == 1
        assert st["canary"]["canaries"] == [key]
        calls = log.get_source.return_value.event.call_args_list
        crit = [c for c in calls if c.args[0] == EventType.CANARY_ACCESSED]
        assert len(crit) == 1 and crit[0].kwargs["level"] == LogLevel.CRITICAL


# ---------------------------------------------------------------------------
# Testes: isca cega/barulhenta + CLI `ekp canary` — 2026-11-08
# ---------------------------------------------------------------------------

import json as _json  # noqa: E402
import logging as _logging  # noqa: E402
import stat  # noqa: E402

from typer.testing import CliRunner  # noqa: E402

from ekprotection.cli.app import app as _ekp_app  # noqa: E402
from ekprotection.config.manager import ConfigManager  # noqa: E402
from ekprotection.monitor import canary as _canary_mod  # noqa: E402
from ekprotection.monitor.canary import (  # noqa: E402
    CANARY_KINDS, bait_content, canary_issues, create_canary,
)


class TestCanaryIssuesAndCli:
    """Abertura com EACCES não gera IN_OPEN: isca ilegível pro dono da home
    (root 0600, modo 000) nunca alertava, e nome padrão do ssh alertava a
    cada conexão. Nenhum dos dois avisava (medido 2026-11-08). Isca era
    feita à mão, editando o YAML."""

    @staticmethod
    def _file(tmp_path: Path, name: str = "backup_prod.pem", mode: int = 0o600) -> Path:
        p = tmp_path / name
        p.write_text("FAKE\n")
        os.chmod(p, mode)
        return p

    @pytest.mark.skipif(os.geteuid() == 0, reason="root lê modo 000")
    @pytest.mark.parametrize("mode", [0o000, 0o200, 0o044])
    def test_unreadable_by_dir_owner_flagged(self, tmp_path, mode):
        p = self._file(tmp_path, mode=mode)
        issues = canary_issues(p)
        os.chmod(p, 0o600)
        assert len(issues) == 1 and "EACCES" in issues[0] and "chown" in issues[0]

    @pytest.mark.parametrize("mode", [0o600, 0o400, 0o644])
    def test_readable_ok(self, tmp_path, mode):
        assert canary_issues(self._file(tmp_path, mode=mode)) == []

    def test_other_owner_not_readable_flagged(self, tmp_path, monkeypatch):
        """Simula isca de root 0600 em dir do usuário (sem precisar de root)."""
        p = self._file(tmp_path)
        real = os.stat_result
        me = os.getuid()

        orig_stat = Path.stat
        def fake_stat(self, *a, **k):
            st = orig_stat(self, *a, **k)
            if self == p:
                return real((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, me + 1, st.st_gid,
                             st.st_size, 0, 0, 0))
            return st
        monkeypatch.setattr(Path, "stat", fake_stat)
        monkeypatch.setattr(_canary_mod.grp, "getgrgid", lambda gid: (_ for _ in ()).throw(KeyError()))
        assert any("EACCES" in i for i in canary_issues(p))

    @pytest.mark.parametrize("name", ["id_rsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519.pub",
                                      "known_hosts", "authorized_keys", "config"])
    def test_ssh_auto_opened_name_flagged(self, tmp_path, name):
        issues = canary_issues(self._file(tmp_path, name))
        assert len(issues) == 1 and "ssh" in issues[0]

    @pytest.mark.parametrize("name", ["id_ed25519_old", "backup_prod.pem", "id_rsa.bak", "wallet.dat"])
    def test_good_names_ok(self, tmp_path, name):
        assert canary_issues(self._file(tmp_path, name)) == []

    def test_missing_file_only_name_check(self, tmp_path):
        assert canary_issues(tmp_path / "nope.pem") == []
        assert len(canary_issues(tmp_path / "id_rsa")) == 1

    @pytest.mark.skipif(os.geteuid() == 0, reason="root lê modo 000")
    def test_resolve_logs_warning(self, tmp_path, caplog):
        p = self._file(tmp_path, mode=0o000)
        with caplog.at_level(_logging.WARNING, logger="ekprotection.monitor.canary"):
            out = resolve_canaries([str(p)])
        os.chmod(p, 0o600)
        assert list(out.values()) == [str(p)]   # continua vigiada
        assert any("EACCES" in r.getMessage() for r in caplog.records)

    @pytest.mark.parametrize("kind", CANARY_KINDS)
    def test_create_canary_kinds(self, tmp_path, kind):
        p = create_canary(tmp_path / f"bait_{kind}", kind)
        st = p.stat()
        assert stat.S_IMODE(st.st_mode) == 0o600 and st.st_uid == os.getuid()
        assert p.read_text() and canary_issues(p) == []
        if kind == "wallet":
            assert _json.loads(p.read_text())["version"] == 3
        if kind == "seed":
            assert len(p.read_text().split()) == 12

    def test_bait_is_random(self):
        assert bait_content("ssh") != bait_content("ssh")
        with pytest.raises(ValueError):
            bait_content("nope")

    def test_create_never_overwrites_or_follows_symlink(self, tmp_path):
        real = self._file(tmp_path, "real.txt")
        with pytest.raises(FileExistsError):
            create_canary(real, "generic")
        assert real.read_text() == "FAKE\n"
        link = tmp_path / "link.pem"
        link.symlink_to(tmp_path / "target_absent")
        with pytest.raises(OSError):
            create_canary(link, "generic")
        assert not (tmp_path / "target_absent").exists()

    # ---- CLI ---------------------------------------------------------

    @staticmethod
    def _run(*args):
        return CliRunner().invoke(_ekp_app, list(args))

    def test_cli_add_list_remove(self, tmp_path, monkeypatch):
        monkeypatch.setenv("EKP_DATA_DIR", str(tmp_path / "data"))
        cfgp = tmp_path / "cfg.yaml"
        home = tmp_path / "home"
        home.mkdir(mode=0o700)
        bait = home / "backup_prod.pem"
        r = self._run("canary", "add", str(bait), "-k", "ssh", "-c", str(cfgp))
        assert r.exit_code == 0, r.output
        assert "BEGIN OPENSSH PRIVATE KEY" in bait.read_text()
        assert stat.S_IMODE(cfgp.stat().st_mode) == 0o600
        cfg = ConfigManager(cfgp).load()
        assert cfg.get("monitor.canary_paths") == [str(bait)]
        assert cfg.exposure_issues == []

        r = self._run("canary", "list", "-c", str(cfgp))
        assert r.exit_code == 0 and "ok" in r.output

        r = self._run("canary", "add", str(bait), "-c", str(cfgp))
        assert r.exit_code == 1 and "já é isca" in r.output

        r = self._run("canary", "remove", str(bait), "-c", str(cfgp))
        assert r.exit_code == 0
        assert ConfigManager(cfgp).load().get("monitor.canary_paths") == []
        assert bait.exists()

    def test_cli_add_refuses_ssh_name_unless_force(self, tmp_path, monkeypatch):
        monkeypatch.setenv("EKP_DATA_DIR", str(tmp_path / "data"))
        cfgp = tmp_path / "cfg.yaml"
        r = self._run("canary", "add", str(tmp_path / "id_ed25519"), "-c", str(cfgp))
        assert r.exit_code == 1 and not (tmp_path / "id_ed25519").exists()
        r = self._run("canary", "add", str(tmp_path / "id_ed25519"), "--force", "-c", str(cfgp))
        assert r.exit_code == 0 and (tmp_path / "id_ed25519").exists()

    def test_cli_add_refuses_existing_file(self, tmp_path, monkeypatch):
        monkeypatch.setenv("EKP_DATA_DIR", str(tmp_path / "data"))
        cfgp = tmp_path / "cfg.yaml"
        f = self._file(tmp_path, "wallet.dat")
        r = self._run("canary", "add", str(f), "-c", str(cfgp))
        assert r.exit_code == 1 and f.read_text() == "FAKE\n"
        r = self._run("canary", "add", str(f), "--existing", "-c", str(cfgp))
        assert r.exit_code == 0
        assert ConfigManager(cfgp).load().get("monitor.canary_paths") == [str(f)]

    @pytest.mark.skipif(os.geteuid() == 0, reason="root lê modo 000")
    def test_cli_existing_unreadable_refused_and_list_fails(self, tmp_path, monkeypatch):
        monkeypatch.setenv("EKP_DATA_DIR", str(tmp_path / "data"))
        cfgp = tmp_path / "cfg.yaml"
        f = self._file(tmp_path, "wallet.dat", mode=0o000)
        try:
            r = self._run("canary", "add", str(f), "--existing", "-c", str(cfgp))
            assert r.exit_code == 1
            assert self._run("canary", "add", str(f), "--existing", "--force", "-c", str(cfgp)).exit_code == 0
            r = self._run("canary", "list", "-c", str(cfgp))
            assert r.exit_code == 1 and "EACCES" in r.output.replace("\n", " ")
        finally:
            os.chmod(f, 0o600)

    def test_cli_refuses_write_on_rejected_config(self, tmp_path, monkeypatch):
        """Config recusada (11-05) carrega defaults; save() apagaria o do usuário."""
        monkeypatch.setenv("EKP_DATA_DIR", str(tmp_path / "data"))
        cfgp = tmp_path / "cfg.yaml"
        cfgp.write_text("daemon:\n  log_level: DEBUG\n")
        os.chmod(cfgp, 0o666)
        before = cfgp.read_text()
        r = self._run("canary", "add", str(tmp_path / "backup.pem"), "-c", str(cfgp))
        assert r.exit_code == 1 and cfgp.read_text() == before
        assert not (tmp_path / "backup.pem").exists()

    @pytest.mark.skipif(os.geteuid() == 0, reason="root lê modo 000")
    def test_e2e_unreadable_canary_is_blind_but_warned(self, tmp_path, caplog):
        """Documenta o limite real: o alerta não sai, mas o aviso sim."""
        p = self._file(tmp_path, mode=0o000)

        async def go():
            q: asyncio.Queue = asyncio.Queue()
            with caplog.at_level(_logging.WARNING, logger="ekprotection.monitor.canary"):
                w = CanaryWatcher([str(p)], q, asyncio.get_running_loop())
            w.start()
            await asyncio.sleep(0.3)
            with pytest.raises(PermissionError):
                open(p).close()
            await asyncio.sleep(0.5)
            w.stop()
            return q.qsize()
        try:
            assert asyncio.run(go()) == 0
        finally:
            os.chmod(p, 0o600)
        assert any("EACCES" in r.getMessage() for r in caplog.records)


class TestCanaryReload:
    """SIGHUP (o ExecReload do deploy/ek-protection.service) matava o daemon
    sem log e o systemd não reiniciava (Restart=on-failure trata SIGHUP como
    saída limpa). E isca nova só valia depois de restart (medido 2026-11-09)."""

    @staticmethod
    def _decoy(tmp_path: Path, name: str = "wallet_backup.json") -> str:
        p = tmp_path / name
        p.write_text("FAKE\n")
        os.chmod(p, 0o600)
        return str(p)

    @staticmethod
    def _drain(q: asyncio.Queue) -> list:
        out = []
        while not q.empty():
            out.append(q.get_nowait())
        return out

    @staticmethod
    async def _cat(path: str) -> None:
        import subprocess
        subprocess.run(["cat", path], stdout=subprocess.DEVNULL, check=True)
        await asyncio.sleep(0.6)

    @pytest.mark.asyncio
    async def test_e2e_added_canary_alerts_after_update(self, tmp_path: Path) -> None:
        a = self._decoy(tmp_path, "a.pem")
        sub = tmp_path / "outro"; sub.mkdir()
        b = self._decoy(sub, "b.json")
        q: asyncio.Queue = asyncio.Queue()
        w = CanaryWatcher([a], q, asyncio.get_running_loop())
        w.start()
        try:
            await asyncio.sleep(0.3)
            diff = w.update([a, b])
            await asyncio.sleep(0.3)
            await self._cat(b)
        finally:
            w.stop()
        assert diff == {"added": [b], "removed": []}
        assert [e.path for e in self._drain(q)] == [b]

    @pytest.mark.asyncio
    async def test_e2e_removed_canary_stops_alerting(self, tmp_path: Path) -> None:
        a = self._decoy(tmp_path, "a.pem")
        b = self._decoy(tmp_path, "b.json")
        q: asyncio.Queue = asyncio.Queue()
        w = CanaryWatcher([a, b], q, asyncio.get_running_loop())
        w.start()
        try:
            await asyncio.sleep(0.3)
            assert w.update([a]) == {"added": [], "removed": [b]}
            await asyncio.sleep(0.3)
            await self._cat(b)
            await self._cat(a)
        finally:
            w.stop()
        assert [e.path for e in self._drain(q)] == [a]

    @pytest.mark.asyncio
    async def test_e2e_update_from_empty_watcher(self, tmp_path: Path) -> None:
        a = self._decoy(tmp_path)
        q: asyncio.Queue = asyncio.Queue()
        w = CanaryWatcher([], q, asyncio.get_running_loop())
        w.start()
        try:
            assert not w.is_running
            w.update([a])
            assert w.is_running
            await asyncio.sleep(0.3)
            await self._cat(a)
        finally:
            w.stop()
        assert len(self._drain(q)) == 1

    @pytest.mark.asyncio
    async def test_update_to_empty_stops_observer(self, tmp_path: Path) -> None:
        a = self._decoy(tmp_path)
        w = CanaryWatcher([a], asyncio.Queue(), asyncio.get_running_loop())
        w.start()
        w.update([])
        assert not w.is_running and w.paths == []

    def test_new_observer_starts_before_old_stops(self, tmp_path: Path) -> None:
        """Sem janela em que nenhuma isca é vigiada."""
        a = self._decoy(tmp_path)
        w = CanaryWatcher([a], asyncio.Queue(), asyncio.new_event_loop())
        order: list[str] = []
        old = MagicMock(); old.is_alive.return_value = True
        old.stop.side_effect = lambda: order.append("old.stop")
        w._observer = old
        w._build_observer = lambda c: order.append("new.start") or MagicMock()
        w.update([a])
        assert order == ["new.start", "old.stop"]

    def test_cooldown_survives_update(self, tmp_path: Path) -> None:
        """Abertura logo depois do reload não duplica o alerta da isca mantida."""
        a = self._decoy(tmp_path)
        real = str(Path(a).resolve())
        w = CanaryWatcher([a], asyncio.Queue(), asyncio.new_event_loop())
        w._last[real] = 123.0
        w._build_observer = lambda c: None
        w.update([a])
        assert w._last == {real: 123.0}
        w.update([])
        assert w._last == {}

    @pytest.mark.asyncio
    async def test_manager_reload_creates_watcher_when_started_without(
        self, cfg: ConfigManager, tmp_path: Path
    ) -> None:
        a = self._decoy(tmp_path)
        mgr = MonitorManager(cfg, MagicMock())
        await mgr.start()
        try:
            assert "canary" not in mgr.status()
            assert mgr.reload_canaries([a]) == {"added": [a], "removed": []}
            assert mgr.status()["canary"]["canaries"] == [a]
        finally:
            await mgr.stop()

    def test_manager_reload_noop_when_not_running(self, cfg: ConfigManager, tmp_path: Path) -> None:
        mgr = MonitorManager(cfg, MagicMock())
        assert mgr.reload_canaries([self._decoy(tmp_path)]) == {"added": [], "removed": []}

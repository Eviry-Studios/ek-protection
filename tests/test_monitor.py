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

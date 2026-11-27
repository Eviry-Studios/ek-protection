"""Loop de overflow do inotify no watchdog 7.x (rotina 03:00, 2026-11-27).

Na VPS, desde 23/11 23:44, o daemon registrava ~1 300–1 900 "Inotify queue
overflowed" por hora sem nenhuma atividade em disco. O loop sobreviveu ao
restart de 26/11 e o processo levou OOM-kill (MemoryMax 400M).

Causa: sem ``event_filter`` o watchdog 7.x pede IN_OPEN/IN_CLOSE_NOWRITE, e a
reconciliação pós-overflow faz ``os.walk`` (abre cada diretório vigiado) →
milhares de eventos → nova overflow → nova reconciliação. Fixes:
1. ``FSWatcher`` agenda com ``_fs_event_filter()`` (sem open/close_nowrite);
2. reconciliação por diferença (não tira e recria todos os watches).
"""
from __future__ import annotations

import asyncio
import logging
import os
import time

import pytest
import watchdog.version
from watchdog.events import FileClosedNoWriteEvent, FileOpenedEvent, FileSystemEventHandler

from ekprotection.monitor import fs_watcher as fsw
from ekprotection.monitor.fs_watcher import FSWatcher

WATCHDOG_MAJOR = watchdog.version.VERSION_MAJOR
needs_wd7 = pytest.mark.skipif(WATCHDOG_MAJOR < 7, reason="reconciliação pós-overflow só existe no watchdog 7.x")


class _OverflowCounter(logging.Handler):
    """Conta os 'Inotify queue overflowed' do kernel (logger inotify_c)."""

    def __init__(self):
        super().__init__(logging.WARNING)
        self.n = 0

    def emit(self, record):
        if record.name.endswith("inotify_c") and "overflowed" in record.getMessage():
            self.n += 1


@pytest.fixture
def overflow_counter():
    h = _OverflowCounter()
    lg = logging.getLogger("watchdog.observers.inotify_c")
    old = lg.level
    lg.addHandler(h)
    lg.setLevel(logging.WARNING)
    yield h
    lg.removeHandler(h)
    lg.setLevel(old)


def _make_tree(base, n_dirs: int) -> None:
    for i in range(n_dirs):
        os.makedirs(os.path.join(base, f"d{i // 50}", f"s{i}"), exist_ok=True)


def _groups(observer):
    """InotifyWatchGroup de cada emitter (watchdog 7.x)."""
    out = []
    for em in list(observer.emitters):
        g = getattr(em, "_inotify", None)
        if g is not None:
            out.append(g)
    return out


@pytest.fixture
def make_watcher():
    made = []

    def _mk(paths):
        loop = asyncio.new_event_loop()
        w = FSWatcher([str(p) for p in paths], asyncio.Queue(), loop)
        w.start()
        made.append((w, loop))
        return w

    yield _mk
    for w, loop in made:
        w.stop()
        loop.close()


# ---------------------------------------------------------------------------
# 1. event_filter
# ---------------------------------------------------------------------------

def test_event_filter_has_no_open_or_close_nowrite():
    ef = fsw._fs_event_filter()
    assert FileOpenedEvent not in ef
    assert FileClosedNoWriteEvent not in ef
    names = {c.__name__ for c in ef}
    # o que o _EKPEventHandler trata continua chegando
    for n in ("FileCreatedEvent", "FileModifiedEvent", "FileClosedEvent",
              "FileDeletedEvent", "FileMovedEvent", "DirCreatedEvent", "DirMovedEvent"):
        assert n in names
    if WATCHDOG_MAJOR >= 7:
        assert "FileAttribEvent" in names   # chmod +x (H021 pós-chmod, a8f02da)


@needs_wd7
def test_inotify_mask_excludes_open_and_close_nowrite(tmp_path, make_watcher):
    from watchdog.observers.inotify_c import InotifyConstants as C
    w = make_watcher([tmp_path])
    groups = _groups(w._observer)
    assert groups
    for g in groups:
        assert not g.event_mask & C.IN_OPEN
        assert not g.event_mask & C.IN_CLOSE_NOWRITE
        for bit in (C.IN_CREATE, C.IN_CLOSE_WRITE, C.IN_ATTRIB, C.IN_MODIFY, C.IN_MOVED_TO, C.IN_DELETE):
            assert g.event_mask & bit


def test_chmod_and_write_still_reach_queue(tmp_path, make_watcher):
    """Regressão: o filtro não pode cegar escrita nem chmod +x."""
    w = make_watcher([tmp_path])
    time.sleep(0.3)
    f = tmp_path / "novo.sh"
    f.write_text("echo oi\n")
    time.sleep(0.3)
    os.chmod(f, 0o755)
    deadline = time.monotonic() + 5
    kinds = set()
    q = w._queue
    while time.monotonic() < deadline:
        w._loop.run_until_complete(asyncio.sleep(0.05))
        while not q.empty():
            ev = q.get_nowait()
            if str(ev.path) == str(f):
                kinds.add(ev.kind.name)
        if {"CREATED", "CLOSED"} <= kinds and len(kinds) >= 3:
            break
    assert "CREATED" in kinds
    assert "CLOSED" in kinds
    if WATCHDOG_MAJOR >= 7:
        assert len(kinds) >= 3, kinds   # + o evento do chmod (MODIFIED/ATTRIB)


# ---------------------------------------------------------------------------
# 2. loop de overflow (kernel real)
# ---------------------------------------------------------------------------

N_LOOP_DIRS = 6000   # ~4 eventos/dir no walk sem filtro > 16 384


@needs_wd7
def test_reconcile_after_overflow_does_not_overflow_again(tmp_path, make_watcher, overflow_counter):
    _make_tree(tmp_path, N_LOOP_DIRS)
    w = make_watcher([tmp_path])
    (g,) = _groups(w._observer)
    time.sleep(1)
    overflow_counter.n = 0
    g.on_queue_overflow()          # o que o reader faz ao ler IN_Q_OVERFLOW
    time.sleep(4)
    assert overflow_counter.n == 0


@needs_wd7
def test_control_unfiltered_watch_overflows_on_reconcile(tmp_path, overflow_counter):
    """Controle: prova que o teste acima mede algo (sem filtro → overflow)."""
    from watchdog.observers.inotify import InotifyObserver
    _make_tree(tmp_path, N_LOOP_DIRS)
    obs = InotifyObserver()
    obs.schedule(FileSystemEventHandler(), str(tmp_path), recursive=True)
    obs.start()
    try:
        (g,) = _groups(obs)
        time.sleep(1)
        overflow_counter.n = 0
        g.on_queue_overflow()
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and overflow_counter.n == 0:
            time.sleep(0.1)
        assert overflow_counter.n >= 1
    finally:
        obs.stop()
        obs.join(10)


# ---------------------------------------------------------------------------
# 3. reconciliação por diferença
# ---------------------------------------------------------------------------

@needs_wd7
def test_patch_installed_and_idempotent(tmp_path, make_watcher):
    from watchdog.observers.inotify import InotifyWatchGroup
    make_watcher([tmp_path])
    assert getattr(InotifyWatchGroup.on_queue_overflow, fsw._OVERFLOW_PATCH_MARK, False)
    assert fsw._install_watchdog_overflow_patch() is True
    assert InotifyWatchGroup.on_queue_overflow is fsw._ekp_on_queue_overflow


@needs_wd7
def test_diff_reconcile_keeps_existing_wds(tmp_path, make_watcher):
    _make_tree(tmp_path, 200)
    w = make_watcher([tmp_path])
    (g,) = _groups(w._observer)
    before = dict(g._active_callbacks_by_path)
    g.on_queue_overflow()
    assert dict(g._active_callbacks_by_path) == before   # nenhum rm_watch/re-add


@needs_wd7
def test_diff_reconcile_adds_missed_and_drops_stale(tmp_path, make_watcher):
    _make_tree(tmp_path, 20)
    w = make_watcher([tmp_path])
    (g,) = _groups(w._observer)
    fd = g._inotify_fd
    # simula eventos perdidos: diretório novo que o watchdog não viu, e um
    # diretório apagado cujo IN_IGNORED "se perdeu" (bookkeeping velho)
    gone = os.fsencode(os.path.join(tmp_path, "d0", "s0"))
    gone_wd = g._active_callbacks_by_path[gone]
    with g._lock:
        missed = os.path.join(tmp_path, "d0", "perdido")
        # cria sem o watchdog registrar: tira o callback do grupo do pai antes
        os.makedirs(missed)
    time.sleep(0.5)
    # força o "perdido" a não estar vigiado (como se o IN_CREATE tivesse caído)
    mwd = g._active_callbacks_by_path.get(os.fsencode(missed))
    if mwd is not None:
        g._remove_callbacks([mwd])
    assert os.fsencode(missed) not in g._active_callbacks_by_path
    os.rmdir(os.fsdecode(gone))
    time.sleep(0.5)
    # recoloca o bookkeeping velho do apagado (IN_IGNORED "perdido")
    g._active_callbacks_by_watch[gone_wd] = gone
    g._active_callbacks_by_path[gone] = gone_wd

    g.on_queue_overflow()

    assert os.fsencode(missed) in g._active_callbacks_by_path
    assert gone not in g._active_callbacks_by_path
    assert gone_wd not in g._active_callbacks_by_watch
    with fd._lock:
        assert g._id in fd._watch_for_wd[g._active_callbacks_by_path[os.fsencode(missed)]].callbacks


@needs_wd7
def test_diff_reconcile_sees_file_in_missed_dir(tmp_path, make_watcher):
    """Depois do overflow, arquivo novo dentro do diretório 'perdido' chega."""
    w = make_watcher([tmp_path])
    (g,) = _groups(w._observer)
    missed = os.path.join(tmp_path, "perdido")
    os.makedirs(missed)
    time.sleep(0.5)
    mwd = g._active_callbacks_by_path.get(os.fsencode(missed))
    if mwd is not None:
        g._remove_callbacks([mwd])
    g.on_queue_overflow()
    q = w._queue
    while not q.empty():
        q.get_nowait()
    f = os.path.join(missed, "x.sh")
    with open(f, "w") as fh:
        fh.write("echo\n")
    seen = False
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and not seen:
        w._loop.run_until_complete(asyncio.sleep(0.05))
        while not q.empty():
            if str(q.get_nowait().path) == f:
                seen = True
    assert seen


@needs_wd7
def test_diff_reconcile_root_error_is_logged_not_raised(tmp_path, make_watcher, caplog, monkeypatch):
    w = make_watcher([tmp_path])
    (g,) = _groups(w._observer)

    def boom(_group):
        raise OSError("raiz sumiu")

    monkeypatch.setattr(fsw, "_ekp_diff_reconcile", boom)
    with caplog.at_level(logging.ERROR, logger="ekprotection.monitor.fs_watcher"):
        g.on_queue_overflow()
    assert any("não foi possível reconciliar" in r.getMessage() for r in caplog.records)


def test_patch_noop_without_expected_structure(monkeypatch):
    import watchdog.observers.inotify as wi
    if not hasattr(wi, "InotifyWatchGroup"):
        assert fsw._install_watchdog_overflow_patch() is False
    else:
        monkeypatch.delattr(wi, "InotifyWatchGroup")
        assert fsw._install_watchdog_overflow_patch() is False

"""RuntimeWarning benigno de callback duplicado do watchdog >= 7 (2026-11-23).

Na VPS (watchdog 7.1.0) cada aviso desses virava uma linha de ~48 KB no journal
(repr de todos os watches do grupo). O FSWatcher instala um filtro estreito:
só essa mensagem, só RuntimeWarning, só vinda de módulo do watchdog.
"""
from __future__ import annotations

import asyncio
import warnings

import pytest
import watchdog.version

from ekprotection.monitor import fs_watcher as fsw
from ekprotection.monitor.fs_watcher import FSWatcher

_MSG = "Callback with id '123' already exists for watch Watch(wd=1, ...). It will be Overwritten."
WATCHDOG_MAJOR = watchdog.version.VERSION_MAJOR


def _emit(msg: str, category=RuntimeWarning, module: str = "watchdog.observers.inotify") -> None:
    warnings.warn_explicit(msg, category, filename="inotify.py", lineno=365, module=module)


@pytest.fixture
def watcher(tmp_path):
    loop = asyncio.new_event_loop()
    w = FSWatcher([str(tmp_path)], asyncio.Queue(), loop)
    yield w
    w.stop()
    loop.close()


def _matching(rec):
    return [r for r in rec if "already exists for watch" in str(r.message)]


def test_filter_suppresses_dup_callback_warning_from_watchdog(watcher):
    with warnings.catch_warnings(record=True) as rec:
        warnings.simplefilter("always")
        watcher.start()
        _emit(_MSG)
    assert _matching(rec) == []


def test_filter_keeps_same_message_from_other_module(watcher):
    with warnings.catch_warnings(record=True) as rec:
        warnings.simplefilter("always")
        watcher.start()
        _emit(_MSG, module="ekprotection.scanner.engine")
        _emit(_MSG, module="notwatchdog")
    assert len(_matching(rec)) == 2


def test_filter_keeps_other_watchdog_warnings(watcher):
    with warnings.catch_warnings(record=True) as rec:
        warnings.simplefilter("always")
        watcher.start()
        _emit("Inotify queue overflowed; something else")
        _emit(_MSG, category=UserWarning)
    assert len(rec) == 2


def test_filter_install_is_idempotent_and_survives_catch_warnings():
    with warnings.catch_warnings():
        before = len(warnings.filters)
        fsw._install_watchdog_dup_callback_filter()
        fsw._install_watchdog_dup_callback_filter()
        fsw._install_watchdog_dup_callback_filter()
        assert len(warnings.filters) == before + 1
    # catch_warnings restaurou a lista (sem o filtro): reinstalar tem que funcionar.
    with warnings.catch_warnings(record=True) as rec:
        warnings.simplefilter("always")
        fsw._install_watchdog_dup_callback_filter()
        _emit(_MSG)
    assert _matching(rec) == []


@pytest.mark.skipif(WATCHDOG_MAJOR < 7, reason="aviso só existe no watchdog >= 7")
def test_real_watchdog_dup_registration_is_silent(watcher, tmp_path):
    """Dispara o aviso real do watchdog 7.x: registra de novo a raiz já vigiada."""
    with warnings.catch_warnings(record=True) as rec:
        warnings.simplefilter("always")
        watcher.start()
        emitters = list(watcher._observer.emitters)
        assert emitters, "observer sem emitter"
        group = emitters[0]._inotify
        assert group is not None
        group._add_callback(str(tmp_path).encode())
    assert _matching(rec) == []


@pytest.mark.skipif(WATCHDOG_MAJOR < 7, reason="aviso só existe no watchdog >= 7")
def test_real_watchdog_dup_registration_warns_without_filter(tmp_path):
    """Controle: sem o filtro (Observer cru), o mesmo gatilho gera o aviso.
    Prova que o teste acima não passa por acaso."""
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers.inotify import InotifyObserver

    obs = InotifyObserver()
    obs.schedule(FileSystemEventHandler(), str(tmp_path), recursive=True)
    obs.start()
    try:
        with warnings.catch_warnings(record=True) as rec:
            warnings.simplefilter("always")
            group = list(obs.emitters)[0]._inotify
            group._add_callback(str(tmp_path).encode())
        assert len(_matching(rec)) == 1
    finally:
        obs.stop()
        obs.join(5)

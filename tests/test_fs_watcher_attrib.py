"""IN_ATTRIB no watchdog >= 7 (2026-11-23).

watchdog 7 entrega chmod/chown como FileAttribEvent (on_attrib). O 6.x mandava
FileModifiedEvent. Sem on_attrib no handler, `chmod +x` depois da escrita não
gerava re-scan na VPS (7.1.0) e o H021 pós-chmod ficava cego. O e2e
`test_end_to_end_chmod_x_after_write_triggers_h021` cobre o caminho real
quando a suíte roda com watchdog 7; estes testes cobrem o mapeamento.
"""
from __future__ import annotations

import asyncio

import pytest
import watchdog.events as wde

from ekprotection.monitor.events import FileEventKind
from ekprotection.monitor.fs_watcher import _EKPEventHandler

HAS_ATTRIB = hasattr(wde, "FileAttribEvent")


def _drain(loop, q):
    loop.run_until_complete(asyncio.sleep(0))
    out = []
    while not q.empty():
        out.append(q.get_nowait())
    return out


@pytest.fixture
def handler_and_queue():
    loop = asyncio.new_event_loop()
    q: asyncio.Queue = asyncio.Queue()
    h = _EKPEventHandler(q, loop, [])
    yield h, q, loop
    loop.close()


@pytest.mark.skipif(not HAS_ATTRIB, reason="FileAttribEvent só existe no watchdog >= 7")
def test_file_attrib_event_becomes_modified(handler_and_queue, tmp_path):
    h, q, loop = handler_and_queue
    p = tmp_path / "tsm"
    p.write_text("x")
    h.dispatch(wde.FileAttribEvent(str(p)))
    evs = _drain(loop, q)
    assert [e.kind for e in evs] == [FileEventKind.MODIFIED]
    assert str(evs[0].path) == str(p)


@pytest.mark.skipif(not HAS_ATTRIB, reason="DirAttribEvent só existe no watchdog >= 7")
def test_dir_attrib_event_is_ignored(handler_and_queue, tmp_path):
    h, q, loop = handler_and_queue
    h.dispatch(wde.DirAttribEvent(str(tmp_path)))
    assert _drain(loop, q) == []


def test_on_attrib_maps_like_modified_without_watchdog7(handler_and_queue, tmp_path):
    """Mesmo sem FileAttribEvent (watchdog 6), o método existe e mapeia igual."""
    h, q, loop = handler_and_queue
    p = tmp_path / "f"
    p.write_text("x")
    h.on_attrib(wde.FileModifiedEvent(str(p)))
    h.on_modified(wde.FileModifiedEvent(str(p)))
    kinds = [e.kind for e in _drain(loop, q)]
    assert kinds == [FileEventKind.MODIFIED, FileEventKind.MODIFIED]

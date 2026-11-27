"""Guarda: a suíte não grava fixtures de malware no /tmp do sistema.

Ver ``tests/conftest.py``. Rodada 2026-11-20: Council #391 (19/11) foi um
CRITICAL falso do daemon da VPS causado por ``tmp_path`` em
``/tmp/pytest-of-hermes``.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from tests.conftest import ekp_test_tmp_root

_SYSTEM_TMP = ("/tmp", "/var/tmp", "/dev/shm")

pytestmark = pytest.mark.skipif(
    ekp_test_tmp_root() is None, reason="EKP_TEST_ALLOW_SYSTEM_TMP=1")


def _under_system_tmp(p: str | Path) -> bool:
    s = str(Path(p).resolve())
    return any(s == d or s.startswith(d + "/") for d in _SYSTEM_TMP)


# Olha onde a pessoa pôs o clone / EKP_TEST_TMPDIR, e não o que o conftest
# calculou: se o redirecionamento quebrar, a guarda continua falhando.
needs_dir_outside_tmp = pytest.mark.skipif(
    _under_system_tmp(os.environ.get("EKP_TEST_TMPDIR")
                      or Path(__file__).resolve().parent.parent),
    reason="clone ou EKP_TEST_TMPDIR dentro de /tmp, /var/tmp ou /dev/shm: os "
           "temporários da suíte caem lá; rode de fora para conferir o isolamento")


@needs_dir_outside_tmp
def test_tmp_path_fora_do_tmp_do_sistema(tmp_path: Path) -> None:
    assert not _under_system_tmp(tmp_path), tmp_path


@needs_dir_outside_tmp
def test_tempfile_fora_do_tmp_do_sistema() -> None:
    assert not _under_system_tmp(tempfile.gettempdir())
    with tempfile.NamedTemporaryFile() as f:
        assert not _under_system_tmp(f.name)


@needs_dir_outside_tmp
def test_subprocesso_herda_tmpdir() -> None:
    out = subprocess.run(
        [sys.executable, "-c", "import tempfile; print(tempfile.gettempdir())"],
        capture_output=True, text=True, check=True, env=os.environ.copy(),
    ).stdout.strip()
    assert not _under_system_tmp(out), out


def test_staging_tmp_path_conta_como_area_temporaria(staging_tmp_path: Path) -> None:
    from ekprotection.heuristics import rules
    p = staging_tmp_path / ".X25-unix" / "tsm"
    assert rules._in_staging_dir(str(p.resolve()))
    hidden = rules._hidden_dir_in_staging(str(p.resolve()))
    assert hidden is not None and hidden.endswith("/.X25-unix"), hidden
    # Sem diretório oculto, o prefixo do teste em si não dispara o H021.
    assert rules._hidden_dir_in_staging(str((staging_tmp_path / "tsm").resolve())) is None


@needs_dir_outside_tmp
def test_tmp_path_comum_nao_conta_como_staging(tmp_path: Path) -> None:
    from ekprotection.heuristics import rules
    assert not rules._in_staging_dir(str((tmp_path / "x").resolve()))

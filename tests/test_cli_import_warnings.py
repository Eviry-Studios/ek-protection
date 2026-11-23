"""O import da CLI não pode depender de API do typer marcada pra remoção (2026-11-23).

typer 0.29 (a versão da VPS) emite DeprecationWarning para ``is_flag``/``flag_value``
em ``typer.Option`` e avisa que vão ser "removed entirely in a future release". Quando
isso acontecer, um ``pip install`` sem pin quebra o ``ekp`` inteiro no import.
"""
from __future__ import annotations

import subprocess
import sys


def test_cli_import_has_no_typer_deprecation():
    code = (
        "import warnings\n"
        "warnings.simplefilter('error', DeprecationWarning)\n"
        "import typer, typer.params\n"  # importar antes: aviso de terceiro no import do typer não conta
        "warnings.filterwarnings('error', category=DeprecationWarning, module=r'typer(\\..*)?$')\n"
        "import ekprotection.cli.app\n"
    )
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr[-2000:]

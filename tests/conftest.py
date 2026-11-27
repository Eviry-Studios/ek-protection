"""
Configuração global da suíte.

Diretório temporário fora de /tmp
---------------------------------
Vários testes gravam scripts com TEXTO de malware (reverse shell, curl|sh,
xmrig...) em ``tmp_path``. Por padrão o pytest usa ``/tmp/pytest-of-<user>``,
e ``/tmp`` é um ``monitor.path`` padrão do próprio EK-Protection. Numa máquina
com o daemon rodando, a suíte gerava alertas CRITICAL falsos (ex.: Council
#391, 19/11/2026, ``/tmp/pytest-of-hermes/.../update.sh`` H002+H006).

Por isso, a menos que ``--basetemp`` seja passado na linha de comando, os
temporários da suíte vão para:

* ``$EKP_TEST_TMPDIR/ekp-pytest`` se a variável existir, ou
* ``<repo>/pytest-tmp`` (no ``.gitignore``). Sem ponto no nome de propósito:
  o H021 trata QUALQUER diretório oculto no caminho de um arquivo em área
  temporária como dropper, e o ``staging_tmp_path`` abaixo deixaria de testar
  alguma coisa.

``TMPDIR`` e ``tempfile.tempdir`` também são apontados para lá, para que
``tempfile.mkdtemp()`` e subprocessos (daemon/CLI nos testes e2e) não voltem
para ``/tmp``. Defina ``EKP_TEST_ALLOW_SYSTEM_TMP=1`` para o comportamento
antigo.

O pytest APAGA o conteúdo do ``basetemp`` no início de cada execução; por isso
o diretório é sempre um subdiretório dedicado, nunca o ``EKP_TEST_TMPDIR`` em si.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent


def ekp_test_tmp_root() -> Path | None:
    """Raiz dos temporários da suíte, ou None se o /tmp do sistema foi pedido."""
    if os.environ.get("EKP_TEST_ALLOW_SYSTEM_TMP") == "1":
        return None
    custom = os.environ.get("EKP_TEST_TMPDIR")
    if custom:
        return Path(custom).expanduser().resolve() / "ekp-pytest"
    return _REPO_ROOT / "pytest-tmp"


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config: pytest.Config) -> None:
    root = ekp_test_tmp_root()
    if root is None:
        return

    if config.option.basetemp is None:
        # basetemp é limpo pelo pytest a cada execução.
        config.option.basetemp = str(root / "basetemp")

    other = root / "tmp"
    other.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.environ["TMPDIR"] = str(other)
    tempfile.tempdir = None   # força o tempfile a reler TMPDIR


def pytest_report_header(config: pytest.Config) -> str | None:
    root = ekp_test_tmp_root()
    if root is None or not str(root.resolve()).startswith(("/tmp/", "/var/tmp/", "/dev/shm/")):
        return None
    return (f"AVISO: temporários da suíte em {root} (área temporária do sistema); um "
            "daemon EK-Protection nesta máquina pode alertar. Rode de fora de /tmp.")


@pytest.fixture
def staging_tmp_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """``tmp_path`` tratado como área temporária (/tmp, /var/tmp, /dev/shm).

    Para testes cuja regra depende do arquivo estar em área de staging
    (H021 diretório oculto, H002 script em /tmp, score de dir suspeito no
    scanner). Em vez de gravar em ``/tmp`` de verdade — e disparar o daemon
    da máquina —, o prefixo do ``tmp_path`` entra nas listas de staging só
    durante o teste.
    """
    from ekprotection.heuristics import rules
    from ekprotection.scanner import engine as scan_engine

    prefix = str(tmp_path.resolve())
    hidden = [p for p in Path(prefix).parts if p.startswith(".")]
    if hidden:
        # O H021 casaria em qualquer arquivo daqui (ver docstring do módulo).
        pytest.fail(f"staging_tmp_path: prefixo com diretório oculto {hidden} "
                    f"({prefix}); use EKP_TEST_TMPDIR sem componente oculto")
    monkeypatch.setattr(rules, "_STAGING_DIRS", rules._STAGING_DIRS + (prefix + "/",))
    monkeypatch.setattr(scan_engine, "_SUSPICIOUS_DIRS",
                        set(scan_engine._SUSPICIOUS_DIRS) | {prefix})
    return tmp_path

"""
ekprotection.main
==================
Entry point do EK-Protection.

Invocado via:
  ekp <comando>           (após pip install -e .)
  python -m ekprotection  (desenvolvimento)
"""

from __future__ import annotations

import sys


def main() -> None:
    """Entry point principal registrado no pyproject.toml."""
    from ekprotection.cli.app import app
    app()


def run() -> None:
    """Alias para uso como python -m ekprotection."""
    main()


if __name__ == "__main__":
    main()

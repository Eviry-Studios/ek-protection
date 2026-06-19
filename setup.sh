#!/usr/bin/env bash
# EK-Protection — Setup script
# Instala dependências e prepara o ambiente de desenvolvimento.
set -euo pipefail

echo "==> EK-Protection Setup"

# Verifica Python
if ! command -v python3 &>/dev/null; then
  echo "ERRO: Python 3.10+ é necessário."
  exit 1
fi

PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "    Python $PY_VERSION detectado."

# Cria venv se não existir
if [ ! -d ".venv" ]; then
  echo "==> Criando ambiente virtual..."
  python3 -m venv .venv
fi

source .venv/bin/activate

echo "==> Instalando dependências..."
pip install --quiet --upgrade pip
pip install --quiet -e ".[dev]"

echo "==> Verificando instalação..."
ekp version

echo ""
echo "✔  Setup concluído!"
echo ""
echo "   Ative o ambiente: source .venv/bin/activate"
echo "   Inicialize:       sudo ekp init"
echo "   Teste:            pytest tests/ -v"

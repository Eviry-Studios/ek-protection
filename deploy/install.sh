#!/usr/bin/env bash
# EK-Protection — Script de instalação para produção
set -euo pipefail

echo "==> EK-Protection Install"

# Verifica root
if [ "$EUID" -ne 0 ]; then
  echo "ERRO: Este script requer root (sudo)."
  exit 1
fi

# Instala dependências Python
echo "==> Instalando pacotes Python..."
pip3 install --quiet ek-protection

# Cria diretórios
echo "==> Criando diretórios..."
install -d -m 750 /etc/ek-protection
install -d -m 750 /var/lib/ek-protection
install -d -m 750 /var/lib/ek-protection/quarantine
install -d -m 750 /var/log/ek-protection
install -d -m 755 /run/ek-protection

# Instala unit systemd
echo "==> Instalando systemd unit..."
install -m 644 deploy/ek-protection.service /etc/systemd/system/
systemctl daemon-reload

# Inicializa configuração
echo "==> Inicializando configuração..."
ekp init

echo ""
echo "✔  Instalação concluída!"
echo ""
echo "   Configure a senha:     ekp auth setup"
echo "   Habilite o serviço:    systemctl enable ek-protection"
echo "   Inicie o serviço:      systemctl start ek-protection"
echo "   Verifique o status:    ekp status"

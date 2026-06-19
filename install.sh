#!/usr/bin/env bash
#
# EK-Protection — Instalador rápido
# ==================================
# Uso (após clonar o repositório):
#   chmod +x install.sh
#   sudo ./install.sh
#
# Ou direto via curl (depois de publicado no GitHub):
#   curl -fsSL https://raw.githubusercontent.com/<usuario>/ek-protection/main/install.sh | sudo bash
#
set -euo pipefail

REPO_URL="https://github.com/Eviry-Studios/ek-protection.git"
INSTALL_DIR="/opt/ek-protection"

# ---------------------------------------------------------------------------
# Cores para output
# ---------------------------------------------------------------------------
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}==>${NC} $1"; }
ok()    { echo -e "${GREEN}✔${NC}  $1"; }
warn()  { echo -e "${YELLOW}⚠${NC}  $1"; }
fail()  { echo -e "${RED}✖${NC}  $1"; exit 1; }

# ---------------------------------------------------------------------------
# Verificações iniciais
# ---------------------------------------------------------------------------
echo ""
echo "  ███████╗██╗  ██╗      ██████╗ ██████╗  ██████╗ ████████╗███████╗ ██████╗████████╗██╗ ██████╗ ███╗   ██╗"
echo "  ██╔════╝██║ ██╔╝      ██╔══██╗██╔══██╗██╔═══██╗╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██║██╔═══██╗████╗  ██║"
echo "  █████╗  █████╔╝ █████╗██████╔╝██████╔╝██║   ██║   ██║   █████╗  ██║        ██║   ██║██║   ██║██╔██╗ ██║"
echo "  ██╔══╝  ██╔═██╗ ╚════╝██╔═══╝ ██╔══██╗██║   ██║   ██║   ██╔══╝  ██║        ██║   ██║██║   ██║██║╚██╗██║"
echo "  ███████╗██║  ██╗      ██║     ██║  ██║╚██████╔╝   ██║   ███████╗╚██████╗   ██║   ██║╚██████╔╝██║ ╚████║"
echo "  ╚══════╝╚═╝  ╚═╝      ╚═╝     ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚══════╝ ╚═════╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝"
echo ""
echo "  Instalador v1.0.0 — EviRyKorp"
echo ""

if [ "$EUID" -ne 0 ]; then
  fail "Este script precisa ser executado como root. Use: sudo ./install.sh"
fi

if ! command -v python3 &>/dev/null; then
  fail "Python 3 não encontrado. Instale com: sudo apt install python3 python3-pip python3-venv"
fi

PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_MAJOR=$(python3 -c 'import sys; print(sys.version_info.major)')
PY_MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)')

if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 10 ]; }; then
  fail "Python 3.10+ é necessário. Versão atual: $PY_VERSION"
fi
ok "Python $PY_VERSION detectado"

if ! command -v git &>/dev/null; then
  warn "git não encontrado. Instalando..."
  apt-get update -qq && apt-get install -y -qq git
fi

# ---------------------------------------------------------------------------
# Clona ou atualiza o repositório
# ---------------------------------------------------------------------------
if [ -d "$INSTALL_DIR" ]; then
  info "Instalação existente encontrada em $INSTALL_DIR. Atualizando..."
  cd "$INSTALL_DIR"
  git pull --quiet
else
  info "Clonando repositório em $INSTALL_DIR..."
  git clone --quiet "$REPO_URL" "$INSTALL_DIR"
  cd "$INSTALL_DIR"
fi
ok "Código-fonte pronto"

# ---------------------------------------------------------------------------
# Cria ambiente virtual e instala
# ---------------------------------------------------------------------------
info "Criando ambiente virtual..."
python3 -m venv "$INSTALL_DIR/.venv"
source "$INSTALL_DIR/.venv/bin/activate"

info "Instalando dependências (isso pode levar um minuto)..."
pip install --quiet --upgrade pip
pip install --quiet -e "$INSTALL_DIR"
ok "EK-Protection instalado em $INSTALL_DIR/.venv"

# ---------------------------------------------------------------------------
# Cria comando global 'ekp' (wrapper, robusto contra espaços e mounts)
# ---------------------------------------------------------------------------
info "Criando comando global 'ekp'..."

# Usamos um wrapper de shell em vez de symlink direto: alguns filesystems
# montados (NTFS/exFAT em /var/mnt/..., comum em dual-boot) não preservam
# o bit de execução em symlinks, e caminhos com espaços quebram o
# ExecStart= do systemd. O wrapper contorna os dois problemas.
cat > /usr/local/bin/ekp << EOF
#!/usr/bin/env bash
exec "$INSTALL_DIR/.venv/bin/python" -m ekprotection.main "\$@"
EOF
chmod +x /usr/local/bin/ekp

cat > /usr/local/bin/ekp-daemon-wrapper.sh << EOF
#!/usr/bin/env bash
exec "$INSTALL_DIR/.venv/bin/python" -m ekprotection.daemon
EOF
chmod +x /usr/local/bin/ekp-daemon-wrapper.sh

ok "Comando 'ekp' disponível globalmente (via wrapper)"

# ---------------------------------------------------------------------------
# Inicializa configuração e diretórios
# ---------------------------------------------------------------------------
info "Inicializando configuração..."
ekp init
ok "Configuração criada em /etc/ek-protection/config.yaml"

# ---------------------------------------------------------------------------
# Cria grupo 'ek-protection' e adiciona quem instalou
# ---------------------------------------------------------------------------
# Permite rodar `ekp status`, `ekp scan file`, etc. sem sudo.
# Operações críticas (auth, quarentena, start/stop do serviço) continuam
# exigindo root — isso só afeta a leitura via socket IPC.
info "Configurando grupo de acesso..."
if ! getent group ek-protection &>/dev/null; then
  groupadd ek-protection
fi

TARGET_USER="${SUDO_USER:-}"
if [ -n "$TARGET_USER" ] && [ "$TARGET_USER" != "root" ]; then
  usermod -aG ek-protection "$TARGET_USER"
  ok "Usuário '$TARGET_USER' adicionado ao grupo 'ek-protection'"
  GROUP_NOTICE=1
else
  warn "Adicione seu usuário manualmente: sudo usermod -aG ek-protection <usuario>"
  GROUP_NOTICE=0
fi

# ---------------------------------------------------------------------------
# Instala unit systemd (usa o wrapper, não o caminho direto do venv)
# ---------------------------------------------------------------------------
if [ -f "$INSTALL_DIR/deploy/ek-protection.service" ]; then
  cp "$INSTALL_DIR/deploy/ek-protection.service" /etc/systemd/system/ek-protection.service
  systemctl daemon-reload
  ok "Serviço systemd instalado (ek-protection.service)"
fi

# ---------------------------------------------------------------------------
# Resumo final
# ---------------------------------------------------------------------------
echo ""
echo -e "${GREEN}✔  Instalação concluída com sucesso!${NC}"
echo ""
echo "  Próximos passos:"
echo ""
echo "    1. Configure sua senha:"
echo "       ${CYAN}sudo ekp auth setup${NC}"
echo ""
echo "    2. Inicie o serviço (roda em segundo plano, sobrevive a reboot):"
echo "       ${CYAN}sudo systemctl enable --now ek-protection${NC}"
echo ""
echo "    3. Verifique se está rodando:"
echo "       ${CYAN}ekp status${NC}"
echo ""
echo "    4. Veja todos os comandos disponíveis:"
echo "       ${CYAN}ekp --help${NC}"
echo ""
if [ "${GROUP_NOTICE:-0}" = "1" ]; then
  echo -e "${YELLOW}  ⚠  Faça logout e login novamente (ou reinicie) para usar${NC}"
  echo -e "${YELLOW}     'ekp status' sem precisar de sudo.${NC}"
  echo ""
fi

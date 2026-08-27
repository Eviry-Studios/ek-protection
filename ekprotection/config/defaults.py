"""
ekprotection.config.defaults
============================
Valores padrão para todas as configurações do EK-Protection.
Este arquivo define a configuração canônica — o ConfigManager parte
daqui e mescla com o arquivo YAML do usuário.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Caminhos base (podem ser sobrescritos via YAML ou variável EKP_DATA_DIR)
# ---------------------------------------------------------------------------
DEFAULT_DATA_DIR = "/var/lib/ek-protection"
DEFAULT_CONFIG_DIR = "/etc/ek-protection"
DEFAULT_CONFIG_FILE = "/etc/ek-protection/config.yaml"
DEFAULT_LOG_DIR = "/var/log/ek-protection"
DEFAULT_QUARANTINE_DIR = "/var/lib/ek-protection/quarantine"
DEFAULT_DB_PATH = "/var/lib/ek-protection/ek-protection.db"
DEFAULT_SOCKET_PATH = "/run/ek-protection/daemon.sock"
DEFAULT_PID_FILE = "/run/ek-protection/daemon.pid"

# ---------------------------------------------------------------------------
# Configuração padrão como dicionário (espelhada no YAML de exemplo)
# ---------------------------------------------------------------------------
DEFAULT_CONFIG: dict = {
    # -- Daemon ---------------------------------------------------------------
    "daemon": {
        "socket_path": DEFAULT_SOCKET_PATH,
        "pid_file": DEFAULT_PID_FILE,
        "log_level": "INFO",          # DEBUG | INFO | WARNING | ERROR | CRITICAL
        "silent_mode": False,          # Suprime alertas interativos
    },

    # -- Monitoramento --------------------------------------------------------
    "monitor": {
        "enabled": True,
        "paths": [                     # Diretórios monitorados por padrão
            "/home",
            "/tmp",
            "/var/tmp",
            "/usr/bin",
            "/usr/sbin",
            "/bin",
            "/sbin",
        ],
        "recursive": True,
        "ignore_patterns": [           # Padrões de arquivo ignorados (glob)
            "*.log",
            "*.tmp",
            "*.pid",
            ".git/*",
        ],
        "poll_interval_ms": 500,       # Intervalo de polling como fallback (ms)
        "auto_scan_new_executables": True,  # dispara scan_file() em CREATED/MOVED/EXECUTED de executáveis
    },

    # -- Scanner --------------------------------------------------------------
    "scanner": {
        "enabled": True,
        "max_file_size_mb": 512,       # Arquivos acima disso são ignorados
        "hash_algorithm": "sha256",
        "quick_scan_paths": [          # Paths para scan rápido
            "/home",
            "/tmp",
            "/var/tmp",
        ],
        "threads": 4,                  # Threads para scan paralelo
    },

    # -- Heurística -----------------------------------------------------------
    "heuristics": {
        "enabled": True,
        "sensitivity": "medium",       # low | medium | high | paranoid
        "check_entropy": True,         # Detecta arquivos com alta entropia (packed/cripto)
        "entropy_threshold": 7.2,      # Shannon entropy threshold (0-8)
        "check_permissions": True,     # Alerta sobre permissões suspeitas
        "check_hidden": True,          # Alerta sobre executáveis ocultos
        "check_script_injection": True,
    },

    # -- Quarentena -----------------------------------------------------------
    "quarantine": {
        "dir": DEFAULT_QUARANTINE_DIR,
        "encrypt": True,               # Criptografa arquivos em quarentena
        "auto_quarantine_critical": True,  # Modo crítico: quarentena automática
        "retention_days": 30,          # Dias até limpeza automática
    },

    # -- Autenticação ---------------------------------------------------------
    "auth": {
        "require_for_critical": True,  # Exige senha para ações críticas
        "session_timeout_minutes": 30, # Timeout da sessão autenticada
        "max_attempts": 5,             # Tentativas antes de lockout
        "lockout_minutes": 15,
    },

    # -- Alertas --------------------------------------------------------------
    "alerts": {
        "terminal": True,              # Alertas no terminal (rich)
        "syslog": True,                # Envia para syslog
        "sound": False,                # Bell no terminal
        "notify_send": False,          # notify-send (requer display)
    },

    # -- Exceções (whitelist) -------------------------------------------------
    "exceptions": {
        "paths": [],                   # Paths excluídos do monitoramento
        "hashes": [],                  # SHA-256 confiáveis
        "processes": [],               # Nomes de processos confiáveis
        "extensions": [                # Extensões excluídas do scanner
            ".iso", ".img", ".vmdk",
        ],
    },

    # -- Assinaturas ----------------------------------------------------------
    "signatures": {
        "db_path": "/var/lib/ek-protection/signatures.db",
        "auto_update": True,
        "update_interval_hours": 24,
        "update_url": "https://raw.githubusercontent.com/Eviry-Studios/ek-protection/main/signatures/",
    },

    # -- Logs -----------------------------------------------------------------
    "logs": {
        "dir": DEFAULT_LOG_DIR,
        "db_path": DEFAULT_DB_PATH,
        "max_size_mb": 100,
        "rotate_count": 5,
        "retention_days": 90,
        "structured": True,            # Grava JSON estruturado além do texto
    },

    # -- Plugins --------------------------------------------------------------
    "plugins": {
        "enabled": False,
        "dir": "/var/lib/ek-protection/plugins",
    },

    # -- Integrações ----------------------------------------------------------
    "integrations": {
        "clamav": {
            "enabled": False,
            "socket": "/run/clamav/clamd.ctl",
        },
    },
}

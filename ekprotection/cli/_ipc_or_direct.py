"""
ekprotection.cli._ipc_or_direct
==================================
Helper único pro padrão "tenta o daemon via IPC, cai pro acesso direto ao
SQLite se ele não estiver rodando" — usado pelos comandos CLI que precisam
funcionar sem sudo (o banco pertence a root, mas o daemon já roda como
root e pode responder via socket Unix).

Antes duplicado em log_commands.py e quarantine_commands.py (ver roadmap
"Patch 11" em docs/architecture.md).
"""

from __future__ import annotations

import os

from ekprotection.config.manager import ConfigManager


def ipc_client(cfg: ConfigManager):
    """
    Cliente IPC pro daemon, se estiver rodando e responder. Retorna None
    se não estiver (chamador cai pro acesso direto ao SQLite).
    """
    socket_path = cfg.get("daemon.socket_path", "/run/ek-protection/daemon.sock")
    data_dir = os.environ.get("EKP_DATA_DIR", "")
    if data_dir:
        socket_path = socket_path.replace("/run/ek-protection", data_dir + "/run")

    from ekprotection.daemon import IPCClient
    client = IPCClient(socket_path)
    return client if client.is_alive() else None

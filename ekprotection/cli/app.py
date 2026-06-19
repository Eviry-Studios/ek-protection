"""
ekprotection.cli.app
=====================
Interface de linha de comando do EK-Protection.

Patches ativos:
  Patch 1: config, status, start, stop, init, version
  Patch 2: ekp auth *
  Patch 3: ekp logs *
"""

from __future__ import annotations

import os
from typing import Optional

import typer

from ekprotection import __version__
from ekprotection.config.manager import ConfigManager
from ekprotection.core.engine import EKEngine
from .display import (
    console, print_banner, print_success,
    print_warning, print_error, print_info, print_status_panel,
)
from .auth_commands    import auth_app
from .log_commands     import logs_app
from .monitor_commands   import monitor_app
from .exception_commands    import exc_app
from .quarantine_commands   import quar_app
from .scan_commands          import scan_app
from .heuristic_commands     import heur_app
from .update_commands        import update_app
from .report_commands        import report_app

app = typer.Typer(
    name="ekp",
    help="EK-Protection — Terminal Antivirus Engine",
    add_completion=False,
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)

config_app = typer.Typer(help="Gerenciar configuração")
app.add_typer(config_app, name="config")
app.add_typer(auth_app,    name="auth")
app.add_typer(logs_app,    name="logs")
app.add_typer(monitor_app, name="monitor")
app.add_typer(exc_app,     name="exceptions")
app.add_typer(quar_app,    name="quarantine")
app.add_typer(scan_app,    name="scan")
app.add_typer(heur_app,    name="heuristics")
app.add_typer(update_app,  name="update")
app.add_typer(report_app,  name="report")


def _load_config(p: str | None = None) -> ConfigManager:
    cfg = ConfigManager(p)
    cfg.load()
    return cfg


def _require_root() -> None:
    if os.geteuid() != 0:
        print_warning("Algumas operações requerem root. Use sudo se necessário.")


@app.callback(invoke_without_command=True)
def main_callback(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-v"),
) -> None:
    """EK-Protection — Motor de proteção terminal para Linux."""
    if version:
        console.print(f"[bold cyan]EK-Protection[/bold cyan] v{__version__}")
        raise typer.Exit()


@app.command("version")
def cmd_version() -> None:
    """Exibe a versão."""
    console.print(f"[bold cyan]EK-Protection[/bold cyan] v{__version__}")
    console.print("[dim]Author: EviRyKorp | License: MIT[/dim]")


@app.command("init")
def cmd_init(
    config: Optional[str] = typer.Option(None, "--config", "-c"),
    force:  bool          = typer.Option(False, "--force", "-f"),
) -> None:
    """Inicializa o EK-Protection (primeira execução)."""
    print_banner()
    console.print("[ekp.brand]Inicializando EK-Protection...[/ekp.brand]\n")
    cfg = ConfigManager(config)
    created = cfg.initialize(force=force)
    if created:
        print_success(f"Configuração criada em: {cfg.config_path}")
        console.print("  1. Configure a senha:  [cyan]ekp auth setup[/cyan]")
        console.print("  2. Inicie o daemon:    [cyan]ekp start[/cyan]")
    else:
        print_warning(f"Configuração já existe em: {cfg.config_path}")
        print_info("Use --force para sobrescrever.")


@app.command("status")
def cmd_status(
    config:      Optional[str] = typer.Option(None, "--config", "-c"),
    json_output: bool          = typer.Option(False, "--json"),
) -> None:
    """Exibe o status atual do EK-Protection."""
    cfg = _load_config(config)
    import os
    socket_path = cfg.get("daemon.socket_path", "/run/ek-protection/daemon.sock")
    data_dir    = os.environ.get("EKP_DATA_DIR", "")
    if data_dir:
        socket_path = socket_path.replace("/run/ek-protection", data_dir + "/run")

    from ekprotection.daemon import IPCClient
    client = IPCClient(socket_path)

    if client.is_alive():
        try:
            resp   = client.send("status")
            status = resp.get("data", {})
        except ConnectionError as exc:
            status = {"state": "ERROR", "error": str(exc)}
    else:
        status = {"state": "STOPPED", "note": "Daemon não está rodando. Use: sudo ekp start"}

    if json_output:
        import json
        console.print_json(json.dumps(status, default=str))
    else:
        print_banner()
        print_status_panel(status)


@app.command("start")
def cmd_start(
    config:     Optional[str] = typer.Option(None, "--config", "-c"),
    foreground: bool          = typer.Option(True, "--foreground/-f", is_flag=True),
) -> None:
    """Inicia o daemon EK-Protection (foreground)."""
    _require_root()
    cfg = _load_config(config)
    print_banner()
    print_info("Iniciando EK-Protection v0.9.0...")

    from ekprotection.daemon import run_daemon
    try:
        run_daemon(config)
    except KeyboardInterrupt:
        print_info("Interrompido pelo usuário.")


async def _run_engine(engine: EKEngine) -> None:
    await engine.start()
    console.print("[ekp.ok]✔[/ekp.ok]  Engine iniciado. Pressione Ctrl+C para parar.")
    await engine.wait()


@app.command("stop")
def cmd_stop(config: Optional[str] = typer.Option(None, "--config", "-c")) -> None:
    """Para o daemon EK-Protection."""
    cfg = _load_config(config)
    import os
    socket_path = cfg.get("daemon.socket_path", "/run/ek-protection/daemon.sock")
    data_dir    = os.environ.get("EKP_DATA_DIR", "")
    if data_dir:
        socket_path = socket_path.replace("/run/ek-protection", data_dir + "/run")

    from ekprotection.daemon import IPCClient
    client = IPCClient(socket_path)

    if not client.is_alive():
        print_warning("Daemon não está rodando.")
        return

    try:
        client.send("stop")
        print_success("Sinal de parada enviado ao daemon.")
    except ConnectionError as exc:
        print_error(str(exc))


@config_app.command("show")
def cmd_config_show(
    config:  Optional[str] = typer.Option(None, "--config", "-c"),
    section: Optional[str] = typer.Argument(None),
) -> None:
    """Exibe a configuração atual."""
    import yaml
    from rich.syntax import Syntax
    from rich.panel  import Panel
    cfg  = _load_config(config)
    data = cfg.data if not section else cfg.data.get(section, {})
    if section and not data:
        print_error(f"Seção '{section}' não encontrada.")
        raise typer.Exit(1)
    s = Syntax(yaml.dump(data, default_flow_style=False, allow_unicode=True, sort_keys=True), "yaml", theme="monokai")
    console.print(Panel(s, title=f"[ekp.brand]Configuração{f' — {section}' if section else ''}[/ekp.brand]", border_style="cyan"))


@config_app.command("set")
def cmd_config_set(
    key:    str            = typer.Argument(...),
    value:  str            = typer.Argument(...),
    config: Optional[str] = typer.Option(None, "--config", "-c"),
) -> None:
    """Define um valor de configuração."""
    cfg = _load_config(config)
    old = cfg.get(key)
    parsed: str | int | float | bool = value
    if value.lower() in ("true","yes"):   parsed = True
    elif value.lower() in ("false","no"): parsed = False
    else:
        try:    parsed = int(value)
        except ValueError:
            try: parsed = float(value)
            except ValueError: parsed = value
    cfg.set(key, parsed)
    cfg.save()
    print_success(f"{key} = {parsed}  [dim](era: {old})[/dim]")

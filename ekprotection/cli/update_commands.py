"""
ekprotection.cli.update_commands
===================================
Comandos CLI para atualização de assinaturas.

  ekp update signatures   — Baixa e aplica assinaturas mais recentes
  ekp update check        — Verifica se há atualização (sem baixar)
  ekp update status       — Status do sistema de atualização
"""

from __future__ import annotations

import os
from pathlib import Path
from typing  import Optional

import typer
from rich.panel import Panel
from rich.table import Table
from rich       import box

from ekprotection.config.manager  import ConfigManager
from ekprotection.scanner.signatures import SignatureDB
from ekprotection.updater.manager import UpdateManager
from ekprotection.updater.fetcher  import UpdateError, ManifestError, ChecksumError
from .display import console, print_success, print_error, print_warning, print_info

update_app = typer.Typer(help="Atualização de assinaturas de ameaças")


def _open_updater(config_path: str | None = None) -> tuple[ConfigManager, UpdateManager, SignatureDB]:
    cfg = ConfigManager(config_path)
    cfg.load()

    sig_raw  = cfg.get("signatures.db_path", "/var/lib/ek-protection/signatures.db")
    data_dir = os.environ.get("EKP_DATA_DIR", "")
    if data_dir:
        sig_raw = sig_raw.replace("/var/lib/ek-protection", data_dir)

    sig_db = SignatureDB(sig_raw)
    sig_db.open()

    updater = UpdateManager(cfg, sig_db=sig_db)
    updater.initialize()
    return cfg, updater, sig_db


@update_app.command("signatures")
def cmd_update_signatures(
    force:       bool          = typer.Option(False, "--force", "-f", help="Força mesmo se já atualizado."),
    config:      Optional[str] = typer.Option(None, "--config", "-c"),
) -> None:
    """Baixa e aplica assinaturas de ameaças mais recentes."""
    cfg, updater, sig_db = _open_updater(config)

    console.print()
    with console.status("[dim]Verificando servidor de assinaturas...[/dim]"):
        try:
            result = updater.update_now(force=force)
        except (UpdateError, ManifestError, ChecksumError) as exc:
            sig_db.close()
            print_error(f"Falha na atualização: {exc}")
            raise typer.Exit(1)

    sig_db.close()
    console.print()

    if result is None:
        print_error("Atualização falhou. Verifique a conectividade e os logs.")
        raise typer.Exit(1)

    if result.updated:
        print_success(f"Assinaturas atualizadas: v{result.version_before} → v{result.version_after}")
        print_info(f"{result.added} novas assinaturas adicionadas.")
    else:
        print_info(f"Já na versão mais recente: {result.version_after}")


@update_app.command("check")
def cmd_update_check(
    config:      Optional[str] = typer.Option(None, "--config", "-c"),
    json_output: bool          = typer.Option(False, "--json"),
) -> None:
    """Verifica se há atualização disponível sem baixar."""
    cfg, updater, sig_db = _open_updater(config)

    with console.status("[dim]Verificando...[/dim]"):
        available, local, remote = updater.check_available()

    sig_db.close()

    if json_output:
        import json
        console.print_json(json.dumps({
            "available": available, "local": local, "remote": remote
        }))
        return

    if available:
        print_warning(f"Atualização disponível: v{local} → v{remote}")
        print_info("Execute: [cyan]ekp update signatures[/cyan]")
    else:
        print_success(f"Assinaturas atualizadas (v{local}).")


@update_app.command("status")
def cmd_update_status(
    config:      Optional[str] = typer.Option(None, "--config", "-c"),
    json_output: bool          = typer.Option(False, "--json"),
) -> None:
    """Exibe status do sistema de atualização."""
    cfg, updater, sig_db = _open_updater(config)
    s = updater.status()
    sig_db.close()

    if json_output:
        import json
        console.print_json(json.dumps(s))
        return

    table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    table.add_column("Campo", style="ekp.label", width=22)
    table.add_column("Valor")

    table.add_row("Auto-update",      "[green]Sim[/green]" if s["auto_update"] else "[dim]Não[/dim]")
    table.add_row("Intervalo",        f"{s['interval_hours']}h")
    table.add_row("Última verificação", s["last_check"])
    table.add_row("Assinaturas",      str(s["signatures"]))
    table.add_row("Versão",           s["sig_version"])
    table.add_row("URL",              f"[dim]{s['update_url']}[/dim]")

    console.print(Panel(
        table,
        title="[ekp.brand]Atualizações — Status[/ekp.brand]",
        border_style="cyan",
    ))

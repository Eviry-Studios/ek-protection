"""
ekprotection.cli.quarantine_commands
======================================
Comandos CLI para gerenciamento de quarentena.

  ekp quarantine list    — Lista itens em quarentena
  ekp quarantine info    — Detalhes de um item
  ekp quarantine restore — Restaura arquivo (requer auth)
  ekp quarantine delete  — Exclui permanentemente (requer auth)
  ekp quarantine stats   — Estatísticas do vault
  ekp quarantine purge   — Limpa registros antigos
"""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing  import Optional

import typer
from rich.panel import Panel
from rich.table import Table
from rich       import box

from ekprotection.config.manager          import ConfigManager
from ekprotection.quarantine.manager      import QuarantineManager, QuarantineError
from ekprotection.quarantine.models       import QuarantineEntry, QuarantineReason, QuarantineStatus
from ekprotection.auth.manager            import AuthManager
from ._ipc_or_direct import ipc_client
from .display import console, print_success, print_error, print_warning, print_info

quar_app = typer.Typer(help="Gerenciar quarentena de arquivos suspeitos")

_STATUS_COLOR = {
    "active":   "red",
    "restored": "green",
    "deleted":  "dim",
}
_RISK_COLOR = {
    "baixo":   "green",
    "médio":   "yellow",
    "alto":    "red",
    "crítico": "bold white on red",
}


def _open_mgr(config_path: str | None = None) -> tuple[ConfigManager, QuarantineManager]:
    cfg = ConfigManager(config_path)
    cfg.load()
    mgr = QuarantineManager(cfg)
    mgr.open()
    return cfg, mgr


def _entry_from_ipc_dict(d: dict) -> QuarantineEntry:
    """Reconstrói um QuarantineEntry a partir do dict retornado pelo daemon via IPC."""
    return QuarantineEntry(
        entry_id=d.get("id"),
        quarantine_id=d["quarantine_id"],
        original_path=d["original_path"],
        sha256=d["sha256"],
        reason=QuarantineReason(d["reason"]),
        status=QuarantineStatus(d["status"]),
        file_size=d.get("file_size"),
        threat_type=d.get("threat_type"),
        risk_level=d.get("risk_level"),
        process_name=d.get("process_name"),
        quarantined_at=datetime.fromisoformat(d["quarantined_at"]),
        restored_at=datetime.fromisoformat(d["restored_at"]) if d.get("restored_at") else None,
        restored_to=d.get("restored_to"),
        comment=d.get("comment", ""),
    )


def _authenticate(cfg: ConfigManager) -> str:
    """Solicita senha e retorna token de sessão."""
    auth = AuthManager(cfg)
    if not auth.is_configured:
        print_error("Autenticação não configurada. Execute: ekp auth setup")
        raise typer.Exit(1)
    password = typer.prompt("Senha", hide_input=True)
    from ekprotection.auth.manager import AuthFailedError, AuthLockedError
    try:
        return auth.authenticate(password)
    except AuthLockedError as exc:
        print_error(f"Conta bloqueada. Aguarde {exc.retry_after:.0f}s.")
        raise typer.Exit(1)
    except AuthFailedError:
        print_error("Senha incorreta.")
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# ekp quarantine list
# ---------------------------------------------------------------------------

@quar_app.command("list")
def cmd_list(
    all_items:   bool          = typer.Option(False, "--all", "-a", help="Inclui restaurados e excluídos."),
    config:      Optional[str] = typer.Option(None, "--config", "-c"),
    json_output: bool          = typer.Option(False, "--json"),
) -> None:
    """Lista arquivos em quarentena."""
    entries = None

    # "--all" precisa do acesso direto (IPC só expõe os ativos). Sem
    # "--all", tenta o daemon primeiro pra funcionar sem sudo.
    if not all_items:
        cfg = ConfigManager(config)
        cfg.load()
        client = ipc_client(cfg)
        if client is not None:
            try:
                resp = client.send("quarantine_list")
                if resp.get("ok"):
                    entries = [_entry_from_ipc_dict(d) for d in resp["data"]]
            except ConnectionError:
                pass  # cai pro acesso direto abaixo

    if entries is None:
        cfg, mgr = _open_mgr(config)
        try:
            entries = mgr.list_all(limit=500) if all_items else mgr.list_active()
        finally:
            mgr.close()

    if json_output:
        import json
        console.print_json(json.dumps([e.to_dict() for e in entries]))
        return

    if not entries:
        print_info("Quarentena vazia." if not all_items else "Nenhum registro encontrado.")
        return

    table = Table(box=box.SIMPLE_HEAD, header_style="ekp.label", padding=(0, 1), expand=True)
    table.add_column("ID",       width=5,  no_wrap=True)
    table.add_column("Status",   width=10, no_wrap=True)
    table.add_column("Risco",    width=9,  no_wrap=True)
    table.add_column("Arquivo",  style="ekp.path")
    table.add_column("Ameaça",   width=20)
    table.add_column("Motivo",   width=16)
    table.add_column("Data",     width=16, style="ekp.muted", no_wrap=True)

    for e in entries:
        sc = _STATUS_COLOR.get(e.status.value, "white")
        rl = e.risk_level or "?"
        rc = _RISK_COLOR.get(rl, "white")
        fname = Path(e.original_path).name
        ts    = e.quarantined_at.strftime("%m-%d %H:%M")
        table.add_row(
            str(e.entry_id),
            f"[{sc}]{e.status.value}[/{sc}]",
            f"[{rc}]{rl}[/{rc}]",
            fname,
            e.threat_type or "—",
            e.reason.value.replace("_", " "),
            ts,
        )

    console.print(Panel(
        table,
        title=f"[ekp.brand]Quarentena — {len(entries)} item(ns)[/ekp.brand]",
        border_style="red" if any(e.status == QuarantineStatus.ACTIVE for e in entries) else "cyan",
    ))


# ---------------------------------------------------------------------------
# ekp quarantine info
# ---------------------------------------------------------------------------

@quar_app.command("info")
def cmd_info(
    entry_id:    int           = typer.Argument(..., help="ID do item (ver: ekp quarantine list)"),
    config:      Optional[str] = typer.Option(None, "--config", "-c"),
    json_output: bool          = typer.Option(False, "--json"),
) -> None:
    """Exibe detalhes completos de um item em quarentena."""
    cfg, mgr = _open_mgr(config)
    try:
        entry = mgr.get_by_id(entry_id)
    finally:
        mgr.close()

    if not entry:
        print_error(f"Item ID {entry_id} não encontrado.")
        raise typer.Exit(1)

    if json_output:
        import json
        console.print_json(json.dumps(entry.to_dict()))
        return

    sc = _STATUS_COLOR.get(entry.status.value, "white")
    rl = entry.risk_level or "?"
    rc = _RISK_COLOR.get(rl, "white")

    table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    table.add_column("Campo", style="ekp.label", width=22)
    table.add_column("Valor", style="ekp.value")

    table.add_row("Status",         f"[{sc}]{entry.status.value.upper()}[/{sc}]")
    table.add_row("Nível de risco", f"[{rc}]{rl.upper()}[/{rc}]")
    table.add_row("─" * 20,         "─" * 40)
    table.add_row("Arquivo original", f"[ekp.path]{entry.original_path}[/ekp.path]")
    table.add_row("SHA-256",          f"[ekp.hash]{entry.sha256}[/ekp.hash]")
    table.add_row("Tamanho",          f"{entry.file_size:,} bytes" if entry.file_size else "—")
    table.add_row("Tipo de ameaça",   entry.threat_type or "—")
    table.add_row("Motivo",           entry.reason.value.replace("_", " "))
    table.add_row("Processo",         entry.process_name or "—")
    table.add_row("─" * 20,           "─" * 40)
    table.add_row("ID quarentena",    f"[dim]{entry.quarantine_id}[/dim]")
    table.add_row("Quarentenado em",  entry.quarantined_at.strftime("%Y-%m-%d %H:%M:%S"))
    if entry.restored_at:
        table.add_row("Restaurado em", entry.restored_at.strftime("%Y-%m-%d %H:%M:%S"))
        table.add_row("Restaurado para", entry.restored_to or "—")
    if entry.comment:
        table.add_row("Comentário",    entry.comment)

    console.print(Panel(
        table,
        title=f"[ekp.danger]Quarentena — Item #{entry_id}[/ekp.danger]",
        border_style="red",
    ))


# ---------------------------------------------------------------------------
# ekp quarantine restore
# ---------------------------------------------------------------------------

@quar_app.command("restore")
def cmd_restore(
    entry_id:    int           = typer.Argument(..., help="ID do item a restaurar"),
    dest:        str           = typer.Option(".", "--dest", "-d", help="Diretório de destino"),
    config:      Optional[str] = typer.Option(None, "--config", "-c"),
) -> None:
    """
    Restaura arquivo da quarentena para o diretório especificado.
    Requer autenticação.
    """
    cfg, mgr = _open_mgr(config)

    entry = mgr.get_by_id(entry_id)
    if not entry:
        mgr.close()
        print_error(f"Item ID {entry_id} não encontrado.")
        raise typer.Exit(1)

    console.print()
    print_warning(f"Restaurar: [ekp.path]{entry.original_path}[/ekp.path]")
    print_warning(f"Para:      [ekp.path]{dest}[/ekp.path]")
    console.print()
    print_info("Esta operação requer autenticação.")

    token = _authenticate(cfg)

    try:
        restored = mgr.restore(entry.quarantine_id, dest_dir=dest, token=token)
        console.print()
        print_success(f"Arquivo restaurado: [ekp.path]{restored}[/ekp.path]")
        print_warning("Revise o arquivo antes de executá-lo.")
    except (QuarantineError, PermissionError) as exc:
        print_error(str(exc))
        raise typer.Exit(1)
    finally:
        mgr.close()


# ---------------------------------------------------------------------------
# ekp quarantine delete
# ---------------------------------------------------------------------------

@quar_app.command("delete")
def cmd_delete(
    entry_id:    int           = typer.Argument(..., help="ID do item a excluir"),
    force:       bool          = typer.Option(False, "--force", "-f"),
    config:      Optional[str] = typer.Option(None, "--config", "-c"),
) -> None:
    """
    Exclui arquivo da quarentena PERMANENTEMENTE.
    Esta operação é irreversível. Requer autenticação.
    """
    cfg, mgr = _open_mgr(config)

    entry = mgr.get_by_id(entry_id)
    if not entry:
        mgr.close()
        print_error(f"Item ID {entry_id} não encontrado.")
        raise typer.Exit(1)

    if not force:
        console.print()
        print_warning(f"ATENÇÃO: Esta ação é IRREVERSÍVEL.")
        print_warning(f"Arquivo: [ekp.path]{entry.original_path}[/ekp.path]")
        console.print()
        confirmed = typer.confirm("Confirma exclusão permanente?", default=False)
        if not confirmed:
            print_info("Cancelado.")
            mgr.close()
            raise typer.Exit(0)

    print_info("Autenticação necessária para exclusão permanente.")
    token = _authenticate(cfg)

    try:
        mgr.delete_permanently(entry.quarantine_id, token=token)
        print_success(f"Item #{entry_id} excluído permanentemente.")
    except (QuarantineError, PermissionError) as exc:
        print_error(str(exc))
        raise typer.Exit(1)
    finally:
        mgr.close()


# ---------------------------------------------------------------------------
# ekp quarantine stats
# ---------------------------------------------------------------------------

@quar_app.command("stats")
def cmd_stats(
    config:      Optional[str] = typer.Option(None, "--config", "-c"),
    json_output: bool          = typer.Option(False, "--json"),
) -> None:
    """Exibe estatísticas do vault de quarentena."""
    cfg, mgr = _open_mgr(config)
    try:
        s = mgr.stats()
    finally:
        mgr.close()

    if json_output:
        import json
        console.print_json(json.dumps(s))
        return

    table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    table.add_column("Campo", style="ekp.label", width=22)
    table.add_column("Valor", style="ekp.value")

    table.add_row("Ativos",          f"[red]{s['active']}[/red]")
    table.add_row("Restaurados",     f"[green]{s['restored']}[/green]")
    table.add_row("Total",           str(s['total']))
    size_kb = (s.get("total_bytes") or 0) // 1024
    table.add_row("Tamanho total",   f"{size_kb:,} KB")
    table.add_row("─" * 20,          "─" * 30)
    for reason, cnt in s.get("by_reason", {}).items():
        table.add_row(f"  {reason.replace('_',' ')}", str(cnt))

    console.print(Panel(
        table,
        title="[ekp.brand]Quarentena — Estatísticas[/ekp.brand]",
        border_style="cyan",
    ))


# ---------------------------------------------------------------------------
# ekp quarantine purge
# ---------------------------------------------------------------------------

@quar_app.command("purge")
def cmd_purge(
    force:  bool          = typer.Option(False, "--force", "-f"),
    config: Optional[str] = typer.Option(None, "--config", "-c"),
) -> None:
    """Remove registros antigos (restaurados/excluídos) conforme retenção configurada."""
    cfg, mgr = _open_mgr(config)
    days = cfg.get("quarantine.retention_days", 30)

    if not force:
        confirmed = typer.confirm(
            f"Remover registros antigos (>{days} dias, status: restaurado/excluído)?",
            default=False,
        )
        if not confirmed:
            print_info("Cancelado.")
            mgr.close()
            raise typer.Exit(0)

    try:
        removed = mgr.purge_old()
        if removed:
            print_success(f"{removed} registros removidos.")
        else:
            print_info("Nenhum registro para remover.")
    finally:
        mgr.close()

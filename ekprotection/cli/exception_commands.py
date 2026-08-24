"""
ekprotection.cli.exception_commands
=====================================
Comandos CLI para gerenciamento de exceções.

  ekp exceptions list           — Lista todas as exceções
  ekp exceptions add whitelist  — Adiciona à whitelist
  ekp exceptions add blacklist  — Adiciona à blacklist
  ekp exceptions remove         — Remove por ID
  ekp exceptions check          — Verifica se path/hash está listado
  ekp exceptions export         — Exporta para JSON
  ekp exceptions import         — Importa de JSON
  ekp exceptions status         — Estatísticas
"""

from __future__ import annotations

import os
from pathlib import Path
from typing  import Optional

import typer
from rich.panel import Panel
from rich.table import Table
from rich       import box

from ekprotection.config.manager      import ConfigManager
from ekprotection.exceptions.models   import ExceptionEntry, ExceptionKind, ExceptionTarget
from ekprotection.exceptions.manager  import ExceptionManager
from ._ipc_or_direct import ipc_client
from .display import console, print_success, print_error, print_warning, print_info

exc_app = typer.Typer(help="Gerenciar exceções (whitelist / blacklist)")
add_app = typer.Typer(help="Adicionar exceção")
exc_app.add_typer(add_app, name="add")

_KIND_COLOR = {
    "whitelist": "green",
    "blacklist": "red",
}
_TARGET_ICON = {
    "path":      "📁",
    "hash":      "🔑",
    "process":   "⚙",
    "extension": "📄",
}


def _open_mgr(config_path: str | None = None) -> tuple[ConfigManager, ExceptionManager]:
    cfg = ConfigManager(config_path)
    cfg.load()
    mgr = ExceptionManager(cfg)
    mgr.open()
    return cfg, mgr


def _entry_from_ipc_dict(d: dict) -> ExceptionEntry:
    """Reconstrói uma ExceptionEntry a partir do dict retornado pelo daemon via IPC."""
    from datetime import datetime
    return ExceptionEntry(
        entry_id=d.get("id"),
        kind=ExceptionKind(d["kind"]),
        target=ExceptionTarget(d["target"]),
        value=d["value"],
        comment=d.get("comment", ""),
        added_at=datetime.fromisoformat(d["added_at"]),
        added_by=d.get("added_by", "user"),
    )


# ---------------------------------------------------------------------------
# ekp exceptions list
# ---------------------------------------------------------------------------

@exc_app.command("list")
def cmd_list(
    kind:        Optional[str] = typer.Option(None, "--kind",   "-k", help="whitelist | blacklist"),
    target:      Optional[str] = typer.Option(None, "--target", "-t", help="path | hash | process | extension"),
    config:      Optional[str] = typer.Option(None, "--config", "-c"),
    json_output: bool          = typer.Option(False, "--json"),
) -> None:
    """Lista todas as exceções cadastradas."""
    cfg = ConfigManager(config)
    cfg.load()

    # Tenta o daemon via IPC primeiro (funciona sem sudo mesmo com o banco
    # pertencendo a root) — mesmo padrão já usado em `ekp logs tail/search`.
    client = ipc_client(cfg)
    if client is not None:
        try:
            resp = client.send("exceptions_list", kind=kind, target=target)
            if resp.get("ok"):
                entries = [_entry_from_ipc_dict(d) for d in resp["data"]]
                _render_list(entries, json_output)
                return
            print_error(resp.get("error", "Erro desconhecido no daemon."))
            raise typer.Exit(1)
        except ConnectionError:
            pass  # cai pro acesso direto abaixo

    cfg, mgr = _open_mgr(config)
    k = ExceptionKind(kind)     if kind   else None
    t = ExceptionTarget(target) if target else None
    try:
        entries = mgr.list_all(kind=k, target=t)
    finally:
        mgr.close()

    _render_list(entries, json_output)


def _render_list(entries: list[ExceptionEntry], json_output: bool) -> None:
    if json_output:
        import json
        console.print_json(json.dumps([e.to_dict() for e in entries]))
        return

    if not entries:
        print_info("Nenhuma exceção cadastrada.")
        return

    table = Table(box=box.SIMPLE_HEAD, header_style="ekp.label", padding=(0, 1), expand=True)
    table.add_column("ID",      width=5,  no_wrap=True)
    table.add_column("Tipo",    width=11, no_wrap=True)
    table.add_column("Alvo",    width=11, no_wrap=True)
    table.add_column("Valor",   style="ekp.path")
    table.add_column("Comentário", style="dim")
    table.add_column("Adicionado", width=19, style="ekp.muted", no_wrap=True)

    for e in entries:
        color  = _KIND_COLOR.get(e.kind.value, "white")
        icon   = _TARGET_ICON.get(e.target.value, "·")
        val    = e.value if len(e.value) <= 60 else e.value[:57] + "…"
        ts     = e.added_at.strftime("%Y-%m-%d %H:%M")
        table.add_row(
            str(e.entry_id),
            f"[{color}]{e.kind.value}[/{color}]",
            f"{icon} {e.target.value}",
            val,
            e.comment or "—",
            ts,
        )

    total = len(entries)
    console.print(Panel(
        table,
        title=f"[ekp.brand]Exceções — {total} registro{'s' if total != 1 else ''}[/ekp.brand]",
        border_style="cyan",
    ))


# ---------------------------------------------------------------------------
# ekp exceptions add whitelist / blacklist
# ---------------------------------------------------------------------------

def _add_entry(
    kind:    ExceptionKind,
    target:  ExceptionTarget,
    value:   str,
    comment: str,
    config:  Optional[str],
) -> None:
    cfg, mgr = _open_mgr(config)
    try:
        entry = {
            ExceptionTarget.PATH:      mgr.add_whitelist_path      if kind == ExceptionKind.WHITELIST else mgr.add_blacklist_path,
            ExceptionTarget.HASH:      mgr.add_whitelist_hash      if kind == ExceptionKind.WHITELIST else mgr.add_blacklist_hash,
            ExceptionTarget.PROCESS:   mgr.add_whitelist_process,
            ExceptionTarget.EXTENSION: mgr.add_whitelist_extension,
        }[target](value, comment)
        color = _KIND_COLOR[kind.value]
        icon  = _TARGET_ICON[target.value]
        print_success(
            f"[{color}]{kind.value}[/{color}] {icon} {target.value}: "
            f"[ekp.path]{value}[/ekp.path]  [dim](ID {entry.entry_id})[/dim]"
        )
    except ValueError as exc:
        print_error(str(exc))
        raise typer.Exit(1)
    except KeyError:
        print_error(f"Operação não suportada: {kind.value}/{target.value}")
        raise typer.Exit(1)
    finally:
        mgr.close()


@add_app.command("whitelist")
def cmd_add_whitelist(
    target:  str           = typer.Argument(..., help="path | hash | process | extension"),
    value:   str           = typer.Argument(..., help="Valor a adicionar"),
    comment: str           = typer.Option("", "--comment", "-m", help="Comentário opcional"),
    config:  Optional[str] = typer.Option(None, "--config", "-c"),
) -> None:
    """Adiciona à whitelist (confiável — ignora detecções)."""
    try:
        t = ExceptionTarget(target.lower())
    except ValueError:
        print_error(f"Alvo inválido: {target}. Use: path, hash, process, extension")
        raise typer.Exit(1)
    _add_entry(ExceptionKind.WHITELIST, t, value, comment, config)


@add_app.command("blacklist")
def cmd_add_blacklist(
    target:  str           = typer.Argument(..., help="path | hash"),
    value:   str           = typer.Argument(..., help="Valor a adicionar"),
    comment: str           = typer.Option("", "--comment", "-m", help="Comentário opcional"),
    config:  Optional[str] = typer.Option(None, "--config", "-c"),
) -> None:
    """Adiciona à blacklist (sempre suspeito — força alerta)."""
    try:
        t = ExceptionTarget(target.lower())
    except ValueError:
        print_error(f"Alvo inválido: {target}. Use: path, hash")
        raise typer.Exit(1)
    if t not in (ExceptionTarget.PATH, ExceptionTarget.HASH):
        print_error("Blacklist suporta apenas: path, hash")
        raise typer.Exit(1)
    _add_entry(ExceptionKind.BLACKLIST, t, value, comment, config)


# ---------------------------------------------------------------------------
# ekp exceptions remove
# ---------------------------------------------------------------------------

@exc_app.command("remove")
def cmd_remove(
    entry_id: int          = typer.Argument(..., help="ID da exceção (ver: ekp exceptions list)"),
    force:    bool         = typer.Option(False, "--force", "-f"),
    config:   Optional[str]= typer.Option(None, "--config", "-c"),
) -> None:
    """Remove uma exceção pelo ID."""
    cfg, mgr = _open_mgr(config)
    try:
        # Mostra o que vai ser removido
        entry = mgr._store.get_by_id(entry_id) if mgr._store else None
        if not entry:
            print_error(f"Exceção ID {entry_id} não encontrada.")
            raise typer.Exit(1)

        if not force:
            color = _KIND_COLOR.get(entry.kind.value, "white")
            console.print(
                f"  Remover [{color}]{entry.kind.value}[/{color}] "
                f"{entry.target.value}: [ekp.path]{entry.value}[/ekp.path]?"
            )
            confirmed = typer.confirm("Confirma?", default=False)
            if not confirmed:
                print_info("Cancelado.")
                raise typer.Exit(0)

        ok = mgr.remove(entry_id)
        if ok:
            print_success(f"Exceção ID {entry_id} removida.")
        else:
            print_error(f"Não foi possível remover ID {entry_id}.")
    finally:
        mgr.close()


# ---------------------------------------------------------------------------
# ekp exceptions check
# ---------------------------------------------------------------------------

@exc_app.command("check")
def cmd_check(
    path:    Optional[str] = typer.Option(None, "--path",    "-p", help="Caminho a verificar"),
    sha256:  Optional[str] = typer.Option(None, "--hash",    "-s", help="Hash SHA-256"),
    process: Optional[str] = typer.Option(None, "--process", "-P", help="Nome do processo"),
    ext:     Optional[str] = typer.Option(None, "--ext",     "-e", help="Extensão (ex: .iso)"),
    config:  Optional[str] = typer.Option(None, "--config",  "-c"),
) -> None:
    """
    Verifica se um item está em alguma lista de exceção.
    Útil para depurar por que um arquivo está sendo ignorado ou forçado.
    """
    if not any([path, sha256, process, ext]):
        print_error("Informe ao menos um argumento: --path, --hash, --process ou --ext")
        raise typer.Exit(1)

    cfg, mgr = _open_mgr(config)
    try:
        result = mgr.check(path=path, sha256=sha256, process=process, ext=ext)
    finally:
        mgr.close()

    console.print()
    if not result.hit:
        console.print("  [dim]·[/dim]  Nenhuma exceção encontrada para os parâmetros informados.")
        return

    color = _KIND_COLOR.get(result.kind.value if result.kind else "", "white")
    e     = result.entry

    table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    table.add_column("Campo", style="ekp.label", width=16)
    table.add_column("Valor")

    table.add_row("Resultado",   f"[{color}]✔ MATCH — {result.kind.value.upper()}[/{color}]")
    if e:
        table.add_row("ID",          str(e.entry_id))
        table.add_row("Alvo",        f"{_TARGET_ICON.get(e.target.value,'·')} {e.target.value}")
        table.add_row("Valor",       f"[ekp.path]{e.value}[/ekp.path]")
        table.add_row("Comentário",  e.comment or "—")
        table.add_row("Adicionado",  e.added_at.strftime("%Y-%m-%d %H:%M:%S"))
        table.add_row("Por",         e.added_by)

    console.print(Panel(
        table,
        title=f"[{color}]Exceção Encontrada[/{color}]",
        border_style=color,
    ))


# ---------------------------------------------------------------------------
# ekp exceptions export / import
# ---------------------------------------------------------------------------

@exc_app.command("export")
def cmd_export(
    output: str            = typer.Argument(..., help="Arquivo de saída (ex: /tmp/exceptions.json)"),
    config: Optional[str]  = typer.Option(None, "--config", "-c"),
) -> None:
    """Exporta todas as exceções para JSON."""
    cfg, mgr = _open_mgr(config)
    try:
        n = mgr.export_json(Path(output))
        print_success(f"{n} exceções exportadas para: {output}")
    finally:
        mgr.close()


@exc_app.command("import")
def cmd_import(
    src:       str           = typer.Argument(..., help="Arquivo JSON de origem"),
    overwrite: bool          = typer.Option(False, "--overwrite", "-o", help="Sobrescreve duplicatas"),
    config:    Optional[str] = typer.Option(None, "--config", "-c"),
) -> None:
    """Importa exceções de um arquivo JSON."""
    cfg, mgr = _open_mgr(config)
    try:
        added, ignored = mgr.import_json(Path(src), overwrite=overwrite)
        print_success(f"{added} exceções importadas. {ignored} ignoradas (duplicatas).")
    except Exception as exc:
        print_error(f"Erro na importação: {exc}")
        raise typer.Exit(1)
    finally:
        mgr.close()


# ---------------------------------------------------------------------------
# ekp exceptions status
# ---------------------------------------------------------------------------

@exc_app.command("status")
def cmd_status(
    config:      Optional[str] = typer.Option(None, "--config", "-c"),
    json_output: bool          = typer.Option(False, "--json"),
) -> None:
    """Exibe estatísticas das exceções cadastradas."""
    cfg, mgr = _open_mgr(config)
    try:
        s = mgr.status()
    finally:
        mgr.close()

    if json_output:
        import json
        console.print_json(json.dumps(s))
        return

    table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    table.add_column("Campo", style="ekp.label", width=16)
    table.add_column("Valor")

    table.add_row("Whitelist", f"[green]{s['whitelist']}[/green] entradas")
    table.add_row("Blacklist", f"[red]{s['blacklist']}[/red] entradas")
    table.add_row("Total",     str(s["total"]))

    console.print(Panel(
        table,
        title="[ekp.brand]Exceções — Status[/ekp.brand]",
        border_style="cyan",
    ))

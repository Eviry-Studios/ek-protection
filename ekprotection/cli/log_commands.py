"""
ekprotection.cli.log_commands
================================
Comandos CLI para visualização e exportação de logs.

  ekp logs tail     — Últimas N entradas (estilo tail)
  ekp logs search   — Busca com filtros
  ekp logs stats    — Estatísticas do banco de logs
  ekp logs export   — Exporta para JSON ou CSV
  ekp logs purge    — Remove entradas antigas
"""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer
from rich.panel import Panel
from rich.table import Table
from rich import box

from ekprotection.config.manager import ConfigManager
from ekprotection.logs.models import EventType, LogEntry, LogLevel, QueryFilter, build_query_filter
from ekprotection.logs.store import LogStore
from ._ipc_or_direct import ipc_client
from .display import console, print_success, print_error, print_warning, print_info

logs_app = typer.Typer(help="Visualizar e gerenciar logs do EK-Protection")

# Mapeamento de cor por nível
_LEVEL_COLOR = {
    "DEBUG":    "dim",
    "INFO":     "white",
    "WARNING":  "yellow",
    "ERROR":    "red",
    "CRITICAL": "bold white on red",
}

# Mapeamento de ícone por nível
_LEVEL_ICON = {
    "DEBUG":    "·",
    "INFO":     "ℹ",
    "WARNING":  "⚠",
    "ERROR":    "✖",
    "CRITICAL": "☠",
}


def _open_store_from_cfg(cfg: ConfigManager) -> LogStore:
    db_raw = cfg.get("logs.db_path", "/var/lib/ek-protection/ek-protection.db")
    data_dir = os.environ.get("EKP_DATA_DIR", "")
    if data_dir:
        db_raw = db_raw.replace("/var/lib/ek-protection", data_dir)

    store = LogStore(db_raw)
    store.open()
    return store


def _open_store(config_path: str | None = None) -> tuple[ConfigManager, LogStore]:
    cfg = ConfigManager(config_path)
    cfg.load()
    return cfg, _open_store_from_cfg(cfg)


def _entry_from_ipc_dict(d: dict):
    """Reconstrói um LogEntry a partir do dict retornado pelo daemon via IPC."""
    return LogEntry(
        entry_id=d.get("id"),
        timestamp=datetime.fromisoformat(d["timestamp"]),
        level=LogLevel(d["level"]),
        event_type=EventType(d["event_type"]),
        message=d["message"],
        source=d.get("source", "core"),
        pid=d.get("pid", 0),
        file_path=d.get("file_path"),
        sha256=d.get("sha256"),
        process=d.get("process"),
        extra=d.get("extra") or {},
    )


def _render_entries_table(entries: list, title: str = "Logs") -> None:
    """Renderiza entradas como tabela Rich."""
    if not entries:
        print_info("Nenhum registro encontrado.")
        return

    table = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="ekp.label",
        expand=True,
        padding=(0, 1),
    )
    table.add_column("ID",        style="dim",       width=6,  no_wrap=True)
    table.add_column("Timestamp", style="ekp.muted", width=19, no_wrap=True)
    table.add_column("Nível",     width=9,  no_wrap=True)
    table.add_column("Tipo",      style="cyan", width=18, no_wrap=True)
    table.add_column("Origem",    style="magenta", width=12, no_wrap=True)
    table.add_column("Mensagem",  style="white")

    for e in entries:
        lvl   = e.level.value
        color = _LEVEL_COLOR.get(lvl, "white")
        icon  = _LEVEL_ICON.get(lvl, "·")
        ts    = e.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        msg   = e.message[:80] + ("…" if len(e.message) > 80 else "")

        table.add_row(
            str(e.entry_id or ""),
            ts,
            f"[{color}]{icon} {lvl}[/{color}]",
            e.event_type.value,
            e.source,
            msg,
        )

    console.print(Panel(table, title=f"[ekp.brand]{title}[/ekp.brand]", border_style="cyan"))


# ---------------------------------------------------------------------------
# ekp logs tail
# ---------------------------------------------------------------------------

@logs_app.command("tail")
def cmd_logs_tail(
    n:      int            = typer.Option(20,   "--lines",  "-n",  help="Número de entradas."),
    level:  Optional[str]  = typer.Option(None, "--level",  "-l",  help="Filtro de nível (INFO, WARNING...)."),
    config: Optional[str]  = typer.Option(None, "--config", "-c"),
) -> None:
    """Exibe as últimas N entradas de log."""
    cfg = ConfigManager(config)
    cfg.load()

    # Sem filtro de nível, tenta o daemon via IPC primeiro (funciona sem
    # sudo mesmo com o banco pertencendo a root). Com filtro, ou se o
    # daemon não estiver rodando, cai pro acesso direto ao SQLite.
    if not level:
        client = ipc_client(cfg)
        if client is not None:
            try:
                resp = client.send("log_tail", n=n)
                if resp.get("ok"):
                    entries = [_entry_from_ipc_dict(d) for d in resp["data"]]
                    _render_entries_table(list(reversed(entries)), f"Últimos {n} registros")
                    return
            except ConnectionError:
                pass  # cai pro acesso direto abaixo

    store = _open_store_from_cfg(cfg)
    f = QueryFilter(
        level      = LogLevel.from_str(level) if level else None,
        limit      = n,
        order_desc = True,
    )

    try:
        entries = store.query(f)
        entries_sorted = list(reversed(entries))  # mais antigos no topo
        _render_entries_table(entries_sorted, f"Últimos {n} registros")
    finally:
        store.close()


# ---------------------------------------------------------------------------
# ekp logs search
# ---------------------------------------------------------------------------

@logs_app.command("search")
def cmd_logs_search(
    query:  Optional[str]  = typer.Option(None, "--query",  "-q", help="Busca no texto da mensagem."),
    level:  Optional[str]  = typer.Option(None, "--level",  "-l", help="Filtro de nível."),
    event:  Optional[str]  = typer.Option(None, "--event",  "-e", help="Tipo de evento (ex: threat.detected)."),
    since:  Optional[str]  = typer.Option(None, "--since",        help="Data inicial (YYYY-MM-DD ou YYYY-MM-DDTHH:MM:SS)."),
    until:  Optional[str]  = typer.Option(None, "--until",        help="Data final."),
    path:   Optional[str]  = typer.Option(None, "--path",   "-p", help="Filtro por caminho de arquivo."),
    limit:  int            = typer.Option(50,   "--limit",        help="Máximo de resultados."),
    config: Optional[str]  = typer.Option(None, "--config", "-c"),
) -> None:
    """Busca nos logs com filtros combinados."""

    def _fail(exc: ValueError) -> None:
        print_error(str(exc))
        raise typer.Exit(1)

    cfg = ConfigManager(config)
    cfg.load()

    # Tenta o daemon via IPC primeiro (funciona sem sudo mesmo com o banco
    # pertencendo a root); mesmo padrão já usado em `ekp logs tail`.
    client = ipc_client(cfg)
    if client is not None:
        try:
            resp = client.send(
                "log_search", query=query, level=level, event=event,
                since=since, until=until, path=path, limit=limit,
            )
            if resp.get("ok"):
                data    = resp["data"]
                entries = [_entry_from_ipc_dict(d) for d in data["entries"]]
                _render_entries_table(
                    list(reversed(entries)),
                    f"Resultados: {len(entries)} de {data['total']} registros",
                )
                return
            _fail(ValueError(resp.get("error", "Erro desconhecido no daemon.")))
        except ConnectionError:
            pass  # cai pro acesso direto abaixo

    store = _open_store_from_cfg(cfg)
    try:
        try:
            f = build_query_filter(
                query=query, level=level, event=event,
                since=since, until=until, path=path, limit=limit,
            )
        except ValueError as exc:
            _fail(exc)

        total = store.count(f)
        entries = store.query(f)
        _render_entries_table(
            list(reversed(entries)),
            f"Resultados: {len(entries)} de {total} registros",
        )
    finally:
        store.close()


# ---------------------------------------------------------------------------
# ekp logs stats
# ---------------------------------------------------------------------------

@logs_app.command("stats")
def cmd_logs_stats(
    config:      Optional[str] = typer.Option(None, "--config", "-c"),
    json_output: bool          = typer.Option(False, "--json"),
) -> None:
    """Exibe estatísticas do banco de logs."""
    cfg, store = _open_store(config)

    try:
        stats = store.stats()
    finally:
        store.close()

    if json_output:
        import json
        console.print_json(json.dumps(stats))
        return

    table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    table.add_column("Campo", style="ekp.label", width=24)
    table.add_column("Valor", style="ekp.value")

    table.add_row("Total de registros", str(stats["total_entries"]))
    table.add_row("Banco de dados",     stats["db_path"])
    size_kb = stats["db_size_bytes"] // 1024
    table.add_row("Tamanho do banco",   f"{size_kb} KB")
    table.add_row("Mais antigo",        stats.get("oldest") or "—")
    table.add_row("Mais recente",       stats.get("newest") or "—")

    table.add_row("─" * 22, "─" * 30)
    for level, cnt in sorted(stats.get("by_level", {}).items()):
        color = _LEVEL_COLOR.get(level, "white")
        icon  = _LEVEL_ICON.get(level, "·")
        table.add_row(
            f"  {level}",
            f"[{color}]{icon} {cnt}[/{color}]",
        )

    console.print(Panel(table, title="[ekp.brand]Logs — Estatísticas[/ekp.brand]", border_style="cyan"))


# ---------------------------------------------------------------------------
# ekp logs export
# ---------------------------------------------------------------------------

@logs_app.command("export")
def cmd_logs_export(
    output: str            = typer.Argument(..., help="Arquivo de saída (ex: /tmp/ekp-logs.json)."),
    fmt:    str            = typer.Option("json", "--format", "-f", help="Formato: json ou csv."),
    level:  Optional[str]  = typer.Option(None, "--level",  "-l"),
    since:  Optional[str]  = typer.Option(None, "--since"),
    config: Optional[str]  = typer.Option(None, "--config", "-c"),
) -> None:
    """Exporta logs para JSON ou CSV."""
    cfg, store = _open_store(config)

    dest = Path(output)

    f: Optional[QueryFilter] = None
    if level or since:
        from datetime import datetime as dt
        f = QueryFilter(
            level  = LogLevel.from_str(level) if level else None,
            since  = dt.strptime(since, "%Y-%m-%d") if since else None,
            limit  = 10 ** 6,
        )

    try:
        if fmt.lower() == "csv":
            count = store.export_csv(dest, f)
        else:
            count = store.export_json(dest, f)
        print_success(f"{count} registros exportados para: {dest}")
    except Exception as exc:
        print_error(f"Erro na exportação: {exc}")
        raise typer.Exit(1)
    finally:
        store.close()


# ---------------------------------------------------------------------------
# ekp logs purge
# ---------------------------------------------------------------------------

@logs_app.command("purge")
def cmd_logs_purge(
    days:   int            = typer.Option(90,    "--days",   "-d", help="Remover entradas mais antigas que N dias."),
    force:  bool           = typer.Option(False, "--force",  "-f", help="Pula confirmação."),
    config: Optional[str]  = typer.Option(None,  "--config", "-c"),
) -> None:
    """Remove registros de log mais antigos que N dias."""
    cfg, store = _open_store(config)

    if not force:
        confirmed = typer.confirm(
            f"Remover todos os logs com mais de {days} dias?", default=False
        )
        if not confirmed:
            print_info("Cancelado.")
            store.close()
            raise typer.Exit(0)

    try:
        removed = store.purge_old(days)
        if removed:
            print_success(f"{removed} registros removidos.")
        else:
            print_info("Nenhum registro para remover.")
    finally:
        store.close()

"""
ekprotection.cli.monitor_commands
===================================
Comandos CLI para o subsistema de monitoramento.

  ekp monitor status  — Estado atual do monitor
  ekp monitor paths   — Lista paths monitorados
  ekp monitor watch   — Live feed de eventos (debug/desenvolvimento)
"""

from __future__ import annotations

import asyncio
from typing import Optional

import typer
from rich.panel  import Panel
from rich.table  import Table
from rich        import box

from ekprotection.config.manager import ConfigManager
from ekprotection.monitor.events import FileEvent, FileEventKind, ProcessEvent, ProcEventKind
from .display import console, print_info, print_warning, print_error

monitor_app = typer.Typer(help="Gerenciar monitoramento em tempo real")

_KIND_ICON = {
    FileEventKind.CREATED:  ("➕", "green"),
    FileEventKind.MODIFIED: ("✎",  "yellow"),
    FileEventKind.DELETED:  ("✖",  "red"),
    FileEventKind.MOVED:    ("➜",  "cyan"),
    FileEventKind.EXECUTED: ("⚡", "bold red"),
}


@monitor_app.command("status")
def cmd_monitor_status(
    config:      Optional[str] = typer.Option(None, "--config", "-c"),
    json_output: bool          = typer.Option(False, "--json"),
) -> None:
    """Exibe status do subsistema de monitoramento."""
    cfg = ConfigManager(config)
    cfg.load()

    enabled   = cfg.get("monitor.enabled", True)
    paths     = cfg.get("monitor.paths", [])
    recursive = cfg.get("monitor.recursive", True)
    ignores   = cfg.get("monitor.ignore_patterns", [])

    if json_output:
        import json
        console.print_json(json.dumps({
            "enabled":  enabled,
            "paths":    paths,
            "recursive": recursive,
            "ignore_patterns": ignores,
        }))
        return

    table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    table.add_column("Campo", style="ekp.label", width=24)
    table.add_column("Valor", style="ekp.value")

    table.add_row(
        "Monitor ativo",
        "[green]Sim[/green]" if enabled else "[red]Não[/red]",
    )
    table.add_row("Paths configurados", str(len(paths)))
    table.add_row("Recursivo",          "[green]Sim[/green]" if recursive else "Não")
    table.add_row("Padrões ignorados",  str(len(ignores)))
    table.add_row("─" * 22, "─" * 30)
    table.add_row(
        "[dim]Nota[/dim]",
        "[dim]Status em tempo real disponível no Patch 9 (daemon IPC)[/dim]",
    )

    console.print(Panel(
        table,
        title="[ekp.brand]Monitor — Configuração[/ekp.brand]",
        border_style="cyan",
    ))


@monitor_app.command("paths")
def cmd_monitor_paths(
    config: Optional[str] = typer.Option(None, "--config", "-c"),
) -> None:
    """Lista os paths que serão monitorados."""
    cfg = ConfigManager(config)
    cfg.load()

    paths   = cfg.get("monitor.paths", [])
    ignores = cfg.get("monitor.ignore_patterns", [])

    import os
    table = Table(box=box.SIMPLE_HEAD, header_style="ekp.label", padding=(0, 1))
    table.add_column("Path",     style="ekp.path")
    table.add_column("Existe",   width=8)
    table.add_column("Acessível", width=10)

    for p in paths:
        exists     = os.path.exists(p)
        accessible = os.access(p, os.R_OK) if exists else False
        table.add_row(
            p,
            "[green]✔[/green]" if exists     else "[red]✖[/red]",
            "[green]✔[/green]" if accessible else "[red]✖[/red]",
        )

    console.print(Panel(table, title="[ekp.brand]Paths Monitorados[/ekp.brand]", border_style="cyan"))

    if ignores:
        console.print()
        console.print("[ekp.label]Padrões ignorados:[/ekp.label]")
        for ig in ignores:
            console.print(f"  [dim]• {ig}[/dim]")


@monitor_app.command("watch")
def cmd_monitor_watch(
    config:    Optional[str] = typer.Option(None, "--config", "-c"),
    duration:  int           = typer.Option(30, "--duration", "-d", help="Segundos de observação."),
    proc:      bool          = typer.Option(False, "--proc", "-p", help="Inclui eventos de processo."),
) -> None:
    """
    Observa eventos de filesystem em tempo real (modo desenvolvimento).
    Exibe eventos ao vivo por N segundos.
    """
    cfg = ConfigManager(config)
    cfg.load()

    paths     = cfg.get("monitor.paths", ["/tmp"])
    recursive = cfg.get("monitor.recursive", True)
    ignores   = cfg.get("monitor.ignore_patterns", [])

    print_info(f"Observando {len(paths)} paths por {duration}s... (Ctrl+C para parar)")
    console.print()

    async def _watch() -> None:
        import asyncio
        from ekprotection.monitor.fs_watcher   import FSWatcher
        from ekprotection.monitor.proc_watcher import ProcWatcher

        loop  = asyncio.get_running_loop()
        queue: asyncio.Queue = asyncio.Queue(maxsize=512)

        watcher = FSWatcher(paths, queue, loop, recursive, ignores)
        watcher.start()

        proc_task = None
        if proc:
            pw = ProcWatcher(queue, interval=2.0)
            proc_task = asyncio.create_task(pw.run())

        try:
            end = loop.time() + duration
            while loop.time() < end:
                try:
                    ev = await asyncio.wait_for(queue.get(), timeout=1.0)
                    _print_live_event(ev)
                    queue.task_done()
                except asyncio.TimeoutError:
                    pass
        except asyncio.CancelledError:
            pass
        finally:
            watcher.stop()
            if proc_task:
                proc_task.cancel()
                try:
                    await proc_task
                except asyncio.CancelledError:
                    pass

    try:
        asyncio.run(_watch())
    except KeyboardInterrupt:
        pass

    console.print()
    print_info("Observação encerrada.")


def _print_live_event(event: object) -> None:
    from ekprotection.monitor.events import FileEvent, ProcessEvent
    from datetime import datetime

    ts = datetime.utcnow().strftime("%H:%M:%S")

    if isinstance(event, FileEvent):
        icon, color = _KIND_ICON.get(event.kind, ("•", "white"))
        console.print(
            f"[dim]{ts}[/dim]  [{color}]{icon} {event.kind.name:<9}[/{color}]"
            f"  [ekp.path]{event.path}[/ekp.path]"
        )
    elif isinstance(event, ProcessEvent):
        if event.kind == ProcEventKind.SUSPICIOUS:
            console.print(
                f"[dim]{ts}[/dim]  [bold red]⚠ PROC_SUSP [/bold red]"
                f"  [ekp.pid]{event.pid}[/ekp.pid]  "
                f"[white]{event.name}[/white]  [dim]{event.reason}[/dim]"
            )
        elif event.kind == ProcEventKind.NEW:
            console.print(
                f"[dim]{ts}[/dim]  [green]+ PROC_NEW  [/green]"
                f"  [ekp.pid]{event.pid}[/ekp.pid]  [white]{event.name}[/white]"
            )

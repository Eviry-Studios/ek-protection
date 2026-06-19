"""
ekprotection.cli.scan_commands
================================
Comandos CLI para scan sob demanda.

  ekp scan file <path>   — Escaneia um arquivo específico
  ekp scan quick         — Scan rápido (paths configurados)
  ekp scan full          — Scan completo
  ekp scan paths <...>   — Escaneia paths específicos
  ekp scan signatures    — Info sobre o banco de assinaturas
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing  import Optional

import typer
from rich.panel    import Panel
from rich.table    import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich          import box

from ekprotection.config.manager   import ConfigManager
from ekprotection.scanner.engine   import ScanEngine
from ekprotection.scanner.result   import ScanVerdict, ScanReport
from ekprotection.scanner.signatures import SignatureDB
from .display import console, print_success, print_error, print_warning, print_info

scan_app = typer.Typer(help="Scanner de arquivos sob demanda")

_VERDICT_STYLE = {
    ScanVerdict.CLEAN:      ("✔", "green",   "LIMPO"),
    ScanVerdict.SUSPICIOUS: ("⚠", "yellow",  "SUSPEITO"),
    ScanVerdict.THREAT:     ("☠", "bold red", "AMEAÇA"),
    ScanVerdict.SKIPPED:    ("·", "dim",      "IGNORADO"),
    ScanVerdict.ERROR:      ("✖", "red",      "ERRO"),
}
_RISK_COLOR = {
    "baixo":   "green",
    "médio":   "yellow",
    "alto":    "red",
    "crítico": "bold white on red",
}


def _build_engine(config_path: str | None = None) -> tuple[ConfigManager, ScanEngine, SignatureDB]:
    cfg = ConfigManager(config_path)
    cfg.load()

    sig_raw  = cfg.get("signatures.db_path", "/var/lib/ek-protection/signatures.db")
    data_dir = os.environ.get("EKP_DATA_DIR", "")
    if data_dir:
        sig_raw = sig_raw.replace("/var/lib/ek-protection", data_dir)

    sig_db = SignatureDB(sig_raw)
    sig_db.open()

    # Tenta carregar ExceptionManager
    exc = None
    try:
        from ekprotection.exceptions.manager import ExceptionManager
        exc = ExceptionManager(cfg)
        exc.open()
    except Exception:
        pass

    engine = ScanEngine(cfg, sig_db=sig_db, exc_manager=exc)
    return cfg, engine, sig_db


def _print_file_result(result, verbose: bool = False) -> None:
    from ekprotection.scanner.result import FileScanResult
    icon, color, label = _VERDICT_STYLE.get(result.verdict, ("·", "white", "?"))
    fname = Path(result.path).name
    line  = f"  [{color}]{icon} {label:<10}[/{color}]  [ekp.path]{fname}[/ekp.path]"

    if result.is_threat:
        rl    = result.risk_level or "?"
        rc    = _RISK_COLOR.get(rl, "white")
        line += f"  [{rc}]{rl}[/{rc}]  [dim]{result.threat_name or ''}[/dim]"
    elif result.verdict == ScanVerdict.SKIPPED and verbose:
        line += f"  [dim]{result.reason or ''}[/dim]"
    elif result.verdict == ScanVerdict.ERROR:
        line += f"  [red]{result.error_msg or ''}[/red]"

    console.print(line)


def _print_report(report: ScanReport, verbose: bool = False) -> None:
    """Painel de sumário de scan."""
    threats = report.threats

    table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    table.add_column("Campo", style="ekp.label", width=22)
    table.add_column("Valor")

    dur = f"{report.duration_ms}ms" if report.duration_ms else "—"
    table.add_row("Tipo de scan",     report.scan_type)
    table.add_row("Arquivos total",   str(report.total_files))
    table.add_row("Escaneados",       str(report.scanned_files))
    table.add_row("Ignorados",        str(report.skipped_files))
    table.add_row("Erros",            str(report.errors))
    table.add_row("Duração",          dur)
    table.add_row("─" * 20,           "─" * 30)

    if threats:
        table.add_row(
            "Ameaças encontradas",
            f"[bold red]{len(threats)}[/bold red]"
        )
        for t in threats[:10]:
            rl   = t.risk_level or "?"
            rc   = _RISK_COLOR.get(rl, "white")
            name = Path(t.path).name
            table.add_row(
                f"  [{rc}]{rl}[/{rc}]",
                f"[ekp.path]{name}[/ekp.path]  [dim]{t.threat_name or ''}[/dim]"
            )
        if len(threats) > 10:
            table.add_row("  ...", f"[dim]+{len(threats)-10} mais[/dim]")
    else:
        table.add_row("Ameaças", "[green]Nenhuma detectada[/green]")

    border = "red" if threats else "green"
    console.print(Panel(
        table,
        title=f"[ekp.brand]Relatório de Scan — {report.scan_type.upper()}[/ekp.brand]",
        border_style=border,
    ))


# ---------------------------------------------------------------------------
# ekp scan file
# ---------------------------------------------------------------------------

@scan_app.command("file")
def cmd_scan_file(
    path:        str           = typer.Argument(..., help="Arquivo a escanear"),
    verbose:     bool          = typer.Option(False, "--verbose", "-v"),
    json_output: bool          = typer.Option(False, "--json"),
    config:      Optional[str] = typer.Option(None, "--config", "-c"),
) -> None:
    """Escaneia um arquivo específico e exibe relatório detalhado."""
    cfg, engine, sig_db = _build_engine(config)

    p = Path(path)
    if not p.exists():
        print_error(f"Arquivo não encontrado: {path}")
        raise typer.Exit(1)

    with console.status(f"[dim]Escaneando {p.name}...[/dim]"):
        result = engine.scan_file(path)

    sig_db.close()

    if json_output:
        import json
        console.print_json(json.dumps(result.to_dict()))
        return

    icon, color, label = _VERDICT_STYLE.get(result.verdict, ("·", "white", "?"))

    table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    table.add_column("Campo", style="ekp.label", width=22)
    table.add_column("Valor")

    table.add_row("Veredicto",   f"[{color}]{icon} {label}[/{color}]")
    if result.risk_level:
        rc = _RISK_COLOR.get(result.risk_level, "white")
        table.add_row("Nível de risco", f"[{rc}]{result.risk_level.upper()}[/{rc}]")
    table.add_row("Arquivo",     f"[ekp.path]{result.path}[/ekp.path]")
    if result.sha256:
        table.add_row("SHA-256",  f"[ekp.hash]{result.sha256}[/ekp.hash]")
    if result.file_size is not None:
        table.add_row("Tamanho",  f"{result.file_size:,} bytes")
    if result.threat_name:
        table.add_row("Ameaça",   f"[red]{result.threat_name}[/red]")
    if result.threat_type:
        table.add_row("Tipo",     result.threat_type)
    if result.reason:
        table.add_row("Motivo",   result.reason)
    if result.entropy is not None:
        table.add_row("Entropia", f"{result.entropy:.3f}")
    table.add_row("ELF",         "[dim]Sim[/dim]" if result.is_elf    else "[dim]Não[/dim]")
    table.add_row("Script",      "[dim]Sim[/dim]" if result.is_script else "[dim]Não[/dim]")
    if result.scan_ms:
        table.add_row("Tempo",   f"{result.scan_ms}ms")

    console.print(Panel(
        table,
        title=f"[{color}]Scan — {p.name}[/{color}]",
        border_style=color if result.is_threat else "cyan",
    ))

    if result.is_critical:
        console.print()
        print_warning("Ameaça crítica detectada! Considere quarentenar:")
        console.print(f"  [cyan]ekp quarantine list[/cyan]")

    raise typer.Exit(1 if result.is_threat else 0)


# ---------------------------------------------------------------------------
# ekp scan quick / full / paths
# ---------------------------------------------------------------------------

def _run_scan(
    report_fn,
    scan_label:  str,
    verbose:     bool,
    json_output: bool,
    config:      Optional[str],
    paths:       Optional[list[str]] = None,
) -> None:
    cfg, engine, sig_db = _build_engine(config)

    scanned_count = 0

    with Progress(
        SpinnerColumn(),
        TextColumn("[ekp.brand]Escaneando[/ekp.brand]"),
        BarColumn(),
        TaskProgressColumn(),
        TextColumn("[dim]{task.description}[/dim]"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("", total=None)

        def on_progress(fpath: str) -> None:
            nonlocal scanned_count
            scanned_count += 1
            progress.update(task, description=Path(fpath).name[:50])

        if paths:
            report = engine.scan_paths(paths, recursive=True, progress_cb=on_progress)
            report.scan_type = scan_label
        else:
            report = report_fn(progress_cb=on_progress)

    sig_db.close()

    if json_output:
        import json
        console.print_json(json.dumps(report.summary()))
        return

    console.print()

    # Mostra ameaças em destaque
    for r in report.threats:
        _print_file_result(r, verbose=True)
    if verbose and not report.threats:
        for r in report.results:
            if r.verdict not in (ScanVerdict.SKIPPED, ScanVerdict.CLEAN):
                _print_file_result(r, verbose=verbose)

    if report.threats:
        console.print()

    _print_report(report, verbose)

    if report.threats_found:
        raise typer.Exit(1)


@scan_app.command("quick")
def cmd_scan_quick(
    verbose:     bool          = typer.Option(False, "--verbose", "-v"),
    json_output: bool          = typer.Option(False, "--json"),
    config:      Optional[str] = typer.Option(None, "--config", "-c"),
) -> None:
    """Scan rápido dos paths configurados (scanner.quick_scan_paths)."""
    _, engine, _ = _build_engine(config)
    _run_scan(engine.scan_quick, "quick", verbose, json_output, config)


@scan_app.command("full")
def cmd_scan_full(
    verbose:     bool          = typer.Option(False, "--verbose", "-v"),
    json_output: bool          = typer.Option(False, "--json"),
    config:      Optional[str] = typer.Option(None, "--config", "-c"),
) -> None:
    """Scan completo de todos os paths monitorados."""
    _, engine, _ = _build_engine(config)
    _run_scan(engine.scan_full, "full", verbose, json_output, config)


@scan_app.command("paths")
def cmd_scan_paths(
    paths:       list[str]     = typer.Argument(..., help="Paths a escanear"),
    verbose:     bool          = typer.Option(False, "--verbose", "-v"),
    json_output: bool          = typer.Option(False, "--json"),
    config:      Optional[str] = typer.Option(None, "--config", "-c"),
) -> None:
    """Escaneia paths específicos (arquivos ou diretórios)."""
    _run_scan(None, "paths", verbose, json_output, config, paths=list(paths))


# ---------------------------------------------------------------------------
# ekp scan signatures
# ---------------------------------------------------------------------------

@scan_app.command("signatures")
def cmd_scan_signatures(
    config:      Optional[str] = typer.Option(None, "--config", "-c"),
    json_output: bool          = typer.Option(False, "--json"),
) -> None:
    """Exibe informações sobre o banco de assinaturas."""
    cfg, _, sig_db = _build_engine(config)

    meta  = sig_db.meta()
    count = sig_db.count()
    sig_db.close()

    if json_output:
        import json
        console.print_json(json.dumps({**meta, "count": count}))
        return

    table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    table.add_column("Campo", style="ekp.label", width=22)
    table.add_column("Valor")

    table.add_row("Assinaturas",  str(count))
    table.add_row("Versão",       meta.get("version", "—"))
    table.add_row("Atualizado",   meta.get("updated_at") or "nunca")

    console.print(Panel(
        table,
        title="[ekp.brand]Banco de Assinaturas[/ekp.brand]",
        border_style="cyan",
    ))
    print_info("Para atualizar: [cyan]ekp update signatures[/cyan]  (disponível no Patch 9)")

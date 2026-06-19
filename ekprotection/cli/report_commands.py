"""
ekprotection.cli.report_commands
===================================
Comandos CLI para geração de relatórios.

  ekp report html   — Gera relatório HTML
  ekp report json   — Gera relatório JSON
  ekp report txt    — Gera relatório em texto
"""

from __future__ import annotations

import os
from datetime import datetime
from pathlib  import Path
from typing   import Optional

import typer

from ekprotection.config.manager    import ConfigManager
from ekprotection.reports.generator import ReportGenerator
from .display import console, print_success, print_error, print_info

report_app = typer.Typer(help="Gerar relatórios de segurança exportáveis")


def _build_generator(config_path: str | None, hours: int) -> tuple[ConfigManager, ReportGenerator]:
    cfg = ConfigManager(config_path)
    cfg.load()

    data_dir = os.environ.get("EKP_DATA_DIR", "")

    # Tenta carregar subsistemas disponíveis
    log_mgr  = None
    quar_mgr = None
    exc_mgr  = None

    try:
        from ekprotection.logs.manager import LogManager
        db = cfg.get("logs.db_path", "/var/lib/ek-protection/ek-protection.db")
        if data_dir: db = db.replace("/var/lib/ek-protection", data_dir)
        cfg.set("logs.db_path", db)
        log_mgr = LogManager(cfg)
        log_mgr.open()
    except Exception:
        pass

    try:
        from ekprotection.quarantine.manager import QuarantineManager
        quar_mgr = QuarantineManager(cfg)
        quar_mgr.open()
    except Exception:
        pass

    try:
        from ekprotection.exceptions.manager import ExceptionManager
        exc_mgr = ExceptionManager(cfg)
        exc_mgr.open()
    except Exception:
        pass

    gen = ReportGenerator(cfg, log_mgr, quar_mgr, None, exc_mgr)
    return cfg, gen


def _auto_output(fmt: str) -> str:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"ekp-report-{ts}.{fmt}"


@report_app.command("html")
def cmd_report_html(
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Arquivo de saída"),
    hours:  int           = typer.Option(24, "--hours", "-h", help="Período em horas"),
    config: Optional[str] = typer.Option(None, "--config", "-c"),
) -> None:
    """Gera relatório HTML de segurança."""
    output = output or _auto_output("html")
    cfg, gen = _build_generator(config, hours)
    with console.status("[dim]Gerando relatório HTML...[/dim]"):
        out = gen.generate(output, fmt="html", since_hours=hours)
    print_success(f"Relatório HTML gerado: [ekp.path]{out}[/ekp.path]")


@report_app.command("json")
def cmd_report_json(
    output: Optional[str] = typer.Option(None, "--output", "-o"),
    hours:  int           = typer.Option(24, "--hours", "-h"),
    config: Optional[str] = typer.Option(None, "--config", "-c"),
) -> None:
    """Gera relatório JSON estruturado."""
    output = output or _auto_output("json")
    cfg, gen = _build_generator(config, hours)
    with console.status("[dim]Gerando relatório JSON...[/dim]"):
        out = gen.generate(output, fmt="json", since_hours=hours)
    print_success(f"Relatório JSON gerado: [ekp.path]{out}[/ekp.path]")


@report_app.command("txt")
def cmd_report_txt(
    output: Optional[str] = typer.Option(None, "--output", "-o"),
    hours:  int           = typer.Option(24, "--hours", "-h"),
    config: Optional[str] = typer.Option(None, "--config", "-c"),
) -> None:
    """Gera relatório em texto puro."""
    output = output or _auto_output("txt")
    cfg, gen = _build_generator(config, hours)
    with console.status("[dim]Gerando relatório TXT...[/dim]"):
        out = gen.generate(output, fmt="txt", since_hours=hours)
    print_success(f"Relatório TXT gerado: [ekp.path]{out}[/ekp.path]")
    # Exibe inline se for pequeno
    content = out.read_text()
    if len(content) < 3000:
        console.print()
        console.print(f"[dim]{content}[/dim]")

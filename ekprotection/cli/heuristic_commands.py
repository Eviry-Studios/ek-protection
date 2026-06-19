"""
ekprotection.cli.heuristic_commands
=====================================
Comandos CLI para o motor heurístico.

  ekp heuristics analyze <path>  — Análise heurística detalhada de um arquivo
  ekp heuristics rules           — Lista todas as regras disponíveis
  ekp heuristics status          — Estado do motor heurístico
"""

from __future__ import annotations

from pathlib import Path
from typing  import Optional

import typer
from rich.panel import Panel
from rich.table import Table
from rich       import box

from ekprotection.config.manager      import ConfigManager
from ekprotection.heuristics.engine   import HeuristicEngine
from ekprotection.heuristics.rules    import ALL_RULES, RULES_BY_ID
from .display import console, print_error, print_info, print_warning

heur_app = typer.Typer(help="Motor de detecção heurística")

_RISK_COLOR = {
    "crítico": "bold white on red",
    "alto":    "red",
    "médio":   "yellow",
    "baixo":   "green",
}
_SEV_COLOR = _RISK_COLOR


def _build_engine(config_path: str | None) -> tuple[ConfigManager, HeuristicEngine]:
    cfg  = ConfigManager(config_path)
    cfg.load()
    heur = HeuristicEngine(cfg)
    return cfg, heur


# ---------------------------------------------------------------------------
# ekp heuristics analyze
# ---------------------------------------------------------------------------

@heur_app.command("analyze")
def cmd_analyze(
    path:        str           = typer.Argument(..., help="Arquivo a analisar"),
    verbose:     bool          = typer.Option(False, "--verbose", "-v", help="Mostra evidências das regras"),
    json_output: bool          = typer.Option(False, "--json"),
    config:      Optional[str] = typer.Option(None, "--config", "-c"),
) -> None:
    """Executa análise heurística completa de um arquivo."""
    if not Path(path).exists():
        print_error(f"Arquivo não encontrado: {path}")
        raise typer.Exit(1)

    cfg, engine = _build_engine(config)

    with console.status(f"[dim]Analisando {Path(path).name} ({len(ALL_RULES)} regras)...[/dim]"):
        result = engine.analyze(path)

    if json_output:
        import json
        console.print_json(json.dumps(result.to_dict()))
        return

    # Cabeçalho de score
    risk  = result.risk_level or "limpo"
    color = _RISK_COLOR.get(risk, "green")

    score_bar = _make_score_bar(result.score)

    console.print()
    console.print(
        f"  [{color}]{'☠' if result.is_critical else '⚠' if result.is_suspicious else '✔'}  "
        f"{risk.upper()}[/{color}]  "
        f"Score: [{color}]{result.score:.1f}/100[/{color}]  "
        f"{score_bar}  "
        f"[dim]confiança {result.confidence*100:.0f}%  {result.analysis_ms}ms[/dim]"
    )
    console.print()

    # Tabela de contexto
    cs = result.context_summary
    ctx_table = Table(show_header=False, box=None, padding=(0, 2))
    ctx_table.add_column("", style="dim", width=14)
    ctx_table.add_column("")
    ctx_table.add_row("Arquivo",    f"[ekp.path]{path}[/ekp.path]")
    if cs.get("entropy") is not None:
        ctx_table.add_row("Entropia",  f"{cs['entropy']:.3f}")
    ctx_table.add_row("ELF",        "Sim" if cs.get("is_elf")        else "Não")
    ctx_table.add_row("Script",     "Sim" if cs.get("is_script")     else "Não")
    ctx_table.add_row("Executável", "Sim" if cs.get("is_executable") else "Não")
    if cs.get("file_size"):
        ctx_table.add_row("Tamanho",  f"{cs['file_size']:,} bytes")
    console.print(ctx_table)
    console.print()

    if not result.matches:
        console.print("  [green]✔[/green]  Nenhuma regra heurística disparada.")
        console.print()
        return

    # Tabela de regras que dispararam
    match_table = Table(
        box=box.SIMPLE_HEAD, header_style="ekp.label",
        padding=(0, 1), expand=True,
    )
    match_table.add_column("Regra",    width=6,  no_wrap=True)
    match_table.add_column("Severidade", width=10)
    match_table.add_column("Peso",     width=5,  no_wrap=True)
    match_table.add_column("Nome",     width=30)
    match_table.add_column("Detalhe")

    for m in result.matches:
        rule = RULES_BY_ID.get(m.rule_id)
        if not rule:
            continue
        sc = _SEV_COLOR.get(rule.severity, "white")
        match_table.add_row(
            f"[dim]{m.rule_id}[/dim]",
            f"[{sc}]{rule.severity}[/{sc}]",
            f"[dim]{rule.weight}[/dim]",
            rule.name,
            m.detail,
        )
        if verbose and m.evidence:
            console.print(f"    [dim]evidência:[/dim] [italic]{m.evidence[:100]}[/italic]")

    console.print(Panel(
        match_table,
        title=f"[{color}]Regras Disparadas — {len(result.matches)}/{len(ALL_RULES)}[/{color}]",
        border_style=color if result.is_suspicious else "cyan",
    ))

    if result.is_critical:
        console.print()
        print_warning("Ameaça crítica! Recomenda-se quarentenar:")
        console.print(f"  [cyan]ekp quarantine list[/cyan]")

    raise typer.Exit(1 if result.is_suspicious else 0)


# ---------------------------------------------------------------------------
# ekp heuristics rules
# ---------------------------------------------------------------------------

@heur_app.command("rules")
def cmd_rules(
    tag:         Optional[str] = typer.Option(None, "--tag", "-t", help="Filtrar por tag"),
    severity:    Optional[str] = typer.Option(None, "--severity", "-s", help="Filtrar por severidade"),
    json_output: bool          = typer.Option(False, "--json"),
) -> None:
    """Lista todas as regras heurísticas disponíveis."""
    rules = ALL_RULES
    if tag:
        rules = [r for r in rules if tag in r.tags]
    if severity:
        rules = [r for r in rules if r.severity == severity.lower()]

    if json_output:
        import json
        console.print_json(json.dumps([
            {"id": r.rule_id, "name": r.name, "severity": r.severity,
             "weight": r.weight, "tags": list(r.tags), "description": r.description}
            for r in rules
        ]))
        return

    table = Table(
        box=box.SIMPLE_HEAD, header_style="ekp.label",
        padding=(0, 1), expand=True,
    )
    table.add_column("ID",        width=6,  no_wrap=True)
    table.add_column("Severidade",width=10)
    table.add_column("Peso",      width=5,  no_wrap=True, justify="right")
    table.add_column("Nome",      width=30)
    table.add_column("Tags",      style="dim")

    for r in rules:
        sc = _SEV_COLOR.get(r.severity, "white")
        table.add_row(
            f"[dim]{r.rule_id}[/dim]",
            f"[{sc}]{r.severity}[/{sc}]",
            str(r.weight),
            r.name,
            ", ".join(r.tags),
        )

    console.print(Panel(
        table,
        title=f"[ekp.brand]Regras Heurísticas — {len(rules)}/{len(ALL_RULES)}[/ekp.brand]",
        border_style="cyan",
    ))


# ---------------------------------------------------------------------------
# ekp heuristics status
# ---------------------------------------------------------------------------

@heur_app.command("status")
def cmd_status(
    config:      Optional[str] = typer.Option(None, "--config", "-c"),
    json_output: bool          = typer.Option(False, "--json"),
) -> None:
    """Exibe configuração e status do motor heurístico."""
    cfg, engine = _build_engine(config)
    s = engine.status()

    if json_output:
        import json
        console.print_json(json.dumps(s))
        return

    table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    table.add_column("Campo", style="ekp.label", width=22)
    table.add_column("Valor")

    table.add_row("Habilitado",    "[green]Sim[/green]" if s["enabled"] else "[red]Não[/red]")
    table.add_row("Sensibilidade", s["sensitivity"])
    table.add_row("Regras total",  str(s["rules_total"]))
    table.add_row("Regras ativas", str(s["rules_active"]))
    table.add_row(
        "Regras desabilitadas",
        str(s["rules_total"] - s["rules_active"]) or "[dim]nenhuma[/dim]",
    )

    console.print(Panel(
        table,
        title="[ekp.brand]Heurísticas — Status[/ekp.brand]",
        border_style="cyan",
    ))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_score_bar(score: float, width: int = 20) -> str:
    """Barra de progresso visual para o score."""
    filled = int(score / 100 * width)
    empty  = width - filled
    if score >= 80:   color = "bold red"
    elif score >= 60: color = "red"
    elif score >= 40: color = "yellow"
    elif score >= 20: color = "green"
    else:             color = "dim"
    return f"[{color}]{'█' * filled}{'░' * empty}[/{color}]"

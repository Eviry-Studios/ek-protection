"""
ekprotection.cli.display
=========================
Componentes visuais Rich para o terminal do EK-Protection.

Centraliza todos os estilos, cores e layouts usados pela CLI,
garantindo identidade visual consistente em todo o projeto.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme
from rich import box

# ---------------------------------------------------------------------------
# Tema de cores EK-Protection
# ---------------------------------------------------------------------------

EKP_THEME = Theme({
    "ekp.title":    "bold white",
    "ekp.brand":    "bold cyan",
    "ekp.ok":       "bold green",
    "ekp.warn":     "bold yellow",
    "ekp.danger":   "bold red",
    "ekp.critical": "bold white on red",
    "ekp.info":     "dim white",
    "ekp.muted":    "dim",
    "ekp.path":     "cyan",
    "ekp.hash":     "dim cyan",
    "ekp.pid":      "magenta",
    "ekp.label":    "bold white",
    "ekp.value":    "white",
})

console = Console(theme=EKP_THEME)
err_console = Console(stderr=True, theme=EKP_THEME)

# ---------------------------------------------------------------------------
# Constantes visuais
# ---------------------------------------------------------------------------

BANNER = r"""
 ███████╗██╗  ██╗      ██████╗ ██████╗  ██████╗ ████████╗███████╗ ██████╗████████╗██╗ ██████╗ ███╗   ██╗
 ██╔════╝██║ ██╔╝      ██╔══██╗██╔══██╗██╔═══██╗╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██║██╔═══██╗████╗  ██║
 █████╗  █████╔╝ █████╗██████╔╝██████╔╝██║   ██║   ██║   █████╗  ██║        ██║   ██║██║   ██║██╔██╗ ██║
 ██╔══╝  ██╔═██╗ ╚════╝██╔═══╝ ██╔══██╗██║   ██║   ██║   ██╔══╝  ██║        ██║   ██║██║   ██║██║╚██╗██║
 ███████╗██║  ██╗      ██║     ██║  ██║╚██████╔╝   ██║   ███████╗╚██████╗   ██║   ██║╚██████╔╝██║ ╚████║
 ╚══════╝╚═╝  ╚═╝      ╚═╝     ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚══════╝ ╚═════╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
"""

BRAND_LINE = "[ekp.brand]EK-Protection[/ekp.brand] [ekp.muted]v0.1.0 — Terminal Antivirus Engine[/ekp.muted]"
SEPARATOR = "[ekp.muted]" + "─" * 70 + "[/ekp.muted]"


# ---------------------------------------------------------------------------
# Funções de apresentação
# ---------------------------------------------------------------------------

def print_banner() -> None:
    """Exibe o banner ASCII completo."""
    console.print(f"[ekp.brand]{BANNER}[/ekp.brand]")
    console.print(BRAND_LINE)
    console.print(SEPARATOR)
    console.print()


def print_status_panel(status: dict[str, Any]) -> None:
    """Painel de status do daemon."""
    state = status.get("state", "UNKNOWN")
    color = "ekp.ok" if state == "RUNNING" else "ekp.warn" if state == "STOPPED" else "ekp.danger"

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Label", style="ekp.label", width=20)
    table.add_column("Value", style="ekp.value")

    table.add_row("Estado", f"[{color}]{state}[/{color}]")
    table.add_row("PID", f"[ekp.pid]{status.get('pid', 'N/A')}[/ekp.pid]")
    table.add_row("Versão", status.get("version", "N/A"))
    table.add_row("Subsistemas", ", ".join(status.get("subsystems", [])) or "nenhum")
    table.add_row("Hora", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    console.print(Panel(table, title="[ekp.brand]EK-Protection — Status[/ekp.brand]", border_style="cyan"))


def print_alert(
    *,
    title: str,
    level: str,       # "info" | "warning" | "danger" | "critical"
    message: str,
    details: dict[str, Any] | None = None,
) -> None:
    """
    Exibe um alerta formatado no terminal.
    Usado pelo sistema de detecção de ameaças.
    """
    level_map = {
        "info":     ("ℹ", "ekp.info",     "blue"),
        "warning":  ("⚠", "ekp.warn",     "yellow"),
        "danger":   ("✖", "ekp.danger",   "red"),
        "critical": ("☠", "ekp.critical", "red"),
    }
    icon, style, border = level_map.get(level, ("•", "ekp.info", "blue"))

    lines = Text()
    lines.append(f"{icon}  {message}\n", style=style)

    if details:
        for k, v in details.items():
            lines.append(f"   {k:<20}", style="ekp.label")
            lines.append(f"{v}\n", style="ekp.value")

    console.print(Panel(lines, title=f"[{style}]{title}[/{style}]", border_style=border))


def print_success(message: str) -> None:
    console.print(f"[ekp.ok]✔[/ekp.ok]  {message}")


def print_warning(message: str) -> None:
    console.print(f"[ekp.warn]⚠[/ekp.warn]  {message}")


def print_error(message: str) -> None:
    err_console.print(f"[ekp.danger]✖[/ekp.danger]  {message}")


def print_info(message: str) -> None:
    console.print(f"[ekp.info]·[/ekp.info]  {message}")


def make_threat_report(
    *,
    process: str,
    pid: int,
    file_path: str,
    sha256: str,
    threat_type: str,
    reason: str,
    risk_level: str,
    recommendations: list[str],
) -> Panel:
    """
    Gera o painel de relatório detalhado de ameaça.
    Retorna um Panel Rich — o chamador decide se exibe imediatamente.
    """
    table = Table(show_header=False, box=box.SIMPLE, padding=(0, 1))
    table.add_column("Campo", style="ekp.label", width=24)
    table.add_column("Valor", style="ekp.value")

    risk_color = {
        "baixo":   "green",
        "médio":   "yellow",
        "alto":    "red",
        "crítico": "bold white on red",
    }.get(risk_level.lower(), "white")

    table.add_row("Processo",          process)
    table.add_row("PID",               f"[ekp.pid]{pid}[/ekp.pid]")
    table.add_row("Caminho",           f"[ekp.path]{file_path}[/ekp.path]")
    table.add_row("SHA-256",           f"[ekp.hash]{sha256}[/ekp.hash]")
    table.add_row("Tipo de ameaça",    threat_type)
    table.add_row("Motivo",            reason)
    table.add_row("Nível de risco",    f"[{risk_color}]{risk_level.upper()}[/{risk_color}]")
    table.add_row("─" * 22,            "─" * 40)

    rec_text = "\n".join(f"  • {r}" for r in recommendations)
    table.add_row("Ações recomendadas", rec_text)

    return Panel(
        table,
        title="[ekp.danger]☠  AMEAÇA DETECTADA[/ekp.danger]",
        border_style="red",
        subtitle=f"[ekp.muted]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/ekp.muted]",
    )

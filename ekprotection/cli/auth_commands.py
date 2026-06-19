"""
ekprotection.cli.auth_commands
================================
Comandos CLI para gerenciamento de autenticação.

Comandos:
  ekp auth setup    — Configura senha inicial (primeira execução)
  ekp auth verify   — Testa a senha atual
  ekp auth change   — Altera a senha
  ekp auth status   — Exibe status de autenticação
  ekp auth reset    — Remove hash (requer root + confirmação)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.panel import Panel
from rich.table import Table
from rich import box

from ekprotection.auth.manager import (
    AuthManager,
    AuthFailedError,
    AuthLockedError,
    AuthNotConfiguredError,
    AuthSessionExpiredError,
    WeakPasswordError,
)
from ekprotection.config.manager import ConfigManager
from .display import console, print_success, print_error, print_warning, print_info

auth_app = typer.Typer(help="Gerenciar autenticação do EK-Protection")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_auth(config_path: str | None = None) -> tuple[ConfigManager, AuthManager]:
    cfg = ConfigManager(config_path)
    cfg.load()
    auth = AuthManager(cfg)
    return cfg, auth


def _prompt_password(prompt: str = "Senha", confirm: bool = False) -> str:
    """Solicita senha de forma segura via terminal."""
    password = typer.prompt(prompt, hide_input=True)
    if confirm:
        confirm_pw = typer.prompt("Confirme a senha", hide_input=True)
        if password != confirm_pw:
            print_error("As senhas não coincidem.")
            raise typer.Exit(1)
    return password


def _print_password_requirements() -> None:
    """Exibe os requisitos de senha."""
    console.print(
        Panel(
            "[white]A senha deve conter:[/white]\n"
            "  • Mínimo [cyan]12 caracteres[/cyan]\n"
            "  • Letras [cyan]maiúsculas e minúsculas[/cyan]\n"
            "  • Pelo menos um [cyan]número[/cyan]\n"
            "  • Pelo menos um [cyan]símbolo especial[/cyan] (!@#$%^&*...)",
            title="[ekp.brand]Requisitos de Senha[/ekp.brand]",
            border_style="cyan",
        )
    )


# ---------------------------------------------------------------------------
# ekp auth setup
# ---------------------------------------------------------------------------

@auth_app.command("setup")
def cmd_auth_setup(
    config: Optional[str] = typer.Option(None, "--config", "-c"),
) -> None:
    """
    Configura a senha de autenticação (primeira execução).
    Deve ser executado antes de iniciar o daemon.
    """
    _, auth = _get_auth(config)

    if auth.is_configured:
        print_warning("Autenticação já configurada.")
        print_info("Para alterar a senha, use: [cyan]ekp auth change[/cyan]")
        raise typer.Exit(0)

    console.print()
    console.print("[ekp.brand]Configuração de Autenticação — EK-Protection[/ekp.brand]")
    console.print()
    _print_password_requirements()
    console.print()

    for attempt in range(3):
        try:
            password = _prompt_password("Nova senha", confirm=True)
            auth.setup(password)
            console.print()
            print_success("Senha configurada com sucesso!")
            print_info("Agora inicie o daemon com: [cyan]ekp start[/cyan]")
            return
        except WeakPasswordError as exc:
            console.print()
            print_error("Senha não atende aos requisitos:")
            for reason in exc.reasons:
                console.print(f"  [red]✖[/red]  {reason}")
            console.print()
            if attempt < 2:
                print_info("Tente novamente.")
            else:
                print_error("Número máximo de tentativas atingido.")
                raise typer.Exit(1)

    raise typer.Exit(1)


# ---------------------------------------------------------------------------
# ekp auth verify
# ---------------------------------------------------------------------------

@auth_app.command("verify")
def cmd_auth_verify(
    config: Optional[str] = typer.Option(None, "--config", "-c"),
) -> None:
    """
    Verifica se a senha atual está correta.
    Útil para testar antes de operações críticas.
    """
    _, auth = _get_auth(config)

    if not auth.is_configured:
        print_error("Autenticação não configurada. Execute: [cyan]ekp auth setup[/cyan]")
        raise typer.Exit(1)

    console.print()
    password = _prompt_password("Senha atual")

    try:
        token = auth.authenticate(password)
        console.print()
        print_success("Autenticação bem-sucedida!")
        print_info(f"Sessão válida por {auth.session_remaining() / 60:.0f} minutos.")
    except AuthLockedError as exc:
        console.print()
        print_error(f"Conta bloqueada. Aguarde {exc.retry_after:.0f} segundos.")
        raise typer.Exit(1)
    except AuthFailedError:
        console.print()
        print_error("Senha incorreta.")
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# ekp auth change
# ---------------------------------------------------------------------------

@auth_app.command("change")
def cmd_auth_change(
    config: Optional[str] = typer.Option(None, "--config", "-c"),
) -> None:
    """
    Altera a senha de autenticação.
    Requer autenticação com a senha atual.
    """
    _, auth = _get_auth(config)

    if not auth.is_configured:
        print_error("Autenticação não configurada. Execute: [cyan]ekp auth setup[/cyan]")
        raise typer.Exit(1)

    console.print()
    console.print("[ekp.brand]Alteração de Senha[/ekp.brand]")
    console.print()

    # Autentica com senha atual
    current_password = _prompt_password("Senha atual")
    try:
        token = auth.authenticate(current_password)
    except AuthLockedError as exc:
        console.print()
        print_error(f"Conta bloqueada. Aguarde {exc.retry_after:.0f} segundos.")
        raise typer.Exit(1)
    except AuthFailedError:
        console.print()
        print_error("Senha atual incorreta.")
        raise typer.Exit(1)

    console.print()
    _print_password_requirements()
    console.print()

    # Define nova senha
    for attempt in range(3):
        try:
            new_password = _prompt_password("Nova senha", confirm=True)
            auth.change_password(token, new_password)
            console.print()
            print_success("Senha alterada com sucesso!")
            print_info("Sua sessão foi encerrada. Faça login novamente.")
            return
        except WeakPasswordError as exc:
            console.print()
            print_error("Nova senha não atende aos requisitos:")
            for reason in exc.reasons:
                console.print(f"  [red]✖[/red]  {reason}")
            console.print()
            if attempt < 2:
                print_info("Tente novamente.")
            else:
                print_error("Número máximo de tentativas atingido.")
                raise typer.Exit(1)

    raise typer.Exit(1)


# ---------------------------------------------------------------------------
# ekp auth status
# ---------------------------------------------------------------------------

@auth_app.command("status")
def cmd_auth_status(
    config: Optional[str] = typer.Option(None, "--config", "-c"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """
    Exibe o status atual do sistema de autenticação.
    """
    _, auth = _get_auth(config)
    status = auth.status()

    if json_output:
        import json
        console.print_json(json.dumps(status))
        return

    table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    table.add_column("Campo", style="ekp.label", width=28)
    table.add_column("Valor", style="ekp.value")

    configured = status["configured"]
    table.add_row(
        "Senha configurada",
        "[green]Sim[/green]" if configured else "[red]Não[/red]"
    )

    session_active = status["session_active"]
    table.add_row(
        "Sessão ativa",
        "[green]Sim[/green]" if session_active else "[dim]Não[/dim]"
    )

    if session_active:
        remaining = status["session_remaining_seconds"]
        table.add_row("Sessão expira em", f"{remaining // 60:.0f}m {remaining % 60:.0f}s")

    locked = status["locked"]
    table.add_row(
        "Conta bloqueada",
        "[red]Sim[/red]" if locked else "[green]Não[/green]"
    )

    if locked:
        lr = status["lockout_remaining_seconds"]
        table.add_row("Bloqueio expira em", f"{lr:.0f}s")

    table.add_row("Arquivo de hash", f"[ekp.path]{status['hash_file']}[/ekp.path]")
    table.add_row("Tentativas falhas", str(status["failed_attempts"]))

    console.print(Panel(
        table,
        title="[ekp.brand]Autenticação — Status[/ekp.brand]",
        border_style="cyan",
    ))


# ---------------------------------------------------------------------------
# ekp auth reset
# ---------------------------------------------------------------------------

@auth_app.command("reset")
def cmd_auth_reset(
    config: Optional[str] = typer.Option(None, "--config", "-c"),
    force: bool = typer.Option(False, "--force", "-f", help="Pula confirmação interativa."),
) -> None:
    """
    Remove o hash de autenticação (reset completo).
    ATENÇÃO: Requer privilégios de root. Irreversível.
    """
    if os.geteuid() != 0:
        print_error("Esta operação requer privilégios de root (sudo).")
        raise typer.Exit(1)

    _, auth = _get_auth(config)

    if not auth.is_configured:
        print_warning("Autenticação não estava configurada.")
        raise typer.Exit(0)

    console.print()
    print_warning("Esta operação remove a senha do EK-Protection.")
    print_warning("Você precisará configurá-la novamente com [cyan]ekp auth setup[/cyan].")
    console.print()

    if not force:
        confirmed = typer.confirm("Confirma o reset da autenticação?", default=False)
        if not confirmed:
            print_info("Operação cancelada.")
            raise typer.Exit(0)

    try:
        auth._hash_file.unlink(missing_ok=True)
        print_success("Hash de autenticação removido.")
        print_info("Execute [cyan]ekp auth setup[/cyan] para configurar nova senha.")
    except OSError as exc:
        print_error(f"Erro ao remover arquivo: {exc}")
        raise typer.Exit(1)

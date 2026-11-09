"""
ekprotection.cli.canary_commands
==================================
Comandos CLI para arquivos-isca (``monitor.canary_paths``).

  ekp canary list            — Lista as iscas e os problemas de cada uma
  ekp canary add PATH        — Cria a isca (0600, conteúdo falso) e registra
  ekp canary remove PATH     — Tira do config (não apaga o arquivo)

Antes (2026-11-04 a 11-07) a isca era feita à mão: editar o YAML (que nasce
0644 no ``vim``, ver config_exposure_issues) e criar o arquivo, muitas vezes
como root 0600 na home do usuário, o que deixa a isca cega (ver
canary_issues). Depois de gravar, add/remove pedem ``reload`` ao daemon via
IPC (mesmo efeito de ``systemctl reload ek-protection``); sem daemon, só grava.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich import box
from rich.table import Table

from ekprotection.config.manager import ConfigManager
from ekprotection.monitor.canary import CANARY_KINDS, canary_issues, create_canary
from ._ipc_or_direct import ipc_client
from .display import console, print_error, print_info, print_success, print_warning

canary_app = typer.Typer(help="Gerenciar arquivos-isca (canary) de credencial/wallet")

_KEY = "monitor.canary_paths"


def _load(config_path: Optional[str]) -> ConfigManager:
    cfg = ConfigManager(config_path)
    cfg.load()
    return cfg


def _load_for_write(config_path: Optional[str]) -> ConfigManager:
    cfg = _load(config_path)
    if cfg.rejected:
        # save() gravaria os defaults por cima do arquivo do usuário.
        print_error(f"Config {cfg.config_path} foi recusada (adulterável); corrija as permissões antes.")
        raise typer.Exit(1)
    return cfg


def _reload_daemon(cfg: ConfigManager) -> None:
    client = ipc_client(cfg)
    if client is None:
        print_info("Daemon não está rodando; a lista nova vale no próximo start.")
        return
    try:
        resp = client.send("reload")
    except Exception as exc:
        print_warning(f"Daemon não recarregou ({exc}); rode `systemctl reload ek-protection`.")
        return
    data = resp.get("data") or {}
    if not resp.get("ok") or not data.get("applied"):
        print_warning(f"Daemon recusou o reload: {data.get('reason') or resp.get('error')}.")
        return
    c = data.get("canaries", {})
    print_success(f"Daemon recarregado: iscas +{len(c.get('added', []))} -{len(c.get('removed', []))}.")


def _same(a: str, b: str) -> bool:
    return Path(a).expanduser().resolve() == Path(b).expanduser().resolve()


@canary_app.command("list")
def cmd_list(
    config: Optional[str] = typer.Option(None, "--config", "-c"),
) -> None:
    """Lista as iscas configuradas e o que impede cada uma de alertar."""
    cfg = _load(config)
    paths = cfg.get(_KEY, []) or []
    if not paths:
        print_info("Nenhum arquivo-isca configurado (ekp canary add PATH).")
        return
    table = Table(box=box.SIMPLE)
    table.add_column("Isca")
    table.add_column("Estado")
    bad = 0
    for raw in paths:
        p = Path(raw).expanduser()
        if not p.is_file():
            state, bad = "[red]não existe (ignorada)[/red]", bad + 1
        else:
            issues = canary_issues(p)
            if issues:
                bad += 1
                state = "[yellow]" + "; ".join(issues) + "[/yellow]"
            else:
                state = f"[green]ok[/green] ({oct(p.stat().st_mode & 0o777)})"
        table.add_row(str(raw), state)
    console.print(table)
    if bad:
        raise typer.Exit(1)


@canary_app.command("add")
def cmd_add(
    path:     str           = typer.Argument(..., help="Caminho da isca (ex.: ~/.ssh/backup_prod.pem)"),
    kind:     str           = typer.Option("generic", "--kind", "-k", help=" | ".join(CANARY_KINDS)),
    existing: bool          = typer.Option(False, "--existing", help="Registra arquivo que já existe, sem criar"),
    force:    bool          = typer.Option(False, "--force", help="Aceita mesmo com problema (nome do ssh, ilegível)"),
    config:   Optional[str] = typer.Option(None, "--config", "-c"),
) -> None:
    """Cria a isca com conteúdo falso (0600, dona = dono do diretório) e registra no config."""
    if kind not in CANARY_KINDS:
        print_error(f"Tipo inválido: {kind} (use {', '.join(CANARY_KINDS)})")
        raise typer.Exit(2)
    p = Path(path).expanduser().absolute()
    cfg = _load_for_write(config)
    paths = list(cfg.get(_KEY, []) or [])
    if any(_same(x, str(p)) for x in paths):
        print_error(f"{p} já é isca.")
        raise typer.Exit(1)

    if existing:
        if not p.is_file():
            print_error(f"{p} não existe (sem --existing a isca é criada).")
            raise typer.Exit(1)
        issues = canary_issues(p)
    else:
        if p.exists() or p.is_symlink():
            print_error(f"{p} já existe; não sobrescrevo (use --existing pra registrar).")
            raise typer.Exit(1)
        if not p.parent.is_dir():
            print_error(f"Diretório {p.parent} não existe.")
            raise typer.Exit(1)
        # Só o nome dá pra checar antes de criar; dono/modo saem certos do create.
        issues = [i for i in canary_issues(p) if i.startswith("nome")]

    if issues and not force:
        for i in issues:
            print_error(i)
        raise typer.Exit(1)
    for i in issues:
        print_warning(i)

    if not existing:
        try:
            create_canary(p, kind)
        except OSError as exc:
            print_error(f"Não foi possível criar {p}: {exc}")
            raise typer.Exit(1)

    paths.append(str(p))
    cfg.set(_KEY, paths)
    cfg.save()
    print_success(f"Isca registrada: {p}")
    _reload_daemon(cfg)


@canary_app.command("remove")
def cmd_remove(
    path:   str           = typer.Argument(...),
    config: Optional[str] = typer.Option(None, "--config", "-c"),
) -> None:
    """Tira a isca do config. O arquivo fica (apague à mão se quiser)."""
    cfg = _load_for_write(config)
    paths = list(cfg.get(_KEY, []) or [])
    kept = [x for x in paths if not _same(x, path)]
    if len(kept) == len(paths):
        print_error(f"{path} não é isca.")
        raise typer.Exit(1)
    cfg.set(_KEY, kept)
    cfg.save()
    print_success(f"Isca removida do config: {path} (arquivo mantido).")
    _reload_daemon(cfg)

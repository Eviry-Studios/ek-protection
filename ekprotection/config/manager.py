"""
ekprotection.config.manager
============================
Gerenciador de configuração do EK-Protection.

Responsabilidades:
  - Carregar config do arquivo YAML (ou criar um padrão se ausente)
  - Mesclar com DEFAULT_CONFIG (deep merge)
  - Expor get/set de chaves em notação de ponto ("daemon.log_level")
  - Salvar alterações de volta ao YAML
  - Resolver caminhos respeitando a variável EKP_DATA_DIR
  - Recusar config adulterável por outro usuário (modelo StrictModes do sshd)
"""

from __future__ import annotations

import copy
import grp
import logging
import os
import pwd
import stat
from pathlib import Path
from typing import Any

import yaml

from .defaults import DEFAULT_CONFIG, DEFAULT_CONFIG_FILE, DEFAULT_CONFIG_DIR

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _deep_merge(base: dict, override: dict) -> dict:
    """
    Mescla `override` sobre `base` recursivamente.
    Valores de `override` prevalecem; chaves ausentes em `override`
    mantêm o valor de `base`.
    """
    result = copy.deepcopy(base)
    for key, value in override.items():
        if (
            key in result
            and isinstance(result[key], dict)
            and isinstance(value, dict)
        ):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _resolve_path(path: str) -> str:
    """
    Substitui prefixo /var/lib/ek-protection por EKP_DATA_DIR se definido.
    Permite que usuários não-root rodem o programa em diretório alternativo.
    """
    data_dir = os.environ.get("EKP_DATA_DIR", "")
    if data_dir and path.startswith("/var/lib/ek-protection"):
        path = path.replace("/var/lib/ek-protection", data_dir, 1)
    return path


# Config adulterável: quem consegue escrever no YAML controla o daemon (que
# roda como root). `plugins.enabled` + `plugins.dir` = código arbitrário
# importado como root; `exceptions.*` = whitelist do próprio malware;
# `monitor.enabled: false` = monitor desligado. Igual ao StrictModes do sshd,
# o arquivo é ignorado (vale o default) se outro usuário puder escrever nele
# ou trocar ele de lugar (dir pai gravável sem sticky bit).
# EKP_CONFIG_STRICT=0 desliga a recusa (só avisa). É variável de ambiente
# de propósito: a chave não pode morar no arquivo que ela protege.
_STRICT_ENV = "EKP_CONFIG_STRICT"


def _trusted_uid(uid: int) -> bool:
    return uid == 0 or uid == os.geteuid()


def _private_group(gid: int, owner_uid: int) -> bool:
    """
    Grupo só do dono (esquema user-private-group do Debian/Ubuntu, umask
    002): escrita de grupo aí não abre nada pra outro usuário. Mesma
    exceção do patch `user-group-modes` do OpenSSH no Debian.
    """
    try:
        owner = pwd.getpwuid(owner_uid).pw_name
        g = grp.getgrgid(gid)
    except KeyError:
        return False
    if any(m != owner for m in g.gr_mem):
        return False
    return all(pw.pw_uid == owner_uid for pw in pwd.getpwall() if pw.pw_gid == gid)


def _writable_by_others(st: os.stat_result) -> bool:
    mode = stat.S_IMODE(st.st_mode)
    if mode & stat.S_IWOTH:
        return True
    return bool(mode & stat.S_IWGRP) and not _private_group(st.st_gid, st.st_uid)


def config_permission_issues(path: Path) -> list[str]:
    """
    Problemas de permissão que deixam outro usuário adulterar `path`.
    Lista vazia = ok (ou arquivo inexistente).
    """
    issues: list[str] = []
    try:
        st = path.stat()
    except OSError:
        return issues
    mode = stat.S_IMODE(st.st_mode)
    if not _trusted_uid(st.st_uid):
        issues.append(f"{path} pertence ao uid {st.st_uid} (esperado root ou {os.geteuid()})")
    if _writable_by_others(st):
        issues.append(f"{path} gravável por grupo/outros (modo {mode:04o})")
    try:
        pst = path.resolve().parent.stat()
    except OSError:
        return issues
    pmode = stat.S_IMODE(pst.st_mode)
    parent = path.resolve().parent
    if not _trusted_uid(pst.st_uid):
        issues.append(f"dir {parent} pertence ao uid {pst.st_uid} (arquivo pode ser trocado)")
    if _writable_by_others(pst) and not pmode & stat.S_ISVTX:
        issues.append(f"dir {parent} gravável por grupo/outros sem sticky bit (modo {pmode:04o})")
    return issues


# ---------------------------------------------------------------------------
# ConfigManager
# ---------------------------------------------------------------------------

class ConfigManager:
    """
    Singleton leve para gerenciar a configuração do EK-Protection.

    Uso:
        cfg = ConfigManager()
        cfg.load()
        value = cfg.get("daemon.log_level")
        cfg.set("daemon.log_level", "DEBUG")
        cfg.save()
    """

    def __init__(self, config_path: str | Path | None = None) -> None:
        self._config_path = Path(
            config_path
            or os.environ.get("EKP_CONFIG", DEFAULT_CONFIG_FILE)
        )
        self._data: dict[str, Any] = {}
        self._loaded = False
        self.permission_issues: list[str] = []
        self.rejected = False

    # ------------------------------------------------------------------
    # Propriedades
    # ------------------------------------------------------------------

    @property
    def config_path(self) -> Path:
        return self._config_path

    @property
    def data(self) -> dict[str, Any]:
        if not self._loaded:
            raise RuntimeError("ConfigManager.load() não foi chamado ainda.")
        return self._data

    # ------------------------------------------------------------------
    # Carregamento
    # ------------------------------------------------------------------

    def load(self) -> "ConfigManager":
        """
        Carrega o YAML de configuração e mescla com os defaults.
        Se o arquivo não existir, usa apenas os defaults (não cria arquivo
        automaticamente — isso é feito por `initialize()`).
        """
        base = copy.deepcopy(DEFAULT_CONFIG)
        self.permission_issues = config_permission_issues(self._config_path)
        self.rejected = False

        if self.permission_issues:
            strict = os.environ.get(_STRICT_ENV, "1") != "0"
            for issue in self.permission_issues:
                logger.critical("Config adulterável: %s", issue)
            if strict:
                logger.critical(
                    "Config %s IGNORADA, usando defaults (corrija com "
                    "`chown root: %s && chmod 600 %s`; %s=0 desliga a recusa).",
                    self._config_path, self._config_path, self._config_path, _STRICT_ENV,
                )
                self.rejected = True
                self._data = base
                self._loaded = True
                return self

        if self._config_path.exists():
            try:
                with self._config_path.open("r", encoding="utf-8") as fh:
                    user_cfg = yaml.safe_load(fh) or {}
                self._data = _deep_merge(base, user_cfg)
                logger.debug("Configuração carregada de %s", self._config_path)
            except yaml.YAMLError as exc:
                logger.error("Erro ao parsear YAML: %s — usando defaults.", exc)
                self._data = base
            except PermissionError:
                logger.warning(
                    "Sem permissão pra ler %s (config 600 root?). Usando defaults.",
                    self._config_path,
                )
                self._data = base
        else:
            logger.warning(
                "Arquivo de configuração não encontrado em %s. Usando defaults.",
                self._config_path,
            )
            self._data = base

        self._loaded = True
        return self

    # ------------------------------------------------------------------
    # Acesso por chave em notação de ponto
    # ------------------------------------------------------------------

    def get(self, key: str, default: Any = None) -> Any:
        """
        Retorna valor pela chave em notação de ponto.
        Ex: cfg.get("daemon.log_level") → "INFO"
        """
        if not self._loaded:
            raise RuntimeError("ConfigManager.load() não foi chamado ainda.")
        parts = key.split(".")
        node: Any = self._data
        for part in parts:
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def set(self, key: str, value: Any) -> None:
        """
        Define valor pela chave em notação de ponto.
        Cria chaves intermediárias se necessário.
        """
        parts = key.split(".")
        node = self._data
        for part in parts[:-1]:
            if part not in node or not isinstance(node[part], dict):
                node[part] = {}
            node = node[part]
        node[parts[-1]] = value

    # ------------------------------------------------------------------
    # Persistência
    # ------------------------------------------------------------------

    def save(self) -> None:
        """
        Grava a configuração atual de volta ao arquivo YAML.

        Escrita atômica (tmp + rename). Arquivo novo nasce 0600: a config
        lista os arquivos-isca (`monitor.canary_paths`) e as exceções, e
        quem lê isso sabe o que evitar. Arquivo existente mantém o modo,
        menos escrita de grupo/outros.
        """
        self._config_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            mode = stat.S_IMODE(self._config_path.stat().st_mode) & ~0o022
        except FileNotFoundError:
            mode = 0o600
        tmp = self._config_path.with_name(f".{self._config_path.name}.{os.getpid()}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                os.fchmod(fh.fileno(), mode)
                yaml.dump(
                    self._data,
                    fh,
                    default_flow_style=False,
                    allow_unicode=True,
                    sort_keys=True,
                )
            os.replace(tmp, self._config_path)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
        logger.info("Configuração salva em %s", self._config_path)

    # ------------------------------------------------------------------
    # Inicialização (primeira execução)
    # ------------------------------------------------------------------

    def initialize(self, force: bool = False) -> bool:
        """
        Cria o arquivo de configuração padrão e os diretórios necessários.
        Retorna True se criou, False se já existia (e force=False).
        """
        if self._config_path.exists() and not force:
            return False

        self._data = copy.deepcopy(DEFAULT_CONFIG)
        self._loaded = True

        # Cria diretórios necessários
        dirs_to_create = [
            self.get("logs.dir"),
            self.get("quarantine.dir"),
            Path(self.get("logs.db_path")).parent,
            Path(self.get("daemon.socket_path")).parent,
        ]
        for d in dirs_to_create:
            if d:
                try:
                    Path(_resolve_path(str(d))).mkdir(parents=True, exist_ok=True)
                except PermissionError:
                    logger.warning("Sem permissão para criar diretório: %s", d)

        self.save()
        logger.info("Configuração inicializada em %s", self._config_path)
        return True

    # ------------------------------------------------------------------
    # Utilitários
    # ------------------------------------------------------------------

    def resolve_path(self, key: str) -> Path:
        """Retorna um Path resolvido para a chave dada."""
        raw = self.get(key, "")
        return Path(_resolve_path(str(raw)))

    def to_dict(self) -> dict[str, Any]:
        """Retorna cópia do dicionário de configuração."""
        return copy.deepcopy(self._data)

    def __repr__(self) -> str:
        return f"ConfigManager(path={self._config_path}, loaded={self._loaded})"

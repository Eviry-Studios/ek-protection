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
"""

from __future__ import annotations

import copy
import logging
import os
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

        if self._config_path.exists():
            try:
                with self._config_path.open("r", encoding="utf-8") as fh:
                    user_cfg = yaml.safe_load(fh) or {}
                self._data = _deep_merge(base, user_cfg)
                logger.debug("Configuração carregada de %s", self._config_path)
            except yaml.YAMLError as exc:
                logger.error("Erro ao parsear YAML: %s — usando defaults.", exc)
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
        """Grava a configuração atual de volta ao arquivo YAML."""
        self._config_path.parent.mkdir(parents=True, exist_ok=True)
        with self._config_path.open("w", encoding="utf-8") as fh:
            yaml.dump(
                self._data,
                fh,
                default_flow_style=False,
                allow_unicode=True,
                sort_keys=True,
            )
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

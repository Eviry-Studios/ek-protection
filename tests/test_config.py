"""
tests/test_config.py
=====================
Testes do sistema de configuração do EK-Protection.

Cobre:
  - Carregamento com defaults quando não há arquivo
  - Deep merge correto de configuração do usuário
  - Acesso por notação de ponto (get/set)
  - Inicialização de diretórios
  - Persistência (save/load round-trip)
"""

from __future__ import annotations

import copy
import tempfile
from pathlib import Path

import pytest
import yaml

from ekprotection.config.manager import ConfigManager, _deep_merge
from ekprotection.config.defaults import DEFAULT_CONFIG


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_config(tmp_path: Path) -> Path:
    """Retorna um caminho para config temporária inexistente."""
    return tmp_path / "config.yaml"


@pytest.fixture
def cfg(tmp_config: Path) -> ConfigManager:
    """ConfigManager carregado com defaults (sem arquivo)."""
    manager = ConfigManager(tmp_config)
    manager.load()
    return manager


# ---------------------------------------------------------------------------
# Testes: _deep_merge
# ---------------------------------------------------------------------------

class TestDeepMerge:
    def test_simple_override(self) -> None:
        base = {"a": 1, "b": 2}
        override = {"b": 99}
        result = _deep_merge(base, override)
        assert result == {"a": 1, "b": 99}

    def test_nested_merge(self) -> None:
        base = {"daemon": {"log_level": "INFO", "silent_mode": False}}
        override = {"daemon": {"log_level": "DEBUG"}}
        result = _deep_merge(base, override)
        assert result["daemon"]["log_level"] == "DEBUG"
        assert result["daemon"]["silent_mode"] is False  # preservado

    def test_does_not_mutate_base(self) -> None:
        base = {"a": {"b": 1}}
        original_base = copy.deepcopy(base)
        _deep_merge(base, {"a": {"b": 2}})
        assert base == original_base

    def test_adds_new_keys(self) -> None:
        base = {"a": 1}
        override = {"b": 2}
        result = _deep_merge(base, override)
        assert result == {"a": 1, "b": 2}


# ---------------------------------------------------------------------------
# Testes: carregamento
# ---------------------------------------------------------------------------

class TestConfigLoading:
    def test_loads_defaults_when_no_file(self, tmp_config: Path) -> None:
        cfg = ConfigManager(tmp_config)
        cfg.load()
        assert cfg.get("daemon.log_level") == "INFO"

    def test_loads_from_yaml(self, tmp_config: Path) -> None:
        # Cria arquivo com override
        tmp_config.parent.mkdir(parents=True, exist_ok=True)
        tmp_config.write_text(
            yaml.dump({"daemon": {"log_level": "DEBUG"}}),
            encoding="utf-8",
        )
        cfg = ConfigManager(tmp_config)
        cfg.load()
        assert cfg.get("daemon.log_level") == "DEBUG"

    def test_merges_user_config_with_defaults(self, tmp_config: Path) -> None:
        tmp_config.parent.mkdir(parents=True, exist_ok=True)
        tmp_config.write_text(
            yaml.dump({"daemon": {"log_level": "DEBUG"}}),
            encoding="utf-8",
        )
        cfg = ConfigManager(tmp_config)
        cfg.load()
        # Override aplicado
        assert cfg.get("daemon.log_level") == "DEBUG"
        # Default preservado para chave não sobrescrita
        assert cfg.get("daemon.silent_mode") is False

    def test_raises_on_get_before_load(self, tmp_config: Path) -> None:
        cfg = ConfigManager(tmp_config)
        with pytest.raises(RuntimeError, match="load\\(\\)"):
            cfg.get("daemon.log_level")


# ---------------------------------------------------------------------------
# Testes: get/set
# ---------------------------------------------------------------------------

class TestGetSet:
    def test_get_simple_key(self, cfg: ConfigManager) -> None:
        assert cfg.get("daemon.log_level") == "INFO"

    def test_get_nested_key(self, cfg: ConfigManager) -> None:
        assert cfg.get("scanner.threads") == 4

    def test_get_returns_default_for_missing_key(self, cfg: ConfigManager) -> None:
        assert cfg.get("nonexistent.key", "fallback") == "fallback"

    def test_get_returns_none_for_missing_key_no_default(self, cfg: ConfigManager) -> None:
        assert cfg.get("nonexistent.key") is None

    def test_set_simple_key(self, cfg: ConfigManager) -> None:
        cfg.set("daemon.log_level", "DEBUG")
        assert cfg.get("daemon.log_level") == "DEBUG"

    def test_set_new_nested_key(self, cfg: ConfigManager) -> None:
        cfg.set("custom.new.key", 42)
        assert cfg.get("custom.new.key") == 42

    def test_set_list_value(self, cfg: ConfigManager) -> None:
        cfg.set("exceptions.paths", ["/tmp", "/home/user"])
        assert cfg.get("exceptions.paths") == ["/tmp", "/home/user"]


# ---------------------------------------------------------------------------
# Testes: persistência
# ---------------------------------------------------------------------------

class TestPersistence:
    def test_save_and_reload(self, tmp_config: Path) -> None:
        tmp_config.parent.mkdir(parents=True, exist_ok=True)
        cfg = ConfigManager(tmp_config)
        cfg.load()
        cfg.set("daemon.log_level", "WARNING")
        cfg.save()

        # Recarrega em nova instância
        cfg2 = ConfigManager(tmp_config)
        cfg2.load()
        assert cfg2.get("daemon.log_level") == "WARNING"

    def test_save_creates_parent_dirs(self, tmp_path: Path) -> None:
        nested_path = tmp_path / "deep" / "nested" / "config.yaml"
        cfg = ConfigManager(nested_path)
        cfg.load()
        cfg.save()
        assert nested_path.exists()


# ---------------------------------------------------------------------------
# Testes: inicialização
# ---------------------------------------------------------------------------

class TestInitialize:
    def test_initialize_creates_config(self, tmp_config: Path) -> None:
        tmp_config.parent.mkdir(parents=True, exist_ok=True)
        cfg = ConfigManager(tmp_config)
        created = cfg.initialize()
        assert created is True
        assert tmp_config.exists()

    def test_initialize_returns_false_if_exists(self, tmp_config: Path) -> None:
        tmp_config.parent.mkdir(parents=True, exist_ok=True)
        cfg = ConfigManager(tmp_config)
        cfg.initialize()
        # Segunda chamada sem force
        created = cfg.initialize()
        assert created is False

    def test_initialize_force_overwrites(self, tmp_config: Path) -> None:
        tmp_config.parent.mkdir(parents=True, exist_ok=True)
        cfg = ConfigManager(tmp_config)
        cfg.initialize()
        cfg.set("daemon.log_level", "DEBUG")
        cfg.save()

        # Force deve resetar para defaults
        cfg2 = ConfigManager(tmp_config)
        cfg2.initialize(force=True)

        cfg3 = ConfigManager(tmp_config)
        cfg3.load()
        assert cfg3.get("daemon.log_level") == "INFO"

    def test_to_dict_returns_copy(self, cfg: ConfigManager) -> None:
        d = cfg.to_dict()
        d["daemon"]["log_level"] = "MODIFIED"
        assert cfg.get("daemon.log_level") == "INFO"  # original não modificado

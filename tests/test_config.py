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


# ---------------------------------------------------------------------------
# Permissões: config adulterável (StrictModes)
# ---------------------------------------------------------------------------

import logging
import os
import stat

from ekprotection.config.manager import config_permission_issues

_EVIL = "plugins:\n  enabled: true\n  dir: /tmp/evil-plugins\n"


@pytest.fixture
def evil_config(tmp_path: Path) -> Path:
    d = tmp_path / "etc"
    d.mkdir(mode=0o755)
    p = d / "config.yaml"
    p.write_text(_EVIL)
    os.chmod(p, 0o644)
    yield p
    os.chmod(d, 0o755)


class TestConfigPermissions:
    def test_safe_config_is_loaded(self, evil_config: Path) -> None:
        c = ConfigManager(evil_config).load()
        assert c.permission_issues == []
        assert not c.rejected
        assert c.get("plugins.enabled") is True

    @pytest.mark.parametrize("mode", [0o666, 0o646, 0o664, 0o620])
    def test_writable_by_others_is_rejected(self, evil_config: Path, mode: int, monkeypatch) -> None:
        from ekprotection.config import manager
        monkeypatch.setattr(manager, "_private_group", lambda gid, uid: False)
        os.chmod(evil_config, mode)
        c = ConfigManager(evil_config).load()
        assert c.rejected
        assert c.get("plugins.enabled") is False
        assert c.get("plugins.dir") == DEFAULT_CONFIG["plugins"]["dir"]

    def test_parent_dir_writable_without_sticky_is_rejected(self, evil_config: Path) -> None:
        os.chmod(evil_config.parent, 0o777)
        c = ConfigManager(evil_config).load()
        assert c.rejected
        assert any("sticky" in i for i in c.permission_issues)

    def test_group_write_ok_when_group_is_private(self, evil_config: Path, monkeypatch) -> None:
        from ekprotection.config import manager
        monkeypatch.setattr(manager, "_private_group", lambda gid, uid: True)
        os.chmod(evil_config, 0o664)
        assert ConfigManager(evil_config).load().permission_issues == []
        os.chmod(evil_config, 0o666)   # outros: nunca
        assert ConfigManager(evil_config).load().rejected

    @pytest.mark.parametrize("gr_mem,primaries,expected", [
        ([], [("alice", 1000)], True),                       # UPG clássico
        (["alice"], [("alice", 1000)], True),                # dono listado como membro
        (["bob"], [("alice", 1000)], False),                 # outro membro
        ([], [("alice", 1000), ("bob", 1001)], False),       # outro usuário com gid primário
    ])
    def test_private_group_detection(self, monkeypatch, gr_mem, primaries, expected) -> None:
        from types import SimpleNamespace as NS
        from ekprotection.config import manager
        users = [NS(pw_name=n, pw_uid=u, pw_gid=500) for n, u in primaries]
        monkeypatch.setattr(manager.pwd, "getpwuid",
                            lambda uid: next(p for p in users if p.pw_uid == uid))
        monkeypatch.setattr(manager.pwd, "getpwall", lambda: users)
        monkeypatch.setattr(manager.grp, "getgrgid", lambda gid: NS(gr_mem=gr_mem))
        assert manager._private_group(500, 1000) is expected

    def test_private_group_unknown_ids(self) -> None:
        from ekprotection.config.manager import _private_group
        assert _private_group(2**31 - 7, os.getuid()) is False

    def test_parent_dir_writable_with_sticky_is_ok(self, evil_config: Path) -> None:
        os.chmod(evil_config.parent, 0o1777)
        c = ConfigManager(evil_config).load()
        assert c.permission_issues == []
        assert c.get("plugins.enabled") is True

    def test_symlink_checks_real_parent(self, evil_config: Path, tmp_path: Path) -> None:
        link = tmp_path / "link.yaml"
        link.symlink_to(evil_config)
        os.chmod(evil_config.parent, 0o777)
        assert ConfigManager(link).load().rejected

    def test_foreign_owner_is_rejected(self, evil_config: Path, monkeypatch) -> None:
        monkeypatch.setattr(os, "geteuid", lambda: os.getuid() + 4242)
        if os.getuid() == 0:
            pytest.skip("rodando como root: uid 0 é sempre confiável")
        c = ConfigManager(evil_config).load()
        assert c.rejected
        assert any("pertence ao uid" in i for i in c.permission_issues)

    def test_strict_off_warns_but_loads(self, evil_config: Path, monkeypatch, caplog) -> None:
        os.chmod(evil_config, 0o666)
        monkeypatch.setenv("EKP_CONFIG_STRICT", "0")
        with caplog.at_level(logging.CRITICAL, logger="ekprotection.config.manager"):
            c = ConfigManager(evil_config).load()
        assert not c.rejected
        assert c.get("plugins.enabled") is True
        assert any("adulterável" in r.getMessage() for r in caplog.records)

    def test_rejection_logs_critical(self, evil_config: Path, caplog) -> None:
        os.chmod(evil_config, 0o666)
        with caplog.at_level(logging.CRITICAL, logger="ekprotection.config.manager"):
            ConfigManager(evil_config).load()
        msgs = [r.getMessage() for r in caplog.records if r.levelno == logging.CRITICAL]
        assert any("IGNORADA" in m for m in msgs)

    def test_missing_file_has_no_issues(self, tmp_path: Path) -> None:
        assert config_permission_issues(tmp_path / "nope.yaml") == []

    def test_unreadable_file_falls_back_to_defaults(self, evil_config: Path) -> None:
        if os.getuid() == 0:
            pytest.skip("root lê arquivo 000")
        os.chmod(evil_config, 0o000)
        try:
            c = ConfigManager(evil_config).load()
        finally:
            os.chmod(evil_config, 0o644)
        assert c.get("plugins.enabled") is False


class TestSavePermissions:
    def test_new_file_is_0600_even_with_open_umask(self, tmp_path: Path) -> None:
        old = os.umask(0o000)
        try:
            p = tmp_path / "c.yaml"
            c = ConfigManager(p).load()
            c.set("monitor.canary_paths", ["/root/seed-phrase.txt"])
            c.save()
        finally:
            os.umask(old)
        assert stat.S_IMODE(p.stat().st_mode) == 0o600

    def test_existing_mode_kept_minus_group_other_write(self, tmp_path: Path) -> None:
        p = tmp_path / "c.yaml"
        p.write_text("{}")
        os.chmod(p, 0o666)
        c = ConfigManager(p)
        c._data, c._loaded = copy.deepcopy(DEFAULT_CONFIG), True
        c.save()
        assert stat.S_IMODE(p.stat().st_mode) == 0o644

    def test_save_is_atomic_and_leaves_no_tmp(self, tmp_path: Path) -> None:
        p = tmp_path / "c.yaml"
        p.write_text("{}")
        ino = p.stat().st_ino
        c = ConfigManager(p).load()
        c.save()
        assert p.stat().st_ino != ino   # rename, não truncate
        assert [x.name for x in tmp_path.iterdir()] == ["c.yaml"]
        assert ConfigManager(p).load().get("daemon.log_level") == "INFO"

    def test_failed_dump_keeps_old_file(self, tmp_path: Path, monkeypatch) -> None:
        p = tmp_path / "c.yaml"
        p.write_text("daemon:\n  log_level: DEBUG\n")
        c = ConfigManager(p).load()
        def boom(*a, **k):
            raise RuntimeError("disco cheio")
        monkeypatch.setattr(yaml, "dump", boom)
        with pytest.raises(RuntimeError):
            c.save()
        assert "DEBUG" in p.read_text()
        assert [x.name for x in tmp_path.iterdir()] == ["c.yaml"]


class TestDaemonRelogsIssues:
    def test_run_daemon_logs_after_setup(self, evil_config: Path, monkeypatch) -> None:
        from ekprotection import daemon
        os.chmod(evil_config, 0o666)
        seen: list[str] = []
        monkeypatch.setattr(daemon, "_setup_logging", lambda *a: None)
        monkeypatch.setattr(daemon.logger, "critical", lambda msg, *a, **k: seen.append(msg % a))
        def stop(coro):
            coro.close()
        monkeypatch.setattr(daemon.asyncio, "run", stop)
        daemon.run_daemon(str(evil_config))
        assert any("IGNORADA" in m for m in seen)
        assert any("gravável" in m for m in seen)


_CANARY = "monitor:\n  canary_paths: [/root/.ssh/id_backup]\n"


@pytest.fixture
def exposed_config(tmp_path: Path):
    d = tmp_path / "etc"
    d.mkdir(mode=0o755)
    p = d / "config.yaml"
    p.write_text(_CANARY)
    os.chmod(p, 0o644)
    yield p
    os.chmod(d, 0o755)


class TestConfigExposure:
    """Config legível por outros com isca/exceção: avisa, não recusa."""

    @pytest.mark.parametrize("body,key", [
        (_CANARY, "monitor.canary_paths"),
        ("exceptions:\n  paths: [/opt/x]\n", "exceptions.paths"),
        ("exceptions:\n  hashes: [abc]\n", "exceptions.hashes"),
        ("exceptions:\n  processes: [miner]\n", "exceptions.processes"),
    ])
    def test_world_readable_with_secret_warns(self, exposed_config: Path, body, key) -> None:
        exposed_config.write_text(body)
        c = ConfigManager(exposed_config).load()
        assert len(c.exposure_issues) == 1
        assert key in c.exposure_issues[0]
        assert "0644" in c.exposure_issues[0]
        assert not c.rejected

    def test_still_loads_values(self, exposed_config: Path) -> None:
        c = ConfigManager(exposed_config).load()
        assert c.get("monitor.canary_paths") == ["/root/.ssh/id_backup"]

    def test_lists_all_present_keys(self, exposed_config: Path) -> None:
        exposed_config.write_text(_CANARY + "exceptions:\n  paths: [/opt/x]\n")
        c = ConfigManager(exposed_config).load()
        assert "monitor.canary_paths, exceptions.paths" in c.exposure_issues[0]

    def test_mode_600_is_ok(self, exposed_config: Path) -> None:
        os.chmod(exposed_config, 0o600)
        assert ConfigManager(exposed_config).load().exposure_issues == []

    def test_no_secret_is_ok(self, exposed_config: Path) -> None:
        exposed_config.write_text("daemon:\n  log_level: INFO\n")
        assert ConfigManager(exposed_config).load().exposure_issues == []

    def test_empty_lists_are_ok(self, exposed_config: Path) -> None:
        exposed_config.write_text("monitor:\n  canary_paths: []\nexceptions:\n  paths: []\n")
        assert ConfigManager(exposed_config).load().exposure_issues == []

    def test_default_extensions_not_counted(self, exposed_config: Path) -> None:
        # exceptions.extensions vem do default público, não é segredo
        exposed_config.write_text("exceptions:\n  extensions: [.iso]\n")
        assert ConfigManager(exposed_config).load().exposure_issues == []

    def test_untraversable_parent_is_ok(self, exposed_config: Path) -> None:
        os.chmod(exposed_config.parent, 0o700)
        assert ConfigManager(exposed_config).load().exposure_issues == []

    def test_group_readable_private_group_ok(self, exposed_config: Path, monkeypatch) -> None:
        from ekprotection.config import manager
        os.chmod(exposed_config, 0o640)
        monkeypatch.setattr(manager, "_private_group", lambda gid, uid: True)
        assert ConfigManager(exposed_config).load().exposure_issues == []

    def test_group_readable_shared_group_warns(self, exposed_config: Path, monkeypatch) -> None:
        from ekprotection.config import manager
        os.chmod(exposed_config, 0o640)
        monkeypatch.setattr(manager, "_private_group", lambda gid, uid: False)
        assert len(ConfigManager(exposed_config).load().exposure_issues) == 1

    def test_logs_warning_with_fix(self, exposed_config: Path, caplog) -> None:
        with caplog.at_level(logging.WARNING, logger="ekprotection"):
            ConfigManager(exposed_config).load()
        msgs = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
        assert any("Config exposta" in m and "chmod 600" in m for m in msgs)

    def test_save_fixes_exposure(self, exposed_config: Path) -> None:
        c = ConfigManager(exposed_config).load()
        os.chmod(exposed_config, 0o600)
        c.save()
        assert ConfigManager(exposed_config).load().exposure_issues == []

    def test_reload_clears_issues(self, exposed_config: Path) -> None:
        c = ConfigManager(exposed_config).load()
        assert c.exposure_issues
        os.chmod(exposed_config, 0o600)
        assert c.load().exposure_issues == []

    def test_daemon_relogs_exposure(self, exposed_config: Path, monkeypatch) -> None:
        from ekprotection import daemon
        seen: list[str] = []
        monkeypatch.setattr(daemon, "_setup_logging", lambda *a: None)
        monkeypatch.setattr(daemon.logger, "warning", lambda msg, *a, **k: seen.append(msg % a))
        def stop(coro):
            coro.close()
        monkeypatch.setattr(daemon.asyncio, "run", stop)
        daemon.run_daemon(str(exposed_config))
        assert any("Config exposta" in m and "canary_paths" in m for m in seen)

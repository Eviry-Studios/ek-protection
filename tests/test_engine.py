"""
tests/test_engine.py
=====================
Testes do EKEngine (core).
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from ekprotection.config.manager import ConfigManager
from ekprotection.core.engine import EKEngine, EngineState


@pytest.fixture
def cfg(tmp_path: Path) -> ConfigManager:
    manager = ConfigManager(tmp_path / "config.yaml")
    manager.load()
    return manager


class TestEngineState:
    def test_initial_state_is_stopped(self, cfg: ConfigManager) -> None:
        engine = EKEngine(cfg)
        assert engine.state == EngineState.STOPPED

    def test_is_running_false_initially(self, cfg: ConfigManager) -> None:
        engine = EKEngine(cfg)
        assert engine.is_running is False

    def test_status_returns_dict(self, cfg: ConfigManager) -> None:
        engine = EKEngine(cfg)
        status = engine.status()
        assert isinstance(status, dict)
        assert "state" in status
        assert "pid" in status
        assert "version" in status

    @pytest.mark.asyncio
    async def test_start_changes_state(self, cfg: ConfigManager) -> None:
        engine = EKEngine(cfg)
        await engine.start()
        assert engine.state == EngineState.RUNNING
        await engine.stop()

    @pytest.mark.asyncio
    async def test_stop_changes_state(self, cfg: ConfigManager) -> None:
        engine = EKEngine(cfg)
        await engine.start()
        await engine.stop()
        assert engine.state == EngineState.STOPPED

    @pytest.mark.asyncio
    async def test_double_start_raises(self, cfg: ConfigManager) -> None:
        engine = EKEngine(cfg)
        await engine.start()
        with pytest.raises(RuntimeError):
            await engine.start()
        await engine.stop()

    def test_register_subsystem(self, cfg: ConfigManager) -> None:
        engine = EKEngine(cfg)
        mock_subsystem = object()
        engine.register("test_module", mock_subsystem)
        assert engine.get_subsystem("test_module") is mock_subsystem

    def test_get_missing_subsystem_returns_none(self, cfg: ConfigManager) -> None:
        engine = EKEngine(cfg)
        assert engine.get_subsystem("nonexistent") is None

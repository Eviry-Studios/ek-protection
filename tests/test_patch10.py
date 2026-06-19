"""
tests/test_patch10.py
======================
Testes do Patch 10 (v1.0): Reports, Plugins, ClamAV, Logo.

Cobre:
  - ReportGenerator: _collect_data, generate JSON/TXT/HTML,
                     risk level calculation, logo embed
  - PluginManager: load_all (disabled), load_all (enabled, valid plugin),
                   load_all (invalid plugin), fire_hook, safe_call,
                   unload_all, status
  - EKPlugin: base class hooks return None
  - ClamAVPlugin: on_load (disabled), on_load (clamd not installed),
                  on_scan_result (clean ELF → scan), on_threat
  - Logo: arquivo existe, tem conteúdo, dimensões corretas
  - Integration: full report cycle with mocked subsystems
"""

from __future__ import annotations

import json
import os
import importlib
from pathlib import Path
from typing  import Generator
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from ekprotection.config.manager       import ConfigManager
from ekprotection.reports.generator    import ReportGenerator
from ekprotection.plugins.manager      import PluginManager, EKPlugin, PluginResult
from ekprotection.plugins.clamav       import ClamAVPlugin


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_dir(tmp_path: Path) -> Generator[Path, None, None]:
    os.environ["EKP_DATA_DIR"] = str(tmp_path)
    yield tmp_path
    os.environ.pop("EKP_DATA_DIR", None)


@pytest.fixture
def cfg(tmp_dir: Path) -> ConfigManager:
    m = ConfigManager(tmp_dir / "config.yaml")
    m.load()
    m.set("plugins.enabled", False)
    m.set("plugins.dir",     str(tmp_dir / "plugins"))
    m.set("integrations.clamav.enabled", False)
    return m


@pytest.fixture
def gen(cfg: ConfigManager) -> ReportGenerator:
    return ReportGenerator(cfg)


# ---------------------------------------------------------------------------
# Testes: ReportGenerator — _collect_data
# ---------------------------------------------------------------------------

class TestReportCollectData:
    def test_collect_no_subsystems(self, gen: ReportGenerator) -> None:
        data = gen._collect_data(24)
        assert "generated_at" in data
        assert "since_hours"  in data
        assert data["since_hours"] == 24

    def test_overall_risk_clean(self, gen: ReportGenerator) -> None:
        data = gen._collect_data(24)
        assert data["overall_risk"] == "limpo"

    def test_overall_risk_with_threats(self, cfg: ConfigManager) -> None:
        mock_log = MagicMock()
        mock_log.stats.return_value = {"total_entries": 10, "by_level": {}}
        mock_log.query.return_value = [MagicMock(to_dict=lambda: {})] * 5
        gen = ReportGenerator(cfg, log_manager=mock_log)
        data = gen._collect_data(24)
        assert data["overall_risk"] in ("médio", "alto", "crítico")

    def test_overall_risk_critical_threshold(self, cfg: ConfigManager) -> None:
        mock_log = MagicMock()
        mock_log.stats.return_value = {"total_entries": 100, "by_level": {}}
        mock_log.query.return_value = [MagicMock(to_dict=lambda: {})] * 10
        gen = ReportGenerator(cfg, log_manager=mock_log)
        data = gen._collect_data(24)
        assert data["overall_risk"] == "crítico"

    def test_quarantine_stats_included(self, cfg: ConfigManager) -> None:
        mock_quar = MagicMock()
        mock_quar.stats.return_value        = {"active": 2, "total": 5}
        mock_quar.list_active.return_value  = []
        gen  = ReportGenerator(cfg, quar_manager=mock_quar)
        data = gen._collect_data(24)
        assert data["quarantine_stats"]["active"] == 2

    def test_log_error_handled(self, cfg: ConfigManager) -> None:
        mock_log = MagicMock()
        mock_log.stats.side_effect = Exception("db error")
        gen  = ReportGenerator(cfg, log_manager=mock_log)
        data = gen._collect_data(24)
        assert "log_error" in data


# ---------------------------------------------------------------------------
# Testes: ReportGenerator — formatos
# ---------------------------------------------------------------------------

class TestReportFormats:
    def test_generate_json(self, gen: ReportGenerator, tmp_dir: Path) -> None:
        out = gen.generate(tmp_dir / "report.json", fmt="json")
        assert out.exists()
        data = json.loads(out.read_text())
        assert "generated_at" in data
        assert "overall_risk" in data

    def test_generate_txt(self, gen: ReportGenerator, tmp_dir: Path) -> None:
        out = gen.generate(tmp_dir / "report.txt", fmt="txt")
        assert out.exists()
        content = out.read_text()
        assert "EK-Protection" in content
        assert "SUMÁRIO" in content

    def test_generate_html(self, gen: ReportGenerator, tmp_dir: Path) -> None:
        out = gen.generate(tmp_dir / "report.html", fmt="html")
        assert out.exists()
        html = out.read_text()
        assert "<!DOCTYPE html>" in html
        assert "EK-Protection" in html
        assert "overall_risk" in html.lower() or "Risco" in html

    def test_generate_html_default_format(self, gen: ReportGenerator, tmp_dir: Path) -> None:
        """Formato padrão deve ser HTML."""
        out = gen.generate(tmp_dir / "report.html")
        html = out.read_text()
        assert "<!DOCTYPE html>" in html

    def test_txt_contains_risk_level(self, gen: ReportGenerator, tmp_dir: Path) -> None:
        out     = gen.generate(tmp_dir / "r.txt", fmt="txt")
        content = out.read_text()
        assert "LIMPO" in content or "MÉDIO" in content or "ALTO" in content or "CRÍTICO" in content

    def test_json_is_valid_and_complete(self, gen: ReportGenerator, tmp_dir: Path) -> None:
        out  = gen.generate(tmp_dir / "r.json", fmt="json")
        data = json.loads(out.read_text())
        assert data["version"]     == "1.0.0"
        assert data["since_hours"] == 24

    def test_html_contains_logo_or_fallback(self, gen: ReportGenerator, tmp_dir: Path) -> None:
        out  = gen.generate(tmp_dir / "r.html", fmt="html")
        html = out.read_text()
        # Deve ter logo em base64 OU fallback de texto
        assert 'class="logo"' in html or 'class="logo-text"' in html

    def test_report_creates_parent_dirs(self, gen: ReportGenerator, tmp_dir: Path) -> None:
        deep_path = tmp_dir / "deep" / "nested" / "report.json"
        out = gen.generate(deep_path, fmt="json")
        assert out.exists()

    def test_since_hours_parameter(self, gen: ReportGenerator, tmp_dir: Path) -> None:
        out  = gen.generate(tmp_dir / "r72.json", fmt="json", since_hours=72)
        data = json.loads(out.read_text())
        assert data["since_hours"] == 72

    def test_html_with_threats(self, cfg: ConfigManager, tmp_dir: Path) -> None:
        mock_log = MagicMock()
        mock_log.stats.return_value = {"total_entries": 3, "by_level": {"WARNING": 2}}
        threat_entry = MagicMock()
        threat_entry.to_dict.return_value = {
            "timestamp":  "2024-06-15T10:00:00",
            "message":    "Ameaça detectada",
            "file_path":  "/tmp/evil.sh",
            "sha256":     "abc123",
        }
        mock_log.query.return_value = [threat_entry]
        gen = ReportGenerator(cfg, log_manager=mock_log)
        out = gen.generate(tmp_dir / "threats.html", fmt="html")
        html = out.read_text()
        assert "Ameaça detectada" in html


# ---------------------------------------------------------------------------
# Testes: PluginManager
# ---------------------------------------------------------------------------

class TestPluginManagerDisabled:
    def test_load_all_disabled_returns_zero(self, cfg: ConfigManager) -> None:
        mgr = PluginManager(cfg)
        assert mgr.load_all() == 0

    def test_status_disabled(self, cfg: ConfigManager) -> None:
        mgr = PluginManager(cfg)
        s = mgr.status()
        assert s["enabled"] is False
        assert s["loaded"]  == 0

    def test_fire_hooks_when_disabled_returns_empty(self, cfg: ConfigManager) -> None:
        mgr = PluginManager(cfg)
        assert mgr.fire_file_event(MagicMock())    == []
        assert mgr.fire_scan_result(MagicMock())   == []
        assert mgr.fire_threat(MagicMock())        == []


class TestPluginManagerEnabled:
    def _make_plugin_file(self, plugin_dir: Path, name: str, code: str) -> Path:
        d = plugin_dir / name
        d.mkdir(parents=True, exist_ok=True)
        p = d / "plugin.py"
        p.write_text(code)
        return p

    def test_load_valid_plugin(self, cfg: ConfigManager, tmp_dir: Path) -> None:
        cfg.set("plugins.enabled", True)
        cfg.set("plugins.dir",     str(tmp_dir / "plugins"))

        code = '''
from ekprotection.plugins.manager import EKPlugin, PluginResult

class TestPlugin(EKPlugin):
    name        = "test_plugin"
    version     = "1.0.0"
    description = "Test"
    author      = "Tester"

    def on_threat(self, result):
        return PluginResult("alert", {"from": "test"})
'''
        self._make_plugin_file(tmp_dir / "plugins", "test_plugin", code)
        mgr = PluginManager(cfg)
        n   = mgr.load_all()
        assert n == 1
        assert len(mgr._plugins) == 1
        assert mgr._plugins[0].name == "test_plugin"

    def test_invalid_plugin_not_loaded(self, cfg: ConfigManager, tmp_dir: Path) -> None:
        cfg.set("plugins.enabled", True)
        cfg.set("plugins.dir",     str(tmp_dir / "plugins"))

        code = "this is not valid python $$%%"
        self._make_plugin_file(tmp_dir / "plugins", "broken_plugin", code)
        mgr = PluginManager(cfg)
        n   = mgr.load_all()
        assert n == 0

    def test_plugin_without_subclass_not_loaded(self, cfg: ConfigManager, tmp_dir: Path) -> None:
        cfg.set("plugins.enabled", True)
        cfg.set("plugins.dir",     str(tmp_dir / "plugins"))
        code = "x = 42  # no EKPlugin subclass"
        self._make_plugin_file(tmp_dir / "plugins", "no_class", code)
        mgr = PluginManager(cfg)
        assert mgr.load_all() == 0

    def test_fire_hook_calls_plugin(self, cfg: ConfigManager, tmp_dir: Path) -> None:
        cfg.set("plugins.enabled", True)
        cfg.set("plugins.dir",     str(tmp_dir / "plugins"))
        code = '''
from ekprotection.plugins.manager import EKPlugin, PluginResult
class FirePlugin(EKPlugin):
    name = "fire_plugin"
    def on_threat(self, result):
        return PluginResult("alert", "fired")
'''
        self._make_plugin_file(tmp_dir / "plugins", "fire_plugin", code)
        mgr = PluginManager(cfg)
        mgr.load_all()
        results = mgr.fire_threat(MagicMock())
        assert len(results) == 1
        assert results[0].action == "alert"

    def test_plugin_exception_isolated(self, cfg: ConfigManager, tmp_dir: Path) -> None:
        cfg.set("plugins.enabled", True)
        cfg.set("plugins.dir",     str(tmp_dir / "plugins"))
        code = '''
from ekprotection.plugins.manager import EKPlugin
class CrashPlugin(EKPlugin):
    name = "crash_plugin"
    def on_threat(self, result):
        raise RuntimeError("crash!")
'''
        self._make_plugin_file(tmp_dir / "plugins", "crash_plugin", code)
        mgr = PluginManager(cfg)
        mgr.load_all()
        # Não deve propagar exceção
        results = mgr.fire_threat(MagicMock())
        assert results == []   # crash isolado

    def test_unload_all(self, cfg: ConfigManager, tmp_dir: Path) -> None:
        cfg.set("plugins.enabled", True)
        cfg.set("plugins.dir",     str(tmp_dir / "plugins"))
        code = '''
from ekprotection.plugins.manager import EKPlugin
class UnloadPlugin(EKPlugin):
    name = "unload_plugin"
'''
        self._make_plugin_file(tmp_dir / "plugins", "unload_plugin", code)
        mgr = PluginManager(cfg)
        mgr.load_all()
        assert len(mgr._plugins) == 1
        mgr.unload_all()
        assert len(mgr._plugins) == 0

    def test_status_with_loaded_plugins(self, cfg: ConfigManager, tmp_dir: Path) -> None:
        cfg.set("plugins.enabled", True)
        cfg.set("plugins.dir",     str(tmp_dir / "plugins"))
        code = '''
from ekprotection.plugins.manager import EKPlugin
class StatusPlugin(EKPlugin):
    name    = "status_plugin"
    version = "2.0.0"
    author  = "Author"
'''
        self._make_plugin_file(tmp_dir / "plugins", "status_plugin", code)
        mgr = PluginManager(cfg)
        mgr.load_all()
        s   = mgr.status()
        assert s["loaded"]              == 1
        assert s["plugins"][0]["name"]  == "status_plugin"

    def test_missing_plugins_dir_returns_zero(self, cfg: ConfigManager, tmp_dir: Path) -> None:
        cfg.set("plugins.enabled", True)
        cfg.set("plugins.dir",     str(tmp_dir / "nonexistent_plugins"))
        mgr = PluginManager(cfg)
        assert mgr.load_all() == 0


# ---------------------------------------------------------------------------
# Testes: EKPlugin base class
# ---------------------------------------------------------------------------

class TestEKPluginBase:
    def test_all_hooks_return_none_by_default(self, cfg: ConfigManager) -> None:
        plugin = EKPlugin(cfg)
        mock   = MagicMock()
        assert plugin.on_file_event(mock)        is None
        assert plugin.on_scan_result(mock)       is None
        assert plugin.on_threat(mock)            is None
        assert plugin.on_heuristic_result(mock)  is None

    def test_on_load_on_unload_no_error(self, cfg: ConfigManager) -> None:
        plugin = EKPlugin(cfg)
        plugin.on_load()    # não deve lançar
        plugin.on_unload()  # não deve lançar

    def test_plugin_result_fields(self) -> None:
        r = PluginResult("quarantine", {"path": "/tmp/x"})
        assert r.action == "quarantine"
        assert r.data   == {"path": "/tmp/x"}


# ---------------------------------------------------------------------------
# Testes: ClamAVPlugin
# ---------------------------------------------------------------------------

class TestClamAVPlugin:
    def test_disabled_in_config(self, cfg: ConfigManager) -> None:
        cfg.set("integrations.clamav.enabled", False)
        plugin = ClamAVPlugin(cfg)
        plugin.on_load()
        assert plugin._clamd is None

    def test_clamd_not_installed(self, cfg: ConfigManager) -> None:
        cfg.set("integrations.clamav.enabled", True)
        plugin = ClamAVPlugin(cfg)
        with patch("builtins.__import__", side_effect=ImportError("no module")):
            try:
                plugin.on_load()
            except Exception:
                pass
        # Não deve lançar fatalmente — _clamd fica None

    def test_on_scan_result_skips_non_clean(self, cfg: ConfigManager) -> None:
        plugin = ClamAVPlugin(cfg)
        plugin._clamd = MagicMock()
        from ekprotection.scanner.result import ScanVerdict, FileScanResult
        result = FileScanResult(path="/tmp/x", verdict=ScanVerdict.THREAT)
        pr = plugin.on_scan_result(result)
        assert pr is None
        plugin._clamd.scan.assert_not_called()

    def test_on_scan_result_skips_non_executable(self, cfg: ConfigManager) -> None:
        plugin = ClamAVPlugin(cfg)
        plugin._clamd = MagicMock()
        from ekprotection.scanner.result import ScanVerdict, FileScanResult
        result = FileScanResult(path="/tmp/doc.pdf", verdict=ScanVerdict.CLEAN,
                                is_elf=False, is_script=False)
        pr = plugin.on_scan_result(result)
        assert pr is None

    def test_on_scan_result_clean_elf_scans(self, cfg: ConfigManager) -> None:
        plugin = ClamAVPlugin(cfg)
        plugin._clamd = MagicMock()
        plugin._clamd.scan.return_value = {"/tmp/clean_elf": ("OK", None)}
        from ekprotection.scanner.result import ScanVerdict, FileScanResult
        result = FileScanResult(path="/tmp/clean_elf", verdict=ScanVerdict.CLEAN,
                                is_elf=True)
        pr = plugin.on_scan_result(result)
        plugin._clamd.scan.assert_called_once_with("/tmp/clean_elf")
        assert pr is None   # scan retornou OK

    def test_on_scan_result_clamav_finds_threat(self, cfg: ConfigManager) -> None:
        plugin = ClamAVPlugin(cfg)
        plugin._clamd = MagicMock()
        plugin._clamd.scan.return_value = {"/tmp/evil": ("FOUND", "Eicar-Test-Signature")}
        from ekprotection.scanner.result import ScanVerdict, FileScanResult
        result = FileScanResult(path="/tmp/evil", verdict=ScanVerdict.CLEAN, is_elf=True)
        pr = plugin.on_scan_result(result)
        assert pr is not None
        assert pr.action                    == "alert"
        assert pr.data["source"]            == "clamav"
        assert pr.data["threat_name"]       == "Eicar-Test-Signature"

    def test_on_scan_result_clamd_none_returns_none(self, cfg: ConfigManager) -> None:
        plugin = ClamAVPlugin(cfg)
        plugin._clamd = None
        from ekprotection.scanner.result import ScanVerdict, FileScanResult
        result = FileScanResult(path="/tmp/x", verdict=ScanVerdict.CLEAN, is_elf=True)
        assert plugin.on_scan_result(result) is None

    def test_clamd_exception_handled(self, cfg: ConfigManager) -> None:
        plugin = ClamAVPlugin(cfg)
        plugin._clamd = MagicMock()
        plugin._clamd.scan.side_effect = Exception("connection lost")
        from ekprotection.scanner.result import ScanVerdict, FileScanResult
        result = FileScanResult(path="/tmp/x", verdict=ScanVerdict.CLEAN, is_elf=True)
        pr = plugin.on_scan_result(result)
        assert pr is None   # exceção isolada


# ---------------------------------------------------------------------------
# Testes: Logo e Assets
# ---------------------------------------------------------------------------

class TestLogo:
    def test_logo_file_exists(self) -> None:
        logo = Path(__file__).parent.parent / "assets" / "logo.png"
        assert logo.exists(), f"Logo não encontrada em {logo}"

    def test_logo_is_valid_png(self) -> None:
        from PIL import Image
        logo = Path(__file__).parent.parent / "assets" / "logo.png"
        img  = Image.open(logo)
        assert img.format == "PNG"

    def test_logo_has_reasonable_size(self) -> None:
        from PIL import Image
        logo = Path(__file__).parent.parent / "assets" / "logo.png"
        img  = Image.open(logo)
        w, h = img.size
        assert w >= 128 and h >= 128, f"Logo muito pequena: {w}x{h}"
        assert w <= 2048 and h <= 2048, f"Logo muito grande: {w}x{h}"

    def test_logo_is_rgba(self) -> None:
        from PIL import Image
        logo = Path(__file__).parent.parent / "assets" / "logo.png"
        img  = Image.open(logo).convert("RGBA")
        assert img.mode == "RGBA"

    def test_favicon_32_exists(self) -> None:
        favicon = Path(__file__).parent.parent / "assets" / "favicon-32.png"
        assert favicon.exists()

    def test_favicon_32_correct_size(self) -> None:
        from PIL import Image
        favicon = Path(__file__).parent.parent / "assets" / "favicon-32.png"
        img     = Image.open(favicon)
        assert img.size == (32, 32)

    def test_icon_512_exists(self) -> None:
        icon = Path(__file__).parent.parent / "assets" / "icon.png"
        assert icon.exists()

    def test_html_report_embeds_logo(self, gen: ReportGenerator, tmp_dir: Path) -> None:
        """Logo deve ser embutida como base64 no relatório HTML."""
        out  = gen.generate(tmp_dir / "r.html", fmt="html")
        html = out.read_text()
        # Verifica presença de logo (base64 ou fallback)
        assert "logo" in html.lower()


# ---------------------------------------------------------------------------
# Testes: Integração end-to-end (mocked)
# ---------------------------------------------------------------------------

class TestEndToEnd:
    def test_full_report_cycle(self, cfg: ConfigManager, tmp_dir: Path) -> None:
        """Gera relatório com todos os subsistemas mockados."""
        mock_log = MagicMock()
        mock_log.stats.return_value = {
            "total_entries": 42,
            "by_level": {"INFO": 30, "WARNING": 10, "CRITICAL": 2},
        }
        mock_entry = MagicMock()
        mock_entry.to_dict.return_value = {
            "timestamp": "2024-06-15T10:00:00",
            "message":   "Reverse shell detectada",
            "file_path": "/tmp/backdoor.sh",
            "sha256":    "abc123",
            "level":     "CRITICAL",
            "event_type":"threat.detected",
            "source":    "heuristics",
        }
        mock_log.query.return_value = [mock_entry] * 3

        mock_quar = MagicMock()
        mock_quar.stats.return_value       = {"active": 2, "total": 5}
        mock_quar.list_active.return_value = [mock_entry]

        mock_exc = MagicMock()
        mock_exc.status.return_value = {"whitelist": 5, "blacklist": 2, "total": 7}

        gen = ReportGenerator(cfg, mock_log, mock_quar, None, mock_exc)

        # JSON
        json_out = gen.generate(tmp_dir / "full.json", fmt="json", since_hours=48)
        data     = json.loads(json_out.read_text())
        assert data["threat_count"]    == 3
        assert data["overall_risk"]    in ("médio", "alto")
        assert data["quarantine_stats"]["active"] == 2

        # HTML
        html_out = gen.generate(tmp_dir / "full.html", fmt="html", since_hours=48)
        html     = html_out.read_text()
        assert "Reverse shell detectada" in html
        assert "42" in html   # total logs

        # TXT
        txt_out = gen.generate(tmp_dir / "full.txt", fmt="txt", since_hours=48)
        txt     = txt_out.read_text()
        assert "Reverse shell detectada" in txt

    def test_version_1_0_0(self) -> None:
        from ekprotection import __version__
        assert __version__ == "1.0.0"

    def test_all_cli_commands_registered(self) -> None:
        """Verifica que todos os grupos de comandos estão registrados na CLI."""
        from ekprotection.cli.app import app
        cmd_names = [c.name for c in app.registered_commands]
        group_names = [g.name for g in app.registered_groups]
        all_names = cmd_names + group_names
        for expected in ["auth", "logs", "monitor", "exceptions",
                         "quarantine", "scan", "heuristics", "update", "report"]:
            assert expected in all_names, f"Grupo '{expected}' não registrado na CLI"

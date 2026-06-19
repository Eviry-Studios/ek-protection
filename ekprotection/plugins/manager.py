"""
ekprotection.plugins.manager
==============================
Arquitetura de plugins do EK-Protection.

Um plugin é um módulo Python em <plugins_dir>/<nome>/plugin.py
que implementa a classe Plugin herdando de EKPlugin.

API mínima de um plugin:

    from ekprotection.plugins.base import EKPlugin, PluginResult

    class MyPlugin(EKPlugin):
        name        = "my_plugin"
        version     = "1.0.0"
        description = "Descrição do plugin"
        author      = "Seu Nome"

        def on_file_event(self, event) -> Optional[PluginResult]:
            # Chamado para cada FileEvent do monitor
            ...

        def on_scan_result(self, result) -> Optional[PluginResult]:
            # Chamado após cada FileScanResult
            ...

        def on_threat(self, result) -> Optional[PluginResult]:
            # Chamado apenas para ameaças detectadas
            ...

Segurança:
  - Plugins só são carregados se plugins.enabled=true no config
  - Erros em plugins são isolados — nunca derrubam o daemon
  - Plugins não têm acesso direto ao banco de dados
  - Cada plugin roda em contexto sandboxado via try/except
"""

from __future__ import annotations

import importlib.util
import logging
import sys
from pathlib import Path
from typing  import Any, Optional

logger = logging.getLogger(__name__)


class PluginResult:
    """Resultado opcional retornado por um hook de plugin."""
    def __init__(self, action: str, data: Any = None) -> None:
        self.action = action   # "alert" | "quarantine" | "whitelist" | "log" | None
        self.data   = data


class EKPlugin:
    """
    Classe base para plugins do EK-Protection.
    Subclasse e sobrescreva os hooks desejados.
    """
    name:        str = "unnamed_plugin"
    version:     str = "0.0.1"
    description: str = ""
    author:      str = ""

    def __init__(self, config: Any) -> None:
        self.config = config
        self._log   = logging.getLogger(f"ekp.plugin.{self.name}")

    # Hooks disponíveis — sobrescreva os que precisar
    def on_load(self) -> None:
        """Chamado quando o plugin é carregado."""

    def on_unload(self) -> None:
        """Chamado quando o plugin é descarregado."""

    def on_file_event(self, event: Any) -> Optional[PluginResult]:
        """Chamado para cada FileEvent do monitor."""
        return None

    def on_scan_result(self, result: Any) -> Optional[PluginResult]:
        """Chamado após cada FileScanResult."""
        return None

    def on_threat(self, result: Any) -> Optional[PluginResult]:
        """Chamado apenas quando uma ameaça é detectada."""
        return None

    def on_heuristic_result(self, result: Any) -> Optional[PluginResult]:
        """Chamado após análise heurística suspeita."""
        return None


class PluginManager:
    """
    Gerenciador de plugins do EK-Protection.

    Carrega plugins da pasta configurada em plugins.dir,
    executa hooks e isola erros.
    """

    def __init__(self, config: Any) -> None:
        self.config   = config
        self._plugins: list[EKPlugin] = []
        self._enabled = config.get("plugins.enabled", False)
        self._dir     = config.get("plugins.dir", "/var/lib/ek-protection/plugins")

    # ------------------------------------------------------------------
    # Ciclo de vida
    # ------------------------------------------------------------------

    def load_all(self) -> int:
        """
        Carrega todos os plugins do diretório configurado.
        Retorna o número de plugins carregados com sucesso.
        """
        if not self._enabled:
            logger.debug("Plugins desabilitados (plugins.enabled=false).")
            return 0

        plugin_dir = Path(self._dir)
        if not plugin_dir.exists():
            logger.debug("Diretório de plugins não existe: %s", plugin_dir)
            return 0

        loaded = 0
        for plugin_path in sorted(plugin_dir.glob("*/plugin.py")):
            name = plugin_path.parent.name
            if self._load_plugin(name, plugin_path):
                loaded += 1

        logger.info("Plugins carregados: %d", loaded)
        return loaded

    def unload_all(self) -> None:
        for plugin in self._plugins:
            self._safe_call(plugin, "on_unload")
        self._plugins.clear()

    # ------------------------------------------------------------------
    # Hooks
    # ------------------------------------------------------------------

    def fire_file_event(self, event: Any) -> list[PluginResult]:
        return self._fire_hook("on_file_event", event)

    def fire_scan_result(self, result: Any) -> list[PluginResult]:
        return self._fire_hook("on_scan_result", result)

    def fire_threat(self, result: Any) -> list[PluginResult]:
        return self._fire_hook("on_threat", result)

    def fire_heuristic_result(self, result: Any) -> list[PluginResult]:
        return self._fire_hook("on_heuristic_result", result)

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def status(self) -> dict:
        return {
            "enabled":       self._enabled,
            "plugins_dir":   self._dir,
            "loaded":        len(self._plugins),
            "plugins":       [
                {"name": p.name, "version": p.version, "author": p.author}
                for p in self._plugins
            ],
        }

    # ------------------------------------------------------------------
    # Internos
    # ------------------------------------------------------------------

    def _load_plugin(self, name: str, path: Path) -> bool:
        """Carrega um plugin pelo caminho. Retorna True se bem-sucedido."""
        try:
            spec   = importlib.util.spec_from_file_location(
                f"ekp_plugin_{name}", str(path)
            )
            module = importlib.util.module_from_spec(spec)   # type: ignore[arg-type]
            spec.loader.exec_module(module)                   # type: ignore[union-attr]

            # Procura subclasse de EKPlugin no módulo
            plugin_cls = None
            for attr in dir(module):
                obj = getattr(module, attr)
                if (
                    isinstance(obj, type)
                    and issubclass(obj, EKPlugin)
                    and obj is not EKPlugin
                ):
                    plugin_cls = obj
                    break

            if plugin_cls is None:
                logger.warning("Plugin '%s' não define subclasse de EKPlugin.", name)
                return False

            instance = plugin_cls(self.config)
            self._safe_call(instance, "on_load")
            self._plugins.append(instance)
            logger.info(
                "Plugin carregado: %s v%s por %s",
                instance.name, instance.version, instance.author,
            )
            return True

        except Exception as exc:
            logger.error("Erro ao carregar plugin '%s': %s", name, exc)
            return False

    def _fire_hook(self, hook: str, *args: Any) -> list[PluginResult]:
        results = []
        for plugin in self._plugins:
            r = self._safe_call(plugin, hook, *args)
            if isinstance(r, PluginResult):
                results.append(r)
        return results

    @staticmethod
    def _safe_call(plugin: EKPlugin, method: str, *args: Any) -> Any:
        """Chama método do plugin isolando exceções."""
        try:
            fn = getattr(plugin, method, None)
            if callable(fn):
                return fn(*args)
        except Exception as exc:
            logger.error(
                "Erro no plugin '%s'.%s: %s", plugin.name, method, exc
            )
        return None

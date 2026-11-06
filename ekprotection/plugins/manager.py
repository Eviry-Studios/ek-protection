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
  - Plugin adulterável por outro usuário não é importado (o daemon roda
    como root): dir de plugins, dir do plugin e plugin.py precisam ser do
    root/euid e sem escrita de grupo/outros. plugin.py é lido de um fd
    aberto com O_NOFOLLOW e compilado direto, sem __pycache__ (um .pyc
    forjado com mtime/tamanho do fonte seria executado no lugar dele).
"""

from __future__ import annotations

import importlib.util
import logging
import os
import stat
from pathlib import Path
from typing  import Any, Optional

from ekprotection.config.manager import _STRICT_ENV, _trusted_uid, _writable_by_others

logger = logging.getLogger(__name__)


def _owner_mode_issues(what: str, path: Path, st: os.stat_result) -> list[str]:
    issues = []
    if not _trusted_uid(st.st_uid):
        issues.append(f"{what} {path} pertence ao uid {st.st_uid} (esperado root ou {os.geteuid()})")
    if _writable_by_others(st):
        issues.append(f"{what} {path} gravável por grupo/outros (modo {stat.S_IMODE(st.st_mode):04o})")
    return issues


def plugin_dir_issues(plugin_dir: Path) -> list[str]:
    """
    Problemas que deixam outro usuário pôr código no dir de plugins.
    Sticky bit não basta aqui (diferente do config): com ele ninguém apaga
    o plugin alheio, mas qualquer um cria um plugin novo.
    """
    real = plugin_dir.resolve()
    issues = _owner_mode_issues("dir de plugins", real, real.stat())
    pst = real.parent.stat()
    if not _trusted_uid(pst.st_uid):
        issues.append(f"dir {real.parent} pertence ao uid {pst.st_uid} (dir de plugins pode ser trocado)")
    if _writable_by_others(pst) and not stat.S_IMODE(pst.st_mode) & stat.S_ISVTX:
        issues.append(f"dir {real.parent} gravável por grupo/outros sem sticky bit (dir de plugins pode ser trocado)")
    return issues


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

        strict = os.environ.get(_STRICT_ENV, "1") != "0"
        if self._refused(plugin_dir_issues(plugin_dir), strict, "nenhum plugin carregado"):
            return 0

        loaded = 0
        for plugin_path in sorted(plugin_dir.glob("*/plugin.py")):
            name = plugin_path.parent.name
            if self._load_plugin(name, plugin_path, strict):
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

    @staticmethod
    def _refused(issues: list[str], strict: bool, consequence: str) -> bool:
        for issue in issues:
            logger.critical(
                "Plugin adulterável: %s — %s. Corrija com chown root:root + chmod go-w.",
                issue, consequence if strict else f"carregando mesmo assim ({_STRICT_ENV}=0)",
            )
        return bool(issues) and strict

    def _read_plugin_source(self, name: str, path: Path, strict: bool) -> Optional[bytes]:
        """Lê plugin.py checando permissão no próprio fd (sem corrida stat/open)."""
        # O_NONBLOCK: um FIFO no lugar do plugin.py travaria o open() do daemon.
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | (os.O_NOFOLLOW if strict else 0)
        if strict and path.parent.is_symlink():
            logger.critical("Plugin '%s' ignorado: dir do plugin é symlink (%s).", name, path.parent)
            return None
        issues = _owner_mode_issues("dir do plugin", path.parent, path.parent.stat())
        try:
            fd = os.open(path, flags)
        except OSError as exc:
            logger.critical("Plugin '%s' ignorado: %s não abriu (%s; symlink é recusado).", name, path, exc)
            return None
        with os.fdopen(fd, "rb") as fh:
            st = os.fstat(fh.fileno())
            if not stat.S_ISREG(st.st_mode):
                logger.critical("Plugin '%s' ignorado: %s não é arquivo regular.", name, path)
                return None
            issues += _owner_mode_issues("plugin", path, st)
            if self._refused(issues, strict, f"plugin '{name}' ignorado"):
                return None
            return fh.read()

    def _load_plugin(self, name: str, path: Path, strict: bool = True) -> bool:
        """Carrega um plugin pelo caminho. Retorna True se bem-sucedido."""
        try:
            source = self._read_plugin_source(name, path, strict)
            if source is None:
                return False
            # Compila do fonte já checado: exec_module() leria __pycache__/*.pyc
            # se existir, e esse arquivo não passou por checagem nenhuma.
            spec   = importlib.util.spec_from_loader(f"ekp_plugin_{name}", loader=None, origin=str(path))
            module = importlib.util.module_from_spec(spec)   # type: ignore[arg-type]
            module.__file__ = str(path)
            exec(compile(source, str(path), "exec"), module.__dict__)

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

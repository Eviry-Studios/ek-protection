"""
ekprotection.plugins.clamav
=============================
Plugin de integração com ClamAV via clamd socket.

Quando habilitado (integrations.clamav.enabled=true), este plugin
complementa o scanner nativo do EK-Protection com o motor ClamAV.

Requisitos:
  - ClamAV instalado: apt install clamav clamav-daemon
  - clamd rodando: systemctl start clamav-daemon
  - clamd>=1.0.2: pip install clamd

Funcionamento:
  - on_scan_result(): reescaneia com ClamAV quando o scanner nativo
    retorna CLEAN (segundo opinião para arquivos suspeitos)
  - on_threat(): valida ameaças nativas contra a base ClamAV
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from .manager import EKPlugin, PluginResult

logger = logging.getLogger(__name__)


class ClamAVPlugin(EKPlugin):
    name        = "clamav"
    version     = "1.0.0"
    description = "Integração com ClamAV como motor antivírus complementar"
    author      = "EviRyKorp"

    def on_load(self) -> None:
        enabled = self.config.get("integrations.clamav.enabled", False)
        if not enabled:
            logger.info("ClamAV: integração desabilitada no config.")
            self._clamd = None
            return

        socket_path = self.config.get(
            "integrations.clamav.socket",
            "/run/clamav/clamd.ctl",
        )
        try:
            import clamd
            self._clamd = clamd.ClamdUnixSocket(path=socket_path)
            version = self._clamd.version()
            logger.info("ClamAV conectado: %s", version)
        except ImportError:
            logger.warning("clamd não instalado. pip install clamd")
            self._clamd = None
        except Exception as exc:
            logger.warning("ClamAV não disponível: %s", exc)
            self._clamd = None

    def on_scan_result(self, result: Any) -> Optional[PluginResult]:
        """Segundo scan com ClamAV para arquivos limpos mas suspeitos."""
        if not self._clamd:
            return None

        from ekprotection.scanner.result import ScanVerdict
        # Só re-escaneia se o scanner nativo marcou como limpo
        # mas o arquivo é executável — "segundo olhar"
        if result.verdict != ScanVerdict.CLEAN:
            return None
        if not (result.is_elf or result.is_script):
            return None

        return self._clam_scan(result.path)

    def on_threat(self, result: Any) -> Optional[PluginResult]:
        """Valida ameaças nativas contra ClamAV."""
        if not self._clamd:
            return None
        return self._clam_scan(result.path)

    def _clam_scan(self, path: str) -> Optional[PluginResult]:
        try:
            scan_result = self._clamd.scan(path)
            if scan_result:
                for fpath, (status, name) in scan_result.items():
                    if status == "FOUND":
                        logger.warning("ClamAV: ameaça em %s — %s", fpath, name)
                        return PluginResult(
                            action="alert",
                            data={
                                "source":      "clamav",
                                "path":        fpath,
                                "threat_name": name,
                                "verdict":     "THREAT",
                            },
                        )
        except Exception as exc:
            logger.debug("ClamAV scan falhou para %s: %s", path, exc)
        return None

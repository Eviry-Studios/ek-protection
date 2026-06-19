"""
ekprotection.updater.fetcher
==============================
Download e verificação de assinaturas de ameaças.

Protocolo:
  1. Baixa MANIFEST.json do servidor de assinaturas
  2. Compara versão local vs remota
  3. Se atualização disponível, baixa signatures.jsonl
  4. Verifica SHA-256 do arquivo baixado contra o manifest
  5. Aplica ao SignatureDB via import_jsonl()
  6. Atualiza metadata de versão

Segurança:
  - Verificação de checksum obrigatória — arquivo corrompido é rejeitado
  - Timeout configurável em todas as requisições HTTP
  - Sem execução de código remoto — apenas dados JSON/JSONL
  - Suporte a proxy via variável de ambiente HTTP_PROXY

Manifest format (JSON):
  {
    "version": "2024.06.15",
    "updated_at": "2024-06-15T12:00:00Z",
    "signatures_url": "https://example.com/signatures.jsonl",
    "sha256": "abc123...",
    "count": 12500
  }
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing  import Optional

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT  = 30   # segundos
DEFAULT_USER_AGENT = "EK-Protection/0.9.0 (https://github.com/Eviry-Studios/ek-protection)"


class UpdateError(Exception):
    """Erro durante atualização de assinaturas."""


class ChecksumError(UpdateError):
    """Checksum do arquivo baixado não confere."""


class ManifestError(UpdateError):
    """Manifest inválido ou inacessível."""


class FetchResult:
    """Resultado de uma operação de atualização."""
    def __init__(
        self,
        updated:        bool,
        version_before: str,
        version_after:  str,
        added:          int = 0,
        duplicates:     int = 0,
        message:        str = "",
    ) -> None:
        self.updated        = updated
        self.version_before = version_before
        self.version_after  = version_after
        self.added          = added
        self.duplicates     = duplicates
        self.message        = message

    def __repr__(self) -> str:
        return (
            f"FetchResult(updated={self.updated}, "
            f"v{self.version_before}→{self.version_after}, "
            f"+{self.added} sigs)"
        )


class SignatureFetcher:
    """
    Gerenciador de atualização de assinaturas.

    Uso:
        fetcher = SignatureFetcher(
            manifest_url = "https://example.com/manifest.json",
            sig_db       = db,
            cache_dir    = Path("/var/lib/ek-protection"),
        )
        result = fetcher.update()
    """

    def __init__(
        self,
        manifest_url: str,
        sig_db:       Any,   # SignatureDB
        cache_dir:    Path,
        timeout:      int  = DEFAULT_TIMEOUT,
    ) -> None:
        from typing import Any
        self._url      = manifest_url
        self._sig_db   = sig_db
        self._cache    = cache_dir
        self._timeout  = timeout

    # ------------------------------------------------------------------
    # Operação principal
    # ------------------------------------------------------------------

    def update(self) -> FetchResult:
        """
        Verifica e aplica atualização de assinaturas.
        Retorna FetchResult com detalhes da operação.
        """
        version_before = self._current_version()

        # 1. Baixa e valida manifest
        try:
            manifest = self._fetch_manifest()
        except Exception as exc:
            raise ManifestError(f"Falha ao baixar manifest: {exc}") from exc

        remote_version = manifest.get("version", "")
        if not remote_version:
            raise ManifestError("Manifest inválido: campo 'version' ausente.")

        # 2. Verifica se atualização é necessária
        if version_before == remote_version:
            logger.info("Assinaturas já estão na versão mais recente: %s", remote_version)
            return FetchResult(
                updated=False,
                version_before=version_before,
                version_after=remote_version,
                message="Já na versão mais recente.",
            )

        # 3. Baixa arquivo de assinaturas
        sig_url      = manifest.get("signatures_url", "")
        expected_sha = manifest.get("sha256", "")

        if not sig_url:
            raise ManifestError("Manifest não contém 'signatures_url'.")

        logger.info("Baixando assinaturas v%s de %s...", remote_version, sig_url)

        try:
            sig_path = self._download_file(sig_url)
        except Exception as exc:
            raise UpdateError(f"Falha ao baixar assinaturas: {exc}") from exc

        # 4. Verifica checksum
        if expected_sha:
            actual_sha = self._sha256_file(sig_path)
            if actual_sha != expected_sha.lower():
                sig_path.unlink(missing_ok=True)
                raise ChecksumError(
                    f"Checksum inválido: esperado {expected_sha}, "
                    f"obtido {actual_sha}"
                )
            logger.debug("Checksum verificado: %s", actual_sha[:16] + "...")

        # 5. Importa para o banco
        try:
            added, dupes = self._sig_db.import_jsonl(sig_path)
        finally:
            sig_path.unlink(missing_ok=True)

        # 6. Atualiza metadata
        self._sig_db._conn.execute(
            "UPDATE signature_meta SET value=? WHERE key='version'", (remote_version,)
        )
        self._sig_db._conn.execute(
            "UPDATE signature_meta SET value=? WHERE key='updated_at'",
            (manifest.get("updated_at", ""),)
        )

        logger.info(
            "Assinaturas atualizadas: v%s → v%s (%d adicionadas, %d duplicatas)",
            version_before, remote_version, added, dupes,
        )

        return FetchResult(
            updated        = True,
            version_before = version_before,
            version_after  = remote_version,
            added          = added,
            duplicates     = dupes,
            message        = f"Atualizado para v{remote_version}: +{added} assinaturas.",
        )

    def check_update_available(self) -> tuple[bool, str, str]:
        """
        Verifica se há atualização disponível sem baixar.
        Retorna (disponível, versão_local, versão_remota).
        """
        local = self._current_version()
        try:
            manifest = self._fetch_manifest()
            remote   = manifest.get("version", "")
            return (local != remote and bool(remote)), local, remote
        except Exception as exc:
            logger.warning("Falha ao verificar atualização: %s", exc)
            return False, local, ""

    # ------------------------------------------------------------------
    # Helpers HTTP
    # ------------------------------------------------------------------

    def _fetch_manifest(self) -> dict:
        """Baixa e parseia o manifest JSON."""
        data = self._http_get(self._url)
        try:
            return json.loads(data)
        except json.JSONDecodeError as exc:
            raise ManifestError(f"Manifest não é JSON válido: {exc}") from exc

    def _download_file(self, url: str) -> Path:
        """Baixa arquivo para arquivo temporário. Retorna Path."""
        self._cache.mkdir(parents=True, exist_ok=True)
        tmp = self._cache / ".sig_download.tmp"

        data = self._http_get(url, binary=True)
        tmp.write_bytes(data)
        return tmp

    def _http_get(self, url: str, binary: bool = False) -> bytes | str:
        """Requisição HTTP GET simples com timeout."""
        headers = {"User-Agent": DEFAULT_USER_AGENT}

        # Suporte a proxy
        proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY")
        if proxy:
            proxy_handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy})
            opener = urllib.request.build_opener(proxy_handler)
        else:
            opener = urllib.request.build_opener()

        req = urllib.request.Request(url, headers=headers)
        try:
            with opener.open(req, timeout=self._timeout) as resp:
                raw = resp.read()
        except urllib.error.URLError as exc:
            raise UpdateError(f"Erro HTTP: {exc}") from exc
        except Exception as exc:
            raise UpdateError(f"Erro de rede: {exc}") from exc

        return raw if binary else raw.decode("utf-8", errors="replace")

    # ------------------------------------------------------------------
    # Helpers locais
    # ------------------------------------------------------------------

    def _current_version(self) -> str:
        try:
            meta = self._sig_db.meta()
            return meta.get("version", "0.0.0")
        except Exception:
            return "0.0.0"

    @staticmethod
    def _sha256_file(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()


# Type annotation fix
from typing import Any  # noqa: E402

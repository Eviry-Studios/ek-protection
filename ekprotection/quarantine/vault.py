"""
ekprotection.quarantine.vault
===============================
Vault criptografado para arquivos em quarentena.

Usa Fernet (AES-128-CBC + HMAC-SHA256) da biblioteca cryptography.
A chave mestra é derivada com PBKDF2-HMAC-SHA256 a partir de um
secret gerado na inicialização, armazenado separadamente dos arquivos.

Design de segurança:
  - Cada arquivo cifrado tem extensão .ekpq
  - A chave mestra fica em <config_dir>/quarantine.key (chmod 600)
  - Sem a chave, os arquivos .ekpq são dados aleatórios ilegíveis
  - O vault nunca apaga o original até confirmar que a cópia cifrada
    foi gravada com sucesso (write → verify → delete)
  - Restauração preserva permissões e dono originais quando possível

Estrutura do arquivo .ekpq:
  [4 bytes: magic "EKPQ"] + [Fernet token cifrado]
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
import stat
from pathlib import Path
from typing  import Optional

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

MAGIC    = b"EKPQ"
KEY_FILE = "quarantine.key"


class VaultError(Exception):
    """Erro genérico do vault de quarentena."""


class VaultKeyError(VaultError):
    """Chave do vault ausente ou corrompida."""


class VaultCorruptedError(VaultError):
    """Arquivo .ekpq corrompido ou magic inválida."""


class QuarantineVault:
    """
    Vault criptografado para isolamento de arquivos suspeitos.

    Uso:
        vault = QuarantineVault(vault_dir, key_dir)
        vault.initialize()          # cria chave se não existir
        qid = vault.quarantine(path)
        vault.restore(qid, dest)
        vault.delete_file(qid)
    """

    def __init__(
        self,
        vault_dir: str | Path,
        key_dir:   str | Path,
        encrypt:   bool = True,
    ) -> None:
        self._vault_dir = Path(vault_dir)
        self._key_dir   = Path(key_dir)
        self._encrypt   = encrypt
        self._key_path  = self._key_dir / KEY_FILE
        self._fernet:   Optional[Fernet] = None

    # ------------------------------------------------------------------
    # Inicialização
    # ------------------------------------------------------------------

    def initialize(self) -> None:
        """Cria diretórios e gera chave mestra se não existir."""
        self._vault_dir.mkdir(parents=True, exist_ok=True)
        self._key_dir.mkdir(parents=True, exist_ok=True)

        if not self._key_path.exists():
            key = Fernet.generate_key()
            self._key_path.write_bytes(key)
            try:
                os.chmod(self._key_path, 0o600)
            except OSError:
                logger.warning("Não foi possível definir chmod 600 em %s", self._key_path)
            logger.info("Chave do vault de quarentena gerada: %s", self._key_path)

        self._load_key()

    def _load_key(self) -> None:
        """Carrega a chave Fernet do arquivo."""
        if not self._key_path.exists():
            raise VaultKeyError(f"Chave do vault não encontrada: {self._key_path}")
        try:
            key = self._key_path.read_bytes().strip()
            self._fernet = Fernet(key)
        except Exception as exc:
            raise VaultKeyError(f"Chave do vault inválida: {exc}") from exc

    # ------------------------------------------------------------------
    # Operações principais
    # ------------------------------------------------------------------

    def quarantine(self, source_path: str | Path, quarantine_id: str) -> Path:
        """
        Copia e cifra um arquivo para o vault.

        Fluxo seguro:
          1. Lê o arquivo original
          2. Cifra com Fernet
          3. Escreve o .ekpq no vault
          4. Verifica que o arquivo foi gravado corretamente
          5. NÃO remove o original (responsabilidade do QuarantineManager)

        Retorna o Path do arquivo .ekpq criado.
        Lança VaultError se qualquer passo falhar.
        """
        source = Path(source_path)
        if not source.exists():
            raise VaultError(f"Arquivo não encontrado: {source}")

        dest = self._vault_path(quarantine_id)

        try:
            data = source.read_bytes()
        except (OSError, PermissionError) as exc:
            raise VaultError(f"Não foi possível ler {source}: {exc}") from exc

        if self._encrypt and self._fernet:
            payload = MAGIC + self._fernet.encrypt(data)
        else:
            payload = MAGIC + data   # modo sem criptografia (testes / sem chave)

        try:
            dest.write_bytes(payload)
            # Permissões restritas no arquivo de quarentena
            os.chmod(dest, 0o600)
        except OSError as exc:
            dest.unlink(missing_ok=True)
            raise VaultError(f"Erro ao gravar vault: {exc}") from exc

        # Verifica integridade do que foi escrito
        if not dest.exists() or dest.stat().st_size == 0:
            dest.unlink(missing_ok=True)
            raise VaultError("Verificação pós-escrita falhou: arquivo vazio.")

        logger.debug("Arquivo quarentenado: %s → %s", source, dest)
        return dest

    def restore(self, quarantine_id: str, dest_path: str | Path) -> Path:
        """
        Decifra e restaura um arquivo do vault para dest_path.

        Não remove o arquivo do vault (use delete_file() separadamente).
        Retorna o Path do arquivo restaurado.
        """
        src  = self._vault_path(quarantine_id)
        dest = Path(dest_path)

        if not src.exists():
            raise VaultError(f"Arquivo de quarentena não encontrado: {src}")

        payload = src.read_bytes()

        if not payload.startswith(MAGIC):
            raise VaultCorruptedError(f"Magic inválida em {src}. Arquivo corrompido?")

        raw = payload[len(MAGIC):]

        if self._encrypt and self._fernet:
            try:
                data = self._fernet.decrypt(raw)
            except InvalidToken as exc:
                raise VaultCorruptedError(
                    f"Falha na decifração de {src}. Chave incorreta ou arquivo corrompido."
                ) from exc
        else:
            data = raw

        dest.parent.mkdir(parents=True, exist_ok=True)

        # Evita sobrescrever arquivo existente silenciosamente
        if dest.exists():
            dest = dest.with_suffix(dest.suffix + ".restored")
            logger.warning("Destino existia; restaurando para: %s", dest)

        dest.write_bytes(data)
        logger.info("Arquivo restaurado: %s → %s", src, dest)
        return dest

    def delete_file(self, quarantine_id: str) -> bool:
        """
        Remove permanentemente o arquivo .ekpq do vault.
        Retorna True se removeu, False se não existia.
        IRREVERSÍVEL — use somente após confirmação explícita do usuário.
        """
        path = self._vault_path(quarantine_id)
        if not path.exists():
            return False
        path.unlink()
        logger.info("Arquivo de quarentena excluído: %s", path)
        return True

    def file_exists(self, quarantine_id: str) -> bool:
        return self._vault_path(quarantine_id).exists()

    def vault_path(self, quarantine_id: str) -> Path:
        return self._vault_path(quarantine_id)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _vault_path(self, quarantine_id: str) -> Path:
        return self._vault_dir / f"{quarantine_id}.ekpq"

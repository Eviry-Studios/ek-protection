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
  - Restauração cria arquivo novo 0600 (dono = quem restaura), nunca segue
    symlink nem sobrescreve, e recusa diretório de destino que passa por
    symlink (2026-11-10). Modo/dono originais NÃO são preservados.

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

# Criação exclusiva: falha se o nome já existe (inclusive symlink pendente)
# e nunca segue symlink no último componente.
_O_NEW_FILE = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC

# Tentativas de nome livre no restore: nome, nome.restored, nome.restored.1..N
_RESTORE_MAX_SUFFIX = 20


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        view = view[n:]


def _write_new_file(path: Path, data: bytes) -> None:
    """Grava arquivo novo 0600 sem janela com modo mais aberto."""
    fd = os.open(path, _O_NEW_FILE, 0o600)
    try:
        os.fchmod(fd, 0o600)
        _write_all(fd, data)
    except BaseException:
        os.close(fd)
        path.unlink(missing_ok=True)
        raise
    os.close(fd)


def _open_dest_dir(directory: Path) -> int:
    """
    Abre o diretório de destino do restore e devolve o fd.

    O restore roda como root (`sudo ekp quarantine restore`) e o nome do
    arquivo é o nome original, que o autor do arquivo quarentenado conhece.
    Se o caminho pedido passa por symlink, quem controla um dos diretórios
    do caminho pode desviar a escrita (ex: ~/restored -> /etc/cron.d). Por
    isso o caminho real do fd aberto tem que ser igual ao pedido.
    """
    requested = os.path.normpath(os.path.abspath(directory))
    try:
        fd = os.open(requested, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError as exc:
        raise VaultError(f"Diretório de destino inválido {requested}: {exc}") from exc
    try:
        real = os.readlink(f"/proc/self/fd/{fd}")
    except OSError:
        real = os.path.realpath(requested)
    if real != requested:
        os.close(fd)
        raise VaultError(
            f"Diretório de destino {requested} passa por symlink (aponta para "
            f"{real}). Restauração recusada; use o caminho real se for intencional."
        )
    return fd


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
        self._key_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

        if not self._key_path.exists():
            # Nasce 0600: write_bytes + chmod deixava a chave legível pelo
            # umask (0644 como root) até o chmod.
            try:
                _write_new_file(self._key_path, Fernet.generate_key())
                logger.info("Chave do vault de quarentena gerada: %s", self._key_path)
            except FileExistsError:
                pass   # outro processo criou ao mesmo tempo; _load_key lê a dele

        self._load_key()

    def _load_key(self) -> None:
        """Carrega a chave Fernet do arquivo."""
        if not self._key_path.exists():
            raise VaultKeyError(f"Chave do vault não encontrada: {self._key_path}")
        self._enforce_key_permissions()
        try:
            key = self._key_path.read_bytes().strip()
            self._fernet = Fernet(key)
        except Exception as exc:
            raise VaultKeyError(f"Chave do vault inválida: {exc}") from exc

    def _enforce_key_permissions(self) -> None:
        """
        Corrige permissões da chave mestra se tiverem se afrouxado desde a
        criação (ex: restore de backup, reinstalação por cima, extração de
        tar/zip que não preserva modo de arquivo) — só era garantido 0600 no
        momento da criação, nunca reverificado num load posterior (achado
        real da tarefa diária, 2026-09-05). Sem isso, a chave que decifra
        todo o conteúdo em quarentena (que pode incluir wallets/credenciais
        capturadas por um scan) podia ficar legível por qualquer usuário
        local sem nenhum aviso.
        """
        try:
            mode = stat.S_IMODE(self._key_path.stat().st_mode)
            if mode != 0o600:
                os.chmod(self._key_path, 0o600)
                logger.warning(
                    "Permissões da chave do vault de quarentena estavam %o, "
                    "corrigidas para 600: %s", mode, self._key_path,
                )
        except OSError as exc:
            logger.warning(
                "Não foi possível verificar/corrigir permissões de %s: %s",
                self._key_path, exc,
            )

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
            _write_new_file(dest, payload)
        except OSError as exc:
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

        if dest.name in ("", ".", ".."):
            raise VaultError(f"Nome de destino inválido: {dest}")

        dest.parent.mkdir(parents=True, exist_ok=True)
        dir_fd = _open_dest_dir(dest.parent)
        try:
            name = self._create_restored(dir_fd, dest.name, data)
        finally:
            os.close(dir_fd)

        restored = Path(os.path.normpath(os.path.abspath(dest.parent))) / name
        if name != dest.name:
            logger.warning("Destino existia; restaurando para: %s", restored)
        logger.info("Arquivo restaurado: %s → %s", src, restored)
        return restored

    @staticmethod
    def _create_restored(dir_fd: int, name: str, data: bytes) -> str:
        """
        Cria o arquivo restaurado dentro de dir_fd e devolve o nome usado.

        Nunca sobrescreve e nunca segue symlink: nome ocupado (arquivo,
        symlink, mesmo pendente) passa pro próximo sufixo. Sempre 0600, porque
        o arquivo pode ser wallet/chave pega por falso positivo e o umask do
        root deixaria 0644.
        """
        candidates = [name, f"{name}.restored"] + [
            f"{name}.restored.{i}" for i in range(1, _RESTORE_MAX_SUFFIX + 1)
        ]
        for candidate in candidates:
            try:
                fd = os.open(candidate, _O_NEW_FILE, 0o600, dir_fd=dir_fd)
            except FileExistsError:
                continue
            except OSError as exc:
                raise VaultError(f"Não foi possível criar {candidate}: {exc}") from exc
            try:
                os.fchmod(fd, 0o600)
                _write_all(fd, data)
            except OSError as exc:
                os.close(fd)
                os.unlink(candidate, dir_fd=dir_fd)
                raise VaultError(f"Erro ao gravar {candidate}: {exc}") from exc
            os.close(fd)
            return candidate
        raise VaultError(
            f"Nenhum nome livre para restaurar {name} ({len(candidates)} tentativas)."
        )

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

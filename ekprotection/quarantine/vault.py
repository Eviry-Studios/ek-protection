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
  - Quarentena lê a origem pelo diretório real aberto uma vez (recusa
    symlink no caminho e no arquivo, só arquivo regular) e só remove o
    original se ainda for o mesmo inode cifrado (2026-11-11).
  - Restauração cria arquivo novo 0600 (dono = quem restaura), nunca segue
    symlink nem sobrescreve, e recusa diretório de destino que passa por
    symlink (2026-11-10). Modo/dono originais NÃO são preservados.

Estrutura do arquivo .ekpq:
  [4 bytes: magic "EKPQ"] + [Fernet token cifrado]
"""

from __future__ import annotations

import errno
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


def _read_all(fd: int) -> bytes:
    chunks = []
    while True:
        chunk = os.read(fd, 1 << 20)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


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


def _open_pinned_dir(directory: Path | str, what: str) -> int:
    """
    Abre um diretório e devolve o fd, recusando caminho que passa por symlink.

    O caminho real do fd aberto tem que ser igual ao pedido (absoluto,
    normalizado). Pega symlink em qualquer componente e não tem corrida,
    porque toda operação seguinte é feita nesse mesmo fd (`dir_fd=`).
    """
    requested = os.path.normpath(os.path.abspath(directory))
    try:
        fd = os.open(requested, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError as exc:
        raise VaultError(f"Diretório {what} inválido {requested}: {exc}") from exc
    try:
        real = os.readlink(f"/proc/self/fd/{fd}")
    except OSError:
        real = os.path.realpath(requested)
    if real != requested:
        os.close(fd)
        raise VaultError(
            f"Diretório {what} {requested} passa por symlink (aponta para "
            f"{real}). Operação recusada; use o caminho real se for intencional."
        )
    return fd


def _open_dest_dir(directory: Path) -> int:
    """
    Diretório de destino do restore.

    O restore roda como root (`sudo ekp quarantine restore`) e o nome do
    arquivo é o nome original, que o autor do arquivo quarentenado conhece.
    Se o caminho pedido passa por symlink, quem controla um dos diretórios
    do caminho pode desviar a escrita (ex: ~/restored -> /etc/cron.d).
    """
    return _open_pinned_dir(directory, "de destino")


class QuarantineSource:
    """
    Origem de uma quarentena, presa ao diretório real e ao inode lido.

    A quarentena roda como root (auto-quarentena do daemon) sobre arquivo
    num diretório que o autor do arquivo controla. Entre a detecção e o
    `unlink`, ele pode trocar o diretório por symlink (`dl -> /etc`) e o
    root apagaria `/etc/<nome>` (2026-11-11). Por isso o diretório é aberto
    uma vez (recusando symlink), o arquivo é lido por `openat` com
    O_NOFOLLOW nesse fd, e o `remove()` só apaga se o nome ainda aponta
    pro mesmo inode que foi cifrado, também via `unlinkat` no mesmo fd.
    """

    def __init__(self, dir_fd: int, name: str, st: os.stat_result,
                 real_path: str, sha256: str, dest: Path) -> None:
        self._dir_fd   = dir_fd
        self.name      = name
        self.size      = st.st_size
        self._dev_ino  = (st.st_dev, st.st_ino)
        self.real_path = real_path
        self.sha256    = sha256      # sha do conteúdo que foi cifrado
        self.dest      = dest

    def remove(self) -> None:
        """Remove o original se ainda for o mesmo inode cifrado."""
        if self._dir_fd < 0:
            raise VaultError("Origem já fechada.")
        try:
            cur = os.stat(self.name, dir_fd=self._dir_fd, follow_symlinks=False)
        except OSError as exc:
            raise VaultError(f"Original sumiu antes da remoção: {exc}") from exc
        if (cur.st_dev, cur.st_ino) != self._dev_ino:
            raise VaultError(
                f"{self.real_path} foi trocado depois de cifrado; original NÃO removido."
            )
        # Mesmo que o nome seja trocado entre o stat e o unlink, o unlinkat
        # só remove uma entrada deste diretório (já verificado como real).
        os.unlink(self.name, dir_fd=self._dir_fd)

    def close(self) -> None:
        if self._dir_fd >= 0:
            os.close(self._dir_fd)
            self._dir_fd = -1

    def __enter__(self) -> "QuarantineSource":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


_O_READ_SRC = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


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
        Copia e cifra um arquivo para o vault. NÃO remove o original.

        Atalho de `quarantine_open()` que já fecha a origem. Quem precisa
        remover o original depois (QuarantineManager) usa `quarantine_open`.
        """
        with self.quarantine_open(source_path, quarantine_id) as src:
            return src.dest

    def quarantine_open(self, source_path: str | Path, quarantine_id: str) -> QuarantineSource:
        """
        Cifra um arquivo para o vault e devolve a origem presa (ver
        QuarantineSource) pra remoção segura. Quem chama fecha (`close()`
        ou `with`).

        Fluxo seguro:
          1. Abre o diretório real (recusa caminho com symlink)
          2. Abre o arquivo com O_NOFOLLOW|O_NONBLOCK nesse fd; só arquivo regular
          3. Lê pelo fd (sha256 calculado do que foi lido), cifra com Fernet
          4. Escreve o .ekpq no vault e verifica
          5. NÃO remove o original (responsabilidade do QuarantineManager)

        Lança VaultError se qualquer passo falhar.
        """
        absolute = os.path.normpath(os.path.abspath(source_path))
        parent, name = os.path.split(absolute)
        if not name or name in (".", ".."):
            raise VaultError(f"Caminho de origem inválido: {source_path}")

        try:
            dir_fd = _open_pinned_dir(parent, "de origem")
        except VaultError as exc:
            if isinstance(exc.__cause__, FileNotFoundError):
                raise VaultError(f"Arquivo não encontrado: {absolute}") from exc
            raise
        try:
            try:
                fd = os.open(name, _O_READ_SRC, dir_fd=dir_fd)
            except FileNotFoundError as exc:
                raise VaultError(f"Arquivo não encontrado: {absolute}") from exc
            except OSError as exc:
                # ELOOP = último componente é symlink (O_NOFOLLOW)
                kind = "é symlink" if exc.errno == errno.ELOOP else str(exc)
                raise VaultError(
                    f"Não foi possível abrir {absolute} ({kind}). Quarentena recusada, "
                    f"nada foi lido nem removido."
                ) from exc
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode):
                    raise VaultError(f"{absolute} não é arquivo regular. Quarentena recusada.")
                data = _read_all(fd)
            except OSError as exc:
                raise VaultError(f"Não foi possível ler {absolute}: {exc}") from exc
            finally:
                os.close(fd)

            dest = self._vault_path(quarantine_id)
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
        except BaseException:
            os.close(dir_fd)
            raise

        logger.debug("Arquivo quarentenado: %s → %s", absolute, dest)
        return QuarantineSource(dir_fd, name, st, absolute,
                                hashlib.sha256(data).hexdigest(), dest)

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

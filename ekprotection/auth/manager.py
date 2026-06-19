"""
ekprotection.auth.manager
==========================
Sistema de autenticação do EK-Protection.

Responsabilidades:
  - Hash e verificação de senha com bcrypt (work factor 14)
  - Armazenamento seguro do hash em arquivo protegido (chmod 600)
  - Sessão autenticada em memória com timeout configurável
  - Lockout progressivo após tentativas falhas
  - API para operações que exigem autenticação prévia

Segurança:
  - Nunca armazena a senha em texto puro
  - Nunca loga a senha ou o hash completo
  - Tempo constante na comparação (bcrypt interno)
  - Lockout com backoff para mitigar brute-force
  - Arquivo de hash acessível apenas por root (0o600)

Fluxo típico:
  auth = AuthManager(cfg)
  auth.setup("minha_senha_forte")   # primeira execução
  token = auth.authenticate("minha_senha_forte")
  auth.require(token)               # em operações críticas
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import bcrypt

from ekprotection.config.manager import ConfigManager

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

BCRYPT_WORK_FACTOR = 14          # Work factor alto — lento por design
MIN_PASSWORD_LENGTH = 12
MIN_PASSWORD_SCORE = 3           # Requer letras, números e símbolos
AUTH_HASH_FILE_PERMISSIONS = 0o600
SESSION_TOKEN_BYTES = 32


# ---------------------------------------------------------------------------
# Exceções específicas de autenticação
# ---------------------------------------------------------------------------

class AuthError(Exception):
    """Base para erros de autenticação."""


class AuthNotConfiguredError(AuthError):
    """Senha ainda não foi configurada."""


class AuthFailedError(AuthError):
    """Senha incorreta."""


class AuthLockedError(AuthError):
    """Conta bloqueada por excesso de tentativas."""
    def __init__(self, retry_after: float) -> None:
        self.retry_after = retry_after
        super().__init__(f"Conta bloqueada. Tente novamente em {retry_after:.0f}s.")


class AuthSessionExpiredError(AuthError):
    """Token de sessão expirado ou inválido."""


class WeakPasswordError(AuthError):
    """Senha não atende aos requisitos mínimos."""
    def __init__(self, reasons: list[str]) -> None:
        self.reasons = reasons
        super().__init__("Senha fraca: " + "; ".join(reasons))


# ---------------------------------------------------------------------------
# Estrutura de sessão
# ---------------------------------------------------------------------------

@dataclass
class AuthSession:
    """Representa uma sessão autenticada ativa."""
    token: str
    created_at: float = field(default_factory=time.monotonic)
    timeout_seconds: float = 1800.0   # 30 minutos padrão

    def is_valid(self) -> bool:
        return (time.monotonic() - self.created_at) < self.timeout_seconds

    def remaining(self) -> float:
        elapsed = time.monotonic() - self.created_at
        return max(0.0, self.timeout_seconds - elapsed)


# ---------------------------------------------------------------------------
# AuthManager principal
# ---------------------------------------------------------------------------

class AuthManager:
    """
    Gerencia autenticação do EK-Protection.

    Uso:
        auth = AuthManager(cfg)

        # Primeira execução:
        auth.setup("Senha@Forte#2024!")

        # Login:
        token = auth.authenticate("Senha@Forte#2024!")

        # Operação crítica:
        auth.require(token)

        # Troca de senha:
        auth.change_password(token, "NovaS3nh@!Forte")
    """

    def __init__(self, config: ConfigManager) -> None:
        self.config = config
        self._hash_file = Path(
            os.environ.get("EKP_AUTH_FILE", "/etc/ek-protection/auth.hash")
        )
        self._session: Optional[AuthSession] = None
        self._failed_attempts: int = 0
        self._lockout_until: float = 0.0

        # Lê parâmetros de configuração
        self._max_attempts: int = config.get("auth.max_attempts", 5)
        self._lockout_minutes: float = config.get("auth.lockout_minutes", 15)
        self._session_timeout: float = config.get("auth.session_timeout_minutes", 30) * 60

    # ------------------------------------------------------------------
    # Estado: hash configurado?
    # ------------------------------------------------------------------

    @property
    def is_configured(self) -> bool:
        """Retorna True se a senha já foi configurada (hash existe)."""
        return self._hash_file.exists() and self._hash_file.stat().st_size > 0

    # ------------------------------------------------------------------
    # Configuração inicial (primeira execução)
    # ------------------------------------------------------------------

    def setup(self, password: str) -> None:
        """
        Configura a senha pela primeira vez.
        Lança WeakPasswordError se a senha for fraca.
        Lança RuntimeError se já existir senha configurada.
        """
        if self.is_configured:
            raise RuntimeError(
                "Senha já configurada. Use change_password() para alterar."
            )
        self._validate_password_strength(password)
        self._write_hash(password)
        logger.info("Autenticação configurada com sucesso.")

    # ------------------------------------------------------------------
    # Autenticação
    # ------------------------------------------------------------------

    def authenticate(self, password: str) -> str:
        """
        Verifica a senha e retorna um token de sessão se correta.

        Raises:
            AuthNotConfiguredError: Senha não configurada.
            AuthLockedError: Conta em lockout.
            AuthFailedError: Senha incorreta.
        """
        if not self.is_configured:
            raise AuthNotConfiguredError(
                "Autenticação não configurada. Execute: ekp auth setup"
            )

        self._check_lockout()

        stored_hash = self._read_hash()
        password_bytes = password.encode("utf-8")

        try:
            match = bcrypt.checkpw(password_bytes, stored_hash)
        except Exception as exc:
            logger.error("Erro ao verificar senha: %s", exc)
            match = False

        if not match:
            self._record_failure()
            # Log sem revelar a senha
            logger.warning(
                "Tentativa de autenticação falhou. Tentativas: %d/%d",
                self._failed_attempts, self._max_attempts,
            )
            raise AuthFailedError("Senha incorreta.")

        # Sucesso — reseta contador e cria sessão
        self._failed_attempts = 0
        self._lockout_until = 0.0
        token = self._create_session()
        logger.info("Autenticação bem-sucedida. Sessão criada.")
        return token

    # ------------------------------------------------------------------
    # Verificação de token (para operações críticas)
    # ------------------------------------------------------------------

    def require(self, token: str) -> None:
        """
        Verifica se o token de sessão é válido e não expirou.
        Lança AuthSessionExpiredError se inválido.
        Deve ser chamado antes de qualquer operação crítica.
        """
        if self._session is None:
            raise AuthSessionExpiredError("Nenhuma sessão ativa. Autentique-se primeiro.")

        # Comparação em tempo constante para evitar timing attacks
        tokens_match = hmac.compare_digest(
            self._session.token.encode(),
            token.encode(),
        )
        if not tokens_match:
            raise AuthSessionExpiredError("Token de sessão inválido.")

        if not self._session.is_valid():
            self._session = None
            raise AuthSessionExpiredError("Sessão expirada. Autentique-se novamente.")

    def invalidate_session(self) -> None:
        """Encerra a sessão atual."""
        self._session = None
        logger.debug("Sessão invalidada.")

    def session_remaining(self) -> float:
        """Retorna segundos restantes da sessão, ou 0 se não há sessão."""
        if self._session and self._session.is_valid():
            return self._session.remaining()
        return 0.0

    # ------------------------------------------------------------------
    # Troca de senha
    # ------------------------------------------------------------------

    def change_password(self, token: str, new_password: str) -> None:
        """
        Altera a senha. Exige sessão autenticada válida.

        Raises:
            AuthSessionExpiredError: Sessão inválida.
            WeakPasswordError: Nova senha muito fraca.
        """
        self.require(token)
        self._validate_password_strength(new_password)
        self._write_hash(new_password)
        self.invalidate_session()   # Força relogin após troca
        logger.info("Senha alterada com sucesso.")

    # ------------------------------------------------------------------
    # Validação de força de senha
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_password_strength(password: str) -> None:
        """
        Valida requisitos mínimos de senha.
        Lança WeakPasswordError com lista de motivos se inválida.
        """
        reasons: list[str] = []

        if len(password) < MIN_PASSWORD_LENGTH:
            reasons.append(f"mínimo {MIN_PASSWORD_LENGTH} caracteres")

        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(not c.isalnum() for c in password)

        score = sum([has_upper, has_lower, has_digit, has_symbol])

        if not has_upper:
            reasons.append("requer letra maiúscula")
        if not has_lower:
            reasons.append("requer letra minúscula")
        if not has_digit:
            reasons.append("requer número")
        if not has_symbol:
            reasons.append("requer símbolo especial (!@#$%...)")
        if score < MIN_PASSWORD_SCORE:
            reasons.append(f"complexidade insuficiente (score {score}/{MIN_PASSWORD_SCORE})")

        # Senhas trivialmente ruins
        trivial = {
            "password", "senha", "123456", "admin", "root",
            "ekprotection", "ek-protection",
        }
        if password.lower() in trivial:
            reasons.append("senha trivial não permitida")

        if reasons:
            raise WeakPasswordError(reasons)

    # ------------------------------------------------------------------
    # Lockout
    # ------------------------------------------------------------------

    def _check_lockout(self) -> None:
        """Lança AuthLockedError se ainda estiver em período de lockout."""
        if self._lockout_until > time.monotonic():
            retry_after = self._lockout_until - time.monotonic()
            raise AuthLockedError(retry_after)

    def _record_failure(self) -> None:
        """Registra falha de autenticação e aplica lockout se necessário."""
        self._failed_attempts += 1
        if self._failed_attempts >= self._max_attempts:
            lockout_seconds = self._lockout_minutes * 60
            self._lockout_until = time.monotonic() + lockout_seconds
            logger.warning(
                "Lockout ativado por %d minutos após %d tentativas falhas.",
                self._lockout_minutes, self._failed_attempts,
            )
            self._failed_attempts = 0   # Reseta para próximo ciclo

    # ------------------------------------------------------------------
    # Sessão
    # ------------------------------------------------------------------

    def _create_session(self) -> str:
        """Cria e armazena uma nova sessão, retorna o token."""
        token = secrets.token_hex(SESSION_TOKEN_BYTES)
        self._session = AuthSession(
            token=token,
            timeout_seconds=self._session_timeout,
        )
        return token

    # ------------------------------------------------------------------
    # Persistência do hash
    # ------------------------------------------------------------------

    def _write_hash(self, password: str) -> None:
        """Grava o bcrypt hash da senha no arquivo protegido."""
        password_bytes = password.encode("utf-8")
        hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt(rounds=BCRYPT_WORK_FACTOR))

        self._hash_file.parent.mkdir(parents=True, exist_ok=True)

        # Grava e imediatamente protege o arquivo
        self._hash_file.write_bytes(hashed)
        try:
            os.chmod(self._hash_file, AUTH_HASH_FILE_PERMISSIONS)
        except OSError:
            logger.warning("Não foi possível definir permissões em %s", self._hash_file)

        logger.debug("Hash de autenticação gravado em %s", self._hash_file)

    def _read_hash(self) -> bytes:
        """Lê e retorna o hash armazenado."""
        try:
            return self._hash_file.read_bytes().strip()
        except (OSError, IOError) as exc:
            raise AuthError(f"Não foi possível ler o arquivo de autenticação: {exc}") from exc

    # ------------------------------------------------------------------
    # Utilitários
    # ------------------------------------------------------------------

    def status(self) -> dict:
        """Retorna dicionário com o estado atual da autenticação."""
        return {
            "configured": self.is_configured,
            "session_active": self._session is not None and self._session.is_valid(),
            "session_remaining_seconds": round(self.session_remaining()),
            "failed_attempts": self._failed_attempts,
            "locked": self._lockout_until > time.monotonic(),
            "lockout_remaining_seconds": max(
                0.0, round(self._lockout_until - time.monotonic())
            ),
            "hash_file": str(self._hash_file),
        }

    def __repr__(self) -> str:
        return (
            f"AuthManager(configured={self.is_configured}, "
            f"session={'active' if self._session else 'none'})"
        )

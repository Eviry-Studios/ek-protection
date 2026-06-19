"""
tests/test_auth.py
===================
Testes do sistema de autenticação (Patch 2).

Cobre:
  - Validação de força de senha
  - Setup inicial
  - Autenticação correta e incorreta
  - Lockout após falhas
  - Sessão: criação, timeout, invalidação
  - Troca de senha
  - Reset
  - Decoradores require_auth e authenticated_operation
"""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import patch

import pytest

from ekprotection.auth.manager import (
    AuthManager,
    AuthError,
    AuthFailedError,
    AuthLockedError,
    AuthNotConfiguredError,
    AuthSessionExpiredError,
    WeakPasswordError,
)
from ekprotection.auth.decorators import require_auth, authenticated_operation
from ekprotection.config.manager import ConfigManager


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

STRONG_PASSWORD = "EviRy@Korp#2024!"
NEW_PASSWORD    = "Novo$Pass#9876Xz"

@pytest.fixture
def cfg(tmp_path: Path) -> ConfigManager:
    manager = ConfigManager(tmp_path / "config.yaml")
    manager.load()
    return manager


@pytest.fixture
def auth(cfg: ConfigManager, tmp_path: Path) -> AuthManager:
    """AuthManager com arquivo de hash em diretório temporário."""
    manager = AuthManager(cfg)
    # Redireciona o arquivo de hash para tmp
    manager._hash_file = tmp_path / "auth.hash"
    return manager


@pytest.fixture
def configured_auth(auth: AuthManager) -> AuthManager:
    """AuthManager já configurado com STRONG_PASSWORD."""
    auth.setup(STRONG_PASSWORD)
    return auth


# ---------------------------------------------------------------------------
# Testes: validação de senha
# ---------------------------------------------------------------------------

class TestPasswordValidation:
    def test_strong_password_passes(self) -> None:
        AuthManager._validate_password_strength(STRONG_PASSWORD)  # não lança

    def test_too_short_fails(self) -> None:
        with pytest.raises(WeakPasswordError) as exc_info:
            AuthManager._validate_password_strength("Abc1!")
        assert any("caracteres" in r for r in exc_info.value.reasons)

    def test_no_uppercase_fails(self) -> None:
        with pytest.raises(WeakPasswordError) as exc_info:
            AuthManager._validate_password_strength("abcdefghij1!")
        assert any("maiúscula" in r for r in exc_info.value.reasons)

    def test_no_lowercase_fails(self) -> None:
        with pytest.raises(WeakPasswordError) as exc_info:
            AuthManager._validate_password_strength("ABCDEFGHIJ1!")
        assert any("minúscula" in r for r in exc_info.value.reasons)

    def test_no_digit_fails(self) -> None:
        with pytest.raises(WeakPasswordError) as exc_info:
            AuthManager._validate_password_strength("AbcDefGhiJkl!")
        assert any("número" in r for r in exc_info.value.reasons)

    def test_no_symbol_fails(self) -> None:
        with pytest.raises(WeakPasswordError) as exc_info:
            AuthManager._validate_password_strength("AbcDefGhiJkl1")
        assert any("símbolo" in r for r in exc_info.value.reasons)

    def test_trivial_password_fails(self) -> None:
        with pytest.raises(WeakPasswordError) as exc_info:
            AuthManager._validate_password_strength("password")
        assert any("trivial" in r for r in exc_info.value.reasons)

    def test_weak_password_error_has_reasons(self) -> None:
        with pytest.raises(WeakPasswordError) as exc_info:
            AuthManager._validate_password_strength("abc")
        assert len(exc_info.value.reasons) > 0


# ---------------------------------------------------------------------------
# Testes: setup
# ---------------------------------------------------------------------------

class TestSetup:
    def test_setup_creates_hash_file(self, auth: AuthManager) -> None:
        assert not auth.is_configured
        auth.setup(STRONG_PASSWORD)
        assert auth.is_configured
        assert auth._hash_file.exists()

    def test_setup_with_weak_password_raises(self, auth: AuthManager) -> None:
        with pytest.raises(WeakPasswordError):
            auth.setup("fraca")

    def test_double_setup_raises(self, configured_auth: AuthManager) -> None:
        with pytest.raises(RuntimeError, match="já configurada"):
            configured_auth.setup(STRONG_PASSWORD)

    def test_hash_file_not_plaintext(self, auth: AuthManager) -> None:
        auth.setup(STRONG_PASSWORD)
        content = auth._hash_file.read_bytes()
        assert STRONG_PASSWORD.encode() not in content
        assert content.startswith(b"$2b$")   # prefixo bcrypt


# ---------------------------------------------------------------------------
# Testes: autenticação
# ---------------------------------------------------------------------------

class TestAuthentication:
    def test_correct_password_returns_token(self, configured_auth: AuthManager) -> None:
        token = configured_auth.authenticate(STRONG_PASSWORD)
        assert isinstance(token, str)
        assert len(token) == 64  # 32 bytes hex = 64 chars

    def test_wrong_password_raises(self, configured_auth: AuthManager) -> None:
        with pytest.raises(AuthFailedError):
            configured_auth.authenticate("SenhaErrada#123!")

    def test_not_configured_raises(self, auth: AuthManager) -> None:
        with pytest.raises(AuthNotConfiguredError):
            auth.authenticate(STRONG_PASSWORD)

    def test_tokens_are_unique(self, configured_auth: AuthManager) -> None:
        # Invalida sessão entre autenticações para gerar novos tokens
        t1 = configured_auth.authenticate(STRONG_PASSWORD)
        configured_auth.invalidate_session()
        t2 = configured_auth.authenticate(STRONG_PASSWORD)
        assert t1 != t2

    def test_failed_attempts_increment(self, configured_auth: AuthManager) -> None:
        for _ in range(2):
            with pytest.raises(AuthFailedError):
                configured_auth.authenticate("Errado@Senha#99!")
        assert configured_auth._failed_attempts == 2

    def test_success_resets_failed_attempts(self, configured_auth: AuthManager) -> None:
        with pytest.raises(AuthFailedError):
            configured_auth.authenticate("Errado@Senha#99!")
        configured_auth.authenticate(STRONG_PASSWORD)
        assert configured_auth._failed_attempts == 0


# ---------------------------------------------------------------------------
# Testes: lockout
# ---------------------------------------------------------------------------

class TestLockout:
    def test_lockout_after_max_attempts(self, cfg: ConfigManager, tmp_path: Path) -> None:
        cfg.set("auth.max_attempts", 3)
        cfg.set("auth.lockout_minutes", 1)
        auth = AuthManager(cfg)
        auth._hash_file = tmp_path / "auth.hash"
        auth.setup(STRONG_PASSWORD)

        for _ in range(3):
            try:
                auth.authenticate("Errada@Pass#9999!")
            except (AuthFailedError, AuthLockedError):
                pass

        with pytest.raises(AuthLockedError) as exc_info:
            auth.authenticate(STRONG_PASSWORD)
        assert exc_info.value.retry_after > 0

    def test_lockout_expires(self, cfg: ConfigManager, tmp_path: Path) -> None:
        cfg.set("auth.max_attempts", 2)
        cfg.set("auth.lockout_minutes", 0.0001)  # ~6ms
        auth = AuthManager(cfg)
        auth._hash_file = tmp_path / "auth.hash"
        auth.setup(STRONG_PASSWORD)

        for _ in range(2):
            try:
                auth.authenticate("Errada@Pass#9999!")
            except (AuthFailedError, AuthLockedError):
                pass

        time.sleep(0.02)  # espera lockout expirar
        # Deve conseguir autenticar agora
        token = auth.authenticate(STRONG_PASSWORD)
        assert token is not None


# ---------------------------------------------------------------------------
# Testes: sessão
# ---------------------------------------------------------------------------

class TestSession:
    def test_valid_token_passes_require(self, configured_auth: AuthManager) -> None:
        token = configured_auth.authenticate(STRONG_PASSWORD)
        configured_auth.require(token)  # não deve lançar

    def test_invalid_token_raises(self, configured_auth: AuthManager) -> None:
        configured_auth.authenticate(STRONG_PASSWORD)
        with pytest.raises(AuthSessionExpiredError):
            configured_auth.require("token_invalido_abc123")

    def test_no_session_raises(self, configured_auth: AuthManager) -> None:
        with pytest.raises(AuthSessionExpiredError):
            configured_auth.require("qualquer_token")

    def test_invalidate_session(self, configured_auth: AuthManager) -> None:
        token = configured_auth.authenticate(STRONG_PASSWORD)
        configured_auth.invalidate_session()
        with pytest.raises(AuthSessionExpiredError):
            configured_auth.require(token)

    def test_expired_session_raises(self, configured_auth: AuthManager) -> None:
        token = configured_auth.authenticate(STRONG_PASSWORD)
        # Simula expiração retroagindo o created_at
        assert configured_auth._session is not None
        configured_auth._session.created_at -= 9999
        with pytest.raises(AuthSessionExpiredError, match="expirada"):
            configured_auth.require(token)

    def test_session_remaining_decreases(self, configured_auth: AuthManager) -> None:
        configured_auth.authenticate(STRONG_PASSWORD)
        r1 = configured_auth.session_remaining()
        time.sleep(0.05)
        r2 = configured_auth.session_remaining()
        assert r2 < r1

    def test_no_session_remaining_is_zero(self, auth: AuthManager) -> None:
        assert auth.session_remaining() == 0.0


# ---------------------------------------------------------------------------
# Testes: troca de senha
# ---------------------------------------------------------------------------

class TestChangePassword:
    def test_change_requires_valid_token(self, configured_auth: AuthManager) -> None:
        with pytest.raises(AuthSessionExpiredError):
            configured_auth.change_password("token_invalido", NEW_PASSWORD)

    def test_change_with_weak_password_raises(self, configured_auth: AuthManager) -> None:
        token = configured_auth.authenticate(STRONG_PASSWORD)
        with pytest.raises(WeakPasswordError):
            configured_auth.change_password(token, "fraca")

    def test_change_password_works(self, configured_auth: AuthManager) -> None:
        token = configured_auth.authenticate(STRONG_PASSWORD)
        configured_auth.change_password(token, NEW_PASSWORD)
        # Após troca, sessão é invalidada
        assert configured_auth._session is None
        # Nova senha funciona
        new_token = configured_auth.authenticate(NEW_PASSWORD)
        assert new_token is not None

    def test_old_password_fails_after_change(self, configured_auth: AuthManager) -> None:
        token = configured_auth.authenticate(STRONG_PASSWORD)
        configured_auth.change_password(token, NEW_PASSWORD)
        with pytest.raises(AuthFailedError):
            configured_auth.authenticate(STRONG_PASSWORD)


# ---------------------------------------------------------------------------
# Testes: status
# ---------------------------------------------------------------------------

class TestStatus:
    def test_status_not_configured(self, auth: AuthManager) -> None:
        s = auth.status()
        assert s["configured"] is False
        assert s["session_active"] is False

    def test_status_configured_no_session(self, configured_auth: AuthManager) -> None:
        s = configured_auth.status()
        assert s["configured"] is True
        assert s["session_active"] is False

    def test_status_with_active_session(self, configured_auth: AuthManager) -> None:
        configured_auth.authenticate(STRONG_PASSWORD)
        s = configured_auth.status()
        assert s["session_active"] is True
        assert s["session_remaining_seconds"] > 0


# ---------------------------------------------------------------------------
# Testes: decoradores
# ---------------------------------------------------------------------------

class TestDecorators:
    def test_require_auth_decorator_allows_valid_token(
        self, configured_auth: AuthManager
    ) -> None:
        token = configured_auth.authenticate(STRONG_PASSWORD)

        @require_auth
        def operacao_critica(*, auth_manager: AuthManager, token: str) -> str:
            return "executado"

        result = operacao_critica(auth_manager=configured_auth, token=token)
        assert result == "executado"

    def test_require_auth_decorator_blocks_invalid_token(
        self, configured_auth: AuthManager
    ) -> None:
        configured_auth.authenticate(STRONG_PASSWORD)

        @require_auth
        def operacao_critica(*, auth_manager: AuthManager, token: str) -> str:
            return "executado"

        with pytest.raises(AuthSessionExpiredError):
            operacao_critica(auth_manager=configured_auth, token="invalido")

    def test_require_auth_missing_kwargs_raises(self) -> None:
        @require_auth
        def func(*, auth_manager, token) -> None:
            pass

        with pytest.raises(ValueError):
            func()

    def test_authenticated_operation_context_manager(
        self, configured_auth: AuthManager
    ) -> None:
        token = configured_auth.authenticate(STRONG_PASSWORD)
        executed = []

        with authenticated_operation(configured_auth, token, "teste"):
            executed.append(True)

        assert executed == [True]

    def test_authenticated_operation_blocks_invalid_token(
        self, configured_auth: AuthManager
    ) -> None:
        configured_auth.authenticate(STRONG_PASSWORD)

        with pytest.raises(AuthSessionExpiredError):
            with authenticated_operation(configured_auth, "invalido", "teste"):
                pass

    def test_authenticated_operation_does_not_suppress_exceptions(
        self, configured_auth: AuthManager
    ) -> None:
        token = configured_auth.authenticate(STRONG_PASSWORD)

        with pytest.raises(ValueError, match="erro interno"):
            with authenticated_operation(configured_auth, token, "teste"):
                raise ValueError("erro interno")

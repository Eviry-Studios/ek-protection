"""
ekprotection.auth — Authentication subsystem.

Exporta as classes e exceções mais usadas para que outros módulos
possam importar diretamente de `ekprotection.auth`.
"""

from .manager import (
    AuthManager,
    AuthSession,
    AuthError,
    AuthNotConfiguredError,
    AuthFailedError,
    AuthLockedError,
    AuthSessionExpiredError,
    WeakPasswordError,
)
from .decorators import require_auth, authenticated_operation

__all__ = [
    "AuthManager",
    "AuthSession",
    "AuthError",
    "AuthNotConfiguredError",
    "AuthFailedError",
    "AuthLockedError",
    "AuthSessionExpiredError",
    "WeakPasswordError",
    "require_auth",
    "authenticated_operation",
]

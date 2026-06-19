"""
ekprotection.auth.decorators
==============================
Decoradores e context managers para proteção de operações críticas.

Uso nos módulos internos:

    from ekprotection.auth.decorators import require_auth

    @require_auth
    def deletar_arquivo(path, *, auth_manager, token, **kwargs):
        ...  # só executa se token for válido

    # Ou via context manager:
    with authenticated_operation(auth_manager, token, "quarentena"):
        quarantine.move(path)
"""

from __future__ import annotations

import functools
import logging
from typing import Callable, TypeVar, Any

from .manager import AuthManager, AuthSessionExpiredError

logger = logging.getLogger(__name__)
F = TypeVar("F", bound=Callable[..., Any])


def require_auth(func: F) -> F:
    """
    Decorador que exige token de sessão válido antes de executar a função.

    A função decorada DEVE receber `auth_manager: AuthManager` e
    `token: str` como kwargs.

    Exemplo:
        @require_auth
        def operacao_critica(path: str, *, auth_manager, token):
            ...
    """
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        auth_manager: AuthManager | None = kwargs.get("auth_manager")
        token: str | None = kwargs.get("token")

        if auth_manager is None or token is None:
            raise ValueError(
                f"{func.__name__} requer 'auth_manager' e 'token' como kwargs."
            )

        auth_manager.require(token)
        logger.debug("Operação crítica autorizada: %s", func.__name__)
        return func(*args, **kwargs)

    return wrapper  # type: ignore[return-value]


class authenticated_operation:
    """
    Context manager para operações críticas.

    Uso:
        with authenticated_operation(auth, token, "deletar quarentena"):
            # código crítico aqui
            quarantine.delete(item_id)
    """

    def __init__(
        self,
        auth_manager: AuthManager,
        token: str,
        operation_name: str = "operação crítica",
    ) -> None:
        self._auth = auth_manager
        self._token = token
        self._op = operation_name

    def __enter__(self) -> "authenticated_operation":
        self._auth.require(self._token)
        logger.info("Operação crítica iniciada: %s", self._op)
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> bool:
        if exc_type is not None:
            logger.warning(
                "Operação crítica '%s' falhou: %s", self._op, exc_val
            )
        else:
            logger.info("Operação crítica concluída: %s", self._op)
        return False   # Não suprime exceções

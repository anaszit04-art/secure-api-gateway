from __future__ import annotations

from functools import lru_cache
from typing import Annotated

from fastapi import (
    Depends,
    HTTPException,
    Request,
    status,
)
from fastapi.security import OAuth2PasswordBearer

from gateway.app.auth.config import (
    AuthSettings,
    load_auth_settings,
)
from gateway.app.auth.models import (
    UserPublic,
    UsernamePolicyError,
    to_public_user,
)
from gateway.app.auth.repository import (
    AsyncInMemoryUserRepository,
    InMemoryUserRepository,
    UserRepository,
    adapt_user_repository,
)
from gateway.app.auth.service import (
    AuthenticationService,
)
from gateway.app.auth.tokens import (
    TokenValidationError,
    decode_access_token,
)
from gateway.app.database.user_repository import (
    PostgreSQLUserRepository,
)


oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="auth/token",
)


# Fallback used only when PostgreSQL is intentionally
# not configured, principally by isolated unit tests.
USER_REPOSITORY = InMemoryUserRepository()

ASYNC_USER_REPOSITORY = (
    AsyncInMemoryUserRepository(
        USER_REPOSITORY
    )
)


@lru_cache(maxsize=1)
def get_auth_settings() -> AuthSettings:
    """
    Load and cache authentication settings.
    """

    return load_auth_settings()


def get_user_repository(
    request: Request,
) -> UserRepository:
    """
    Resolve the user repository for this application.

    Docker/runtime:
        PostgreSQLUserRepository

    Isolated tests without DATABASE_URL:
        async adapter around the in-memory repository
    """

    session_factory = getattr(
        request.app.state,
        "database_session_factory",
        None,
    )

    if session_factory is None:
        return ASYNC_USER_REPOSITORY

    return PostgreSQLUserRepository(
        session_factory
    )


def get_authentication_service(
    settings: Annotated[
        AuthSettings,
        Depends(get_auth_settings),
    ],
    repository: Annotated[
        UserRepository,
        Depends(get_user_repository),
    ],
) -> AuthenticationService:
    """
    Build the authentication service dependency.
    """

    return AuthenticationService(
        repository=repository,
        settings=settings,
    )


def unauthorized_exception() -> HTTPException:
    """
    Build a consistent OAuth2 authentication error.
    """

    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials.",
        headers={
            "WWW-Authenticate": "Bearer",
        },
    )


async def get_current_user(
    token: Annotated[
        str,
        Depends(oauth2_scheme),
    ],
    settings: Annotated[
        AuthSettings,
        Depends(get_auth_settings),
    ],
    repository: Annotated[
        UserRepository,
        Depends(get_user_repository),
    ],
) -> UserPublic:
    """
    Validate a Bearer token and load its active user.
    """

    async_repository = (
        adapt_user_repository(
            repository
        )
    )

    try:
        claims = decode_access_token(
            token=token,
            settings=settings,
        )

        stored_user = (
            await async_repository
            .get_by_username(
                claims.subject
            )
        )

    except (
        TokenValidationError,
        UsernamePolicyError,
    ) as exc:
        raise unauthorized_exception() from exc

    if (
        stored_user is None
        or not stored_user.is_active
    ):
        raise unauthorized_exception()

    return to_public_user(
        stored_user
    )

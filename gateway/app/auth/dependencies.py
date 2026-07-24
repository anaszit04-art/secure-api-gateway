from functools import lru_cache
from typing import Annotated

from fastapi import (
    Depends,
    HTTPException,
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
    InMemoryUserRepository,
)
from gateway.app.auth.service import (
    AuthenticationService,
)
from gateway.app.auth.tokens import (
    TokenValidationError,
    decode_access_token,
)


oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="auth/token",
)

USER_REPOSITORY = InMemoryUserRepository()


@lru_cache(maxsize=1)
def get_auth_settings() -> AuthSettings:
    """
    Load and cache authentication settings.
    """
    return load_auth_settings()


def get_user_repository() -> InMemoryUserRepository:
    """
    Return the shared development repository.
    """
    return USER_REPOSITORY


def get_authentication_service(
    settings: Annotated[
        AuthSettings,
        Depends(get_auth_settings),
    ],
    repository: Annotated[
        InMemoryUserRepository,
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


def get_current_user(
    token: Annotated[
        str,
        Depends(oauth2_scheme),
    ],
    settings: Annotated[
        AuthSettings,
        Depends(get_auth_settings),
    ],
    repository: Annotated[
        InMemoryUserRepository,
        Depends(get_user_repository),
    ],
) -> UserPublic:
    """
    Validate a Bearer token and return its active user.
    """
    try:
        claims = decode_access_token(
            token=token,
            settings=settings,
        )

        stored_user = repository.get_by_username(
            claims.subject
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

    return to_public_user(stored_user)

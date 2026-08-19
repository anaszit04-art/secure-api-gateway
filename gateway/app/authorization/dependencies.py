from __future__ import annotations

from typing import Annotated, Final

from fastapi import (
    Depends,
    HTTPException,
    Request,
    status,
)

from gateway.app.auth.dependencies import (
    get_current_user,
)
from gateway.app.auth.models import (
    UserPublic,
)
from gateway.app.authorization.repository import (
    AuthorizationRepository,
    AuthorizationRepositoryBackendError,
)
from gateway.app.authorization.service import (
    AuthorizationDeniedError,
    AuthorizationService,
)
from gateway.app.database.authorization_repository import (
    PostgreSQLAuthorizationRepository,
)
from gateway.app.proxy.registry import (
    is_registered_service,
)


PROXY_READ_METHODS: Final[
    frozenset[str]
] = frozenset(
    {
        "GET",
        "HEAD",
        "OPTIONS",
    }
)


PROXY_WRITE_METHODS: Final[
    frozenset[str]
] = frozenset(
    {
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
    }
)


def authorization_backend_unavailable() -> HTTPException:
    """
    Fail closed when the RBAC persistence backend
    cannot be reached.
    """

    return HTTPException(
        status_code=(
            status.HTTP_503_SERVICE_UNAVAILABLE
        ),
        detail=(
            "Authorization service is temporarily "
            "unavailable."
        ),
        headers={
            "Retry-After": "1",
        },
    )


def authorization_denied() -> HTTPException:
    """
    Return a stable response for authenticated users
    that do not possess the required permission.
    """

    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Permission denied.",
    )


def get_authorization_repository(
    request: Request,
) -> AuthorizationRepository:
    """
    Resolve the PostgreSQL RBAC repository.

    Authorization deliberately has no permissive
    in-memory fallback. Missing persistent storage
    therefore fails closed.
    """

    session_factory = getattr(
        request.app.state,
        "database_session_factory",
        None,
    )

    if session_factory is None:
        raise (
            authorization_backend_unavailable()
        )

    return PostgreSQLAuthorizationRepository(
        session_factory
    )


def get_authorization_service(
    repository: Annotated[
        AuthorizationRepository,
        Depends(
            get_authorization_repository
        ),
    ],
) -> AuthorizationService:
    """
    Build the authorization domain service.
    """

    return AuthorizationService(
        repository
    )


def resolve_proxy_permission(
    *,
    service_name: str,
    method: str,
) -> str:
    """
    Derive the required permission exclusively from
    trusted Gateway routing information.

    The client never supplies its role or permission.
    """

    if not is_registered_service(
        service_name
    ):
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail=(
                f"Unknown service: {service_name}"
            ),
        )

    normalized_method = (
        method.strip().upper()
    )

    if (
        normalized_method
        in PROXY_READ_METHODS
    ):
        action = "read"

    elif (
        normalized_method
        in PROXY_WRITE_METHODS
    ):
        action = "write"

    else:
        # Deny by default for any method that has not
        # been explicitly classified.
        raise authorization_denied()

    return (
        f"proxy:{service_name}:{action}"
    )


async def enforce_proxy_authorization(
    request: Request,
    service_name: str,
    current_user: Annotated[
        UserPublic,
        Depends(get_current_user),
    ],
    service: Annotated[
        AuthorizationService,
        Depends(
            get_authorization_service
        ),
    ],
) -> None:
    """
    Enforce the RBAC policy for a proxied request.

    Authentication proves identity.
    PostgreSQL RBAC decides current authorization.
    """

    required_permission = (
        resolve_proxy_permission(
            service_name=service_name,
            method=request.method,
        )
    )

    try:
        await service.require_permission(
            user_id=current_user.id,
            permission_code=(
                required_permission
            ),
        )

    except AuthorizationDeniedError as exc:
        raise authorization_denied() from exc

    except (
        AuthorizationRepositoryBackendError
    ) as exc:
        raise (
            authorization_backend_unavailable()
        ) from exc


def require_permission(
    permission_code: str,
):
    """
    Build a reusable FastAPI dependency enforcing one
    explicit permission for the authenticated user.

    The required permission is defined by server-side
    code and can never be supplied by the client.
    """

    async def dependency(
        current_user: Annotated[
            UserPublic,
            Depends(get_current_user),
        ],
        service: Annotated[
            AuthorizationService,
            Depends(
                get_authorization_service
            ),
        ],
    ) -> UserPublic:
        try:
            await service.require_permission(
                user_id=current_user.id,
                permission_code=(
                    permission_code
                ),
            )

        except AuthorizationDeniedError as exc:
            raise authorization_denied() from exc

        except (
            AuthorizationRepositoryBackendError
        ) as exc:
            raise (
                authorization_backend_unavailable()
            ) from exc

        return current_user

    return dependency

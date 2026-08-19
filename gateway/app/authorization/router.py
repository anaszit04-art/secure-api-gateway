from __future__ import annotations

from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
)

from gateway.app.auth.models import (
    UserPublic,
    UsernamePolicyError,
)
from gateway.app.auth.repository import (
    UserRepository,
    UserRepositoryBackendError,
)
from gateway.app.authorization.dependencies import (
    authorization_backend_unavailable,
    get_authorization_service,
    require_permission,
)
from gateway.app.authorization.models import (
    RoleMutationResponse,
    RoleNamePolicyError,
    UserRolesResponse,
    normalize_role_name,
)
from gateway.app.authorization.repository import (
    AuthorizationRepositoryBackendError,
    RoleNotFoundError,
)
from gateway.app.authorization.service import (
    AuthorizationService,
)
from gateway.app.auth.dependencies import (
    authentication_database_unavailable,
    get_user_repository,
)


router = APIRouter(
    prefix="/authorization",
    tags=[
        "authorization",
    ],
)


async def get_target_user(
    *,
    username: str,
    repository: UserRepository,
):
    """
    Resolve a role-management target through the
    authentication repository.

    Unknown users return 404 while database failures
    remain fail-closed.
    """

    try:
        user = await repository.get_by_username(
            username
        )

    except UserRepositoryBackendError as exc:
        raise (
            authentication_database_unavailable()
        ) from exc

    except UsernamePolicyError as exc:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail="User not found.",
        ) from exc

    if user is None:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail="User not found.",
        )

    return user


@router.get(
    "/users/{username}/roles",
    response_model=UserRolesResponse,
)
async def read_user_roles(
    username: str,
    _: Annotated[
        UserPublic,
        Depends(
            require_permission(
                "authorization:roles:read"
            )
        ),
    ],
    user_repository: Annotated[
        UserRepository,
        Depends(get_user_repository),
    ],
    authorization_service: Annotated[
        AuthorizationService,
        Depends(
            get_authorization_service
        ),
    ],
) -> UserRolesResponse:
    target = await get_target_user(
        username=username,
        repository=user_repository,
    )

    try:
        roles = (
            await authorization_service
            .get_role_names_for_user(
                target.id
            )
        )

    except (
        AuthorizationRepositoryBackendError
    ) as exc:
        raise (
            authorization_backend_unavailable()
        ) from exc

    return UserRolesResponse(
        user_id=target.id,
        username=target.username,
        roles=tuple(
            sorted(
                roles
            )
        ),
    )


@router.put(
    "/users/{username}/roles/{role_name}",
    response_model=RoleMutationResponse,
)
async def assign_user_role(
    username: str,
    role_name: str,
    _: Annotated[
        UserPublic,
        Depends(
            require_permission(
                "authorization:roles:manage"
            )
        ),
    ],
    user_repository: Annotated[
        UserRepository,
        Depends(get_user_repository),
    ],
    authorization_service: Annotated[
        AuthorizationService,
        Depends(
            get_authorization_service
        ),
    ],
) -> RoleMutationResponse:
    target = await get_target_user(
        username=username,
        repository=user_repository,
    )

    try:
        normalized_role = (
            normalize_role_name(
                role_name
            )
        )

        changed = (
            await authorization_service
            .assign_role(
                user_id=target.id,
                role_name=normalized_role,
            )
        )

    except (
        RoleNotFoundError,
        RoleNamePolicyError,
    ) as exc:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail="Role not found.",
        ) from exc

    except (
        AuthorizationRepositoryBackendError
    ) as exc:
        raise (
            authorization_backend_unavailable()
        ) from exc

    return RoleMutationResponse(
        user_id=target.id,
        username=target.username,
        role=normalized_role,
        changed=changed,
    )


@router.delete(
    "/users/{username}/roles/{role_name}",
    response_model=RoleMutationResponse,
)
async def remove_user_role(
    username: str,
    role_name: str,
    _: Annotated[
        UserPublic,
        Depends(
            require_permission(
                "authorization:roles:manage"
            )
        ),
    ],
    user_repository: Annotated[
        UserRepository,
        Depends(get_user_repository),
    ],
    authorization_service: Annotated[
        AuthorizationService,
        Depends(
            get_authorization_service
        ),
    ],
) -> RoleMutationResponse:
    target = await get_target_user(
        username=username,
        repository=user_repository,
    )

    try:
        normalized_role = (
            normalize_role_name(
                role_name
            )
        )

        changed = (
            await authorization_service
            .remove_role(
                user_id=target.id,
                role_name=normalized_role,
            )
        )

    except (
        RoleNotFoundError,
        RoleNamePolicyError,
    ) as exc:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail="Role not found.",
        ) from exc

    except (
        AuthorizationRepositoryBackendError
    ) as exc:
        raise (
            authorization_backend_unavailable()
        ) from exc

    return RoleMutationResponse(
        user_id=target.id,
        username=target.username,
        role=normalized_role,
        changed=changed,
    )

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Request,
    status,
)

from gateway.app.audit.dependencies import (
    AuditServiceDependency,
    record_request_security_event,
)
from gateway.app.audit.models import (
    AuditEventType,
    AuditOutcome,
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
    request: Request,
    audit_service,
    actor_user_id: UUID,
    permission_code: str,
):
    """
    Resolve a role-management target.

    Target usernames are never copied into security
    audit events. Backend failures are represented only
    through pseudonymous actor identity and stable
    reason codes.
    """

    try:
        user = await repository.get_by_username(
            username
        )

    except UserRepositoryBackendError as exc:
        await record_request_security_event(
            request=request,
            audit_service=audit_service,
            event_type=(
                AuditEventType
                .AUTHENTICATION_BACKEND_UNAVAILABLE
            ),
            outcome=AuditOutcome.UNAVAILABLE,
            actor_user_id=actor_user_id,
            permission_code=permission_code,
            method=request.method,
            status_code=503,
            reason_code=(
                "authorization_target_lookup_unavailable"
            ),
        )

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
    request: Request,
    actor: Annotated[
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
    audit_service: AuditServiceDependency,
) -> UserRolesResponse:
    permission_code = (
        "authorization:roles:read"
    )

    target = await get_target_user(
        username=username,
        repository=user_repository,
        request=request,
        audit_service=audit_service,
        actor_user_id=actor.id,
        permission_code=permission_code,
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
        await record_request_security_event(
            request=request,
            audit_service=audit_service,
            event_type=(
                AuditEventType
                .AUTHORIZATION_BACKEND_UNAVAILABLE
            ),
            outcome=AuditOutcome.UNAVAILABLE,
            actor_user_id=actor.id,
            target_user_id=target.id,
            permission_code=permission_code,
            method=request.method,
            status_code=503,
            reason_code=(
                "role_list_repository_unavailable"
            ),
        )

        raise (
            authorization_backend_unavailable()
        ) from exc

    await record_request_security_event(
        request=request,
        audit_service=audit_service,
        event_type=(
            AuditEventType.ROLE_LIST_READ
        ),
        outcome=AuditOutcome.SUCCESS,
        actor_user_id=actor.id,
        target_user_id=target.id,
        permission_code=permission_code,
        method=request.method,
        status_code=200,
        reason_code="roles_read",
    )

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
    request: Request,
    actor: Annotated[
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
    audit_service: AuditServiceDependency,
) -> RoleMutationResponse:
    permission_code = (
        "authorization:roles:manage"
    )

    target = await get_target_user(
        username=username,
        repository=user_repository,
        request=request,
        audit_service=audit_service,
        actor_user_id=actor.id,
        permission_code=permission_code,
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
        await record_request_security_event(
            request=request,
            audit_service=audit_service,
            event_type=(
                AuditEventType
                .AUTHORIZATION_BACKEND_UNAVAILABLE
            ),
            outcome=AuditOutcome.UNAVAILABLE,
            actor_user_id=actor.id,
            target_user_id=target.id,
            permission_code=permission_code,
            role_name=normalized_role,
            method=request.method,
            status_code=503,
            reason_code=(
                "role_assignment_repository_unavailable"
            ),
        )

        raise (
            authorization_backend_unavailable()
        ) from exc

    await record_request_security_event(
        request=request,
        audit_service=audit_service,
        event_type=(
            AuditEventType.ROLE_ASSIGNED
        ),
        outcome=AuditOutcome.SUCCESS,
        actor_user_id=actor.id,
        target_user_id=target.id,
        permission_code=permission_code,
        role_name=normalized_role,
        method=request.method,
        status_code=200,
        reason_code=(
            "role_assigned"
            if changed
            else "role_already_assigned"
        ),
    )

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
    request: Request,
    actor: Annotated[
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
    audit_service: AuditServiceDependency,
) -> RoleMutationResponse:
    permission_code = (
        "authorization:roles:manage"
    )

    target = await get_target_user(
        username=username,
        repository=user_repository,
        request=request,
        audit_service=audit_service,
        actor_user_id=actor.id,
        permission_code=permission_code,
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
        await record_request_security_event(
            request=request,
            audit_service=audit_service,
            event_type=(
                AuditEventType
                .AUTHORIZATION_BACKEND_UNAVAILABLE
            ),
            outcome=AuditOutcome.UNAVAILABLE,
            actor_user_id=actor.id,
            target_user_id=target.id,
            permission_code=permission_code,
            role_name=normalized_role,
            method=request.method,
            status_code=503,
            reason_code=(
                "role_removal_repository_unavailable"
            ),
        )

        raise (
            authorization_backend_unavailable()
        ) from exc

    await record_request_security_event(
        request=request,
        audit_service=audit_service,
        event_type=(
            AuditEventType.ROLE_REMOVED
        ),
        outcome=AuditOutcome.SUCCESS,
        actor_user_id=actor.id,
        target_user_id=target.id,
        permission_code=permission_code,
        role_name=normalized_role,
        method=request.method,
        status_code=200,
        reason_code=(
            "role_removed"
            if changed
            else "role_not_assigned"
        ),
    )

    return RoleMutationResponse(
        user_id=target.id,
        username=target.username,
        role=normalized_role,
        changed=changed,
    )

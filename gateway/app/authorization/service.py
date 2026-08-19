from __future__ import annotations

from uuid import UUID

from gateway.app.authorization.models import (
    normalize_permission_code,
    normalize_role_name,
)
from gateway.app.authorization.repository import (
    AuthorizationRepository,
)


class AuthorizationDeniedError(
    PermissionError
):
    """
    Raised when an authenticated user does not possess
    the permission required by a policy.
    """


class AuthorizationService:
    """
    Coordinate RBAC authorization decisions.

    The service knows nothing about SQLAlchemy,
    PostgreSQL, HTTP or FastAPI.
    """

    def __init__(
        self,
        repository: AuthorizationRepository,
    ) -> None:
        self._repository = repository

    async def get_role_names_for_user(
        self,
        user_id: UUID,
    ) -> frozenset[str]:
        return (
            await self._repository
            .get_role_names_for_user(
                user_id
            )
        )

    async def get_permission_codes_for_user(
        self,
        user_id: UUID,
    ) -> frozenset[str]:
        return (
            await self._repository
            .get_permission_codes_for_user(
                user_id
            )
        )

    async def has_permission(
        self,
        *,
        user_id: UUID,
        permission_code: str,
    ) -> bool:
        normalized_permission = (
            normalize_permission_code(
                permission_code
            )
        )

        return (
            await self._repository.has_permission(
                user_id=user_id,
                permission_code=(
                    normalized_permission
                ),
            )
        )

    async def require_permission(
        self,
        *,
        user_id: UUID,
        permission_code: str,
    ) -> None:
        """
        Enforce a permission using deny-by-default
        semantics.
        """

        allowed = await self.has_permission(
            user_id=user_id,
            permission_code=permission_code,
        )

        if not allowed:
            raise AuthorizationDeniedError(
                "Permission denied."
            )

    async def assign_role(
        self,
        *,
        user_id: UUID,
        role_name: str,
    ) -> bool:
        normalized_role = (
            normalize_role_name(
                role_name
            )
        )

        return await self._repository.assign_role(
            user_id=user_id,
            role_name=normalized_role,
        )

    async def remove_role(
        self,
        *,
        user_id: UUID,
        role_name: str,
    ) -> bool:
        normalized_role = (
            normalize_role_name(
                role_name
            )
        )

        return await self._repository.remove_role(
            user_id=user_id,
            role_name=normalized_role,
        )

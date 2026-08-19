from __future__ import annotations

from typing import Protocol
from uuid import UUID


class AuthorizationRepositoryBackendError(
    RuntimeError
):
    """
    Raised when the authorization persistence backend
    cannot complete an operation.

    Database implementation details must never cross
    this boundary.
    """


class RoleNotFoundError(LookupError):
    """
    Raised when a requested authorization role
    does not exist.
    """


class UserAuthorizationNotFoundError(
    LookupError
):
    """
    Raised when a role mutation targets a user that
    does not exist.
    """


class AuthorizationRepository(Protocol):
    """
    Asynchronous persistence contract used by the
    authorization domain.
    """

    async def get_role_names_for_user(
        self,
        user_id: UUID,
    ) -> frozenset[str]:
        ...

    async def get_permission_codes_for_user(
        self,
        user_id: UUID,
    ) -> frozenset[str]:
        ...

    async def has_permission(
        self,
        *,
        user_id: UUID,
        permission_code: str,
    ) -> bool:
        ...

    async def assign_role(
        self,
        *,
        user_id: UUID,
        role_name: str,
    ) -> bool:
        """
        Return True when a new assignment is created.

        Return False when the assignment already exists.
        """
        ...

    async def remove_role(
        self,
        *,
        user_id: UUID,
        role_name: str,
    ) -> bool:
        """
        Return True when an assignment is removed.

        Return False when the user did not have the role.
        """
        ...

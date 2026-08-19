from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from gateway.app.authorization.repository import (
    AuthorizationRepositoryBackendError,
)
from gateway.app.authorization.service import (
    AuthorizationDeniedError,
    AuthorizationService,
)


class FakeAuthorizationRepository:
    def __init__(
        self,
        *,
        roles: frozenset[str] | None = None,
        permissions: frozenset[str] | None = None,
        allowed: bool = False,
        fail_permission_check: bool = False,
    ) -> None:
        self.roles = (
            roles
            if roles is not None
            else frozenset()
        )

        self.permissions = (
            permissions
            if permissions is not None
            else frozenset()
        )

        self.allowed = allowed
        self.fail_permission_check = (
            fail_permission_check
        )

        self.permission_calls: list[
            tuple[UUID, str]
        ] = []

        self.assign_calls: list[
            tuple[UUID, str]
        ] = []

        self.remove_calls: list[
            tuple[UUID, str]
        ] = []

    async def get_role_names_for_user(
        self,
        user_id: UUID,
    ) -> frozenset[str]:
        del user_id
        return self.roles

    async def get_permission_codes_for_user(
        self,
        user_id: UUID,
    ) -> frozenset[str]:
        del user_id
        return self.permissions

    async def has_permission(
        self,
        *,
        user_id: UUID,
        permission_code: str,
    ) -> bool:
        self.permission_calls.append(
            (
                user_id,
                permission_code,
            )
        )

        if self.fail_permission_check:
            raise (
                AuthorizationRepositoryBackendError(
                    "authorization backend unavailable"
                )
            )

        return self.allowed

    async def assign_role(
        self,
        *,
        user_id: UUID,
        role_name: str,
    ) -> bool:
        self.assign_calls.append(
            (
                user_id,
                role_name,
            )
        )

        return True

    async def remove_role(
        self,
        *,
        user_id: UUID,
        role_name: str,
    ) -> bool:
        self.remove_calls.append(
            (
                user_id,
                role_name,
            )
        )

        return True


@pytest.mark.anyio
async def test_get_roles_delegates_to_repository() -> None:
    repository = (
        FakeAuthorizationRepository(
            roles=frozenset(
                {
                    "user",
                    "operator",
                }
            )
        )
    )

    service = AuthorizationService(
        repository
    )

    roles = (
        await service
        .get_role_names_for_user(
            uuid4()
        )
    )

    assert roles == frozenset(
        {
            "user",
            "operator",
        }
    )


@pytest.mark.anyio
async def test_get_permissions_delegates_to_repository() -> None:
    repository = (
        FakeAuthorizationRepository(
            permissions=frozenset(
                {
                    "proxy:service-a:read",
                }
            )
        )
    )

    service = AuthorizationService(
        repository
    )

    permissions = (
        await service
        .get_permission_codes_for_user(
            uuid4()
        )
    )

    assert permissions == frozenset(
        {
            "proxy:service-a:read",
        }
    )


@pytest.mark.anyio
async def test_has_permission_normalizes_code() -> None:
    repository = (
        FakeAuthorizationRepository(
            allowed=True
        )
    )

    service = AuthorizationService(
        repository
    )

    user_id = uuid4()

    allowed = (
        await service.has_permission(
            user_id=user_id,
            permission_code=(
                " PROXY:SERVICE-A:READ "
            ),
        )
    )

    assert allowed is True

    assert repository.permission_calls == [
        (
            user_id,
            "proxy:service-a:read",
        )
    ]


@pytest.mark.anyio
async def test_require_permission_allows_access() -> None:
    service = AuthorizationService(
        FakeAuthorizationRepository(
            allowed=True
        )
    )

    await service.require_permission(
        user_id=uuid4(),
        permission_code=(
            "proxy:service-a:read"
        ),
    )


@pytest.mark.anyio
async def test_require_permission_denies_by_default() -> None:
    service = AuthorizationService(
        FakeAuthorizationRepository(
            allowed=False
        )
    )

    with pytest.raises(
        AuthorizationDeniedError,
        match="Permission denied",
    ):
        await service.require_permission(
            user_id=uuid4(),
            permission_code=(
                "proxy:service-a:write"
            ),
        )


@pytest.mark.anyio
async def test_backend_failure_is_not_treated_as_denial() -> None:
    service = AuthorizationService(
        FakeAuthorizationRepository(
            fail_permission_check=True
        )
    )

    with pytest.raises(
        AuthorizationRepositoryBackendError,
    ):
        await service.require_permission(
            user_id=uuid4(),
            permission_code=(
                "proxy:service-a:read"
            ),
        )


@pytest.mark.anyio
async def test_assign_role_normalizes_name() -> None:
    repository = (
        FakeAuthorizationRepository()
    )

    service = AuthorizationService(
        repository
    )

    user_id = uuid4()

    result = await service.assign_role(
        user_id=user_id,
        role_name=" OPERATOR ",
    )

    assert result is True

    assert repository.assign_calls == [
        (
            user_id,
            "operator",
        )
    ]


@pytest.mark.anyio
async def test_remove_role_normalizes_name() -> None:
    repository = (
        FakeAuthorizationRepository()
    )

    service = AuthorizationService(
        repository
    )

    user_id = uuid4()

    result = await service.remove_role(
        user_id=user_id,
        role_name=" OPERATOR ",
    )

    assert result is True

    assert repository.remove_calls == [
        (
            user_id,
            "operator",
        )
    ]

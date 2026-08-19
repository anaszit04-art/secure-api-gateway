from __future__ import annotations

from datetime import (
    datetime,
    timezone,
)
from typing import Iterator
from uuid import UUID

from fastapi.testclient import TestClient

from gateway.app.auth.dependencies import (
    get_current_user,
    get_user_repository,
)
from gateway.app.auth.models import (
    StoredUser,
    UserPublic,
)
from gateway.app.authorization.dependencies import (
    get_authorization_service,
)
from gateway.app.authorization.repository import (
    RoleNotFoundError,
)
from gateway.app.authorization.service import (
    AuthorizationDeniedError,
)
from gateway.app.main import app


ADMIN = UserPublic(
    id=UUID(
        "90000000-0000-0000-0000-000000000001"
    ),
    username="admin-test",
    is_active=True,
    created_at=datetime(
        2026,
        8,
        19,
        tzinfo=timezone.utc,
    ),
)


TARGET_ID = UUID(
    "90000000-0000-0000-0000-000000000002"
)


TARGET = StoredUser(
    id=TARGET_ID,
    username="target-user",
    hashed_password="test-hash",
    is_active=True,
    created_at=datetime(
        2026,
        8,
        19,
        tzinfo=timezone.utc,
    ),
)


class FakeUserRepository:
    async def get_by_username(
        self,
        username: str,
    ):
        if username == TARGET.username:
            return TARGET

        return None


class FakeAuthorizationService:
    def __init__(self) -> None:
        self.allowed = True

        self.roles = frozenset(
            {
                "user",
            }
        )

        self.assign_result = True
        self.remove_result = True

        self.permission_calls: list[
            tuple[UUID, str]
        ] = []

        self.assign_calls: list[
            tuple[UUID, str]
        ] = []

        self.remove_calls: list[
            tuple[UUID, str]
        ] = []

    async def require_permission(
        self,
        *,
        user_id: UUID,
        permission_code: str,
    ) -> None:
        self.permission_calls.append(
            (
                user_id,
                permission_code,
            )
        )

        if not self.allowed:
            raise AuthorizationDeniedError(
                "Permission denied."
            )

    async def get_role_names_for_user(
        self,
        user_id: UUID,
    ) -> frozenset[str]:
        assert user_id == TARGET_ID
        return self.roles

    async def assign_role(
        self,
        *,
        user_id: UUID,
        role_name: str,
    ) -> bool:
        if role_name == "missing-role":
            raise RoleNotFoundError(
                "Role not found."
            )

        self.assign_calls.append(
            (
                user_id,
                role_name,
            )
        )

        return self.assign_result

    async def remove_role(
        self,
        *,
        user_id: UUID,
        role_name: str,
    ) -> bool:
        if role_name == "missing-role":
            raise RoleNotFoundError(
                "Role not found."
            )

        self.remove_calls.append(
            (
                user_id,
                role_name,
            )
        )

        return self.remove_result


def build_context():
    service = FakeAuthorizationService()

    original = (
        app.dependency_overrides.copy()
    )

    app.dependency_overrides[
        get_current_user
    ] = lambda: ADMIN

    app.dependency_overrides[
        get_user_repository
    ] = lambda: FakeUserRepository()

    app.dependency_overrides[
        get_authorization_service
    ] = lambda: service

    return service, original


def restore_overrides(
    original: dict,
) -> None:
    app.dependency_overrides.clear()
    app.dependency_overrides.update(
        original
    )


def test_read_user_roles() -> None:
    service, original = build_context()

    try:
        with TestClient(app) as client:
            response = client.get(
                "/authorization/users/"
                "target-user/roles"
            )

        assert response.status_code == 200

        assert response.json() == {
            "user_id": str(TARGET_ID),
            "username": "target-user",
            "roles": [
                "user",
            ],
        }

        assert service.permission_calls == [
            (
                ADMIN.id,
                "authorization:roles:read",
            )
        ]

    finally:
        restore_overrides(
            original
        )


def test_assign_role() -> None:
    service, original = build_context()

    try:
        with TestClient(app) as client:
            response = client.put(
                "/authorization/users/"
                "target-user/roles/operator"
            )

        assert response.status_code == 200

        assert response.json() == {
            "user_id": str(TARGET_ID),
            "username": "target-user",
            "role": "operator",
            "changed": True,
        }

        assert service.permission_calls == [
            (
                ADMIN.id,
                "authorization:roles:manage",
            )
        ]

        assert service.assign_calls == [
            (
                TARGET_ID,
                "operator",
            )
        ]

    finally:
        restore_overrides(
            original
        )


def test_assign_role_is_idempotent() -> None:
    service, original = build_context()

    service.assign_result = False

    try:
        with TestClient(app) as client:
            response = client.put(
                "/authorization/users/"
                "target-user/roles/operator"
            )

        assert response.status_code == 200
        assert (
            response.json()["changed"]
            is False
        )

    finally:
        restore_overrides(
            original
        )


def test_remove_role() -> None:
    service, original = build_context()

    try:
        with TestClient(app) as client:
            response = client.delete(
                "/authorization/users/"
                "target-user/roles/operator"
            )

        assert response.status_code == 200
        assert (
            response.json()["changed"]
            is True
        )

        assert service.permission_calls == [
            (
                ADMIN.id,
                "authorization:roles:manage",
            )
        ]

        assert service.remove_calls == [
            (
                TARGET_ID,
                "operator",
            )
        ]

    finally:
        restore_overrides(
            original
        )


def test_unknown_user_returns_404() -> None:
    _, original = build_context()

    try:
        with TestClient(app) as client:
            response = client.get(
                "/authorization/users/"
                "missing-user/roles"
            )

        assert response.status_code == 404

        assert response.json() == {
            "detail": "User not found."
        }

    finally:
        restore_overrides(
            original
        )


def test_unknown_role_returns_404() -> None:
    _, original = build_context()

    try:
        with TestClient(app) as client:
            response = client.put(
                "/authorization/users/"
                "target-user/roles/missing-role"
            )

        assert response.status_code == 404

        assert response.json() == {
            "detail": "Role not found."
        }

    finally:
        restore_overrides(
            original
        )


def test_permission_denied_returns_403() -> None:
    service, original = build_context()

    service.allowed = False

    try:
        with TestClient(app) as client:
            response = client.put(
                "/authorization/users/"
                "target-user/roles/operator"
            )

        assert response.status_code == 403

        assert response.json() == {
            "detail": "Permission denied."
        }

        assert service.assign_calls == []

    finally:
        restore_overrides(
            original
        )


def test_invalid_role_name_returns_404() -> None:
    _, original = build_context()

    try:
        with TestClient(app) as client:
            response = client.put(
                "/authorization/users/"
                "target-user/roles/admin!"
            )

        assert response.status_code == 404

        assert response.json() == {
            "detail": "Role not found."
        }

    finally:
        restore_overrides(
            original
        )


def test_malformed_target_username_returns_404() -> None:
    class RejectingUserRepository:
        async def get_by_username(
            self,
            username: str,
        ):
            del username

            from gateway.app.auth.models import (
                UsernamePolicyError,
            )

            raise UsernamePolicyError(
                "invalid username"
            )

    service, original = build_context()

    app.dependency_overrides[
        get_user_repository
    ] = lambda: RejectingUserRepository()

    try:
        with TestClient(app) as client:
            response = client.get(
                "/authorization/users/"
                "ab/roles"
            )

        assert response.status_code == 404

        assert response.json() == {
            "detail": "User not found."
        }

        assert service.permission_calls == [
            (
                ADMIN.id,
                "authorization:roles:read",
            )
        ]

    finally:
        restore_overrides(
            original
        )

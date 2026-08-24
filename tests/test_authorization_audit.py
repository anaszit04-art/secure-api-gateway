from __future__ import annotations

from datetime import (
    datetime,
    timezone,
)
from typing import Iterator
from uuid import UUID

import pytest

from fastapi.testclient import TestClient

from gateway.app.audit.dependencies import (
    get_audit_service,
)
from gateway.app.audit.models import (
    AuditEventType,
    AuditOutcome,
    SecurityAuditEvent,
)
from gateway.app.auth.dependencies import (
    get_current_user,
    get_user_repository,
)
from gateway.app.auth.models import (
    StoredUser,
    UserPublic,
)
from gateway.app.auth.repository import (
    UserRepositoryBackendError,
)
from gateway.app.authorization.dependencies import (
    get_authorization_service,
)
from gateway.app.authorization.repository import (
    AuthorizationRepositoryBackendError,
)
from gateway.app.authorization.service import (
    AuthorizationDeniedError,
)
from gateway.app.main import app
from gateway.app.rate_limit.dependencies import (
    get_rate_limiter,
)
from gateway.app.rate_limit.models import (
    RateLimitDecision,
)


ACTOR = UserPublic(
    id=UUID(
        "72000000-0000-0000-"
        "0000-000000000001"
    ),
    username="admin-audit",
    is_active=True,
    created_at=datetime(
        2026,
        8,
        24,
        tzinfo=timezone.utc,
    ),
)


TARGET = StoredUser(
    id=UUID(
        "72000000-0000-0000-"
        "0000-000000000002"
    ),
    username="target-audit",
    hashed_password="test-hash",
    is_active=True,
    created_at=datetime(
        2026,
        8,
        24,
        tzinfo=timezone.utc,
    ),
)


class FakeAuditService:
    def __init__(self) -> None:
        self.events: list[
            SecurityAuditEvent
        ] = []

    async def record(
        self,
        event: SecurityAuditEvent,
    ) -> None:
        self.events.append(
            event
        )


class FakeUserRepository:
    def __init__(self) -> None:
        self.error: Exception | None = None

    async def get_by_username(
        self,
        username: str,
    ):
        if self.error is not None:
            raise self.error

        if username == TARGET.username:
            return TARGET

        return None


class FakeAuthorizationService:
    def __init__(self) -> None:
        self.allowed = True
        self.permission_error: Exception | None = None
        self.operation_error: Exception | None = None

        self.roles = frozenset(
            {
                "user",
            }
        )

        self.assign_result = True
        self.remove_result = True

    async def require_permission(
        self,
        **_: object,
    ) -> None:
        if self.permission_error is not None:
            raise self.permission_error

        if not self.allowed:
            raise AuthorizationDeniedError(
                "Permission denied."
            )

    async def get_role_names_for_user(
        self,
        user_id,
    ):
        assert user_id == TARGET.id

        if self.operation_error is not None:
            raise self.operation_error

        return self.roles

    async def assign_role(
        self,
        *,
        user_id,
        role_name,
    ):
        assert user_id == TARGET.id
        assert role_name == "operator"

        if self.operation_error is not None:
            raise self.operation_error

        return self.assign_result

    async def remove_role(
        self,
        *,
        user_id,
        role_name,
    ):
        assert user_id == TARGET.id
        assert role_name == "operator"

        if self.operation_error is not None:
            raise self.operation_error

        return self.remove_result


class FakeAllowedRateLimiter:
    async def check(
        self,
        **_: object,
    ) -> RateLimitDecision:
        return RateLimitDecision(
            allowed=True,
            limit=60,
            remaining=59,
            retry_after_seconds=0,
            reset_after_seconds=1,
        )


@pytest.fixture
def authorization_audit_context() -> Iterator[
    tuple[
        TestClient,
        FakeAuthorizationService,
        FakeUserRepository,
        FakeAuditService,
    ]
]:
    authorization = (
        FakeAuthorizationService()
    )

    users = FakeUserRepository()
    audit = FakeAuditService()

    original = (
        app.dependency_overrides.copy()
    )

    app.dependency_overrides[
        get_current_user
    ] = lambda: ACTOR

    app.dependency_overrides[
        get_user_repository
    ] = lambda: users

    app.dependency_overrides[
        get_authorization_service
    ] = lambda: authorization

    app.dependency_overrides[
        get_rate_limiter
    ] = lambda: FakeAllowedRateLimiter()

    app.dependency_overrides[
        get_audit_service
    ] = lambda: audit

    try:
        with TestClient(app) as client:
            yield (
                client,
                authorization,
                users,
                audit,
            )

    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(
            original
        )


def test_proxy_authorization_denial_is_audited(
    authorization_audit_context,
) -> None:
    (
        client,
        authorization,
        _,
        audit,
    ) = authorization_audit_context

    authorization.allowed = False

    response = client.post(
        "/api/service-a/echo"
    )

    assert response.status_code == 403
    assert len(audit.events) == 1

    event = audit.events[0]

    assert event.event_type == (
        AuditEventType.AUTHORIZATION_DENIED
    )

    assert event.outcome == (
        AuditOutcome.DENIED
    )

    assert event.actor_user_id == ACTOR.id

    assert event.permission_code == (
        "proxy:service-a:write"
    )

    assert event.service_name == (
        "service-a"
    )

    assert event.method == "POST"
    assert event.status_code == 403

    assert (
        str(event.request_id)
        == response.headers["x-request-id"]
    )


def test_proxy_authorization_backend_failure_is_audited(
    authorization_audit_context,
) -> None:
    (
        client,
        authorization,
        _,
        audit,
    ) = authorization_audit_context

    authorization.permission_error = (
        AuthorizationRepositoryBackendError(
            "database unavailable"
        )
    )

    response = client.get(
        "/api/service-a/ping"
    )

    assert response.status_code == 503
    assert len(audit.events) == 1

    event = audit.events[0]

    assert event.event_type == (
        AuditEventType
        .AUTHORIZATION_BACKEND_UNAVAILABLE
    )

    assert event.outcome == (
        AuditOutcome.UNAVAILABLE
    )

    assert event.actor_user_id == ACTOR.id
    assert event.status_code == 503


def test_role_list_read_is_audited(
    authorization_audit_context,
) -> None:
    client, _, _, audit = (
        authorization_audit_context
    )

    response = client.get(
        "/authorization/users/"
        "target-audit/roles"
    )

    assert response.status_code == 200

    event = audit.events[-1]

    assert event.event_type == (
        AuditEventType.ROLE_LIST_READ
    )

    assert event.actor_user_id == ACTOR.id
    assert event.target_user_id == TARGET.id

    assert event.permission_code == (
        "authorization:roles:read"
    )

    assert event.status_code == 200


def test_role_assignment_is_audited(
    authorization_audit_context,
) -> None:
    client, _, _, audit = (
        authorization_audit_context
    )

    response = client.put(
        "/authorization/users/"
        "target-audit/roles/operator"
    )

    assert response.status_code == 200

    event = audit.events[-1]

    assert event.event_type == (
        AuditEventType.ROLE_ASSIGNED
    )

    assert event.actor_user_id == ACTOR.id
    assert event.target_user_id == TARGET.id
    assert event.role_name == "operator"

    assert event.reason_code == (
        "role_assigned"
    )


def test_idempotent_role_assignment_is_audited(
    authorization_audit_context,
) -> None:
    (
        client,
        authorization,
        _,
        audit,
    ) = authorization_audit_context

    authorization.assign_result = False

    response = client.put(
        "/authorization/users/"
        "target-audit/roles/operator"
    )

    assert response.status_code == 200
    assert response.json()["changed"] is False

    assert audit.events[-1].reason_code == (
        "role_already_assigned"
    )


def test_role_removal_is_audited(
    authorization_audit_context,
) -> None:
    client, _, _, audit = (
        authorization_audit_context
    )

    response = client.delete(
        "/authorization/users/"
        "target-audit/roles/operator"
    )

    assert response.status_code == 200

    event = audit.events[-1]

    assert event.event_type == (
        AuditEventType.ROLE_REMOVED
    )

    assert event.actor_user_id == ACTOR.id
    assert event.target_user_id == TARGET.id

    assert event.reason_code == (
        "role_removed"
    )


def test_admin_permission_denial_is_audited(
    authorization_audit_context,
) -> None:
    (
        client,
        authorization,
        _,
        audit,
    ) = authorization_audit_context

    authorization.allowed = False

    response = client.put(
        "/authorization/users/"
        "target-audit/roles/operator"
    )

    assert response.status_code == 403
    assert len(audit.events) == 1

    event = audit.events[0]

    assert event.event_type == (
        AuditEventType.AUTHORIZATION_DENIED
    )

    assert event.permission_code == (
        "authorization:roles:manage"
    )

    assert event.actor_user_id == ACTOR.id

    # Permission failure occurs before target lookup.
    assert event.target_user_id is None


def test_target_lookup_backend_failure_is_audited_without_username(
    authorization_audit_context,
) -> None:
    (
        client,
        _,
        users,
        audit,
    ) = authorization_audit_context

    users.error = UserRepositoryBackendError(
        "database unavailable"
    )

    response = client.get(
        "/authorization/users/"
        "target-audit/roles"
    )

    assert response.status_code == 503
    assert len(audit.events) == 1

    event = audit.events[0]

    assert event.event_type == (
        AuditEventType
        .AUTHENTICATION_BACKEND_UNAVAILABLE
    )

    assert event.outcome == (
        AuditOutcome.UNAVAILABLE
    )

    assert event.actor_user_id == ACTOR.id
    assert event.target_user_id is None

    assert event.reason_code == (
        "authorization_target_lookup_unavailable"
    )

    serialized = repr(
        event
    )

    assert "target-audit" not in serialized

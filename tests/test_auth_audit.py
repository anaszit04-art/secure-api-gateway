from __future__ import annotations

from datetime import (
    datetime,
    timezone,
)
from typing import Iterator
from uuid import (
    UUID,
)

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
    get_authentication_service,
)
from gateway.app.auth.models import (
    AuthenticationResult,
    UserPublic,
)
from gateway.app.auth.repository import (
    UserRepositoryBackendError,
)
from gateway.app.auth.service import (
    INVALID_CREDENTIALS_MESSAGE,
    AuthenticationError,
)
from gateway.app.main import app
from gateway.app.rate_limit.dependencies import (
    get_rate_limiter,
)
from gateway.app.rate_limit.login import (
    LoginProtectionBackendError,
    LoginProtectionDecision,
)
from gateway.app.rate_limit.login_dependencies import (
    get_login_protection,
)
from gateway.app.rate_limit.models import (
    RateLimitDecision,
)


TEST_USER = UserPublic(
    id=UUID(
        "71000000-0000-0000-"
        "0000-000000000001"
    ),
    username="anas",
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


class FakeAuthenticationService:
    def __init__(self) -> None:
        self.auth_error: Exception | None = None
        self.register_error: Exception | None = None
        self.auth_calls = 0
        self.register_calls = 0

    async def register_user(
        self,
        registration,
    ) -> UserPublic:
        del registration

        self.register_calls += 1

        if self.register_error is not None:
            raise self.register_error

        return TEST_USER

    async def authenticate_and_create_result(
        self,
        **_: object,
    ) -> AuthenticationResult:
        self.auth_calls += 1

        if self.auth_error is not None:
            raise self.auth_error

        return AuthenticationResult(
            access_token="signed.test.token",
            user=TEST_USER,
        )


class FakeAllowedRateLimiter:
    async def check(
        self,
        **_: object,
    ) -> RateLimitDecision:
        return RateLimitDecision(
            allowed=True,
            limit=10,
            remaining=9,
            retry_after_seconds=0,
            reset_after_seconds=5,
        )


class FakeLoginProtection:
    def __init__(self) -> None:
        self.lock_decision = (
            LoginProtectionDecision(
                locked=False,
                failures=0,
                retry_after_seconds=0,
            )
        )

        self.failure_decision = (
            LoginProtectionDecision(
                locked=False,
                failures=1,
                retry_after_seconds=0,
            )
        )

        self.check_error: Exception | None = None
        self.failure_error: Exception | None = None
        self.reset_error: Exception | None = None

    async def check_lock(
        self,
        **_: object,
    ) -> LoginProtectionDecision:
        if self.check_error is not None:
            raise self.check_error

        return self.lock_decision

    async def record_failure(
        self,
        **_: object,
    ) -> LoginProtectionDecision:
        if self.failure_error is not None:
            raise self.failure_error

        return self.failure_decision

    async def reset(
        self,
        **_: object,
    ) -> bool:
        if self.reset_error is not None:
            raise self.reset_error

        return True


@pytest.fixture
def audit_context() -> Iterator[
    tuple[
        TestClient,
        FakeAuthenticationService,
        FakeLoginProtection,
        FakeAuditService,
    ]
]:
    auth = FakeAuthenticationService()
    protection = FakeLoginProtection()
    audit = FakeAuditService()

    original = (
        app.dependency_overrides.copy()
    )

    app.dependency_overrides[
        get_authentication_service
    ] = lambda: auth

    app.dependency_overrides[
        get_rate_limiter
    ] = lambda: FakeAllowedRateLimiter()

    app.dependency_overrides[
        get_login_protection
    ] = lambda: protection

    app.dependency_overrides[
        get_audit_service
    ] = lambda: audit

    try:
        with TestClient(app) as client:
            yield (
                client,
                auth,
                protection,
                audit,
            )

    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(
            original
        )


def submit_login(
    client: TestClient,
):
    return client.post(
        "/auth/token",
        data={
            "username": "anas",
            "password": (
                "correct-horse-battery-staple"
            ),
        },
    )


def test_registration_success_is_audited(
    audit_context,
) -> None:
    client, _, _, audit = audit_context

    response = client.post(
        "/auth/register",
        json={
            "username": "anas",
            "password": (
                "correct-horse-battery-staple"
            ),
        },
    )

    assert response.status_code == 201
    assert len(audit.events) == 1

    event = audit.events[0]

    assert event.event_type == (
        AuditEventType.USER_REGISTERED
    )

    assert event.outcome == (
        AuditOutcome.SUCCESS
    )

    assert (
        event.target_user_id
        == TEST_USER.id
    )

    assert event.status_code == 201

    assert (
        str(event.request_id)
        == response.headers["x-request-id"]
    )


def test_successful_login_is_audited(
    audit_context,
) -> None:
    client, _, _, audit = audit_context

    response = submit_login(
        client
    )

    assert response.status_code == 200
    assert len(audit.events) == 1

    event = audit.events[0]

    assert event.event_type == (
        AuditEventType.LOGIN_SUCCEEDED
    )

    assert event.outcome == (
        AuditOutcome.SUCCESS
    )

    assert (
        event.actor_user_id
        == TEST_USER.id
    )

    assert event.target_user_id is None

    assert (
        str(event.request_id)
        == response.headers["x-request-id"]
    )


def test_invalid_credentials_are_audited_without_identity(
    audit_context,
) -> None:
    client, auth, _, audit = audit_context

    auth.auth_error = AuthenticationError(
        INVALID_CREDENTIALS_MESSAGE
    )

    response = submit_login(
        client
    )

    assert response.status_code == 401
    assert len(audit.events) == 1

    event = audit.events[0]

    assert event.event_type == (
        AuditEventType.LOGIN_FAILED
    )

    assert event.outcome == (
        AuditOutcome.FAILURE
    )

    assert event.actor_user_id is None
    assert event.target_user_id is None
    assert event.status_code == 401

    assert event.reason_code == (
        "invalid_credentials"
    )


def test_existing_account_lock_is_audited(
    audit_context,
) -> None:
    (
        client,
        auth,
        protection,
        audit,
    ) = audit_context

    protection.lock_decision = (
        LoginProtectionDecision(
            locked=True,
            failures=5,
            retry_after_seconds=240,
        )
    )

    response = submit_login(
        client
    )

    assert response.status_code == 429
    assert auth.auth_calls == 0

    assert [
        event.event_type
        for event in audit.events
    ] == [
        AuditEventType.ACCOUNT_LOCKED,
    ]


def test_threshold_failure_records_failure_and_lock(
    audit_context,
) -> None:
    (
        client,
        auth,
        protection,
        audit,
    ) = audit_context

    auth.auth_error = AuthenticationError(
        INVALID_CREDENTIALS_MESSAGE
    )

    protection.failure_decision = (
        LoginProtectionDecision(
            locked=True,
            failures=5,
            retry_after_seconds=300,
        )
    )

    response = submit_login(
        client
    )

    assert response.status_code == 429

    assert [
        event.event_type
        for event in audit.events
    ] == [
        AuditEventType.LOGIN_FAILED,
        AuditEventType.ACCOUNT_LOCKED,
    ]


def test_authentication_database_failure_is_audited(
    audit_context,
) -> None:
    client, auth, _, audit = audit_context

    auth.auth_error = (
        UserRepositoryBackendError(
            "database unavailable"
        )
    )

    response = submit_login(
        client
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

    assert event.status_code == 503


def test_login_protection_failure_is_audited(
    audit_context,
) -> None:
    (
        client,
        _,
        protection,
        audit,
    ) = audit_context

    protection.check_error = (
        LoginProtectionBackendError(
            "Redis unavailable"
        )
    )

    response = submit_login(
        client
    )

    assert response.status_code == 503
    assert len(audit.events) == 1

    event = audit.events[0]

    assert event.event_type == (
        AuditEventType
        .RATE_LIMIT_BACKEND_UNAVAILABLE
    )

    assert event.outcome == (
        AuditOutcome.UNAVAILABLE
    )

    assert event.status_code == 503

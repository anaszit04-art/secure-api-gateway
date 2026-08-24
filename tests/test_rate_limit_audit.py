from __future__ import annotations

from datetime import (
    datetime,
    timezone,
)
from typing import Iterator
from uuid import UUID

from fastapi.testclient import TestClient
from prometheus_client import generate_latest

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
    get_current_user,
)
from gateway.app.auth.models import (
    UserPublic,
)
from gateway.app.authorization.dependencies import (
    get_authorization_service,
)
from gateway.app.main import app
from gateway.app.rate_limit.dependencies import (
    get_rate_limiter,
)
from gateway.app.rate_limit.login_dependencies import (
    get_login_protection,
)
from gateway.app.rate_limit.models import (
    RateLimitDecision,
    RateLimitPolicy,
)
from gateway.app.rate_limit.service import (
    RateLimitBackendError,
)


TEST_USER = UserPublic(
    id=UUID(
        "73000000-0000-0000-"
        "0000-000000000001"
    ),
    username="rate-audit-user",
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


class FakeAuthorizationService:
    async def require_permission(
        self,
        **_: object,
    ) -> None:
        return None


class FakeRateLimiter:
    def __init__(self) -> None:
        self.decision = RateLimitDecision(
            allowed=True,
            limit=60,
            remaining=59,
            retry_after_seconds=0,
            reset_after_seconds=1,
        )

        self.error: Exception | None = None

        self.identities: list[str] = []

    async def check(
        self,
        *,
        identity: str,
        policy: RateLimitPolicy,
    ) -> RateLimitDecision:
        del policy

        self.identities.append(
            identity
        )

        if self.error is not None:
            raise self.error

        return self.decision


class FakeAuthenticationService:
    async def authenticate_and_create_result(
        self,
        **_: object,
    ):
        raise AssertionError(
            "Authentication must not run when "
            "the login IP limiter rejects."
        )


class FakeLoginProtection:
    async def check_lock(
        self,
        **_: object,
    ):
        raise AssertionError(
            "Login protection must not run when "
            "the IP limiter rejects."
        )


def test_proxy_rate_limit_rejection_is_audited() -> None:
    limiter = FakeRateLimiter()

    limiter.decision = RateLimitDecision(
        allowed=False,
        limit=60,
        remaining=0,
        retry_after_seconds=3,
        reset_after_seconds=60,
    )

    audit = FakeAuditService()

    original = (
        app.dependency_overrides.copy()
    )

    app.dependency_overrides[
        get_current_user
    ] = lambda: TEST_USER

    app.dependency_overrides[
        get_authorization_service
    ] = lambda: FakeAuthorizationService()

    app.dependency_overrides[
        get_rate_limiter
    ] = lambda: limiter

    app.dependency_overrides[
        get_audit_service
    ] = lambda: audit

    try:
        with TestClient(app) as client:
            response = client.get(
                "/api/service-a/ping"
            )

    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(
            original
        )

    assert response.status_code == 429
    assert len(audit.events) == 1

    event = audit.events[0]

    assert event.event_type == (
        AuditEventType.RATE_LIMIT_REJECTED
    )

    assert event.outcome == (
        AuditOutcome.DENIED
    )

    assert event.actor_user_id == (
        TEST_USER.id
    )

    assert event.service_name == (
        "service-a"
    )

    assert event.method == "GET"
    assert event.status_code == 429

    assert event.reason_code == (
        "proxy_rate_limit_exceeded"
    )

    assert (
        str(event.request_id)
        == response.headers["x-request-id"]
    )


def test_proxy_rate_limit_backend_failure_is_audited() -> None:
    limiter = FakeRateLimiter()

    limiter.error = RateLimitBackendError(
        "Redis unavailable"
    )

    audit = FakeAuditService()

    original = (
        app.dependency_overrides.copy()
    )

    app.dependency_overrides[
        get_current_user
    ] = lambda: TEST_USER

    app.dependency_overrides[
        get_authorization_service
    ] = lambda: FakeAuthorizationService()

    app.dependency_overrides[
        get_rate_limiter
    ] = lambda: limiter

    app.dependency_overrides[
        get_audit_service
    ] = lambda: audit

    try:
        with TestClient(app) as client:
            response = client.get(
                "/api/service-a/ping"
            )

    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(
            original
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

    assert event.actor_user_id == (
        TEST_USER.id
    )

    assert event.status_code == 503


def test_login_ip_rate_limit_rejection_is_audited_without_ip() -> None:
    limiter = FakeRateLimiter()

    limiter.decision = RateLimitDecision(
        allowed=False,
        limit=10,
        remaining=0,
        retry_after_seconds=5,
        reset_after_seconds=50,
    )

    audit = FakeAuditService()

    original = (
        app.dependency_overrides.copy()
    )

    app.dependency_overrides[
        get_rate_limiter
    ] = lambda: limiter

    app.dependency_overrides[
        get_authentication_service
    ] = lambda: FakeAuthenticationService()

    app.dependency_overrides[
        get_login_protection
    ] = lambda: FakeLoginProtection()

    app.dependency_overrides[
        get_audit_service
    ] = lambda: audit

    try:
        with TestClient(app) as client:
            response = client.post(
                "/auth/token",
                data={
                    "username": "anas",
                    "password": (
                        "not-used-because-throttled"
                    ),
                },
                headers={
                    "X-Forwarded-For": (
                        "203.0.113.99"
                    ),
                },
            )

    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(
            original
        )

    assert response.status_code == 429
    assert len(audit.events) == 1

    event = audit.events[0]

    assert event.event_type == (
        AuditEventType.RATE_LIMIT_REJECTED
    )

    assert event.actor_user_id is None
    assert event.target_user_id is None
    assert event.status_code == 429

    assert event.reason_code == (
        "login_ip_rate_limit_exceeded"
    )

    serialized = repr(
        event
    )

    assert "203.0.113.99" not in serialized
    assert "anas" not in serialized


def test_login_ip_rate_limit_backend_failure_is_audited_without_ip() -> None:
    limiter = FakeRateLimiter()

    limiter.error = RateLimitBackendError(
        "Redis unavailable"
    )

    audit = FakeAuditService()

    original = (
        app.dependency_overrides.copy()
    )

    app.dependency_overrides[
        get_rate_limiter
    ] = lambda: limiter

    app.dependency_overrides[
        get_authentication_service
    ] = lambda: FakeAuthenticationService()

    app.dependency_overrides[
        get_login_protection
    ] = lambda: FakeLoginProtection()

    app.dependency_overrides[
        get_audit_service
    ] = lambda: audit

    try:
        with TestClient(app) as client:
            response = client.post(
                "/auth/token",
                data={
                    "username": "anas",
                    "password": (
                        "not-used-because-redis-failed"
                    ),
                },
            )

    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(
            original
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

    assert event.actor_user_id is None
    assert event.target_user_id is None

    assert event.reason_code == (
        "login_ip_rate_limit_backend_unavailable"
    )


def render_current_app_metrics() -> str:
    return generate_latest(
        app.state.metrics.registry
    ).decode(
        "utf-8"
    )


def test_proxy_rejection_updates_rate_limit_metrics() -> None:
    limiter = FakeRateLimiter()

    limiter.decision = RateLimitDecision(
        allowed=False,
        limit=60,
        remaining=0,
        retry_after_seconds=3,
        reset_after_seconds=60,
    )

    original = (
        app.dependency_overrides.copy()
    )

    app.dependency_overrides[
        get_current_user
    ] = lambda: TEST_USER

    app.dependency_overrides[
        get_authorization_service
    ] = lambda: FakeAuthorizationService()

    app.dependency_overrides[
        get_rate_limiter
    ] = lambda: limiter

    app.dependency_overrides[
        get_audit_service
    ] = lambda: FakeAuditService()

    try:
        with TestClient(app) as client:
            response = client.get(
                "/api/service-a/ping"
            )

            rendered = (
                render_current_app_metrics()
            )

    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(
            original
        )

    assert response.status_code == 429

    assert (
        'gateway_rate_limit_decisions_total'
        '{decision="rejected",scope="proxy"} '
        '1.0'
        in rendered
    )

    assert (
        'gateway_security_events_total'
        '{event_type="rate_limit_rejected",'
        'outcome="denied"} 1.0'
        in rendered
    )


def test_proxy_backend_failure_updates_unavailable_metric() -> None:
    limiter = FakeRateLimiter()

    limiter.error = RateLimitBackendError(
        "Redis unavailable"
    )

    original = (
        app.dependency_overrides.copy()
    )

    app.dependency_overrides[
        get_current_user
    ] = lambda: TEST_USER

    app.dependency_overrides[
        get_authorization_service
    ] = lambda: FakeAuthorizationService()

    app.dependency_overrides[
        get_rate_limiter
    ] = lambda: limiter

    app.dependency_overrides[
        get_audit_service
    ] = lambda: FakeAuditService()

    try:
        with TestClient(app) as client:
            response = client.get(
                "/api/service-a/ping"
            )

            rendered = (
                render_current_app_metrics()
            )

    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(
            original
        )

    assert response.status_code == 503

    assert (
        'gateway_rate_limit_decisions_total'
        '{decision="unavailable",scope="proxy"} '
        '1.0'
        in rendered
    )


def test_login_rejection_updates_rate_limit_metrics() -> None:
    limiter = FakeRateLimiter()

    limiter.decision = RateLimitDecision(
        allowed=False,
        limit=10,
        remaining=0,
        retry_after_seconds=5,
        reset_after_seconds=50,
    )

    original = (
        app.dependency_overrides.copy()
    )

    app.dependency_overrides[
        get_rate_limiter
    ] = lambda: limiter

    app.dependency_overrides[
        get_authentication_service
    ] = lambda: FakeAuthenticationService()

    app.dependency_overrides[
        get_login_protection
    ] = lambda: FakeLoginProtection()

    app.dependency_overrides[
        get_audit_service
    ] = lambda: FakeAuditService()

    try:
        with TestClient(app) as client:
            response = client.post(
                "/auth/token",
                data={
                    "username": "anas",
                    "password": "unused",
                },
            )

            rendered = (
                render_current_app_metrics()
            )

    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(
            original
        )

    assert response.status_code == 429

    assert (
        'gateway_rate_limit_decisions_total'
        '{decision="rejected",scope="login"} '
        '1.0'
        in rendered
    )


def test_login_backend_failure_updates_unavailable_metric() -> None:
    limiter = FakeRateLimiter()

    limiter.error = RateLimitBackendError(
        "Redis unavailable"
    )

    original = (
        app.dependency_overrides.copy()
    )

    app.dependency_overrides[
        get_rate_limiter
    ] = lambda: limiter

    app.dependency_overrides[
        get_authentication_service
    ] = lambda: FakeAuthenticationService()

    app.dependency_overrides[
        get_login_protection
    ] = lambda: FakeLoginProtection()

    app.dependency_overrides[
        get_audit_service
    ] = lambda: FakeAuditService()

    try:
        with TestClient(app) as client:
            response = client.post(
                "/auth/token",
                data={
                    "username": "anas",
                    "password": "unused",
                },
            )

            rendered = (
                render_current_app_metrics()
            )

    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(
            original
        )

    assert response.status_code == 503

    assert (
        'gateway_rate_limit_decisions_total'
        '{decision="unavailable",scope="login"} '
        '1.0'
        in rendered
    )

from __future__ import annotations

from datetime import (
    datetime,
    timezone,
)
from typing import Any
from uuid import UUID

import httpx

from fastapi import (
    HTTPException,
)
from fastapi.testclient import TestClient

from gateway.app.audit.dependencies import (
    get_audit_service,
)
from gateway.app.audit.repository import (
    AuditRepositoryBackendError,
)
from gateway.app.auth.dependencies import (
    get_current_user,
)
from gateway.app.auth.models import (
    UserPublic,
)
from gateway.app.authorization.dependencies import (
    get_authorization_service,
)
from gateway.app.authorization.service import (
    AuthorizationDeniedError,
)
from gateway.app.main import app
from gateway.app.proxy.resilience import (
    CircuitBreakerRegistry,
    UpstreamResilienceSettings,
)
from gateway.app.rate_limit.dependencies import (
    get_rate_limiter,
)
from gateway.app.rate_limit.models import (
    RateLimitDecision,
)


TEST_USER = UserPublic(
    id=UUID(
        "76000000-0000-0000-"
        "0000-000000000001"
    ),
    username="boundary-test-user",
    is_active=True,
    created_at=datetime(
        2026,
        8,
        24,
        tzinfo=timezone.utc,
    ),
)


class FakeAuthorizationService:
    def __init__(
        self,
        *,
        allowed: bool = True,
    ) -> None:
        self.allowed = allowed

    async def require_permission(
        self,
        **_: object,
    ) -> None:
        if not self.allowed:
            raise AuthorizationDeniedError(
                "Permission denied."
            )


class FakeRateLimiter:
    def __init__(
        self,
        *,
        allowed: bool = True,
    ) -> None:
        self.allowed = allowed

    async def check(
        self,
        **_: object,
    ) -> RateLimitDecision:
        if self.allowed:
            return RateLimitDecision(
                allowed=True,
                limit=60,
                remaining=59,
                retry_after_seconds=0,
                reset_after_seconds=1,
            )

        return RateLimitDecision(
            allowed=False,
            limit=60,
            remaining=0,
            retry_after_seconds=3,
            reset_after_seconds=60,
        )


class FailingAuditService:
    async def record(
        self,
        event,
    ) -> None:
        del event

        raise AuditRepositoryBackendError(
            "audit persistence unavailable"
        )


class FailingUpstreamClient:
    def __init__(self) -> None:
        self.calls: list[
            dict[str, Any]
        ] = []

    async def request(
        self,
        **kwargs: Any,
    ) -> httpx.Response:
        self.calls.append(
            kwargs
        )

        request = httpx.Request(
            kwargs["method"],
            kwargs["url"],
        )

        raise httpx.ConnectError(
            "upstream unavailable",
            request=request,
        )


def configure_single_failure_circuit() -> None:
    settings = (
        UpstreamResilienceSettings(
            max_attempts=1,
            retry_base_delay_seconds=0,
            failure_threshold=1,
            recovery_timeout_seconds=60,
        )
    )

    app.state.upstream_resilience_settings = (
        settings
    )

    app.state.upstream_circuit_breakers = (
        CircuitBreakerRegistry(
            service_names=(
                "service-a",
                "service-b",
            ),
            settings=settings,
        )
    )


def test_401_boundary_never_touches_upstream_or_circuit() -> None:
    original = (
        app.dependency_overrides.copy()
    )

    upstream = FailingUpstreamClient()
    authorization = (
        FakeAuthorizationService(
            allowed=True
        )
    )
    limiter = FakeRateLimiter(
        allowed=True
    )

    authenticated = {
        "allowed": False,
    }

    def resolve_user():
        if not authenticated[
            "allowed"
        ]:
            raise HTTPException(
                status_code=401,
                detail=(
                    "Not authenticated"
                ),
                headers={
                    "WWW-Authenticate": (
                        "Bearer"
                    ),
                },
            )

        return TEST_USER

    app.dependency_overrides[
        get_current_user
    ] = resolve_user

    app.dependency_overrides[
        get_authorization_service
    ] = lambda: authorization

    app.dependency_overrides[
        get_rate_limiter
    ] = lambda: limiter

    try:
        with TestClient(app) as client:
            app.state.http_client = (
                upstream
            )

            configure_single_failure_circuit()

            rejected = client.get(
                "/api/service-a/ping"
            )

            assert (
                rejected.status_code
                == 401
            )

            assert upstream.calls == []

            authenticated[
                "allowed"
            ] = True

            first_authorized = (
                client.get(
                    "/api/service-a/ping"
                )
            )

            assert (
                first_authorized.status_code
                == 502
            )

            assert len(
                upstream.calls
            ) == 1

            after_open = client.get(
                "/api/service-a/ping"
            )

            assert (
                after_open.status_code
                == 503
            )

            assert len(
                upstream.calls
            ) == 1

    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(
            original
        )


def test_403_boundary_never_touches_upstream_or_circuit() -> None:
    original = (
        app.dependency_overrides.copy()
    )

    upstream = FailingUpstreamClient()

    authorization = (
        FakeAuthorizationService(
            allowed=False
        )
    )

    limiter = FakeRateLimiter(
        allowed=True
    )

    app.dependency_overrides[
        get_current_user
    ] = lambda: TEST_USER

    app.dependency_overrides[
        get_authorization_service
    ] = lambda: authorization

    app.dependency_overrides[
        get_rate_limiter
    ] = lambda: limiter

    try:
        with TestClient(app) as client:
            app.state.http_client = (
                upstream
            )

            configure_single_failure_circuit()

            denied = client.get(
                "/api/service-a/ping"
            )

            assert denied.status_code == 403
            assert upstream.calls == []

            authorization.allowed = True

            first_authorized = (
                client.get(
                    "/api/service-a/ping"
                )
            )

            assert (
                first_authorized.status_code
                == 502
            )

            assert len(
                upstream.calls
            ) == 1

            after_open = client.get(
                "/api/service-a/ping"
            )

            assert (
                after_open.status_code
                == 503
            )

            assert len(
                upstream.calls
            ) == 1

    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(
            original
        )


def test_429_boundary_never_touches_upstream_or_circuit() -> None:
    original = (
        app.dependency_overrides.copy()
    )

    upstream = FailingUpstreamClient()

    authorization = (
        FakeAuthorizationService(
            allowed=True
        )
    )

    limiter = FakeRateLimiter(
        allowed=False
    )

    app.dependency_overrides[
        get_current_user
    ] = lambda: TEST_USER

    app.dependency_overrides[
        get_authorization_service
    ] = lambda: authorization

    app.dependency_overrides[
        get_rate_limiter
    ] = lambda: limiter

    try:
        with TestClient(app) as client:
            app.state.http_client = (
                upstream
            )

            configure_single_failure_circuit()

            throttled = client.get(
                "/api/service-a/ping"
            )

            assert (
                throttled.status_code
                == 429
            )

            assert upstream.calls == []

            limiter.allowed = True

            first_allowed = client.get(
                "/api/service-a/ping"
            )

            assert (
                first_allowed.status_code
                == 502
            )

            assert len(
                upstream.calls
            ) == 1

            after_open = client.get(
                "/api/service-a/ping"
            )

            assert (
                after_open.status_code
                == 503
            )

            assert len(
                upstream.calls
            ) == 1

    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(
            original
        )


def test_audit_persistence_failure_does_not_change_403() -> None:
    original = (
        app.dependency_overrides.copy()
    )

    upstream = FailingUpstreamClient()

    authorization = (
        FakeAuthorizationService(
            allowed=False
        )
    )

    app.dependency_overrides[
        get_current_user
    ] = lambda: TEST_USER

    app.dependency_overrides[
        get_authorization_service
    ] = lambda: authorization

    app.dependency_overrides[
        get_rate_limiter
    ] = lambda: FakeRateLimiter(
        allowed=True
    )

    app.dependency_overrides[
        get_audit_service
    ] = lambda: FailingAuditService()

    try:
        with TestClient(app) as client:
            app.state.http_client = (
                upstream
            )

            configure_single_failure_circuit()

            response = client.get(
                "/api/service-a/ping"
            )

            assert (
                response.status_code
                == 403
            )

            assert response.json() == {
                "detail": (
                    "Permission denied."
                )
            }

            assert upstream.calls == []

    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(
            original
        )

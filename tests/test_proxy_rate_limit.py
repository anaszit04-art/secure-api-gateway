from datetime import datetime, timezone
from typing import Any, Iterator
from uuid import UUID

import httpx
import pytest

from fastapi.testclient import TestClient

from gateway.app.auth.dependencies import (
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
from gateway.app.rate_limit.models import (
    RateLimitDecision,
    RateLimitPolicy,
)
from gateway.app.rate_limit.service import (
    RateLimitBackendError,
)


TEST_USER = UserPublic(
    id=UUID(
        "5267805d-632c-447e-"
        "91b3-e92a60d0281f"
    ),
    username="anas",
    is_active=True,
    created_at=datetime(
        2026,
        7,
        30,
        tzinfo=timezone.utc,
    ),
)


class FakeAllowedAuthorizationService:
    async def require_permission(
        self,
        **_: Any,
    ) -> None:
        return None


class FakeUpstreamClient:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def request(
        self,
        **kwargs: Any,
    ) -> httpx.Response:
        self.calls.append(kwargs)

        return httpx.Response(
            status_code=200,
            json={
                "message": "pong",
                "service": "service-a",
            },
            headers={
                "Content-Type": "application/json",
            },
        )


class FakeRateLimiter:
    def __init__(
        self,
        *,
        decision: RateLimitDecision | None = None,
        error: Exception | None = None,
    ) -> None:
        self.decision = decision
        self.error = error
        self.calls: list[
            tuple[str, RateLimitPolicy]
        ] = []

    async def check(
        self,
        *,
        identity: str,
        policy: RateLimitPolicy,
    ) -> RateLimitDecision:
        self.calls.append(
            (
                identity,
                policy,
            )
        )

        if self.error is not None:
            raise self.error

        if self.decision is None:
            raise AssertionError(
                "No rate-limit decision configured."
            )

        return self.decision


@pytest.fixture
def proxy_context() -> Iterator[
    tuple[
        TestClient,
        FakeUpstreamClient,
        FakeRateLimiter,
    ]
]:
    upstream = FakeUpstreamClient()

    limiter = FakeRateLimiter(
        decision=RateLimitDecision(
            allowed=True,
            limit=60,
            remaining=42,
            retry_after_seconds=0,
            reset_after_seconds=18,
        )
    )

    original_overrides = (
        app.dependency_overrides.copy()
    )

    app.dependency_overrides[
        get_current_user
    ] = lambda: TEST_USER

    app.dependency_overrides[
        get_rate_limiter
    ] = lambda: limiter

    app.dependency_overrides[
        get_authorization_service
    ] = (
        lambda: FakeAllowedAuthorizationService()
    )

    try:
        with TestClient(app) as client:
            app.state.http_client = upstream

            yield client, upstream, limiter
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(
            original_overrides
        )


def test_allowed_proxy_request_has_rate_limit_headers(
    proxy_context: tuple[
        TestClient,
        FakeUpstreamClient,
        FakeRateLimiter,
    ],
) -> None:
    client, upstream, limiter = proxy_context

    response = client.get(
        "/api/service-a/ping"
    )

    assert response.status_code == 200

    assert response.headers[
        "x-ratelimit-limit"
    ] == "60"

    assert response.headers[
        "x-ratelimit-remaining"
    ] == "42"

    assert response.headers[
        "x-ratelimit-reset"
    ] == "18"

    assert "retry-after" not in response.headers

    assert len(upstream.calls) == 1
    assert len(limiter.calls) == 1

    identity, policy = limiter.calls[0]

    assert identity == str(TEST_USER.id)
    assert policy.name == (
        "authenticated-proxy"
    )
    assert policy.capacity == 60
    assert policy.refill_rate_per_second == 1


def test_denied_proxy_request_returns_429(
    proxy_context: tuple[
        TestClient,
        FakeUpstreamClient,
        FakeRateLimiter,
    ],
) -> None:
    client, upstream, limiter = proxy_context

    limiter.decision = RateLimitDecision(
        allowed=False,
        limit=60,
        remaining=0,
        retry_after_seconds=3,
        reset_after_seconds=60,
    )

    response = client.get(
        "/api/service-a/ping"
    )

    assert response.status_code == 429

    assert response.json() == {
        "detail": "Rate limit exceeded."
    }

    assert response.headers[
        "retry-after"
    ] == "3"

    assert response.headers[
        "x-ratelimit-limit"
    ] == "60"

    assert response.headers[
        "x-ratelimit-remaining"
    ] == "0"

    assert response.headers[
        "x-ratelimit-reset"
    ] == "60"

    assert upstream.calls == []
    assert len(limiter.calls) == 1


def test_proxy_returns_503_when_redis_fails(
    proxy_context: tuple[
        TestClient,
        FakeUpstreamClient,
        FakeRateLimiter,
    ],
) -> None:
    client, upstream, limiter = proxy_context

    limiter.error = RateLimitBackendError(
        "Redis unavailable"
    )

    response = client.get(
        "/api/service-a/ping"
    )

    assert response.status_code == 503

    assert response.headers[
        "retry-after"
    ] == "1"

    assert response.json() == {
        "detail": (
            "Rate-limit service is temporarily "
            "unavailable."
        )
    }

    assert upstream.calls == []
    assert len(limiter.calls) == 1

from __future__ import annotations

from datetime import (
    datetime,
    timezone,
)
from typing import (
    Any,
    Iterator,
)
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
        "74000000-0000-0000-"
        "0000-000000000001"
    ),
    username="resilience-test-user",
    is_active=True,
    created_at=datetime(
        2026,
        8,
        24,
        tzinfo=timezone.utc,
    ),
)


class FakeAuthorizationService:
    async def require_permission(
        self,
        **_: object,
    ) -> None:
        return None


class FakeRateLimiter:
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


class SequenceAsyncClient:
    def __init__(
        self,
        outcomes: list[
            httpx.Response | Exception
        ],
    ) -> None:
        self.outcomes = list(
            outcomes
        )

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

        if not self.outcomes:
            raise AssertionError(
                "No upstream outcome remains."
            )

        outcome = self.outcomes.pop(
            0
        )

        if isinstance(
            outcome,
            Exception,
        ):
            raise outcome

        return outcome


def connect_error() -> httpx.ConnectError:
    return httpx.ConnectError(
        "connection failed",
        request=httpx.Request(
            "GET",
            "http://service-a/ping",
        ),
    )


def read_timeout() -> httpx.ReadTimeout:
    return httpx.ReadTimeout(
        "read timed out",
        request=httpx.Request(
            "GET",
            "http://service-a/ping",
        ),
    )


@pytest.fixture
def proxy_context() -> Iterator[
    tuple[
        TestClient,
        SequenceAsyncClient,
    ]
]:
    original = (
        app.dependency_overrides.copy()
    )

    app.dependency_overrides[
        get_current_user
    ] = lambda: TEST_USER

    app.dependency_overrides[
        get_rate_limiter
    ] = lambda: FakeRateLimiter()

    app.dependency_overrides[
        get_authorization_service
    ] = lambda: FakeAuthorizationService()

    try:
        with TestClient(app) as client:
            fake = SequenceAsyncClient(
                []
            )

            app.state.http_client = fake

            yield (
                client,
                fake,
            )

    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(
            original
        )


def configure_resilience(
    *,
    max_attempts: int = 2,
    failure_threshold: int = 3,
    recovery_seconds: float = 60,
) -> None:
    settings = (
        UpstreamResilienceSettings(
            max_attempts=max_attempts,
            retry_base_delay_seconds=0,
            failure_threshold=(
                failure_threshold
            ),
            recovery_timeout_seconds=(
                recovery_seconds
            ),
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


def test_get_connect_failure_retries_then_succeeds(
    proxy_context,
) -> None:
    client, upstream = proxy_context

    configure_resilience()

    upstream.outcomes.extend(
        [
            connect_error(),
            httpx.Response(
                200,
                json={
                    "message": "pong",
                },
            ),
        ]
    )

    response = client.get(
        "/api/service-a/ping"
    )

    assert response.status_code == 200

    assert response.json() == {
        "message": "pong",
    }

    assert len(upstream.calls) == 2


def test_post_connect_failure_is_not_retried(
    proxy_context,
) -> None:
    client, upstream = proxy_context

    configure_resilience()

    upstream.outcomes.extend(
        [
            connect_error(),
            httpx.Response(
                200
            ),
        ]
    )

    response = client.post(
        "/api/service-a/echo",
        json={
            "value": 1,
        },
    )

    assert response.status_code == 502
    assert len(upstream.calls) == 1


def test_read_timeout_is_not_retried(
    proxy_context,
) -> None:
    client, upstream = proxy_context

    configure_resilience()

    upstream.outcomes.extend(
        [
            read_timeout(),
            httpx.Response(
                200
            ),
        ]
    )

    response = client.get(
        "/api/service-a/ping"
    )

    assert response.status_code == 504
    assert len(upstream.calls) == 1


def test_open_circuit_returns_503_without_network_call(
    proxy_context,
) -> None:
    client, upstream = proxy_context

    configure_resilience(
        max_attempts=1,
        failure_threshold=1,
        recovery_seconds=60,
    )

    upstream.outcomes.append(
        connect_error()
    )

    first = client.get(
        "/api/service-a/ping"
    )

    assert first.status_code == 502
    assert len(upstream.calls) == 1

    second = client.get(
        "/api/service-a/ping"
    )

    assert second.status_code == 503

    assert second.json() == {
        "detail": (
            "Upstream service temporarily "
            "unavailable"
        )
    }

    assert int(
        second.headers["retry-after"]
    ) >= 1

    assert len(upstream.calls) == 1


def test_upstream_5xx_opens_circuit_without_retry(
    proxy_context,
) -> None:
    client, upstream = proxy_context

    configure_resilience(
        failure_threshold=1,
        recovery_seconds=60,
    )

    upstream.outcomes.append(
        httpx.Response(
            503,
            json={
                "detail": "service degraded",
            },
        )
    )

    first = client.get(
        "/api/service-a/ping"
    )

    assert first.status_code == 503

    assert first.json() == {
        "detail": "service degraded",
    }

    assert len(upstream.calls) == 1

    second = client.get(
        "/api/service-a/ping"
    )

    assert second.status_code == 503

    assert second.json() == {
        "detail": (
            "Upstream service temporarily "
            "unavailable"
        )
    }

    assert "retry-after" in (
        second.headers
    )

    assert len(upstream.calls) == 1


def test_service_b_remains_available_when_service_a_circuit_is_open(
    proxy_context,
) -> None:
    client, upstream = proxy_context

    configure_resilience(
        max_attempts=1,
        failure_threshold=1,
        recovery_seconds=60,
    )

    upstream.outcomes.extend(
        [
            connect_error(),
            httpx.Response(
                200,
                json={
                    "service": "service-b",
                },
            ),
        ]
    )

    failed_a = client.get(
        "/api/service-a/ping"
    )

    assert failed_a.status_code == 502

    blocked_a = client.get(
        "/api/service-a/ping"
    )

    assert blocked_a.status_code == 503

    healthy_b = client.get(
        "/api/service-b/ping"
    )

    assert healthy_b.status_code == 200

    assert healthy_b.json() == {
        "service": "service-b",
    }

    assert len(upstream.calls) == 2


def test_retry_and_circuit_events_reach_prometheus(
    proxy_context,
) -> None:
    from prometheus_client import (
        generate_latest,
    )

    client, upstream = proxy_context

    configure_resilience(
        max_attempts=2,
        failure_threshold=1,
        recovery_seconds=60,
    )

    upstream.outcomes.extend(
        [
            connect_error(),
            connect_error(),
        ]
    )

    first = client.get(
        "/api/service-a/ping"
    )

    assert first.status_code == 502

    second = client.get(
        "/api/service-a/ping"
    )

    assert second.status_code == 503

    rendered = generate_latest(
        app.state.metrics.registry
    ).decode(
        "utf-8"
    )

    assert (
        'gateway_upstream_resilience_events_total'
        '{event="retry",service="service-a"} '
        '1.0'
        in rendered
    )

    assert (
        'gateway_upstream_resilience_events_total'
        '{event="circuit_open",service="service-a"} '
        '1.0'
        in rendered
    )

    assert (
        'gateway_upstream_resilience_events_total'
        '{event="circuit_rejected",service="service-a"} '
        '1.0'
        in rendered
    )

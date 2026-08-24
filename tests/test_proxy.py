import json

from datetime import datetime, timezone
from typing import Any, Iterator
from uuid import UUID

import pytest

import httpx
from fastapi.testclient import TestClient

from gateway.app.auth.dependencies import (
    get_current_user,
)
from gateway.app.authorization.dependencies import (
    get_authorization_service,
)
from gateway.app.auth.models import UserPublic

from gateway.app.main import app
from gateway.app.rate_limit.dependencies import (
    get_rate_limiter,
)
from gateway.app.rate_limit.models import (
    RateLimitDecision,
)


class FakeAllowedAuthorizationService:
    async def require_permission(
        self,
        **_: Any,
    ) -> None:
        return None


TEST_CURRENT_USER = UserPublic(
    id=UUID(
        "7f963fc4-f5de-4db0-b8ab-50949d63bc0a"
    ),
    username="proxy-test-user",
    is_active=True,
    created_at=datetime(
        2026,
        7,
        24,
        tzinfo=timezone.utc,
    ),
)


@pytest.fixture(autouse=True)
def override_proxy_authentication() -> Iterator[None]:
    """
    Isolate the legacy proxy-behaviour tests from JWT.

    Authentication itself is tested separately.
    """
    original_overrides = (
        app.dependency_overrides.copy()
    )

    app.dependency_overrides[
        get_current_user
    ] = lambda: TEST_CURRENT_USER

    app.dependency_overrides[
        get_rate_limiter
    ] = lambda: FakeAllowedRateLimiter()

    app.dependency_overrides[
        get_authorization_service
    ] = (
        lambda: FakeAllowedAuthorizationService()
    )

    try:
        yield
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(
            original_overrides
        )


class FakeAllowedRateLimiter:
    async def check(
        self,
        **_: Any,
    ) -> RateLimitDecision:
        return RateLimitDecision(
            allowed=True,
            limit=60,
            remaining=59,
            retry_after_seconds=0,
            reset_after_seconds=1,
        )


class FakeAsyncClient:
    def __init__(
        self,
        *,
        response: httpx.Response | None = None,
        error: Exception | None = None,
    ) -> None:
        self.response = response
        self.error = error
        self.calls: list[dict[str, Any]] = []

    async def request(
        self,
        **kwargs: Any,
    ) -> httpx.Response:
        self.calls.append(kwargs)

        if self.error is not None:
            raise self.error

        if self.response is None:
            raise AssertionError(
                "The fake client has no configured response."
            )

        return self.response


def call_gateway(
    fake_client: FakeAsyncClient,
    method: str,
    path: str,
    **kwargs: Any,
) -> httpx.Response:
    with TestClient(app) as client:
        app.state.http_client = fake_client

        return client.request(
            method,
            path,
            **kwargs,
        )


def test_proxy_forwards_path_and_repeated_query_parameters() -> None:
    fake_client = FakeAsyncClient(
        response=httpx.Response(
            status_code=200,
            json={
                "service": "service-b",
                "product": {
                    "id": 2,
                },
            },
            headers={
                "Content-Type": "application/json",
                "X-Upstream-ID": "service-b-instance-1",
                "Server": "upstream-server",
                "Date": "Tue, 21 Jul 2026 11:00:00 GMT",
            },
        )
    )

    response = call_gateway(
        fake_client,
        "GET",
        "/api/service-b/products/2"
        "?tag=python&tag=security",
    )

    assert response.status_code == 200
    assert response.json() == {
        "service": "service-b",
        "product": {
            "id": 2,
        },
    }

    assert len(fake_client.calls) == 1

    upstream_call = fake_client.calls[0]

    assert upstream_call["method"] == "GET"
    assert upstream_call["url"] == (
        "http://127.0.0.1:8002/products/2"
    )
    assert upstream_call["params"] == [
        ("tag", "python"),
        ("tag", "security"),
    ]

    assert response.headers["x-upstream-id"] == (
        "service-b-instance-1"
    )


def test_proxy_forwards_json_and_replaces_spoofed_ip_headers() -> None:
    payload = {
        "source": "gateway",
        "enabled": True,
    }

    fake_client = FakeAsyncClient(
        response=httpx.Response(
            status_code=200,
            json={
                "service": "service-a",
                "received": payload,
            },
            headers={
                "Content-Type": "application/json",
            },
        )
    )

    response = call_gateway(
        fake_client,
        "POST",
        "/api/service-a/echo",
        json=payload,
        headers={
            "X-Forwarded-For": "203.0.113.10",
            "Forwarded": "for=203.0.113.10",
            "X-Real-IP": "203.0.113.10",
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "service": "service-a",
        "received": payload,
    }

    upstream_call = fake_client.calls[0]

    assert json.loads(
        upstream_call["content"]
    ) == payload

    outgoing_headers = upstream_call["headers"]

    assert outgoing_headers["x-forwarded-for"] == (
        "testclient"
    )
    assert "forwarded" not in outgoing_headers
    assert "x-real-ip" not in outgoing_headers


def test_proxy_preserves_upstream_404_response() -> None:
    fake_client = FakeAsyncClient(
        response=httpx.Response(
            status_code=404,
            json={
                "detail": "Product not found",
            },
            headers={
                "Content-Type": "application/json",
            },
        )
    )

    response = call_gateway(
        fake_client,
        "GET",
        "/api/service-b/products/999",
    )

    assert response.status_code == 404
    assert response.json() == {
        "detail": "Product not found",
    }


def test_proxy_rejects_unknown_service_without_upstream_call() -> None:
    fake_client = FakeAsyncClient(
        response=httpx.Response(
            status_code=200,
            json={
                "unexpected": True,
            },
        )
    )

    response = call_gateway(
        fake_client,
        "GET",
        "/api/service-c/ping",
    )

    assert response.status_code == 404
    assert response.json() == {
        "detail": "Unknown service: service-c",
    }

    assert fake_client.calls == []


def test_proxy_returns_502_when_connection_fails() -> None:
    upstream_request = httpx.Request(
        "GET",
        "http://127.0.0.1:8001/ping",
    )

    fake_client = FakeAsyncClient(
        error=httpx.ConnectError(
            "Connection failed",
            request=upstream_request,
        )
    )

    response = call_gateway(
        fake_client,
        "GET",
        "/api/service-a/ping",
    )

    assert response.status_code == 502
    assert response.json() == {
        "detail": "Upstream service unavailable",
    }


def test_proxy_returns_504_when_upstream_times_out() -> None:
    upstream_request = httpx.Request(
        "GET",
        "http://127.0.0.1:8001/ping",
    )

    fake_client = FakeAsyncClient(
        error=httpx.ReadTimeout(
            "Read timed out",
            request=upstream_request,
        )
    )

    response = call_gateway(
        fake_client,
        "GET",
        "/api/service-a/ping",
    )

    assert response.status_code == 504
    assert response.json() == {
        "detail": "Upstream service timeout",
    }


def test_proxy_replaces_and_propagates_request_id() -> None:
    fake_client = FakeAsyncClient(
        response=httpx.Response(
            status_code=200,
            json={
                "message": "pong",
            },
            headers={
                "Content-Type": "application/json",
                "X-Request-ID": (
                    "upstream-controlled-id"
                ),
            },
        )
    )

    response = call_gateway(
        fake_client,
        "GET",
        "/api/service-a/ping",
        headers={
            "X-Request-ID": (
                "client-controlled-id"
            ),
        },
    )

    assert response.status_code == 200

    gateway_request_id = (
        response.headers[
            "x-request-id"
        ]
    )

    assert gateway_request_id not in {
        "client-controlled-id",
        "upstream-controlled-id",
    }

    UUID(
        gateway_request_id
    )

    upstream_headers = (
        fake_client.calls[0][
            "headers"
        ]
    )

    assert (
        upstream_headers[
            "x-request-id"
        ]
        == gateway_request_id
    )

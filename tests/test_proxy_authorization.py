from __future__ import annotations

from datetime import (
    datetime,
    timezone,
)
from typing import Any, Iterator
from uuid import UUID

import httpx
import pytest

from fastapi import HTTPException
from fastapi.testclient import TestClient

from gateway.app.auth.dependencies import (
    get_current_user,
)
from gateway.app.auth.models import (
    UserPublic,
)
from gateway.app.authorization.dependencies import (
    get_authorization_service,
    resolve_proxy_permission,
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


TEST_USER = UserPublic(
    id=UUID(
        "1ea13b78-4afd-4f05-"
        "a867-f143082f81ef"
    ),
    username="authorization-test-user",
    is_active=True,
    created_at=datetime(
        2026,
        8,
        19,
        tzinfo=timezone.utc,
    ),
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


class FakeAuthorizationService:
    def __init__(
        self,
        *,
        allowed: bool = True,
        backend_failure: bool = False,
    ) -> None:
        self.allowed = allowed
        self.backend_failure = (
            backend_failure
        )

        self.calls: list[
            tuple[UUID, str]
        ] = []

    async def require_permission(
        self,
        *,
        user_id: UUID,
        permission_code: str,
    ) -> None:
        self.calls.append(
            (
                user_id,
                permission_code,
            )
        )

        if self.backend_failure:
            raise (
                AuthorizationRepositoryBackendError(
                    "database unavailable"
                )
            )

        if not self.allowed:
            raise AuthorizationDeniedError(
                "Permission denied."
            )


class FakeUpstreamClient:
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

        return httpx.Response(
            status_code=200,
            json={
                "status": "ok",
            },
            headers={
                "Content-Type": "application/json",
            },
        )


@pytest.mark.parametrize(
    "method",
    [
        "GET",
        "HEAD",
        "OPTIONS",
    ],
)
def test_safe_methods_require_read_permission(
    method: str,
) -> None:
    assert (
        resolve_proxy_permission(
            service_name="service-a",
            method=method,
        )
        == "proxy:service-a:read"
    )


@pytest.mark.parametrize(
    "method",
    [
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
    ],
)
def test_mutating_methods_require_write_permission(
    method: str,
) -> None:
    assert (
        resolve_proxy_permission(
            service_name="service-b",
            method=method,
        )
        == "proxy:service-b:write"
    )


def test_unknown_service_is_rejected() -> None:
    with pytest.raises(
        HTTPException
    ) as captured:
        resolve_proxy_permission(
            service_name="service-c",
            method="GET",
        )

    assert (
        captured.value.status_code
        == 404
    )


def test_unknown_method_is_denied_by_default() -> None:
    with pytest.raises(
        HTTPException
    ) as captured:
        resolve_proxy_permission(
            service_name="service-a",
            method="TRACE",
        )

    assert (
        captured.value.status_code
        == 403
    )


@pytest.fixture
def proxy_authorization_context() -> Iterator[
    tuple[
        TestClient,
        FakeAuthorizationService,
        FakeUpstreamClient,
    ]
]:
    authorization = (
        FakeAuthorizationService()
    )

    upstream = FakeUpstreamClient()

    original_overrides = (
        app.dependency_overrides.copy()
    )

    app.dependency_overrides[
        get_current_user
    ] = lambda: TEST_USER

    app.dependency_overrides[
        get_rate_limiter
    ] = lambda: FakeAllowedRateLimiter()

    app.dependency_overrides[
        get_authorization_service
    ] = lambda: authorization

    try:
        with TestClient(app) as client:
            app.state.http_client = upstream

            yield (
                client,
                authorization,
                upstream,
            )

    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(
            original_overrides
        )


def test_allowed_request_reaches_upstream(
    proxy_authorization_context: tuple[
        TestClient,
        FakeAuthorizationService,
        FakeUpstreamClient,
    ],
) -> None:
    (
        client,
        authorization,
        upstream,
    ) = proxy_authorization_context

    response = client.get(
        "/api/service-a/ping"
    )

    assert response.status_code == 200

    assert authorization.calls == [
        (
            TEST_USER.id,
            "proxy:service-a:read",
        )
    ]

    assert len(
        upstream.calls
    ) == 1


def test_denied_request_returns_403_without_upstream_call(
    proxy_authorization_context: tuple[
        TestClient,
        FakeAuthorizationService,
        FakeUpstreamClient,
    ],
) -> None:
    (
        client,
        authorization,
        upstream,
    ) = proxy_authorization_context

    authorization.allowed = False

    response = client.post(
        "/api/service-a/echo",
        json={
            "test": True,
        },
    )

    assert response.status_code == 403

    assert response.json() == {
        "detail": "Permission denied."
    }

    assert authorization.calls == [
        (
            TEST_USER.id,
            "proxy:service-a:write",
        )
    ]

    assert upstream.calls == []


def test_authorization_backend_failure_returns_503(
    proxy_authorization_context: tuple[
        TestClient,
        FakeAuthorizationService,
        FakeUpstreamClient,
    ],
) -> None:
    (
        client,
        authorization,
        upstream,
    ) = proxy_authorization_context

    authorization.backend_failure = True

    response = client.get(
        "/api/service-b/products"
    )

    assert response.status_code == 503

    assert response.headers[
        "retry-after"
    ] == "1"

    assert response.json() == {
        "detail": (
            "Authorization service is temporarily "
            "unavailable."
        )
    }

    assert upstream.calls == []

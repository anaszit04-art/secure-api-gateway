from dataclasses import replace
from typing import Any, Iterator

import httpx
import pytest

from fastapi.testclient import TestClient

from gateway.app.auth.config import AuthSettings
from gateway.app.auth.dependencies import (
    get_auth_settings,
    get_user_repository,
)
from gateway.app.auth.repository import (
    InMemoryUserRepository,
)
from gateway.app.auth.tokens import (
    create_access_token,
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
)


class FakeAllowedAuthorizationService:
    async def require_permission(
        self,
        **_: Any,
    ) -> None:
        return None


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
    """
    Minimal upstream HTTP client used by proxy auth tests.
    """

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


@pytest.fixture
def auth_settings() -> AuthSettings:
    return AuthSettings(
        secret_key="a" * 48,
        algorithm="HS256",
        access_token_minutes=15,
        issuer="secure-api-gateway",
        audience="secure-api-clients",
    )


@pytest.fixture
def proxy_auth_context(
    auth_settings: AuthSettings,
) -> Iterator[
    tuple[
        TestClient,
        FakeAsyncClient,
        InMemoryUserRepository,
        AuthSettings,
    ]
]:
    repository = InMemoryUserRepository()
    fake_client = FakeAsyncClient()

    original_overrides = (
        app.dependency_overrides.copy()
    )

    app.dependency_overrides[
        get_auth_settings
    ] = lambda: auth_settings

    app.dependency_overrides[
        get_user_repository
    ] = lambda: repository

    app.dependency_overrides[
        get_rate_limiter
    ] = lambda: FakeAllowedRateLimiter()

    app.dependency_overrides[
        get_authorization_service
    ] = (
        lambda: FakeAllowedAuthorizationService()
    )

    try:
        with TestClient(app) as client:
            app.state.http_client = fake_client

            yield (
                client,
                fake_client,
                repository,
                auth_settings,
            )
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(
            original_overrides
        )


def create_active_user(
    repository: InMemoryUserRepository,
) -> None:
    repository.create_user(
        username="anas",
        hashed_password="test-password-hash",
    )


def create_bearer_header(
    *,
    subject: str,
    settings: AuthSettings,
) -> dict[str, str]:
    token = create_access_token(
        subject=subject,
        settings=settings,
    )

    return {
        "Authorization": f"Bearer {token}",
    }


def test_proxy_requires_bearer_token(
    proxy_auth_context: tuple[
        TestClient,
        FakeAsyncClient,
        InMemoryUserRepository,
        AuthSettings,
    ],
) -> None:
    client, fake_client, _, _ = (
        proxy_auth_context
    )

    response = client.get(
        "/api/service-a/ping"
    )

    assert response.status_code == 401
    assert response.headers[
        "www-authenticate"
    ] == "Bearer"

    assert fake_client.calls == []


def test_proxy_rejects_malformed_token(
    proxy_auth_context: tuple[
        TestClient,
        FakeAsyncClient,
        InMemoryUserRepository,
        AuthSettings,
    ],
) -> None:
    client, fake_client, _, _ = (
        proxy_auth_context
    )

    response = client.get(
        "/api/service-a/ping",
        headers={
            "Authorization": (
                "Bearer malformed-token"
            ),
        },
    )

    assert response.status_code == 401
    assert response.headers[
        "www-authenticate"
    ] == "Bearer"

    assert fake_client.calls == []


def test_proxy_rejects_token_for_unknown_user(
    proxy_auth_context: tuple[
        TestClient,
        FakeAsyncClient,
        InMemoryUserRepository,
        AuthSettings,
    ],
) -> None:
    (
        client,
        fake_client,
        _,
        settings,
    ) = proxy_auth_context

    response = client.get(
        "/api/service-a/ping",
        headers=create_bearer_header(
            subject="unknown-user",
            settings=settings,
        ),
    )

    assert response.status_code == 401
    assert fake_client.calls == []


def test_proxy_rejects_inactive_user(
    proxy_auth_context: tuple[
        TestClient,
        FakeAsyncClient,
        InMemoryUserRepository,
        AuthSettings,
    ],
) -> None:
    (
        client,
        fake_client,
        repository,
        settings,
    ) = proxy_auth_context

    create_active_user(repository)

    stored_user = repository.get_by_username(
        "anas"
    )

    assert stored_user is not None

    repository._users_by_username[
        "anas"
    ] = replace(
        stored_user,
        is_active=False,
    )

    response = client.get(
        "/api/service-a/ping",
        headers=create_bearer_header(
            subject="anas",
            settings=settings,
        ),
    )

    assert response.status_code == 401
    assert fake_client.calls == []


def test_proxy_accepts_valid_active_user(
    proxy_auth_context: tuple[
        TestClient,
        FakeAsyncClient,
        InMemoryUserRepository,
        AuthSettings,
    ],
) -> None:
    (
        client,
        fake_client,
        repository,
        settings,
    ) = proxy_auth_context

    create_active_user(repository)

    response = client.get(
        "/api/service-a/ping",
        headers=create_bearer_header(
            subject="anas",
            settings=settings,
        ),
    )

    assert response.status_code == 200

    assert response.json() == {
        "message": "pong",
        "service": "service-a",
    }

    assert len(fake_client.calls) == 1

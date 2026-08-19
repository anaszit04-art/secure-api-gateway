from __future__ import annotations

from datetime import (
    datetime,
    timedelta,
    timezone,
)
from typing import Any, Iterator
from uuid import (
    UUID,
    uuid4,
)

import httpx
import jwt
import pytest

from fastapi.testclient import TestClient

from gateway.app.auth.config import (
    AuthSettings,
)
from gateway.app.auth.dependencies import (
    get_auth_settings,
    get_current_user,
    get_user_repository,
)
from gateway.app.auth.models import (
    UserPublic,
)
from gateway.app.auth.repository import (
    InMemoryUserRepository,
)
from gateway.app.auth.tokens import (
    ACCESS_TOKEN_TYPE,
)
from gateway.app.authorization.dependencies import (
    get_authorization_service,
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


TEST_USER_ID = UUID(
    "81000000-0000-0000-0000-000000000001"
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
        allowed: bool = False,
    ) -> None:
        self.allowed = allowed

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


@pytest.fixture
def auth_settings() -> AuthSettings:
    return AuthSettings(
        secret_key="s" * 48,
        algorithm="HS256",
        access_token_minutes=15,
        issuer="secure-api-gateway",
        audience="secure-api-clients",
    )


def build_privilege_claim_token(
    settings: AuthSettings,
) -> str:
    now = datetime.now(
        timezone.utc
    )

    payload = {
        "sub": "normal-user",
        "iat": now,
        "exp": (
            now
            + timedelta(
                minutes=15
            )
        ),
        "iss": settings.issuer,
        "aud": settings.audience,
        "jti": str(
            uuid4()
        ),
        "type": ACCESS_TOKEN_TYPE,

        # Deliberately forged privilege claims.
        "role": "admin",
        "permissions": [
            "authorization:roles:manage",
            "proxy:service-a:write",
        ],
    }

    return jwt.encode(
        payload,
        settings.secret_key,
        algorithm=settings.algorithm,
    )


@pytest.fixture
def security_context(
    auth_settings: AuthSettings,
) -> Iterator[
    tuple[
        TestClient,
        FakeAuthorizationService,
        FakeUpstreamClient,
        str,
    ]
]:
    users = InMemoryUserRepository()

    stored = users.create_user(
        username="normal-user",
        hashed_password="test-hash",
    )

    authorization = (
        FakeAuthorizationService(
            allowed=False
        )
    )

    upstream = FakeUpstreamClient()

    token = build_privilege_claim_token(
        auth_settings
    )

    original = (
        app.dependency_overrides.copy()
    )

    app.dependency_overrides[
        get_auth_settings
    ] = lambda: auth_settings

    app.dependency_overrides[
        get_user_repository
    ] = lambda: users

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
                token,
            )

    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(
            original
        )

    del stored


def test_signed_privilege_claims_do_not_grant_proxy_write(
    security_context,
) -> None:
    (
        client,
        authorization,
        upstream,
        token,
    ) = security_context

    response = client.post(
        "/api/service-a/echo",
        headers={
            "Authorization": (
                f"Bearer {token}"
            ),
        },
        json={
            "attack": "jwt-claims",
        },
    )

    assert response.status_code == 403

    assert response.json() == {
        "detail": "Permission denied."
    }

    assert len(
        authorization.calls
    ) == 1

    checked_user_id, checked_permission = (
        authorization.calls[0]
    )

    assert isinstance(
        checked_user_id,
        UUID,
    )

    assert checked_permission == (
        "proxy:service-a:write"
    )

    assert upstream.calls == []


def test_spoofed_role_headers_do_not_grant_proxy_write(
    security_context,
) -> None:
    (
        client,
        authorization,
        upstream,
        token,
    ) = security_context

    response = client.post(
        "/api/service-a/echo",
        headers={
            "Authorization": (
                f"Bearer {token}"
            ),
            "X-Role": "admin",
            "X-User-Role": "admin",
            "X-Permission": (
                "proxy:service-a:write"
            ),
            "X-Authorization-Role": "admin",
        },
        json={
            "attack": "header-spoofing",
        },
    )

    assert response.status_code == 403

    assert authorization.calls[
        0
    ][1] == "proxy:service-a:write"

    assert upstream.calls == []


def test_spoofed_authorization_headers_are_not_forwarded(
    security_context,
) -> None:
    (
        client,
        authorization,
        upstream,
        token,
    ) = security_context

    authorization.allowed = True

    response = client.get(
        "/api/service-a/ping",
        headers={
            "Authorization": (
                f"Bearer {token}"
            ),
            "X-Role": "admin",
            "X-User-Role": "admin",
            "X-Permission": (
                "proxy:service-a:write"
            ),
            "X-Authorization-Role": "admin",
        },
    )

    assert response.status_code == 200
    assert len(upstream.calls) == 1

    outgoing = {
        name.lower(): value
        for name, value
        in upstream.calls[0][
            "headers"
        ].items()
    }

    assert "x-role" not in outgoing
    assert "x-user-role" not in outgoing
    assert "x-permission" not in outgoing

    assert (
        "x-authorization-role"
        not in outgoing
    )


def test_trace_method_is_never_proxied(
    security_context,
) -> None:
    (
        client,
        _,
        upstream,
        token,
    ) = security_context

    response = client.request(
        "TRACE",
        "/api/service-a/ping",
        headers={
            "Authorization": (
                f"Bearer {token}"
            ),
        },
    )

    assert response.status_code == 405
    assert upstream.calls == []


def test_authorization_fails_closed_without_persistence() -> None:
    user = UserPublic(
        id=TEST_USER_ID,
        username="security-user",
        is_active=True,
        created_at=datetime(
            2026,
            8,
            19,
            tzinfo=timezone.utc,
        ),
    )

    upstream = FakeUpstreamClient()

    original = (
        app.dependency_overrides.copy()
    )

    app.dependency_overrides[
        get_current_user
    ] = lambda: user

    app.dependency_overrides[
        get_rate_limiter
    ] = lambda: FakeAllowedRateLimiter()

    app.dependency_overrides.pop(
        get_authorization_service,
        None,
    )

    try:
        with TestClient(app) as client:
            app.state.http_client = upstream

            app.state.database_session_factory = (
                None
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
                "Authorization service is temporarily "
                "unavailable."
            )
        }

        assert upstream.calls == []

    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(
            original
        )

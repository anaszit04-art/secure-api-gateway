from __future__ import annotations

from typing import Any, Iterator

import pytest

from fastapi.testclient import TestClient
from sqlalchemy.exc import SQLAlchemyError

from gateway.app.auth.config import AuthSettings
from gateway.app.auth.dependencies import (
    get_auth_settings,
    get_authentication_service,
    get_user_repository,
)
from gateway.app.auth.repository import (
    UserRepositoryBackendError,
)
from gateway.app.auth.tokens import (
    create_access_token,
)
from gateway.app.database.user_repository import (
    PostgreSQLUserRepository,
)
from gateway.app.main import app
from gateway.app.rate_limit.dependencies import (
    get_rate_limiter,
)
from gateway.app.rate_limit.login import (
    LoginProtectionDecision,
)
from gateway.app.rate_limit.login_dependencies import (
    get_login_protection,
)
from gateway.app.rate_limit.models import (
    RateLimitDecision,
)


class FailingUserRepository:
    async def create_user(
        self,
        **_: Any,
    ) -> Any:
        raise UserRepositoryBackendError(
            "database unavailable"
        )

    async def get_by_username(
        self,
        username: str,
    ) -> Any:
        del username

        raise UserRepositoryBackendError(
            "database unavailable"
        )

    async def update_password_hash(
        self,
        **_: Any,
    ) -> Any:
        raise UserRepositoryBackendError(
            "database unavailable"
        )

    async def count(
        self,
    ) -> int:
        raise UserRepositoryBackendError(
            "database unavailable"
        )


class FailingAuthenticationService:
    async def authenticate_and_create_token(
        self,
        **_: Any,
    ) -> str:
        raise UserRepositoryBackendError(
            "database unavailable"
        )


class FakeAllowedRateLimiter:
    async def check(
        self,
        **_: Any,
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
        self.failure_calls = 0
        self.reset_calls = 0

    async def check_lock(
        self,
        **_: Any,
    ) -> LoginProtectionDecision:
        return LoginProtectionDecision(
            locked=False,
            failures=0,
            retry_after_seconds=0,
        )

    async def record_failure(
        self,
        **_: Any,
    ) -> LoginProtectionDecision:
        self.failure_calls += 1

        return LoginProtectionDecision(
            locked=False,
            failures=1,
            retry_after_seconds=0,
        )

    async def reset(
        self,
        **_: Any,
    ) -> bool:
        self.reset_calls += 1
        return True


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
def clean_overrides() -> Iterator[None]:
    original = (
        app.dependency_overrides.copy()
    )

    try:
        yield
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(
            original
        )


def assert_database_503(
    response: Any,
) -> None:
    assert response.status_code == 503

    assert response.headers[
        "retry-after"
    ] == "1"

    assert response.json() == {
        "detail": (
            "Authentication database is "
            "temporarily unavailable."
        )
    }


def test_register_fails_closed_when_database_is_unavailable(
    clean_overrides: None,
    auth_settings: AuthSettings,
) -> None:
    app.dependency_overrides[
        get_auth_settings
    ] = lambda: auth_settings

    app.dependency_overrides[
        get_user_repository
    ] = lambda: FailingUserRepository()

    with TestClient(app) as client:
        response = client.post(
            "/auth/register",
            json={
                "username": "anas",
                "password": (
                    "correct-horse-battery-staple"
                ),
            },
        )

    assert_database_503(
        response
    )


def test_token_database_failure_is_not_recorded_as_bad_password(
    clean_overrides: None,
) -> None:
    protection = FakeLoginProtection()

    app.dependency_overrides[
        get_authentication_service
    ] = (
        lambda: FailingAuthenticationService()
    )

    app.dependency_overrides[
        get_rate_limiter
    ] = lambda: FakeAllowedRateLimiter()

    app.dependency_overrides[
        get_login_protection
    ] = lambda: protection

    with TestClient(app) as client:
        response = client.post(
            "/auth/token",
            data={
                "username": "anas",
                "password": "secret-password",
            },
        )

    assert_database_503(
        response
    )

    assert protection.failure_calls == 0
    assert protection.reset_calls == 0


def test_me_fails_closed_when_database_is_unavailable(
    clean_overrides: None,
    auth_settings: AuthSettings,
) -> None:
    app.dependency_overrides[
        get_auth_settings
    ] = lambda: auth_settings

    app.dependency_overrides[
        get_user_repository
    ] = lambda: FailingUserRepository()

    token = create_access_token(
        subject="anas",
        settings=auth_settings,
    )

    with TestClient(app) as client:
        response = client.get(
            "/auth/me",
            headers={
                "Authorization": (
                    f"Bearer {token}"
                ),
            },
        )

    assert_database_503(
        response
    )


def test_proxy_auth_fails_closed_when_database_is_unavailable(
    clean_overrides: None,
    auth_settings: AuthSettings,
) -> None:
    app.dependency_overrides[
        get_auth_settings
    ] = lambda: auth_settings

    app.dependency_overrides[
        get_user_repository
    ] = lambda: FailingUserRepository()

    app.dependency_overrides[
        get_rate_limiter
    ] = lambda: FakeAllowedRateLimiter()

    token = create_access_token(
        subject="anas",
        settings=auth_settings,
    )

    with TestClient(app) as client:
        response = client.get(
            "/api/service-a/ping",
            headers={
                "Authorization": (
                    f"Bearer {token}"
                ),
            },
        )

    assert_database_503(
        response
    )


class ExplodingSession:
    async def __aenter__(
        self,
    ) -> ExplodingSession:
        return self

    async def __aexit__(
        self,
        exc_type: object,
        exc: object,
        traceback: object,
    ) -> None:
        return None

    async def execute(
        self,
        statement: object,
    ) -> Any:
        del statement

        raise SQLAlchemyError(
            "database unavailable"
        )


class ExplodingSessionFactory:
    def __call__(
        self,
    ) -> ExplodingSession:
        return ExplodingSession()


@pytest.mark.anyio
async def test_postgres_repository_hides_sqlalchemy_failure() -> None:
    repository = PostgreSQLUserRepository(
        ExplodingSessionFactory()
    )

    with pytest.raises(
        UserRepositoryBackendError,
        match=(
            "User persistence backend "
            "is unavailable"
        ),
    ):
        await repository.get_by_username(
            "anas"
        )

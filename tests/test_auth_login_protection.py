from typing import Any, Iterator

import pytest

from fastapi.testclient import TestClient
from gateway.app.auth.dependencies import (
    get_authentication_service,
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
    LoginProtectionPolicy,
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


class FakeAuthenticationService:
    def __init__(
        self,
        *,
        token: str = "signed.test.token",
        error: Exception | None = None,
    ) -> None:
        self.token = token
        self.error = error
        self.calls: list[
            tuple[str, str]
        ] = []

    async def authenticate_and_create_token(
        self,
        *,
        username: str,
        password: str,
    ) -> str:
        self.calls.append(
            (
                username,
                password,
            )
        )

        if self.error is not None:
            raise self.error

        return self.token


class FakeLoginRateLimiter:
    def __init__(
        self,
        *,
        decision: RateLimitDecision | None = None,
        error: Exception | None = None,
    ) -> None:
        self.decision = decision or RateLimitDecision(
            allowed=True,
            limit=10,
            remaining=9,
            retry_after_seconds=0,
            reset_after_seconds=5,
        )
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

        return self.decision


class FakeLoginProtection:
    def __init__(
        self,
        *,
        lock_decision: (
            LoginProtectionDecision | None
        ) = None,
        failure_decision: (
            LoginProtectionDecision | None
        ) = None,
        check_error: Exception | None = None,
        failure_error: Exception | None = None,
        reset_error: Exception | None = None,
    ) -> None:
        self.lock_decision = (
            lock_decision
            or LoginProtectionDecision(
                locked=False,
                failures=0,
                retry_after_seconds=0,
            )
        )

        self.failure_decision = (
            failure_decision
            or LoginProtectionDecision(
                locked=False,
                failures=1,
                retry_after_seconds=0,
            )
        )

        self.check_error = check_error
        self.failure_error = failure_error
        self.reset_error = reset_error

        self.check_calls: list[
            tuple[str, LoginProtectionPolicy]
        ] = []

        self.failure_calls: list[
            tuple[str, LoginProtectionPolicy]
        ] = []

        self.reset_calls: list[
            tuple[str, LoginProtectionPolicy]
        ] = []

    async def check_lock(
        self,
        *,
        identifier: str,
        policy: LoginProtectionPolicy,
    ) -> LoginProtectionDecision:
        self.check_calls.append(
            (
                identifier,
                policy,
            )
        )

        if self.check_error is not None:
            raise self.check_error

        return self.lock_decision

    async def record_failure(
        self,
        *,
        identifier: str,
        policy: LoginProtectionPolicy,
    ) -> LoginProtectionDecision:
        self.failure_calls.append(
            (
                identifier,
                policy,
            )
        )

        if self.failure_error is not None:
            raise self.failure_error

        return self.failure_decision

    async def reset(
        self,
        *,
        identifier: str,
        policy: LoginProtectionPolicy,
    ) -> bool:
        self.reset_calls.append(
            (
                identifier,
                policy,
            )
        )

        if self.reset_error is not None:
            raise self.reset_error

        return True


@pytest.fixture
def login_context() -> Iterator[
    tuple[
        TestClient,
        FakeAuthenticationService,
        FakeLoginRateLimiter,
        FakeLoginProtection,
    ]
]:
    auth_service = FakeAuthenticationService()
    rate_limiter = FakeLoginRateLimiter()
    protection = FakeLoginProtection()

    original_overrides = (
        app.dependency_overrides.copy()
    )

    app.dependency_overrides[
        get_authentication_service
    ] = lambda: auth_service

    app.dependency_overrides[
        get_rate_limiter
    ] = lambda: rate_limiter

    app.dependency_overrides[
        get_login_protection
    ] = lambda: protection

    try:
        with TestClient(app) as client:
            yield (
                client,
                auth_service,
                rate_limiter,
                protection,
            )
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(
            original_overrides
        )


def submit_login(
    client: TestClient,
    *,
    username: str = "anas",
    password: str = "secret-password",
) -> Any:
    return client.post(
        "/auth/token",
        data={
            "username": username,
            "password": password,
        },
        headers={
            "X-Forwarded-For": "203.0.113.50",
        },
    )


def test_successful_login_resets_account_state(
    login_context: tuple[
        TestClient,
        FakeAuthenticationService,
        FakeLoginRateLimiter,
        FakeLoginProtection,
    ],
) -> None:
    (
        client,
        auth_service,
        rate_limiter,
        protection,
    ) = login_context

    response = submit_login(client)

    assert response.status_code == 200
    assert response.json() == {
        "access_token": "signed.test.token",
        "token_type": "bearer",
    }

    assert response.headers[
        "x-ratelimit-limit"
    ] == "10"

    assert response.headers[
        "x-ratelimit-remaining"
    ] == "9"

    assert len(auth_service.calls) == 1
    assert len(protection.check_calls) == 1
    assert len(protection.failure_calls) == 0
    assert len(protection.reset_calls) == 1

    identity, policy = rate_limiter.calls[0]

    assert identity != "203.0.113.50"
    assert policy.name == "login-ip"


def test_locked_account_returns_429(
    login_context: tuple[
        TestClient,
        FakeAuthenticationService,
        FakeLoginRateLimiter,
        FakeLoginProtection,
    ],
) -> None:
    client, auth_service, _, protection = (
        login_context
    )

    protection.lock_decision = (
        LoginProtectionDecision(
            locked=True,
            failures=5,
            retry_after_seconds=240,
        )
    )

    response = submit_login(client)

    assert response.status_code == 429
    assert response.headers[
        "retry-after"
    ] == "240"

    assert response.json() == {
        "detail": (
            "Too many authentication attempts."
        )
    }

    assert auth_service.calls == []


def test_invalid_credentials_record_failure(
    login_context: tuple[
        TestClient,
        FakeAuthenticationService,
        FakeLoginRateLimiter,
        FakeLoginProtection,
    ],
) -> None:
    client, auth_service, _, protection = (
        login_context
    )

    auth_service.error = AuthenticationError(
        INVALID_CREDENTIALS_MESSAGE
    )

    response = submit_login(client)

    assert response.status_code == 401
    assert response.headers[
        "www-authenticate"
    ] == "Bearer"

    assert response.headers[
        "x-ratelimit-limit"
    ] == "10"

    assert response.json() == {
        "detail": INVALID_CREDENTIALS_MESSAGE
    }

    assert len(protection.failure_calls) == 1
    assert protection.reset_calls == []


def test_threshold_failure_returns_429(
    login_context: tuple[
        TestClient,
        FakeAuthenticationService,
        FakeLoginRateLimiter,
        FakeLoginProtection,
    ],
) -> None:
    client, auth_service, _, protection = (
        login_context
    )

    auth_service.error = AuthenticationError(
        INVALID_CREDENTIALS_MESSAGE
    )

    protection.failure_decision = (
        LoginProtectionDecision(
            locked=True,
            failures=5,
            retry_after_seconds=300,
        )
    )

    response = submit_login(client)

    assert response.status_code == 429
    assert response.headers[
        "retry-after"
    ] == "300"

    assert response.json() == {
        "detail": (
            "Too many authentication attempts."
        )
    }


def test_ip_limit_blocks_before_authentication(
    login_context: tuple[
        TestClient,
        FakeAuthenticationService,
        FakeLoginRateLimiter,
        FakeLoginProtection,
    ],
) -> None:
    (
        client,
        auth_service,
        rate_limiter,
        protection,
    ) = login_context

    rate_limiter.decision = RateLimitDecision(
        allowed=False,
        limit=10,
        remaining=0,
        retry_after_seconds=5,
        reset_after_seconds=50,
    )

    response = submit_login(client)

    assert response.status_code == 429
    assert response.headers[
        "retry-after"
    ] == "5"

    assert response.headers[
        "x-ratelimit-remaining"
    ] == "0"

    assert auth_service.calls == []
    assert protection.check_calls == []


def test_lock_check_backend_failure_returns_503(
    login_context: tuple[
        TestClient,
        FakeAuthenticationService,
        FakeLoginRateLimiter,
        FakeLoginProtection,
    ],
) -> None:
    client, auth_service, _, protection = (
        login_context
    )

    protection.check_error = (
        LoginProtectionBackendError(
            "Redis unavailable"
        )
    )

    response = submit_login(client)

    assert response.status_code == 503
    assert response.headers[
        "retry-after"
    ] == "1"
    assert auth_service.calls == []


def test_failure_record_backend_failure_returns_503(
    login_context: tuple[
        TestClient,
        FakeAuthenticationService,
        FakeLoginRateLimiter,
        FakeLoginProtection,
    ],
) -> None:
    client, auth_service, _, protection = (
        login_context
    )

    auth_service.error = AuthenticationError(
        INVALID_CREDENTIALS_MESSAGE
    )

    protection.failure_error = (
        LoginProtectionBackendError(
            "Redis unavailable"
        )
    )

    response = submit_login(client)

    assert response.status_code == 503
    assert response.headers[
        "retry-after"
    ] == "1"


def test_reset_backend_failure_does_not_issue_token(
    login_context: tuple[
        TestClient,
        FakeAuthenticationService,
        FakeLoginRateLimiter,
        FakeLoginProtection,
    ],
) -> None:
    client, _, _, protection = login_context

    protection.reset_error = (
        LoginProtectionBackendError(
            "Redis unavailable"
        )
    )

    response = submit_login(client)

    assert response.status_code == 503
    assert "access_token" not in response.text


def test_ip_backend_failure_returns_503(
    login_context: tuple[
        TestClient,
        FakeAuthenticationService,
        FakeLoginRateLimiter,
        FakeLoginProtection,
    ],
) -> None:
    (
        client,
        auth_service,
        rate_limiter,
        protection,
    ) = login_context

    rate_limiter.error = RateLimitBackendError(
        "Redis unavailable"
    )

    response = submit_login(client)

    assert response.status_code == 503
    assert response.headers[
        "retry-after"
    ] == "1"

    assert auth_service.calls == []
    assert protection.check_calls == []

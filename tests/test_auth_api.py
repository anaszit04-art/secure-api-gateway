from dataclasses import replace
from typing import Iterator

import pytest

from fastapi.testclient import TestClient

from gateway.app.auth.config import (
    AuthSettings,
)
from gateway.app.auth.dependencies import (
    get_auth_settings,
    get_user_repository,
)
from gateway.app.auth.repository import (
    InMemoryUserRepository,
)
from gateway.app.auth.tokens import (
    decode_access_token,
)
from gateway.app.main import app


VALID_PASSWORD = "correct-horse-battery-staple"


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
def api_context(
    auth_settings: AuthSettings,
) -> Iterator[
    tuple[
        TestClient,
        InMemoryUserRepository,
        AuthSettings,
    ]
]:
    repository = InMemoryUserRepository()

    app.dependency_overrides[
        get_auth_settings
    ] = lambda: auth_settings

    app.dependency_overrides[
        get_user_repository
    ] = lambda: repository

    with TestClient(app) as client:
        yield client, repository, auth_settings

    app.dependency_overrides.clear()


def register_user(
    client: TestClient,
) -> None:
    response = client.post(
        "/auth/register",
        json={
            "username": "Anas",
            "password": VALID_PASSWORD,
        },
    )

    assert response.status_code == 201


def obtain_token(
    client: TestClient,
) -> str:
    response = client.post(
        "/auth/token",
        data={
            "username": "anas",
            "password": VALID_PASSWORD,
        },
    )

    assert response.status_code == 200

    return response.json()["access_token"]


def test_register_returns_safe_public_user(
    api_context: tuple[
        TestClient,
        InMemoryUserRepository,
        AuthSettings,
    ],
) -> None:
    client, repository, _ = api_context

    response = client.post(
        "/auth/register",
        json={
            "username": "  ANAS ",
            "password": VALID_PASSWORD,
        },
    )

    assert response.status_code == 201

    response_body = response.json()

    assert response_body["username"] == "anas"
    assert response_body["is_active"] is True
    assert "id" in response_body
    assert "created_at" in response_body
    assert "password" not in response_body
    assert "hashed_password" not in response_body
    assert repository.count() == 1


def test_register_rejects_duplicate_username(
    api_context: tuple[
        TestClient,
        InMemoryUserRepository,
        AuthSettings,
    ],
) -> None:
    client, _, _ = api_context

    register_user(client)

    response = client.post(
        "/auth/register",
        json={
            "username": " ANAS ",
            "password": VALID_PASSWORD,
        },
    )

    assert response.status_code == 409

    assert response.json() == {
        "detail": "Username is already registered."
    }


def test_register_rejects_extra_fields(
    api_context: tuple[
        TestClient,
        InMemoryUserRepository,
        AuthSettings,
    ],
) -> None:
    client, _, _ = api_context

    response = client.post(
        "/auth/register",
        json={
            "username": "anas",
            "password": VALID_PASSWORD,
            "role": "administrator",
        },
    )

    assert response.status_code == 422


def test_token_endpoint_returns_valid_access_token(
    api_context: tuple[
        TestClient,
        InMemoryUserRepository,
        AuthSettings,
    ],
) -> None:
    client, _, settings = api_context

    register_user(client)

    response = client.post(
        "/auth/token",
        data={
            "username": " ANAS ",
            "password": VALID_PASSWORD,
        },
    )

    assert response.status_code == 200

    response_body = response.json()

    assert response_body["token_type"] == "bearer"
    assert response_body["access_token"]

    claims = decode_access_token(
        token=response_body["access_token"],
        settings=settings,
    )

    assert claims.subject == "anas"


def test_token_endpoint_rejects_invalid_credentials(
    api_context: tuple[
        TestClient,
        InMemoryUserRepository,
        AuthSettings,
    ],
) -> None:
    client, _, _ = api_context

    register_user(client)

    response = client.post(
        "/auth/token",
        data={
            "username": "anas",
            "password": "incorrect-password-value",
        },
    )

    assert response.status_code == 401
    assert response.headers[
        "www-authenticate"
    ] == "Bearer"

    assert response.json() == {
        "detail": "Invalid username or password."
    }


def test_me_requires_bearer_token(
    api_context: tuple[
        TestClient,
        InMemoryUserRepository,
        AuthSettings,
    ],
) -> None:
    client, _, _ = api_context

    response = client.get("/auth/me")

    assert response.status_code == 401
    assert response.headers[
        "www-authenticate"
    ] == "Bearer"


def test_me_returns_authenticated_user(
    api_context: tuple[
        TestClient,
        InMemoryUserRepository,
        AuthSettings,
    ],
) -> None:
    client, _, _ = api_context

    register_user(client)
    token = obtain_token(client)

    response = client.get(
        "/auth/me",
        headers={
            "Authorization": f"Bearer {token}",
        },
    )

    assert response.status_code == 200
    assert response.json()["username"] == "anas"
    assert "hashed_password" not in response.json()


def test_me_rejects_tampered_token(
    api_context: tuple[
        TestClient,
        InMemoryUserRepository,
        AuthSettings,
    ],
) -> None:
    client, _, _ = api_context

    register_user(client)
    token = obtain_token(client)

    header, payload, signature = token.split(".")

    replacement = (
        "A"
        if signature[0] != "A"
        else "B"
    )

    tampered_token = ".".join(
        (
            header,
            payload,
            replacement + signature[1:],
        )
    )

    response = client.get(
        "/auth/me",
        headers={
            "Authorization": (
                f"Bearer {tampered_token}"
            ),
        },
    )

    assert response.status_code == 401
    assert response.headers[
        "www-authenticate"
    ] == "Bearer"


def test_me_rejects_inactive_user(
    api_context: tuple[
        TestClient,
        InMemoryUserRepository,
        AuthSettings,
    ],
) -> None:
    client, repository, _ = api_context

    register_user(client)
    token = obtain_token(client)

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
        "/auth/me",
        headers={
            "Authorization": f"Bearer {token}",
        },
    )

    assert response.status_code == 401

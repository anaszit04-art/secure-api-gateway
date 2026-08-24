from dataclasses import replace

import pytest

from gateway.app.auth.config import AuthSettings
from gateway.app.auth.models import (
    UserRegistration,
)
from gateway.app.auth.passwords import (
    verify_password,
)
from gateway.app.auth.repository import (
    InMemoryUserRepository,
    UserAlreadyExistsError,
)
from gateway.app.auth.service import (
    DUMMY_PASSWORD_HASH,
    INVALID_CREDENTIALS_MESSAGE,
    AuthenticationError,
    AuthenticationService,
)
from gateway.app.auth.tokens import (
    decode_access_token,
)


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
def auth_system(
    auth_settings: AuthSettings,
) -> tuple[
    InMemoryUserRepository,
    AuthenticationService,
]:
    repository = InMemoryUserRepository()

    service = AuthenticationService(
        repository=repository,
        settings=auth_settings,
    )

    return repository, service


async def register_default_user(
    service: AuthenticationService,
) -> None:
    await service.register_user(
        UserRegistration(
            username="Anas",
            password=VALID_PASSWORD,
        )
    )


@pytest.mark.anyio
async def test_register_user_hashes_password(
    auth_system: tuple[
        InMemoryUserRepository,
        AuthenticationService,
    ],
) -> None:
    repository, service = auth_system

    public_user = await service.register_user(
        UserRegistration(
            username=" Anas ",
            password=VALID_PASSWORD,
        )
    )

    stored_user = repository.get_by_username(
        "anas"
    )

    assert stored_user is not None
    assert public_user.username == "anas"

    assert (
        stored_user.hashed_password
        != VALID_PASSWORD
    )

    assert verify_password(
        VALID_PASSWORD,
        stored_user.hashed_password,
    ) is True

    assert not hasattr(
        public_user,
        "hashed_password",
    )


@pytest.mark.anyio
async def test_register_user_rejects_duplicate_username(
    auth_system: tuple[
        InMemoryUserRepository,
        AuthenticationService,
    ],
) -> None:
    _, service = auth_system

    await register_default_user(
        service
    )

    with pytest.raises(
        UserAlreadyExistsError,
    ):
        await service.register_user(
            UserRegistration(
                username=" ANAS ",
                password=VALID_PASSWORD,
            )
        )


@pytest.mark.anyio
async def test_authenticate_user_accepts_valid_credentials(
    auth_system: tuple[
        InMemoryUserRepository,
        AuthenticationService,
    ],
) -> None:
    _, service = auth_system

    await register_default_user(
        service
    )

    authenticated_user = (
        await service.authenticate_user(
            username=" ANAS ",
            password=VALID_PASSWORD,
        )
    )

    assert (
        authenticated_user.username
        == "anas"
    )


@pytest.mark.anyio
async def test_authenticate_user_rejects_wrong_password(
    auth_system: tuple[
        InMemoryUserRepository,
        AuthenticationService,
    ],
) -> None:
    _, service = auth_system

    await register_default_user(
        service
    )

    with pytest.raises(
        AuthenticationError,
        match=INVALID_CREDENTIALS_MESSAGE,
    ):
        await service.authenticate_user(
            username="anas",
            password=(
                "incorrect-password-value"
            ),
        )


@pytest.mark.anyio
async def test_authenticate_unknown_user_uses_dummy_hash(
    auth_system: tuple[
        InMemoryUserRepository,
        AuthenticationService,
    ],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, service = auth_system

    verification_calls: list[
        tuple[str, str]
    ] = []

    def fake_verify_password(
        password: str,
        hashed_password: str,
    ) -> bool:
        verification_calls.append(
            (
                password,
                hashed_password,
            )
        )

        return False

    monkeypatch.setattr(
        "gateway.app.auth.service.verify_password",
        fake_verify_password,
    )

    with pytest.raises(
        AuthenticationError,
        match=INVALID_CREDENTIALS_MESSAGE,
    ):
        await service.authenticate_user(
            username="unknown-user",
            password="any-password-value",
        )

    assert verification_calls == [
        (
            "any-password-value",
            DUMMY_PASSWORD_HASH,
        )
    ]


@pytest.mark.anyio
async def test_authenticate_rejects_malformed_username(
    auth_system: tuple[
        InMemoryUserRepository,
        AuthenticationService,
    ],
) -> None:
    _, service = auth_system

    with pytest.raises(
        AuthenticationError,
        match=INVALID_CREDENTIALS_MESSAGE,
    ):
        await service.authenticate_user(
            username="**",
            password="any-password-value",
        )


@pytest.mark.anyio
async def test_authentication_updates_outdated_hash(
    auth_system: tuple[
        InMemoryUserRepository,
        AuthenticationService,
    ],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, service = auth_system

    await register_default_user(
        service
    )

    monkeypatch.setattr(
        (
            "gateway.app.auth.service."
            "verify_and_update_password"
        ),
        lambda password, hashed_password: (
            True,
            "replacement-password-hash",
        ),
    )

    authenticated_user = (
        await service.authenticate_user(
            username="anas",
            password=VALID_PASSWORD,
        )
    )

    stored_user = repository.get_by_username(
        "anas"
    )

    assert stored_user is not None

    assert (
        authenticated_user.hashed_password
        == "replacement-password-hash"
    )

    assert (
        stored_user.hashed_password
        == "replacement-password-hash"
    )


@pytest.mark.anyio
async def test_authentication_rejects_inactive_user(
    auth_system: tuple[
        InMemoryUserRepository,
        AuthenticationService,
    ],
) -> None:
    repository, service = auth_system

    await register_default_user(
        service
    )

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

    with pytest.raises(
        AuthenticationError,
        match=INVALID_CREDENTIALS_MESSAGE,
    ):
        await service.authenticate_user(
            username="anas",
            password=VALID_PASSWORD,
        )


@pytest.mark.anyio
async def test_authenticate_and_create_token(
    auth_system: tuple[
        InMemoryUserRepository,
        AuthenticationService,
    ],
    auth_settings: AuthSettings,
) -> None:
    _, service = auth_system

    await register_default_user(
        service
    )

    token = (
        await service
        .authenticate_and_create_token(
            username="anas",
            password=VALID_PASSWORD,
        )
    )

    claims = decode_access_token(
        token=token,
        settings=auth_settings,
    )

    assert claims.subject == "anas"


@pytest.mark.anyio
async def test_authenticate_and_create_result_returns_user_identity(
    auth_system: tuple[
        InMemoryUserRepository,
        AuthenticationService,
    ],
    auth_settings: AuthSettings,
) -> None:
    _, service = auth_system

    await register_default_user(
        service
    )

    result = (
        await service
        .authenticate_and_create_result(
            username="anas",
            password=VALID_PASSWORD,
        )
    )

    assert result.user.username == "anas"
    assert result.user.is_active is True

    claims = decode_access_token(
        token=result.access_token,
        settings=auth_settings,
    )

    assert (
        claims.subject
        == result.user.username
    )

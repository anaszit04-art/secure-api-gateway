import pytest

from gateway.app.database.config import (
    DatabaseConfigurationError,
    DatabaseSettings,
)


VALID_URL = (
    "postgresql+asyncpg://"
    "gateway:secret-value@"
    "postgres:5432/gateway"
)


def test_database_settings_use_secure_defaults() -> None:
    settings = (
        DatabaseSettings.from_environment(
            {
                "DATABASE_URL": VALID_URL,
            }
        )
    )

    assert settings.url == VALID_URL
    assert settings.pool_size == 5
    assert settings.max_overflow == 10

    assert (
        settings.pool_timeout_seconds
        == 5.0
    )

    assert (
        settings.connect_timeout_seconds
        == 5.0
    )

    assert settings.verify_on_startup is False

    assert (
        settings.application_name
        == "secure-api-gateway"
    )


def test_database_settings_accept_overrides() -> None:
    settings = (
        DatabaseSettings.from_environment(
            {
                "DATABASE_URL": VALID_URL,
                "DATABASE_POOL_SIZE": "8",
                "DATABASE_MAX_OVERFLOW": "16",
                (
                    "DATABASE_POOL_TIMEOUT_"
                    "SECONDS"
                ): "7.5",
                (
                    "DATABASE_CONNECT_TIMEOUT_"
                    "SECONDS"
                ): "3.5",
                (
                    "DATABASE_VERIFY_"
                    "ON_STARTUP"
                ): "true",
                (
                    "DATABASE_APPLICATION_NAME"
                ): "gateway-tests",
            }
        )
    )

    assert settings.pool_size == 8
    assert settings.max_overflow == 16

    assert (
        settings.pool_timeout_seconds
        == 7.5
    )

    assert (
        settings.connect_timeout_seconds
        == 3.5
    )

    assert settings.verify_on_startup is True

    assert (
        settings.application_name
        == "gateway-tests"
    )


@pytest.mark.parametrize(
    "database_url",
    [
        "",
        "http://gateway:secret@postgres/gateway",
        "postgresql+asyncpg://",
        (
            "postgresql+asyncpg://"
            "gateway@postgres:5432/gateway"
        ),
        (
            "postgresql+asyncpg://"
            "gateway:secret@/gateway"
        ),
        (
            "postgresql+asyncpg://"
            "gateway:secret@postgres:bad/gateway"
        ),
        (
            "postgresql+asyncpg://"
            "gateway:secret@postgres:5432/"
        ),
    ],
)
def test_database_settings_reject_invalid_urls(
    database_url: str,
) -> None:
    with pytest.raises(
        DatabaseConfigurationError
    ):
        DatabaseSettings.from_environment(
            {
                "DATABASE_URL": database_url,
            }
        )


@pytest.mark.parametrize(
    "value",
    [
        "0",
        "-1",
        "101",
        "invalid",
    ],
)
def test_database_settings_reject_invalid_pool_size(
    value: str,
) -> None:
    with pytest.raises(
        DatabaseConfigurationError
    ):
        DatabaseSettings.from_environment(
            {
                "DATABASE_URL": VALID_URL,
                "DATABASE_POOL_SIZE": value,
            }
        )


@pytest.mark.parametrize(
    "value",
    [
        "-1",
        "201",
        "invalid",
    ],
)
def test_database_settings_reject_invalid_max_overflow(
    value: str,
) -> None:
    with pytest.raises(
        DatabaseConfigurationError
    ):
        DatabaseSettings.from_environment(
            {
                "DATABASE_URL": VALID_URL,
                "DATABASE_MAX_OVERFLOW": value,
            }
        )


@pytest.mark.parametrize(
    "name",
    [
        "DATABASE_POOL_TIMEOUT_SECONDS",
        "DATABASE_CONNECT_TIMEOUT_SECONDS",
    ],
)
@pytest.mark.parametrize(
    "value",
    [
        "0",
        "-1",
        "61",
        "invalid",
    ],
)
def test_database_settings_reject_invalid_timeouts(
    name: str,
    value: str,
) -> None:
    with pytest.raises(
        DatabaseConfigurationError
    ):
        DatabaseSettings.from_environment(
            {
                "DATABASE_URL": VALID_URL,
                name: value,
            }
        )


@pytest.mark.parametrize(
    "value",
    [
        "true",
        "1",
        "yes",
        "on",
    ],
)
def test_database_startup_verification_accepts_true_values(
    value: str,
) -> None:
    settings = (
        DatabaseSettings.from_environment(
            {
                "DATABASE_URL": VALID_URL,
                (
                    "DATABASE_VERIFY_"
                    "ON_STARTUP"
                ): value,
            }
        )
    )

    assert settings.verify_on_startup is True


@pytest.mark.parametrize(
    "value",
    [
        "false",
        "0",
        "no",
        "off",
    ],
)
def test_database_startup_verification_accepts_false_values(
    value: str,
) -> None:
    settings = (
        DatabaseSettings.from_environment(
            {
                "DATABASE_URL": VALID_URL,
                (
                    "DATABASE_VERIFY_"
                    "ON_STARTUP"
                ): value,
            }
        )
    )

    assert settings.verify_on_startup is False


def test_database_startup_verification_rejects_invalid_value() -> None:
    with pytest.raises(
        DatabaseConfigurationError
    ):
        DatabaseSettings.from_environment(
            {
                "DATABASE_URL": VALID_URL,
                (
                    "DATABASE_VERIFY_"
                    "ON_STARTUP"
                ): "sometimes",
            }
        )


@pytest.mark.parametrize(
    "value",
    [
        "",
        " gateway ",
        "gateway/service",
        "x" * 65,
    ],
)
def test_database_settings_reject_invalid_application_name(
    value: str,
) -> None:
    with pytest.raises(
        DatabaseConfigurationError
    ):
        DatabaseSettings.from_environment(
            {
                "DATABASE_URL": VALID_URL,
                (
                    "DATABASE_APPLICATION_NAME"
                ): value,
            }
        )


def test_redacted_url_hides_password() -> None:
    settings = DatabaseSettings(
        url=VALID_URL
    )

    assert (
        settings.redacted_url
        == (
            "postgresql+asyncpg://"
            "gateway:***@"
            "postgres:5432/gateway"
        )
    )

    assert (
        "secret-value"
        not in settings.redacted_url
    )

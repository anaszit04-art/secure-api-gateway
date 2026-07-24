import pytest

from gateway.app.auth.config import (
    AuthConfigurationError,
    load_auth_settings,
)


def configure_valid_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "JWT_SECRET_KEY",
        "a" * 48,
    )


def clear_optional_auth_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    optional_variables = (
        "JWT_ALGORITHM",
        "JWT_ACCESS_TOKEN_MINUTES",
        "JWT_ISSUER",
        "JWT_AUDIENCE",
    )

    for variable_name in optional_variables:
        monkeypatch.delenv(
            variable_name,
            raising=False,
        )


def test_auth_settings_use_secure_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_valid_secret(monkeypatch)
    clear_optional_auth_environment(monkeypatch)

    settings = load_auth_settings()

    assert settings.secret_key == "a" * 48
    assert settings.algorithm == "HS256"
    assert settings.access_token_minutes == 15
    assert settings.issuer == "secure-api-gateway"
    assert settings.audience == "secure-api-clients"


def test_auth_settings_accept_environment_overrides(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_valid_secret(monkeypatch)

    monkeypatch.setenv(
        "JWT_ACCESS_TOKEN_MINUTES",
        "30",
    )
    monkeypatch.setenv(
        "JWT_ISSUER",
        "local-gateway",
    )
    monkeypatch.setenv(
        "JWT_AUDIENCE",
        "local-clients",
    )

    settings = load_auth_settings()

    assert settings.access_token_minutes == 30
    assert settings.issuer == "local-gateway"
    assert settings.audience == "local-clients"


def test_auth_settings_reject_short_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "JWT_SECRET_KEY",
        "too-short",
    )

    with pytest.raises(
        AuthConfigurationError,
        match="JWT_SECRET_KEY must contain at least 32",
    ):
        load_auth_settings()


@pytest.mark.parametrize(
    "invalid_value",
    [
        "0",
        "-1",
        "not-a-number",
    ],
)
def test_auth_settings_reject_invalid_token_duration(
    monkeypatch: pytest.MonkeyPatch,
    invalid_value: str,
) -> None:
    configure_valid_secret(monkeypatch)

    monkeypatch.setenv(
        "JWT_ACCESS_TOKEN_MINUTES",
        invalid_value,
    )

    with pytest.raises(
        AuthConfigurationError,
        match=(
            "JWT_ACCESS_TOKEN_MINUTES "
            "must be a positive integer"
        ),
    ):
        load_auth_settings()


def test_auth_settings_reject_excessive_token_duration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_valid_secret(monkeypatch)

    monkeypatch.setenv(
        "JWT_ACCESS_TOKEN_MINUTES",
        "1441",
    )

    with pytest.raises(
        AuthConfigurationError,
        match=(
            "JWT_ACCESS_TOKEN_MINUTES "
            "cannot exceed 1440"
        ),
    ):
        load_auth_settings()


def test_auth_settings_reject_unsupported_algorithm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_valid_secret(monkeypatch)

    monkeypatch.setenv(
        "JWT_ALGORITHM",
        "none",
    )

    with pytest.raises(
        AuthConfigurationError,
        match="Unsupported JWT algorithm: none",
    ):
        load_auth_settings()


@pytest.mark.parametrize(
    "variable_name",
    [
        "JWT_ISSUER",
        "JWT_AUDIENCE",
    ],
)
def test_auth_settings_reject_empty_identity_fields(
    monkeypatch: pytest.MonkeyPatch,
    variable_name: str,
) -> None:
    configure_valid_secret(monkeypatch)

    monkeypatch.setenv(
        variable_name,
        "   ",
    )

    with pytest.raises(
        AuthConfigurationError,
    ):
        load_auth_settings()

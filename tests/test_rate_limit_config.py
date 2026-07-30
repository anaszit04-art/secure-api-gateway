import pytest

from gateway.app.rate_limit.config import (
    RateLimitConfigError,
    RedisSettings,
)


def test_redis_settings_use_secure_defaults() -> None:
    settings = RedisSettings.from_environment(
        {}
    )

    assert settings.url == (
        "redis://redis:6379/0"
    )
    assert settings.key_prefix == (
        "secure-api-gateway"
    )
    assert (
        settings.connect_timeout_seconds
        == 2.0
    )
    assert (
        settings.socket_timeout_seconds
        == 2.0
    )
    assert settings.max_connections == 20
    assert (
        settings.health_check_interval_seconds
        == 30
    )


def test_redis_settings_accept_environment_overrides() -> None:
    settings = RedisSettings.from_environment(
        {
            "REDIS_URL": (
                "rediss://user:secret@"
                "cache.example:6380/2"
            ),
            "REDIS_KEY_PREFIX": "gateway:test",
            (
                "REDIS_CONNECT_TIMEOUT_SECONDS"
            ): "1.5",
            (
                "REDIS_SOCKET_TIMEOUT_SECONDS"
            ): "2.5",
            "REDIS_MAX_CONNECTIONS": "40",
            (
                "REDIS_HEALTH_CHECK_"
                "INTERVAL_SECONDS"
            ): "45",
        }
    )

    assert settings.url == (
        "rediss://user:secret@"
        "cache.example:6380/2"
    )
    assert settings.key_prefix == (
        "gateway:test"
    )
    assert (
        settings.connect_timeout_seconds
        == 1.5
    )
    assert (
        settings.socket_timeout_seconds
        == 2.5
    )
    assert settings.max_connections == 40
    assert (
        settings.health_check_interval_seconds
        == 45
    )


@pytest.mark.parametrize(
    "url",
    [
        "",
        "http://redis:6379/0",
        "redis://",
        "redis://redis:not-a-port/0",
    ],
)
def test_redis_settings_reject_invalid_urls(
    url: str,
) -> None:
    with pytest.raises(
        RateLimitConfigError
    ):
        RedisSettings(
            url=url,
        )


@pytest.mark.parametrize(
    "prefix",
    [
        "",
        " contains-spaces ",
        ":starts-with-colon",
        "x" * 65,
    ],
)
def test_redis_settings_reject_invalid_key_prefix(
    prefix: str,
) -> None:
    with pytest.raises(
        RateLimitConfigError
    ):
        RedisSettings(
            key_prefix=prefix,
        )


@pytest.mark.parametrize(
    "value",
    [
        "0",
        "-1",
        "not-a-number",
    ],
)
def test_rejects_invalid_connect_timeout(
    value: str,
) -> None:
    with pytest.raises(
        RateLimitConfigError
    ):
        RedisSettings.from_environment(
            {
                (
                    "REDIS_CONNECT_TIMEOUT_SECONDS"
                ): value,
            }
        )


@pytest.mark.parametrize(
    "value",
    [
        "0",
        "61",
        "not-a-number",
    ],
)
def test_rejects_invalid_socket_timeout(
    value: str,
) -> None:
    with pytest.raises(
        RateLimitConfigError
    ):
        RedisSettings.from_environment(
            {
                (
                    "REDIS_SOCKET_TIMEOUT_SECONDS"
                ): value,
            }
        )


@pytest.mark.parametrize(
    "value",
    [
        "0",
        "-1",
        "1001",
        "not-an-integer",
    ],
)
def test_rejects_invalid_max_connections(
    value: str,
) -> None:
    with pytest.raises(
        RateLimitConfigError
    ):
        RedisSettings.from_environment(
            {
                "REDIS_MAX_CONNECTIONS": value,
            }
        )


@pytest.mark.parametrize(
    "value",
    [
        "-1",
        "3601",
        "not-an-integer",
    ],
)
def test_rejects_invalid_health_check_interval(
    value: str,
) -> None:
    with pytest.raises(
        RateLimitConfigError
    ):
        RedisSettings.from_environment(
            {
                (
                    "REDIS_HEALTH_CHECK_"
                    "INTERVAL_SECONDS"
                ): value,
            }
        )


def test_redacted_url_hides_password() -> None:
    settings = RedisSettings(
        url=(
            "rediss://gateway:"
            "super-secret-password@"
            "redis.example:6380/3"
        )
    )

    assert settings.redacted_url == (
        "rediss://gateway:***@"
        "redis.example:6380/3"
    )
    assert (
        "super-secret-password"
        not in settings.redacted_url
    )
    assert (
        "super-secret-password"
        not in repr(settings)
    )

import asyncio

from typing import Any

from redis.exceptions import (
    ConnectionError as RedisConnectionError,
)

from gateway.app.rate_limit.client import (
    RedisUnavailableError,
    close_redis_client,
    create_redis_client,
    verify_redis_connection,
)
from gateway.app.rate_limit.config import (
    RedisSettings,
)


class FakeRedisClient:
    def __init__(
        self,
        *,
        ping_result: bool = True,
        ping_error: Exception | None = None,
    ) -> None:
        self.ping_result = ping_result
        self.ping_error = ping_error
        self.ping_calls = 0
        self.close_calls = 0

    async def ping(self) -> bool:
        self.ping_calls += 1

        if self.ping_error is not None:
            raise self.ping_error

        return self.ping_result

    async def aclose(self) -> None:
        self.close_calls += 1


def test_create_redis_client_uses_settings() -> None:
    settings = RedisSettings(
        url="redis://cache.internal:6380/2",
        key_prefix="gateway:test",
        connect_timeout_seconds=1.5,
        socket_timeout_seconds=2.5,
        max_connections=7,
        health_check_interval_seconds=45,
    )

    client = create_redis_client(settings)

    connection_kwargs: dict[str, Any] = (
        client.connection_pool.connection_kwargs
    )

    assert connection_kwargs["host"] == (
        "cache.internal"
    )
    assert connection_kwargs["port"] == 6380
    assert connection_kwargs["db"] == 2
    assert (
        connection_kwargs[
            "socket_connect_timeout"
        ]
        == 1.5
    )
    assert (
        connection_kwargs["socket_timeout"]
        == 2.5
    )
    assert (
        connection_kwargs["decode_responses"]
        is True
    )
    assert (
        connection_kwargs[
            "health_check_interval"
        ]
        == 45
    )
    assert (
        connection_kwargs["client_name"]
        == "gateway:test-rate-limit"
    )
    assert (
        client.connection_pool.max_connections
        == 7
    )

    asyncio.run(
        close_redis_client(client)
    )


def test_verify_redis_connection_accepts_pong() -> None:
    client = FakeRedisClient()

    asyncio.run(
        verify_redis_connection(client)
    )

    assert client.ping_calls == 1


def test_verify_redis_connection_rejects_false_response() -> None:
    client = FakeRedisClient(
        ping_result=False,
    )

    try:
        asyncio.run(
            verify_redis_connection(client)
        )
    except RedisUnavailableError as exc:
        assert str(exc) == (
            "Redis returned an invalid "
            "PING response."
        )
    else:
        raise AssertionError(
            "RedisUnavailableError was not raised."
        )


def test_verify_redis_connection_wraps_redis_error() -> None:
    client = FakeRedisClient(
        ping_error=RedisConnectionError(
            "Connection refused"
        ),
    )

    try:
        asyncio.run(
            verify_redis_connection(client)
        )
    except RedisUnavailableError as exc:
        assert str(exc) == (
            "Redis is unavailable."
        )
        assert isinstance(
            exc.__cause__,
            RedisConnectionError,
        )
    else:
        raise AssertionError(
            "RedisUnavailableError was not raised."
        )


def test_close_redis_client_closes_pool() -> None:
    client = FakeRedisClient()

    asyncio.run(
        close_redis_client(client)
    )

    assert client.close_calls == 1

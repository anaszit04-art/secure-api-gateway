from __future__ import annotations

from typing import Protocol

import redis.asyncio as redis_async

from redis.exceptions import RedisError

from gateway.app.rate_limit.config import (
    RedisSettings,
)


class RedisUnavailableError(RuntimeError):
    """Raised when Redis cannot be used safely."""


class AsyncRedisClient(Protocol):
    """
    Minimal Redis client interface required by the application.

    The protocol also makes the component easy to unit test
    without a live Redis server.
    """

    async def ping(self) -> bool:
        """Check whether the Redis server is reachable."""

    async def aclose(self) -> None:
        """Close the client and its connection pool."""


def create_redis_client(
    settings: RedisSettings,
) -> redis_async.Redis:
    """
    Create an asynchronous Redis client with a bounded pool.

    The method does not open a network connection immediately.
    redis-py connects lazily when the first command is executed.
    """

    return redis_async.Redis.from_url(
        settings.url,
        encoding="utf-8",
        decode_responses=True,
        socket_connect_timeout=(
            settings.connect_timeout_seconds
        ),
        socket_timeout=(
            settings.socket_timeout_seconds
        ),
        socket_keepalive=True,
        max_connections=settings.max_connections,
        health_check_interval=(
            settings.health_check_interval_seconds
        ),
        retry_on_timeout=False,
        client_name=(
            f"{settings.key_prefix}-rate-limit"
        ),
    )


async def verify_redis_connection(
    client: AsyncRedisClient,
) -> None:
    """
    Verify that Redis answers a PING command.

    A domain-specific exception prevents redis-py implementation
    details from leaking into the FastAPI application layer.
    """

    try:
        response = await client.ping()
    except RedisError as exc:
        raise RedisUnavailableError(
            "Redis is unavailable."
        ) from exc

    if response is not True:
        raise RedisUnavailableError(
            "Redis returned an invalid PING response."
        )


async def close_redis_client(
    client: AsyncRedisClient,
) -> None:
    """
    Close the Redis client and its internal connection pool.
    """

    await client.aclose()

import asyncio

from typing import Any

from redis.exceptions import (
    ConnectionError as RedisConnectionError,
)

from gateway.app.rate_limit.config import (
    RedisSettings,
)
from gateway.app.rate_limit.models import (
    RateLimitPolicy,
)
from gateway.app.rate_limit.service import (
    RateLimitBackendError,
    RedisRateLimiter,
)
from gateway.app.rate_limit.scripts import (
    TOKEN_BUCKET_SCRIPT,
)


class FakeRedisScriptClient:
    def __init__(
        self,
        *,
        response: Any = None,
        error: Exception | None = None,
    ) -> None:
        self.response = (
            [1, "9", 0, 1000]
            if response is None
            else response
        )
        self.error = error
        self.calls: list[
            tuple[str, int, tuple[Any, ...]]
        ] = []

    async def eval(
        self,
        script: str,
        numkeys: int,
        *keys_and_args: Any,
    ) -> Any:
        self.calls.append(
            (
                script,
                numkeys,
                keys_and_args,
            )
        )

        if self.error is not None:
            raise self.error

        return self.response


def create_limiter(
    client: FakeRedisScriptClient,
) -> RedisRateLimiter:
    return RedisRateLimiter(
        client=client,
        settings=RedisSettings(
            key_prefix="gateway:test",
        ),
        clock_ms=lambda: 1_700_000_000_000,
    )


def create_policy() -> RateLimitPolicy:
    return RateLimitPolicy(
        name="proxy",
        capacity=10,
        refill_rate_per_second=2.5,
        cost=1,
    )


def test_limiter_accepts_allowed_response() -> None:
    client = FakeRedisScriptClient(
        response=[1, "4.25", 0, 2300],
    )

    decision = asyncio.run(
        create_limiter(client).check(
            identity="anas",
            policy=create_policy(),
        )
    )

    assert decision.allowed is True
    assert decision.limit == 10
    assert decision.remaining == 4
    assert decision.retry_after_seconds == 0
    assert decision.reset_after_seconds == 3


def test_limiter_accepts_denied_response() -> None:
    client = FakeRedisScriptClient(
        response=[0, "0.25", 300, 3900],
    )

    decision = asyncio.run(
        create_limiter(client).check(
            identity="anas",
            policy=create_policy(),
        )
    )

    assert decision.allowed is False
    assert decision.remaining == 0
    assert decision.retry_after_seconds == 1
    assert decision.reset_after_seconds == 4


def test_limiter_hashes_identity_in_redis_key() -> None:
    client = FakeRedisScriptClient()

    asyncio.run(
        create_limiter(client).check(
            identity="anas@example.com",
            policy=create_policy(),
        )
    )

    _, numkeys, arguments = client.calls[0]
    redis_key = arguments[0]

    assert numkeys == 1
    assert redis_key.startswith(
        "gateway:test:rate-limit:proxy:"
    )
    assert "anas@example.com" not in redis_key
    assert len(redis_key.rsplit(":", 1)[1]) == 64


def test_limiter_sends_expected_script_arguments() -> None:
    client = FakeRedisScriptClient()

    asyncio.run(
        create_limiter(client).check(
            identity="anas",
            policy=create_policy(),
        )
    )

    script, numkeys, arguments = (
        client.calls[0]
    )

    assert script == TOKEN_BUCKET_SCRIPT
    assert numkeys == 1
    assert arguments[1:] == (
        10,
        2.5,
        1,
        1_700_000_000_000,
        8000,
    )


def test_limiter_rejects_empty_identity() -> None:
    client = FakeRedisScriptClient()

    try:
        asyncio.run(
            create_limiter(client).check(
                identity="   ",
                policy=create_policy(),
            )
        )
    except ValueError:
        pass
    else:
        raise AssertionError(
            "ValueError was not raised."
        )

    assert client.calls == []


def test_limiter_wraps_redis_errors() -> None:
    client = FakeRedisScriptClient(
        error=RedisConnectionError(
            "Connection refused"
        )
    )

    try:
        asyncio.run(
            create_limiter(client).check(
                identity="anas",
                policy=create_policy(),
            )
        )
    except RateLimitBackendError as exc:
        assert isinstance(
            exc.__cause__,
            RedisConnectionError,
        )
    else:
        raise AssertionError(
            "RateLimitBackendError "
            "was not raised."
        )


def test_limiter_rejects_invalid_result_length() -> None:
    client = FakeRedisScriptClient(
        response=[1, "9"],
    )

    try:
        asyncio.run(
            create_limiter(client).check(
                identity="anas",
                policy=create_policy(),
            )
        )
    except RateLimitBackendError:
        pass
    else:
        raise AssertionError(
            "RateLimitBackendError "
            "was not raised."
        )


def test_limiter_rejects_invalid_decision_flag() -> None:
    client = FakeRedisScriptClient(
        response=[2, "9", 0, 1000],
    )

    try:
        asyncio.run(
            create_limiter(client).check(
                identity="anas",
                policy=create_policy(),
            )
        )
    except RateLimitBackendError:
        pass
    else:
        raise AssertionError(
            "RateLimitBackendError "
            "was not raised."
        )


def test_limiter_rejects_non_numeric_tokens() -> None:
    client = FakeRedisScriptClient(
        response=[1, "invalid", 0, 1000],
    )

    try:
        asyncio.run(
            create_limiter(client).check(
                identity="anas",
                policy=create_policy(),
            )
        )
    except RateLimitBackendError:
        pass
    else:
        raise AssertionError(
            "RateLimitBackendError "
            "was not raised."
        )


def test_limiter_clamps_remaining_tokens() -> None:
    client = FakeRedisScriptClient(
        response=[1, "999", 0, 0],
    )

    decision = asyncio.run(
        create_limiter(client).check(
            identity="anas",
            policy=create_policy(),
        )
    )

    assert decision.remaining == 10

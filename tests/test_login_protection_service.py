import asyncio

from typing import Any

from redis.exceptions import (
    ConnectionError as RedisConnectionError,
)

from gateway.app.rate_limit.login import (
    LoginProtectionBackendError,
    LoginProtectionPolicy,
    RedisLoginProtection,
)
from gateway.app.rate_limit.login_scripts import (
    LOGIN_FAILURE_SCRIPT,
    LOGIN_LOCK_STATUS_SCRIPT,
    LOGIN_RESET_SCRIPT,
)


class FakeRedisLoginClient:
    def __init__(
        self,
        *,
        responses: list[Any] | None = None,
        error: Exception | None = None,
    ) -> None:
        self.responses = (
            [[0, 0, 0]]
            if responses is None
            else list(responses)
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

        if not self.responses:
            raise AssertionError(
                "No fake Redis response configured."
            )

        return self.responses.pop(0)


def create_policy() -> LoginProtectionPolicy:
    return LoginProtectionPolicy(
        name="account-login",
        failure_threshold=5,
        failure_window_seconds=900,
        lockout_seconds=300,
    )


def create_protection(
    client: FakeRedisLoginClient,
) -> RedisLoginProtection:
    return RedisLoginProtection(
        client=client,
        key_prefix="gateway:test",
        clock_ms=lambda: 1_700_000_000_000,
    )


def test_check_lock_returns_unlocked_state() -> None:
    client = FakeRedisLoginClient(
        responses=[
            [0, 2, 0],
        ]
    )

    decision = asyncio.run(
        create_protection(client).check_lock(
            identifier="anas",
            policy=create_policy(),
        )
    )

    assert decision.locked is False
    assert decision.failures == 2
    assert decision.retry_after_seconds == 0


def test_check_lock_returns_locked_state() -> None:
    client = FakeRedisLoginClient(
        responses=[
            [1, 5, 299_001],
        ]
    )

    decision = asyncio.run(
        create_protection(client).check_lock(
            identifier="anas",
            policy=create_policy(),
        )
    )

    assert decision.locked is True
    assert decision.failures == 5
    assert decision.retry_after_seconds == 300


def test_record_failure_increments_counter() -> None:
    client = FakeRedisLoginClient(
        responses=[
            [0, 3, 0],
        ]
    )

    decision = asyncio.run(
        create_protection(client).record_failure(
            identifier="anas",
            policy=create_policy(),
        )
    )

    assert decision.locked is False
    assert decision.failures == 3


def test_record_failure_can_lock_account() -> None:
    client = FakeRedisLoginClient(
        responses=[
            [1, 5, 300_000],
        ]
    )

    decision = asyncio.run(
        create_protection(client).record_failure(
            identifier="anas",
            policy=create_policy(),
        )
    )

    assert decision.locked is True
    assert decision.failures == 5
    assert decision.retry_after_seconds == 300


def test_reset_deletes_existing_state() -> None:
    client = FakeRedisLoginClient(
        responses=[
            1,
        ]
    )

    deleted = asyncio.run(
        create_protection(client).reset(
            identifier="anas",
            policy=create_policy(),
        )
    )

    assert deleted is True
    assert client.calls[0][0] == (
        LOGIN_RESET_SCRIPT
    )


def test_equivalent_identifiers_use_same_key() -> None:
    client = FakeRedisLoginClient(
        responses=[
            [0, 0, 0],
            [0, 0, 0],
        ]
    )

    protection = create_protection(client)

    asyncio.run(
        protection.check_lock(
            identifier="  ANAS ",
            policy=create_policy(),
        )
    )

    asyncio.run(
        protection.check_lock(
            identifier="anas",
            policy=create_policy(),
        )
    )

    first_key = client.calls[0][2][0]
    second_key = client.calls[1][2][0]

    assert first_key == second_key


def test_redis_key_hides_login_identifier() -> None:
    client = FakeRedisLoginClient()

    asyncio.run(
        create_protection(client).check_lock(
            identifier="anas@example.com",
            policy=create_policy(),
        )
    )

    redis_key = client.calls[0][2][0]

    assert redis_key.startswith(
        "gateway:test:login-protection:"
        "account-login:"
    )
    assert "anas@example.com" not in redis_key
    assert len(redis_key.rsplit(":", 1)[1]) == 64


def test_check_lock_sends_expected_arguments() -> None:
    client = FakeRedisLoginClient()

    asyncio.run(
        create_protection(client).check_lock(
            identifier="anas",
            policy=create_policy(),
        )
    )

    script, numkeys, arguments = (
        client.calls[0]
    )

    assert script == LOGIN_LOCK_STATUS_SCRIPT
    assert numkeys == 1
    assert arguments[1:] == (
        1_700_000_000_000,
    )


def test_record_failure_sends_expected_arguments() -> None:
    client = FakeRedisLoginClient()

    asyncio.run(
        create_protection(client).record_failure(
            identifier="anas",
            policy=create_policy(),
        )
    )

    script, numkeys, arguments = (
        client.calls[0]
    )

    assert script == LOGIN_FAILURE_SCRIPT
    assert numkeys == 1
    assert arguments[1:] == (
        5,
        1_700_000_000_000,
        900_000,
        300_000,
    )


def test_check_lock_wraps_redis_error() -> None:
    client = FakeRedisLoginClient(
        error=RedisConnectionError(
            "Connection refused"
        )
    )

    try:
        asyncio.run(
            create_protection(client).check_lock(
                identifier="anas",
                policy=create_policy(),
            )
        )
    except LoginProtectionBackendError as exc:
        assert isinstance(
            exc.__cause__,
            RedisConnectionError,
        )
    else:
        raise AssertionError(
            "LoginProtectionBackendError "
            "was not raised."
        )


def test_record_failure_wraps_redis_error() -> None:
    client = FakeRedisLoginClient(
        error=RedisConnectionError(
            "Connection refused"
        )
    )

    try:
        asyncio.run(
            create_protection(client).record_failure(
                identifier="anas",
                policy=create_policy(),
            )
        )
    except LoginProtectionBackendError:
        pass
    else:
        raise AssertionError(
            "LoginProtectionBackendError "
            "was not raised."
        )


def test_rejects_invalid_response_length() -> None:
    client = FakeRedisLoginClient(
        responses=[
            [0, 1],
        ]
    )

    try:
        asyncio.run(
            create_protection(client).check_lock(
                identifier="anas",
                policy=create_policy(),
            )
        )
    except LoginProtectionBackendError:
        pass
    else:
        raise AssertionError(
            "LoginProtectionBackendError "
            "was not raised."
        )


def test_rejects_invalid_lock_flag() -> None:
    client = FakeRedisLoginClient(
        responses=[
            [2, 5, 300_000],
        ]
    )

    try:
        asyncio.run(
            create_protection(client).check_lock(
                identifier="anas",
                policy=create_policy(),
            )
        )
    except LoginProtectionBackendError:
        pass
    else:
        raise AssertionError(
            "LoginProtectionBackendError "
            "was not raised."
        )


def test_reset_rejects_invalid_result() -> None:
    client = FakeRedisLoginClient(
        responses=[
            2,
        ]
    )

    try:
        asyncio.run(
            create_protection(client).reset(
                identifier="anas",
                policy=create_policy(),
            )
        )
    except LoginProtectionBackendError:
        pass
    else:
        raise AssertionError(
            "LoginProtectionBackendError "
            "was not raised."
        )

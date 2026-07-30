from __future__ import annotations

import hashlib
import math
import re
import unicodedata

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from redis.exceptions import RedisError

from gateway.app.rate_limit.login_scripts import (
    LOGIN_FAILURE_SCRIPT,
    LOGIN_LOCK_STATUS_SCRIPT,
    LOGIN_RESET_SCRIPT,
)
from gateway.app.rate_limit.service import (
    current_time_milliseconds,
)


_LOGIN_POLICY_NAME_PATTERN = re.compile(
    r"^[a-z0-9][a-z0-9:_-]{0,63}$"
)


class LoginProtectionPolicyError(ValueError):
    """Raised when a login-protection policy is invalid."""


class LoginProtectionBackendError(RuntimeError):
    """Raised when the Redis protection backend fails."""


@dataclass(
    frozen=True,
    slots=True,
)
class LoginProtectionPolicy:
    """
    Configuration of temporary account lockout.

    failure_threshold:
        Number of failures that triggers a lock.

    failure_window_seconds:
        Sliding period during which failures are retained.

    lockout_seconds:
        Duration of the temporary lock.
    """

    name: str
    failure_threshold: int
    failure_window_seconds: int
    lockout_seconds: int

    def __post_init__(self) -> None:
        normalized_name = self.name.strip()

        if normalized_name != self.name:
            raise LoginProtectionPolicyError(
                "Policy name must not contain leading "
                "or trailing whitespace."
            )

        if not _LOGIN_POLICY_NAME_PATTERN.fullmatch(
            normalized_name
        ):
            raise LoginProtectionPolicyError(
                "Policy name must contain 1 to 64 "
                "lowercase letters, numbers, ':', "
                "'_' or '-'."
            )

        self._validate_integer(
            name="failure_threshold",
            value=self.failure_threshold,
            minimum=1,
            maximum=100,
        )

        self._validate_integer(
            name="failure_window_seconds",
            value=self.failure_window_seconds,
            minimum=1,
            maximum=86_400,
        )

        self._validate_integer(
            name="lockout_seconds",
            value=self.lockout_seconds,
            minimum=1,
            maximum=86_400,
        )

    @staticmethod
    def _validate_integer(
        *,
        name: str,
        value: int,
        minimum: int,
        maximum: int,
    ) -> None:
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or value < minimum
            or value > maximum
        ):
            raise LoginProtectionPolicyError(
                f"{name} must be an integer between "
                f"{minimum} and {maximum}."
            )


@dataclass(
    frozen=True,
    slots=True,
)
class LoginProtectionDecision:
    """Current state of an account protection bucket."""

    locked: bool
    failures: int
    retry_after_seconds: int

    def __post_init__(self) -> None:
        if not isinstance(self.locked, bool):
            raise ValueError(
                "locked must be a boolean."
            )

        if (
            isinstance(self.failures, bool)
            or not isinstance(self.failures, int)
            or self.failures < 0
        ):
            raise ValueError(
                "failures must be a non-negative integer."
            )

        if (
            isinstance(
                self.retry_after_seconds,
                bool,
            )
            or not isinstance(
                self.retry_after_seconds,
                int,
            )
            or self.retry_after_seconds < 0
        ):
            raise ValueError(
                "retry_after_seconds must be "
                "a non-negative integer."
            )

        if (
            not self.locked
            and self.retry_after_seconds != 0
        ):
            raise ValueError(
                "An unlocked account cannot have "
                "a retry delay."
            )


class AsyncRedisLoginClient(Protocol):
    async def eval(
        self,
        script: str,
        numkeys: int,
        *keys_and_args: Any,
    ) -> Any:
        """Execute an atomic Redis Lua script."""


def canonicalize_login_identifier(
    identifier: str,
) -> str:
    """
    Produce a stable identifier for login protection.

    This normalization is intentionally less restrictive than
    the username validation policy. Invalid and unknown usernames
    must also be protected against repeated authentication attempts.
    """

    if not isinstance(identifier, str):
        raise ValueError(
            "Login identifier must be a string."
        )

    normalized_identifier = unicodedata.normalize(
        "NFKC",
        identifier,
    ).strip().casefold()

    if not normalized_identifier:
        return "<empty-login-identifier>"

    return normalized_identifier


class RedisLoginProtection:
    """
    Redis-backed account failure tracker and temporary lock.
    """

    def __init__(
        self,
        *,
        client: AsyncRedisLoginClient,
        key_prefix: str,
        clock_ms: Callable[[], int] = (
            current_time_milliseconds
        ),
    ) -> None:
        normalized_prefix = key_prefix.strip()

        if not normalized_prefix:
            raise ValueError(
                "Redis key prefix must not be empty."
            )

        self._client = client
        self._key_prefix = normalized_prefix
        self._clock_ms = clock_ms

    async def check_lock(
        self,
        *,
        identifier: str,
        policy: LoginProtectionPolicy,
    ) -> LoginProtectionDecision:
        """
        Return the current lock status without incrementing
        the failure counter.
        """

        key = self._build_key(
            identifier=identifier,
            policy=policy,
        )

        now_ms = self._read_clock()

        raw_result = await self._evaluate(
            LOGIN_LOCK_STATUS_SCRIPT,
            key,
            now_ms,
        )

        return self._parse_decision(
            raw_result
        )

    async def record_failure(
        self,
        *,
        identifier: str,
        policy: LoginProtectionPolicy,
    ) -> LoginProtectionDecision:
        """
        Atomically record an authentication failure.
        """

        key = self._build_key(
            identifier=identifier,
            policy=policy,
        )

        now_ms = self._read_clock()

        raw_result = await self._evaluate(
            LOGIN_FAILURE_SCRIPT,
            key,
            policy.failure_threshold,
            now_ms,
            policy.failure_window_seconds * 1000,
            policy.lockout_seconds * 1000,
        )

        return self._parse_decision(
            raw_result
        )

    async def reset(
        self,
        *,
        identifier: str,
        policy: LoginProtectionPolicy,
    ) -> bool:
        """
        Delete the account failure state after successful login.
        """

        key = self._build_key(
            identifier=identifier,
            policy=policy,
        )

        raw_result = await self._evaluate(
            LOGIN_RESET_SCRIPT,
            key,
        )

        try:
            deleted = int(raw_result)
        except (
            TypeError,
            ValueError,
            OverflowError,
        ) as exc:
            raise LoginProtectionBackendError(
                "Redis returned an invalid reset result."
            ) from exc

        if deleted not in (0, 1):
            raise LoginProtectionBackendError(
                "Redis returned an invalid reset result."
            )

        return deleted == 1

    async def _evaluate(
        self,
        script: str,
        key: str,
        *arguments: Any,
    ) -> Any:
        try:
            return await self._client.eval(
                script,
                1,
                key,
                *arguments,
            )
        except RedisError as exc:
            raise LoginProtectionBackendError(
                "Redis login-protection backend "
                "is unavailable."
            ) from exc

    def _build_key(
        self,
        *,
        identifier: str,
        policy: LoginProtectionPolicy,
    ) -> str:
        canonical_identifier = (
            canonicalize_login_identifier(
                identifier
            )
        )

        digest = hashlib.sha256(
            canonical_identifier.encode("utf-8")
        ).hexdigest()

        return (
            f"{self._key_prefix}"
            f":login-protection"
            f":{policy.name}"
            f":{digest}"
        )

    def _read_clock(self) -> int:
        now_ms = self._clock_ms()

        if (
            isinstance(now_ms, bool)
            or not isinstance(now_ms, int)
            or now_ms < 0
        ):
            raise ValueError(
                "The login-protection clock returned "
                "an invalid timestamp."
            )

        return now_ms

    @staticmethod
    def _parse_decision(
        raw_result: Any,
    ) -> LoginProtectionDecision:
        if (
            not isinstance(
                raw_result,
                (list, tuple),
            )
            or len(raw_result) != 3
        ):
            raise LoginProtectionBackendError(
                "Redis returned an invalid "
                "login-protection response."
            )

        try:
            locked_value = int(raw_result[0])
            failures = int(raw_result[1])
            retry_after_ms = int(raw_result[2])
        except (
            TypeError,
            ValueError,
            OverflowError,
        ) as exc:
            raise LoginProtectionBackendError(
                "Redis returned malformed "
                "login-protection values."
            ) from exc

        if locked_value not in (0, 1):
            raise LoginProtectionBackendError(
                "Redis returned an invalid lock state."
            )

        if failures < 0 or retry_after_ms < 0:
            raise LoginProtectionBackendError(
                "Redis returned invalid "
                "login-protection measurements."
            )

        locked = locked_value == 1

        if not locked and retry_after_ms != 0:
            raise LoginProtectionBackendError(
                "Redis returned an inconsistent "
                "login-protection response."
            )

        return LoginProtectionDecision(
            locked=locked,
            failures=failures,
            retry_after_seconds=(
                math.ceil(retry_after_ms / 1000)
                if locked
                else 0
            ),
        )

from __future__ import annotations

import hashlib
import math
import time

from collections.abc import Callable
from typing import Any, Protocol

from redis.exceptions import RedisError

from gateway.app.rate_limit.config import (
    RedisSettings,
)
from gateway.app.rate_limit.models import (
    RateLimitDecision,
    RateLimitPolicy,
)
from gateway.app.rate_limit.scripts import (
    TOKEN_BUCKET_SCRIPT,
)


class RateLimitBackendError(RuntimeError):
    """Raised when Redis cannot evaluate the limiter."""


class AsyncRedisScriptClient(Protocol):
    async def eval(
        self,
        script: str,
        numkeys: int,
        *keys_and_args: Any,
    ) -> Any:
        """Execute a Redis Lua script."""


def current_time_milliseconds() -> int:
    """Return current Unix time in milliseconds."""

    return time.time_ns() // 1_000_000


class RedisRateLimiter:
    """Distributed token bucket backed by Redis."""

    def __init__(
        self,
        *,
        client: AsyncRedisScriptClient,
        settings: RedisSettings,
        clock_ms: Callable[[], int] = (
            current_time_milliseconds
        ),
    ) -> None:
        self._client = client
        self._key_prefix = settings.key_prefix
        self._clock_ms = clock_ms

    async def check(
        self,
        *,
        identity: str,
        policy: RateLimitPolicy,
    ) -> RateLimitDecision:
        normalized_identity = identity.strip()

        if not normalized_identity:
            raise ValueError(
                "Rate-limit identity must not "
                "be empty."
            )

        key = self._build_key(
            identity=normalized_identity,
            policy=policy,
        )

        now_ms = self._clock_ms()

        if (
            isinstance(now_ms, bool)
            or not isinstance(now_ms, int)
            or now_ms < 0
        ):
            raise ValueError(
                "The rate-limit clock returned "
                "an invalid timestamp."
            )

        try:
            raw_result = await self._client.eval(
                TOKEN_BUCKET_SCRIPT,
                1,
                key,
                policy.capacity,
                policy.refill_rate_per_second,
                policy.cost,
                now_ms,
                policy.state_ttl_seconds * 1000,
            )
        except RedisError as exc:
            raise RateLimitBackendError(
                "Redis rate-limit backend "
                "is unavailable."
            ) from exc

        return self._parse_result(
            raw_result=raw_result,
            policy=policy,
        )

    def _build_key(
        self,
        *,
        identity: str,
        policy: RateLimitPolicy,
    ) -> str:
        digest = hashlib.sha256(
            identity.encode("utf-8")
        ).hexdigest()

        return (
            f"{self._key_prefix}"
            f":rate-limit"
            f":{policy.name}"
            f":{digest}"
        )

    @staticmethod
    def _parse_result(
        *,
        raw_result: Any,
        policy: RateLimitPolicy,
    ) -> RateLimitDecision:
        if (
            not isinstance(
                raw_result,
                (list, tuple),
            )
            or len(raw_result) != 4
        ):
            raise RateLimitBackendError(
                "Redis returned an invalid "
                "rate-limit response."
            )

        try:
            allowed_value = int(raw_result[0])
            tokens = float(raw_result[1])
            retry_after_ms = int(raw_result[2])
            reset_after_ms = int(raw_result[3])
        except (
            TypeError,
            ValueError,
            OverflowError,
        ) as exc:
            raise RateLimitBackendError(
                "Redis returned malformed "
                "rate-limit values."
            ) from exc

        if allowed_value not in (0, 1):
            raise RateLimitBackendError(
                "Redis returned an invalid "
                "rate-limit decision."
            )

        if (
            not math.isfinite(tokens)
            or retry_after_ms < 0
            or reset_after_ms < 0
        ):
            raise RateLimitBackendError(
                "Redis returned invalid "
                "rate-limit measurements."
            )

        remaining = max(
            0,
            min(
                policy.capacity,
                math.floor(tokens),
            ),
        )

        allowed = allowed_value == 1

        return RateLimitDecision(
            allowed=allowed,
            limit=policy.capacity,
            remaining=remaining,
            retry_after_seconds=(
                0
                if allowed
                else math.ceil(
                    retry_after_ms / 1000
                )
            ),
            reset_after_seconds=math.ceil(
                reset_after_ms / 1000
            ),
        )

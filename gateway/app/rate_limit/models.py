from __future__ import annotations

import math
import re

from dataclasses import dataclass


_POLICY_NAME_PATTERN = re.compile(
    r"^[a-z0-9][a-z0-9:_-]{0,63}$"
)


class RateLimitPolicyError(ValueError):
    """Raised when a rate-limit policy is invalid."""


@dataclass(
    frozen=True,
    slots=True,
)
class RateLimitPolicy:
    """
    Token bucket configuration.

    capacity:
        Maximum number of tokens in the bucket.

    refill_rate_per_second:
        Number of tokens added every second.

    cost:
        Number of tokens consumed by one operation.
    """

    name: str
    capacity: int
    refill_rate_per_second: float
    cost: int = 1

    def __post_init__(self) -> None:
        normalized_name = self.name.strip()

        if normalized_name != self.name:
            raise RateLimitPolicyError(
                "Policy name must not contain leading "
                "or trailing whitespace."
            )

        if not _POLICY_NAME_PATTERN.fullmatch(
            normalized_name
        ):
            raise RateLimitPolicyError(
                "Policy name must contain 1 to 64 "
                "lowercase letters, numbers, ':', "
                "'_' or '-'."
            )

        if (
            isinstance(self.capacity, bool)
            or not isinstance(self.capacity, int)
            or self.capacity < 1
            or self.capacity > 1_000_000
        ):
            raise RateLimitPolicyError(
                "Capacity must be an integer between "
                "1 and 1000000."
            )

        if (
            isinstance(
                self.refill_rate_per_second,
                bool,
            )
            or not isinstance(
                self.refill_rate_per_second,
                (int, float),
            )
            or not math.isfinite(
                self.refill_rate_per_second
            )
            or self.refill_rate_per_second <= 0
            or self.refill_rate_per_second
            > 1_000_000
        ):
            raise RateLimitPolicyError(
                "Refill rate must be finite, greater "
                "than 0 and at most 1000000."
            )

        if (
            isinstance(self.cost, bool)
            or not isinstance(self.cost, int)
            or self.cost < 1
            or self.cost > self.capacity
        ):
            raise RateLimitPolicyError(
                "Cost must be an integer between "
                "1 and the bucket capacity."
            )

    @property
    def state_ttl_seconds(self) -> int:
        """
        Expire inactive buckets after twice the time required
        for a completely empty bucket to refill.
        """

        seconds_to_full = (
            self.capacity
            / self.refill_rate_per_second
        )

        return max(
            1,
            math.ceil(seconds_to_full * 2),
        )


@dataclass(
    frozen=True,
    slots=True,
)
class RateLimitDecision:
    """Result returned by the token bucket."""

    allowed: bool
    limit: int
    remaining: int
    retry_after_seconds: int
    reset_after_seconds: int

    def __post_init__(self) -> None:
        if not isinstance(self.allowed, bool):
            raise ValueError(
                "allowed must be a boolean."
            )

        if (
            isinstance(self.limit, bool)
            or not isinstance(self.limit, int)
            or self.limit < 1
        ):
            raise ValueError(
                "limit must be a positive integer."
            )

        if (
            isinstance(self.remaining, bool)
            or not isinstance(self.remaining, int)
            or self.remaining < 0
            or self.remaining > self.limit
        ):
            raise ValueError(
                "remaining must be between "
                "0 and limit."
            )

        for name, value in (
            (
                "retry_after_seconds",
                self.retry_after_seconds,
            ),
            (
                "reset_after_seconds",
                self.reset_after_seconds,
            ),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 0
            ):
                raise ValueError(
                    f"{name} must be a "
                    "non-negative integer."
                )

        if (
            self.allowed
            and self.retry_after_seconds != 0
        ):
            raise ValueError(
                "An allowed request cannot have "
                "a retry delay."
            )

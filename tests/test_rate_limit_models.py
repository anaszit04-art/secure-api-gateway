import math

import pytest

from gateway.app.rate_limit.models import (
    RateLimitDecision,
    RateLimitPolicy,
    RateLimitPolicyError,
)


def test_policy_accepts_valid_values() -> None:
    policy = RateLimitPolicy(
        name="authenticated-proxy",
        capacity=60,
        refill_rate_per_second=1.0,
        cost=1,
    )

    assert policy.name == (
        "authenticated-proxy"
    )
    assert policy.capacity == 60
    assert policy.refill_rate_per_second == 1
    assert policy.cost == 1


@pytest.mark.parametrize(
    "name",
    [
        "",
        " Proxy",
        ":proxy",
        "x" * 65,
    ],
)
def test_policy_rejects_invalid_names(
    name: str,
) -> None:
    with pytest.raises(
        RateLimitPolicyError
    ):
        RateLimitPolicy(
            name=name,
            capacity=10,
            refill_rate_per_second=1,
        )


@pytest.mark.parametrize(
    "capacity",
    [
        0,
        -1,
        True,
        1.5,
    ],
)
def test_policy_rejects_invalid_capacity(
    capacity: object,
) -> None:
    with pytest.raises(
        RateLimitPolicyError
    ):
        RateLimitPolicy(
            name="proxy",
            capacity=capacity,  # type: ignore[arg-type]
            refill_rate_per_second=1,
        )


@pytest.mark.parametrize(
    "refill_rate",
    [
        0,
        -1,
        True,
        math.inf,
        math.nan,
    ],
)
def test_policy_rejects_invalid_refill_rate(
    refill_rate: object,
) -> None:
    with pytest.raises(
        RateLimitPolicyError
    ):
        RateLimitPolicy(
            name="proxy",
            capacity=10,
            refill_rate_per_second=(
                refill_rate  # type: ignore[arg-type]
            ),
        )


@pytest.mark.parametrize(
    ("cost", "capacity"),
    [
        (0, 10),
        (-1, 10),
        (True, 10),
        (11, 10),
    ],
)
def test_policy_rejects_invalid_cost(
    cost: object,
    capacity: int,
) -> None:
    with pytest.raises(
        RateLimitPolicyError
    ):
        RateLimitPolicy(
            name="proxy",
            capacity=capacity,
            refill_rate_per_second=1,
            cost=cost,  # type: ignore[arg-type]
        )


def test_policy_calculates_state_ttl() -> None:
    policy = RateLimitPolicy(
        name="proxy",
        capacity=10,
        refill_rate_per_second=2.5,
    )

    assert policy.state_ttl_seconds == 8


def test_decision_accepts_valid_values() -> None:
    decision = RateLimitDecision(
        allowed=True,
        limit=60,
        remaining=59,
        retry_after_seconds=0,
        reset_after_seconds=1,
    )

    assert decision.allowed is True
    assert decision.limit == 60
    assert decision.remaining == 59

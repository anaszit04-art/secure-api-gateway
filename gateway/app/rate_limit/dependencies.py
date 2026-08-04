from __future__ import annotations

from typing import Annotated

from fastapi import (
    Depends,
    HTTPException,
    Request,
    status,
)

from gateway.app.auth.dependencies import (
    get_current_user,
)
from gateway.app.auth.models import (
    UserPublic,
)
from gateway.app.rate_limit.models import (
    RateLimitDecision,
    RateLimitPolicy,
)
from gateway.app.rate_limit.service import (
    RateLimitBackendError,
    RedisRateLimiter,
)


PROXY_RATE_LIMIT_POLICY = RateLimitPolicy(
    name="authenticated-proxy",
    capacity=60,
    refill_rate_per_second=1.0,
    cost=1,
)


def get_rate_limiter(
    request: Request,
) -> RedisRateLimiter:
    """
    Return the Redis rate limiter initialized by the
    FastAPI lifespan.
    """

    limiter = getattr(
        request.app.state,
        "rate_limiter",
        None,
    )

    if limiter is None:
        raise HTTPException(
            status_code=(
                status.HTTP_503_SERVICE_UNAVAILABLE
            ),
            detail=(
                "Rate-limit service is unavailable."
            ),
            headers={
                "Retry-After": "1",
            },
        )

    return limiter


def get_proxy_rate_limit_policy() -> RateLimitPolicy:
    """
    Return the policy applied to authenticated proxy
    requests.

    The bucket permits a burst of 60 requests and
    refills at one token per second.
    """

    return PROXY_RATE_LIMIT_POLICY


def build_rate_limit_headers(
    decision: RateLimitDecision,
) -> dict[str, str]:
    """
    Build headers describing the current bucket state.
    """

    headers = {
        "X-RateLimit-Limit": str(
            decision.limit
        ),
        "X-RateLimit-Remaining": str(
            decision.remaining
        ),
        "X-RateLimit-Reset": str(
            decision.reset_after_seconds
        ),
    }

    if not decision.allowed:
        headers["Retry-After"] = str(
            max(
                1,
                decision.retry_after_seconds,
            )
        )

    return headers


async def enforce_proxy_rate_limit(
    current_user: Annotated[
        UserPublic,
        Depends(get_current_user),
    ],
    limiter: Annotated[
        RedisRateLimiter,
        Depends(get_rate_limiter),
    ],
    policy: Annotated[
        RateLimitPolicy,
        Depends(get_proxy_rate_limit_policy),
    ],
) -> RateLimitDecision:
    """
    Apply the authenticated proxy policy.

    The internal UUID is used instead of the username
    to produce a stable, non-readable Redis identity.
    """

    try:
        decision = await limiter.check(
            identity=str(current_user.id),
            policy=policy,
        )
    except RateLimitBackendError as exc:
        raise HTTPException(
            status_code=(
                status.HTTP_503_SERVICE_UNAVAILABLE
            ),
            detail=(
                "Rate-limit service is temporarily "
                "unavailable."
            ),
            headers={
                "Retry-After": "1",
            },
        ) from exc

    if not decision.allowed:
        raise HTTPException(
            status_code=(
                status.HTTP_429_TOO_MANY_REQUESTS
            ),
            detail="Rate limit exceeded.",
            headers=build_rate_limit_headers(
                decision
            ),
        )

    return decision

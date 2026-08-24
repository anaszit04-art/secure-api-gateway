from __future__ import annotations

from typing import Annotated

from fastapi import (
    Depends,
    HTTPException,
    Request,
    status,
)

from gateway.app.audit.dependencies import (
    AuditServiceDependency,
    record_request_security_event,
)
from gateway.app.audit.models import (
    AuditEventType,
    AuditOutcome,
)
from gateway.app.auth.dependencies import (
    get_current_user,
)
from gateway.app.auth.models import (
    UserPublic,
)
from gateway.app.observability.metrics import (
    record_rate_limit_metric_best_effort,
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
    request: Request,
    service_name: str,
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
    audit_service: AuditServiceDependency,
) -> RateLimitDecision:
    """
    Apply the authenticated proxy policy.

    The internal UUID is used instead of the username
    to produce a stable, non-readable Redis identity.

    Rejections and Redis backend failures are audited
    using the Gateway-owned request correlation ID.
    """

    try:
        decision = await limiter.check(
            identity=str(
                current_user.id
            ),
            policy=policy,
        )

    except RateLimitBackendError as exc:
        record_rate_limit_metric_best_effort(
            request=request,
            scope="proxy",
            decision="unavailable",
        )

        await record_request_security_event(
            request=request,
            audit_service=audit_service,
            event_type=(
                AuditEventType
                .RATE_LIMIT_BACKEND_UNAVAILABLE
            ),
            outcome=AuditOutcome.UNAVAILABLE,
            actor_user_id=current_user.id,
            service_name=service_name,
            method=request.method,
            status_code=503,
            reason_code=(
                "proxy_rate_limit_backend_unavailable"
            ),
        )

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

    record_rate_limit_metric_best_effort(
        request=request,
        scope="proxy",
        decision=(
            "allowed"
            if decision.allowed
            else "rejected"
        ),
    )

    if not decision.allowed:
        await record_request_security_event(
            request=request,
            audit_service=audit_service,
            event_type=(
                AuditEventType.RATE_LIMIT_REJECTED
            ),
            outcome=AuditOutcome.DENIED,
            actor_user_id=current_user.id,
            service_name=service_name,
            method=request.method,
            status_code=429,
            reason_code=(
                "proxy_rate_limit_exceeded"
            ),
        )

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

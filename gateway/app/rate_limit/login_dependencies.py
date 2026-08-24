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
from gateway.app.rate_limit.dependencies import (
    build_rate_limit_headers,
    get_rate_limiter,
)
from gateway.app.rate_limit.login import (
    LoginProtectionPolicy,
    RedisLoginProtection,
)
from gateway.app.rate_limit.models import (
    RateLimitDecision,
    RateLimitPolicy,
)
from gateway.app.rate_limit.service import (
    RateLimitBackendError,
    RedisRateLimiter,
)


LOGIN_IP_RATE_LIMIT_POLICY = RateLimitPolicy(
    name="login-ip",
    capacity=10,
    refill_rate_per_second=0.2,
    cost=1,
)

ACCOUNT_LOGIN_PROTECTION_POLICY = (
    LoginProtectionPolicy(
        name="account-login",
        failure_threshold=5,
        failure_window_seconds=900,
        lockout_seconds=300,
    )
)


def get_login_protection(
    request: Request,
) -> RedisLoginProtection:
    """
    Return the login-protection service created during
    application startup.
    """

    protection = getattr(
        request.app.state,
        "login_protection",
        None,
    )

    if protection is None:
        raise authentication_protection_unavailable()

    return protection


def get_login_ip_policy() -> RateLimitPolicy:
    """
    Return the policy applied to login requests by IP.

    The policy allows a burst of ten attempts and then
    refills one attempt every five seconds.
    """

    return LOGIN_IP_RATE_LIMIT_POLICY


def get_account_login_policy() -> LoginProtectionPolicy:
    """
    Return the temporary account-lockout policy.
    """

    return ACCOUNT_LOGIN_PROTECTION_POLICY


def get_direct_client_address(
    request: Request,
) -> str:
    """
    Return the direct network peer.

    X-Forwarded-For is deliberately ignored until trusted
    reverse-proxy handling is explicitly configured.
    """

    if request.client is None:
        return "<unknown-client>"

    host = request.client.host.strip()

    if not host:
        return "<unknown-client>"

    return host


def authentication_protection_unavailable() -> HTTPException:
    """
    Return the consistent fail-closed backend error.
    """

    return HTTPException(
        status_code=(
            status.HTTP_503_SERVICE_UNAVAILABLE
        ),
        detail=(
            "Authentication protection service "
            "is temporarily unavailable."
        ),
        headers={
            "Retry-After": "1",
        },
    )


def too_many_authentication_attempts(
    *,
    retry_after_seconds: int,
    additional_headers: dict[str, str] | None = None,
) -> HTTPException:
    """
    Return a generic throttling response without revealing
    whether the requested account exists.
    """

    headers = dict(
        additional_headers or {}
    )

    headers["Retry-After"] = str(
        max(
            1,
            retry_after_seconds,
        )
    )

    return HTTPException(
        status_code=(
            status.HTTP_429_TOO_MANY_REQUESTS
        ),
        detail="Too many authentication attempts.",
        headers=headers,
    )


async def enforce_login_ip_rate_limit(
    request: Request,
    limiter: Annotated[
        RedisRateLimiter,
        Depends(get_rate_limiter),
    ],
    policy: Annotated[
        RateLimitPolicy,
        Depends(get_login_ip_policy),
    ],
    audit_service: AuditServiceDependency,
) -> RateLimitDecision:
    """
    Apply a token bucket to the direct client address.

    The direct address is used only as the Redis
    identity. It is deliberately excluded from the
    security audit event.
    """

    identity = get_direct_client_address(
        request
    )

    try:
        decision = await limiter.check(
            identity=identity,
            policy=policy,
        )

    except RateLimitBackendError as exc:
        await record_request_security_event(
            request=request,
            audit_service=audit_service,
            event_type=(
                AuditEventType
                .RATE_LIMIT_BACKEND_UNAVAILABLE
            ),
            outcome=AuditOutcome.UNAVAILABLE,
            method=request.method,
            status_code=503,
            reason_code=(
                "login_ip_rate_limit_backend_unavailable"
            ),
        )

        raise (
            authentication_protection_unavailable()
        ) from exc

    if not decision.allowed:
        await record_request_security_event(
            request=request,
            audit_service=audit_service,
            event_type=(
                AuditEventType.RATE_LIMIT_REJECTED
            ),
            outcome=AuditOutcome.DENIED,
            method=request.method,
            status_code=429,
            reason_code=(
                "login_ip_rate_limit_exceeded"
            ),
        )

        raise too_many_authentication_attempts(
            retry_after_seconds=(
                decision.retry_after_seconds
            ),
            additional_headers=(
                build_rate_limit_headers(
                    decision
                )
            ),
        )

    return decision

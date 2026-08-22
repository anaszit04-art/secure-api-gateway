from __future__ import annotations

from dataclasses import dataclass
from datetime import (
    datetime,
    timezone,
)
from enum import StrEnum
from uuid import (
    UUID,
    uuid4,
)


class AuditEventType(StrEnum):
    """
    Stable security-event taxonomy.

    Values are suitable for logs and persistent
    storage. They must not contain user-controlled
    information.
    """

    USER_REGISTERED = "user_registered"

    LOGIN_SUCCEEDED = "login_succeeded"
    LOGIN_FAILED = "login_failed"
    ACCOUNT_LOCKED = "account_locked"

    AUTHENTICATION_BACKEND_UNAVAILABLE = (
        "authentication_backend_unavailable"
    )

    AUTHORIZATION_DENIED = (
        "authorization_denied"
    )

    AUTHORIZATION_BACKEND_UNAVAILABLE = (
        "authorization_backend_unavailable"
    )

    ROLE_LIST_READ = "role_list_read"
    ROLE_ASSIGNED = "role_assigned"
    ROLE_REMOVED = "role_removed"

    RATE_LIMIT_REJECTED = (
        "rate_limit_rejected"
    )

    RATE_LIMIT_BACKEND_UNAVAILABLE = (
        "rate_limit_backend_unavailable"
    )


class AuditOutcome(StrEnum):
    """
    Stable outcome classification for security events.
    """

    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"
    UNAVAILABLE = "unavailable"


def _validate_optional_code(
    *,
    name: str,
    value: str | None,
    max_length: int = 160,
) -> None:
    if value is None:
        return

    if not isinstance(
        value,
        str,
    ):
        raise TypeError(
            f"{name} must be a string or None."
        )

    if (
        not value
        or value != value.strip()
        or len(value) > max_length
    ):
        raise ValueError(
            f"{name} has an invalid value."
        )


@dataclass(
    frozen=True,
    slots=True,
)
class SecurityAuditEvent:
    """
    Immutable security-audit event.

    The schema deliberately contains no password,
    JWT, Authorization header, request body, query
    string, raw client path or arbitrary metadata.

    User UUIDs provide a stable pseudonymous identity
    without embedding usernames in operational logs.
    """

    event_id: UUID
    occurred_at: datetime

    event_type: AuditEventType
    outcome: AuditOutcome

    request_id: UUID

    actor_user_id: UUID | None = None
    target_user_id: UUID | None = None

    permission_code: str | None = None
    role_name: str | None = None
    service_name: str | None = None
    method: str | None = None

    status_code: int | None = None
    reason_code: str | None = None

    def __post_init__(self) -> None:
        if (
            self.occurred_at.tzinfo
            is None
            or self.occurred_at.utcoffset()
            is None
        ):
            raise ValueError(
                "occurred_at must be timezone-aware."
            )

        if (
            self.status_code is not None
            and not (
                100
                <= self.status_code
                <= 599
            )
        ):
            raise ValueError(
                "status_code must be between "
                "100 and 599."
            )

        _validate_optional_code(
            name="permission_code",
            value=self.permission_code,
        )

        _validate_optional_code(
            name="role_name",
            value=self.role_name,
        )

        _validate_optional_code(
            name="service_name",
            value=self.service_name,
        )

        _validate_optional_code(
            name="method",
            value=self.method,
            max_length=16,
        )

        _validate_optional_code(
            name="reason_code",
            value=self.reason_code,
        )


def create_security_audit_event(
    *,
    event_type: AuditEventType,
    outcome: AuditOutcome,
    request_id: UUID | str,
    actor_user_id: UUID | None = None,
    target_user_id: UUID | None = None,
    permission_code: str | None = None,
    role_name: str | None = None,
    service_name: str | None = None,
    method: str | None = None,
    status_code: int | None = None,
    reason_code: str | None = None,
) -> SecurityAuditEvent:
    """
    Create one trusted immutable audit event.

    request_id comes from the Gateway-owned request
    context introduced in Phase 6.2.
    """

    normalized_request_id = (
        request_id
        if isinstance(
            request_id,
            UUID,
        )
        else UUID(
            request_id
        )
    )

    normalized_method = (
        method.upper()
        if method is not None
        else None
    )

    return SecurityAuditEvent(
        event_id=uuid4(),
        occurred_at=datetime.now(
            timezone.utc
        ),
        event_type=event_type,
        outcome=outcome,
        request_id=normalized_request_id,
        actor_user_id=actor_user_id,
        target_user_id=target_user_id,
        permission_code=permission_code,
        role_name=role_name,
        service_name=service_name,
        method=normalized_method,
        status_code=status_code,
        reason_code=reason_code,
    )

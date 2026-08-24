from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import (
    Depends,
    Request,
)

from gateway.app.audit.logging import (
    emit_audit_persistence_failure,
    emit_security_audit_event,
)
from gateway.app.audit.models import (
    AuditEventType,
    AuditOutcome,
    SecurityAuditEvent,
    create_security_audit_event,
)
from gateway.app.audit.repository import (
    AuditRepositoryBackendError,
)
from gateway.app.audit.service import (
    AuditService,
)
from gateway.app.database.audit_repository import (
    PostgreSQLAuditRepository,
)


def get_audit_service(
    request: Request,
) -> AuditService | None:
    """
    Resolve persistent security auditing when a
    PostgreSQL session factory exists.

    Isolated tests intentionally running without a
    configured database receive no persistent service.
    They still retain structured audit logging through
    record_security_event_best_effort().

    Runtime PostgreSQL failures happen later inside the
    repository and are handled as best-effort audit
    persistence failures.
    """

    session_factory = getattr(
        request.app.state,
        "database_session_factory",
        None,
    )

    if session_factory is None:
        return None

    repository = PostgreSQLAuditRepository(
        session_factory
    )

    return AuditService(
        repository
    )


AuditServiceDependency = Annotated[
    AuditService | None,
    Depends(get_audit_service),
]


def get_trusted_request_id(
    request: Request,
) -> UUID:
    """
    Return the Gateway-owned request correlation ID.

    The value originates from RequestContextMiddleware,
    not from an untrusted client header.
    """

    request_id = getattr(
        request.state,
        "request_id",
        None,
    )

    if not isinstance(
        request_id,
        str,
    ):
        raise RuntimeError(
            "Trusted request ID is unavailable."
        )

    return UUID(
        request_id
    )


async def record_security_event_best_effort(
    *,
    service: AuditService | None,
    event: SecurityAuditEvent,
) -> None:
    """
    Record one security event without changing an
    already-determined business outcome.

    With persistent auditing configured:
        AuditService emits JSON then attempts PostgreSQL.

    Without persistent auditing:
        emit the bounded JSON event only.

    If PostgreSQL audit persistence fails:
        preserve the original business result and emit
        an explicit persistence warning.
    """

    if service is None:
        emit_security_audit_event(
            event
        )
        return

    try:
        await service.record(
            event
        )

    except AuditRepositoryBackendError:
        emit_audit_persistence_failure(
            event
        )


async def record_request_security_event(
    *,
    request: Request,
    audit_service: AuditService | None,
    event_type: AuditEventType,
    outcome: AuditOutcome,
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
    Create and record a security event using the
    Gateway-owned request correlation identifier.

    No client-controlled request identifier is accepted.
    """

    event = create_security_audit_event(
        event_type=event_type,
        outcome=outcome,
        request_id=(
            get_trusted_request_id(
                request
            )
        ),
        actor_user_id=actor_user_id,
        target_user_id=target_user_id,
        permission_code=permission_code,
        role_name=role_name,
        service_name=service_name,
        method=method,
        status_code=status_code,
        reason_code=reason_code,
    )

    await record_security_event_best_effort(
        service=audit_service,
        event=event,
    )

    return event

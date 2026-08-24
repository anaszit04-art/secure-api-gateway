from __future__ import annotations

from gateway.app.audit.logging import (
    emit_security_audit_event,
)
from gateway.app.audit.models import (
    SecurityAuditEvent,
)
from gateway.app.audit.repository import (
    AuditRepository,
)


class AuditService:
    """
    Coordinate security-audit logging and persistent
    storage.

    The bounded JSON event is emitted first so that an
    audit signal remains observable even when the
    PostgreSQL persistence attempt subsequently fails.

    Persistence errors intentionally remain visible to
    callers. Integration policy is decided by the
    security-sensitive calling layer.
    """

    def __init__(
        self,
        repository: AuditRepository,
    ) -> None:
        self._repository = repository

    async def record(
        self,
        event: SecurityAuditEvent,
    ) -> None:
        emit_security_audit_event(
            event
        )

        await self._repository.append_event(
            event
        )

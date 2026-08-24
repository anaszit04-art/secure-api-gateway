from __future__ import annotations

from typing import Protocol

from gateway.app.audit.models import (
    SecurityAuditEvent,
)


class AuditRepositoryBackendError(
    RuntimeError
):
    """
    Raised when persistent security-audit storage
    cannot complete an operation.

    Database implementation details must never cross
    this boundary.
    """


class AuditRepository(Protocol):
    """
    Append-only persistence contract for security
    audit events.
    """

    async def append_event(
        self,
        event: SecurityAuditEvent,
    ) -> None:
        """
        Persist one immutable security event.
        """
        ...

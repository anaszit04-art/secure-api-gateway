from __future__ import annotations

from uuid import uuid4

import pytest

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


class FakeAuditRepository:
    def __init__(
        self,
        *,
        error: Exception | None = None,
    ) -> None:
        self.error = error

        self.events: list[
            SecurityAuditEvent
        ] = []

    async def append_event(
        self,
        event: SecurityAuditEvent,
    ) -> None:
        self.events.append(
            event
        )

        if self.error is not None:
            raise self.error


def make_event() -> SecurityAuditEvent:
    return create_security_audit_event(
        event_type=(
            AuditEventType.LOGIN_FAILED
        ),
        outcome=AuditOutcome.FAILURE,
        request_id=uuid4(),
        status_code=401,
        reason_code="invalid_credentials",
    )


@pytest.mark.anyio
async def test_audit_service_logs_then_persists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    order: list[str] = []

    event = make_event()

    repository = FakeAuditRepository()

    original_append = (
        repository.append_event
    )

    async def append_event(
        value: SecurityAuditEvent,
    ) -> None:
        order.append(
            "persist"
        )

        await original_append(
            value
        )

    repository.append_event = append_event  # type: ignore[method-assign]

    def emit_event(
        value: SecurityAuditEvent,
    ) -> None:
        assert value is event

        order.append(
            "log"
        )

    monkeypatch.setattr(
        "gateway.app.audit.service."
        "emit_security_audit_event",
        emit_event,
    )

    service = AuditService(
        repository
    )

    await service.record(
        event
    )

    assert order == [
        "log",
        "persist",
    ]

    assert repository.events == [
        event,
    ]


@pytest.mark.anyio
async def test_audit_service_exposes_persistence_failure_after_logging(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    emitted: list[
        SecurityAuditEvent
    ] = []

    event = make_event()

    error = AuditRepositoryBackendError(
        "audit backend unavailable"
    )

    repository = FakeAuditRepository(
        error=error
    )

    monkeypatch.setattr(
        "gateway.app.audit.service."
        "emit_security_audit_event",
        emitted.append,
    )

    service = AuditService(
        repository
    )

    with pytest.raises(
        AuditRepositoryBackendError,
    ) as captured:
        await service.record(
            event
        )

    assert (
        captured.value
        is error
    )

    assert emitted == [
        event,
    ]

    assert repository.events == [
        event,
    ]

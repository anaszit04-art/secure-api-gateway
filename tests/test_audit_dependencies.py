from __future__ import annotations

from types import SimpleNamespace
from uuid import (
    UUID,
    uuid4,
)

import pytest

from gateway.app.audit.dependencies import (
    get_audit_service,
    get_trusted_request_id,
    record_security_event_best_effort,
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


class FakeAuditService:
    def __init__(
        self,
        *,
        error: Exception | None = None,
    ) -> None:
        self.error = error

        self.events: list[
            SecurityAuditEvent
        ] = []

    async def record(
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


def make_request(
    *,
    request_id: str | None = None,
    session_factory=None,
):
    state = SimpleNamespace(
        database_session_factory=(
            session_factory
        )
    )

    app = SimpleNamespace(
        state=state
    )

    request_state = SimpleNamespace()

    if request_id is not None:
        request_state.request_id = (
            request_id
        )

    return SimpleNamespace(
        app=app,
        state=request_state,
    )


def test_get_audit_service_returns_none_without_database() -> None:
    request = make_request()

    assert (
        get_audit_service(
            request
        )
        is None
    )


def test_get_audit_service_uses_postgresql_when_available() -> None:
    def session_factory():
        raise AssertionError(
            "Factory must not be opened while "
            "building the dependency."
        )

    request = make_request(
        session_factory=session_factory
    )

    service = get_audit_service(
        request
    )

    assert service is not None


def test_trusted_request_id_is_loaded_from_request_context() -> None:
    expected = uuid4()

    request = make_request(
        request_id=str(
            expected
        )
    )

    resolved = get_trusted_request_id(
        request
    )

    assert isinstance(
        resolved,
        UUID,
    )

    assert resolved == expected


def test_missing_trusted_request_id_is_rejected() -> None:
    request = make_request()

    with pytest.raises(
        RuntimeError,
        match=(
            "Trusted request ID is unavailable"
        ),
    ):
        get_trusted_request_id(
            request
        )


@pytest.mark.anyio
async def test_best_effort_uses_audit_service() -> None:
    service = FakeAuditService()

    event = make_event()

    await record_security_event_best_effort(
        service=service,
        event=event,
    )

    assert service.events == [
        event,
    ]


@pytest.mark.anyio
async def test_best_effort_logs_when_persistence_is_not_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    emitted: list[
        SecurityAuditEvent
    ] = []

    event = make_event()

    monkeypatch.setattr(
        "gateway.app.audit.dependencies."
        "emit_security_audit_event",
        emitted.append,
    )

    await record_security_event_best_effort(
        service=None,
        event=event,
    )

    assert emitted == [
        event,
    ]


@pytest.mark.anyio
async def test_best_effort_suppresses_persistence_failure_and_warns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    warnings: list[
        SecurityAuditEvent
    ] = []

    error = AuditRepositoryBackendError(
        "audit backend unavailable"
    )

    service = FakeAuditService(
        error=error
    )

    event = make_event()

    monkeypatch.setattr(
        "gateway.app.audit.dependencies."
        "emit_audit_persistence_failure",
        warnings.append,
    )

    await record_security_event_best_effort(
        service=service,
        event=event,
    )

    assert service.events == [
        event,
    ]

    assert warnings == [
        event,
    ]

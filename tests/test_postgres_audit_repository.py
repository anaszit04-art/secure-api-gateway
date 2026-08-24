from __future__ import annotations

from uuid import uuid4

import pytest

from sqlalchemy.exc import (
    SQLAlchemyError,
)

from gateway.app.audit.models import (
    AuditEventType,
    AuditOutcome,
    create_security_audit_event,
)
from gateway.app.audit.repository import (
    AuditRepositoryBackendError,
)
from gateway.app.database.audit_repository import (
    PostgreSQLAuditRepository,
    event_to_record,
)
from gateway.app.database.models import (
    AuditEventRecord,
)


class FakeSession:
    def __init__(
        self,
        *,
        add_error: Exception | None = None,
        commit_error: Exception | None = None,
    ) -> None:
        self.add_error = add_error
        self.commit_error = (
            commit_error
        )

        self.added: list[
            object
        ] = []

        self.committed = False
        self.rolled_back = False

    async def __aenter__(
        self,
    ) -> FakeSession:
        return self

    async def __aexit__(
        self,
        exc_type: object,
        exc: object,
        traceback: object,
    ) -> None:
        return None

    def add(
        self,
        value: object,
    ) -> None:
        if self.add_error is not None:
            raise self.add_error

        self.added.append(
            value
        )

    async def commit(
        self,
    ) -> None:
        if self.commit_error is not None:
            raise self.commit_error

        self.committed = True

    async def rollback(
        self,
    ) -> None:
        self.rolled_back = True


class FakeSessionFactory:
    def __init__(
        self,
        session: FakeSession,
    ) -> None:
        self.session = session
        self.calls = 0

    def __call__(
        self,
    ) -> FakeSession:
        self.calls += 1

        return self.session


def make_event():
    return create_security_audit_event(
        event_type=(
            AuditEventType.ROLE_ASSIGNED
        ),
        outcome=AuditOutcome.SUCCESS,
        request_id=uuid4(),
        actor_user_id=uuid4(),
        target_user_id=uuid4(),
        permission_code=(
            "authorization:roles:manage"
        ),
        role_name="operator",
        status_code=200,
        reason_code="role_changed",
    )


def test_event_to_record_maps_domain_event() -> None:
    event = make_event()

    record = event_to_record(
        event
    )

    assert isinstance(
        record,
        AuditEventRecord,
    )

    assert record.id == event.event_id

    assert (
        record.occurred_at
        == event.occurred_at
    )

    assert record.event_type == (
        "role_assigned"
    )

    assert record.outcome == (
        "success"
    )

    assert (
        record.request_id
        == event.request_id
    )

    assert (
        record.actor_user_id
        == event.actor_user_id
    )

    assert (
        record.target_user_id
        == event.target_user_id
    )

    assert (
        record.permission_code
        == event.permission_code
    )

    assert record.role_name == (
        "operator"
    )

    assert record.status_code == 200


@pytest.mark.anyio
async def test_append_event_commits_record() -> None:
    session = FakeSession()

    factory = FakeSessionFactory(
        session
    )

    repository = (
        PostgreSQLAuditRepository(
            factory
        )
    )

    event = make_event()

    await repository.append_event(
        event
    )

    assert factory.calls == 1

    assert len(
        session.added
    ) == 1

    record = session.added[0]

    assert isinstance(
        record,
        AuditEventRecord,
    )

    assert (
        record.id
        == event.event_id
    )

    assert session.committed is True
    assert session.rolled_back is False


@pytest.mark.anyio
async def test_append_event_rolls_back_commit_failure() -> None:
    error = SQLAlchemyError(
        "database unavailable"
    )

    session = FakeSession(
        commit_error=error
    )

    repository = (
        PostgreSQLAuditRepository(
            FakeSessionFactory(
                session
            )
        )
    )

    with pytest.raises(
        AuditRepositoryBackendError,
        match=(
            "Security audit persistence "
            "backend is unavailable"
        ),
    ) as captured:
        await repository.append_event(
            make_event()
        )

    assert session.rolled_back is True

    assert (
        captured.value.__cause__
        is error
    )


@pytest.mark.anyio
async def test_append_event_translates_add_failure() -> None:
    error = SQLAlchemyError(
        "database unavailable"
    )

    session = FakeSession(
        add_error=error
    )

    repository = (
        PostgreSQLAuditRepository(
            FakeSessionFactory(
                session
            )
        )
    )

    with pytest.raises(
        AuditRepositoryBackendError,
    ) as captured:
        await repository.append_event(
            make_event()
        )

    assert session.committed is False

    assert (
        captured.value.__cause__
        is error
    )

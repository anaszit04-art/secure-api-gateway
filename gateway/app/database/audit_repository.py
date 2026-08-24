from __future__ import annotations

from typing import Any

from sqlalchemy.exc import (
    SQLAlchemyError,
)

from gateway.app.audit.models import (
    SecurityAuditEvent,
)
from gateway.app.audit.repository import (
    AuditRepositoryBackendError,
)
from gateway.app.database.client import (
    DatabaseSessionFactory,
)
from gateway.app.database.models import (
    AuditEventRecord,
)


BACKEND_ERROR_MESSAGE = (
    "Security audit persistence backend "
    "is unavailable."
)


def event_to_record(
    event: SecurityAuditEvent,
) -> AuditEventRecord:
    """
    Convert a validated audit-domain event into its
    persistent SQLAlchemy representation.
    """

    return AuditEventRecord(
        id=event.event_id,
        occurred_at=event.occurred_at,
        event_type=event.event_type.value,
        outcome=event.outcome.value,
        request_id=event.request_id,
        actor_user_id=event.actor_user_id,
        target_user_id=event.target_user_id,
        permission_code=(
            event.permission_code
        ),
        role_name=event.role_name,
        service_name=event.service_name,
        method=event.method,
        status_code=event.status_code,
        reason_code=event.reason_code,
    )


async def rollback_quietly(
    session: Any,
) -> None:
    """
    Best-effort rollback without replacing the
    original persistence failure.
    """

    try:
        await session.rollback()

    except (
        SQLAlchemyError,
        OSError,
    ):
        return


def backend_error(
    exception: BaseException,
) -> AuditRepositoryBackendError:
    """
    Translate infrastructure failures into the
    stable audit repository error contract.
    """

    return AuditRepositoryBackendError(
        BACKEND_ERROR_MESSAGE
    )


class PostgreSQLAuditRepository:
    """
    Asynchronous append-only PostgreSQL audit
    repository.

    SQLAlchemy / asyncpg details remain hidden behind
    the audit persistence boundary.
    """

    def __init__(
        self,
        session_factory: (
            DatabaseSessionFactory
        ),
    ) -> None:
        self._session_factory = (
            session_factory
        )

    async def append_event(
        self,
        event: SecurityAuditEvent,
    ) -> None:
        record = event_to_record(
            event
        )

        try:
            async with (
                self._session_factory()
                as session
            ):
                session.add(
                    record
                )

                try:
                    await session.commit()

                except (
                    SQLAlchemyError,
                    OSError,
                ) as exc:
                    await rollback_quietly(
                        session
                    )

                    raise backend_error(
                        exc
                    ) from exc

        except AuditRepositoryBackendError:
            raise

        except (
            SQLAlchemyError,
            OSError,
        ) as exc:
            raise backend_error(
                exc
            ) from exc

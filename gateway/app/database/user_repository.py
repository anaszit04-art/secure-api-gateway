from __future__ import annotations

from datetime import (
    datetime,
    timezone,
)
from uuid import uuid4

from sqlalchemy import (
    func,
    select,
)
from sqlalchemy.exc import (
    IntegrityError,
)

from gateway.app.auth.models import (
    StoredUser,
    normalize_username,
)
from gateway.app.auth.repository import (
    UserAlreadyExistsError,
    UserNotFoundError,
)
from gateway.app.database.client import (
    DatabaseSessionFactory,
)
from gateway.app.database.models import (
    UserRecord,
)


UNIQUE_VIOLATION_SQLSTATE = "23505"


def record_to_stored_user(
    record: UserRecord,
) -> StoredUser:
    """
    Convert the persistence model into the
    authentication domain representation.
    """
    return StoredUser(
        id=record.id,
        username=record.username,
        hashed_password=(
            record.hashed_password
        ),
        is_active=record.is_active,
        created_at=record.created_at,
    )


def is_unique_violation(
    exception: IntegrityError,
) -> bool:
    """
    Detect a PostgreSQL unique-constraint violation
    without depending on a single asyncpg wrapper layer.
    """

    candidates = (
        exception.orig,
        getattr(
            exception.orig,
            "__cause__",
            None,
        ),
        getattr(
            exception.orig,
            "__context__",
            None,
        ),
    )

    for candidate in candidates:
        if candidate is None:
            continue

        sqlstate = (
            getattr(
                candidate,
                "sqlstate",
                None,
            )
            or getattr(
                candidate,
                "pgcode",
                None,
            )
        )

        if (
            sqlstate
            == UNIQUE_VIOLATION_SQLSTATE
        ):
            return True

    return False


class PostgreSQLUserRepository:
    """
    Asynchronous PostgreSQL-backed user repository.

    Each operation owns a short-lived AsyncSession while
    the shared SQLAlchemy engine/pool lives for the
    lifetime of the FastAPI process.
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

    async def create_user(
        self,
        *,
        username: str,
        hashed_password: str,
    ) -> StoredUser:
        normalized_username = (
            normalize_username(
                username
            )
        )

        if not hashed_password.strip():
            raise ValueError(
                "Hashed password cannot be empty."
            )

        now = datetime.now(
            timezone.utc
        )

        record = UserRecord(
            id=uuid4(),
            username=normalized_username,
            hashed_password=(
                hashed_password
            ),
            is_active=True,
            created_at=now,
            updated_at=now,
        )

        async with (
            self._session_factory()
            as session
        ):
            session.add(
                record
            )

            try:
                await session.commit()
            except IntegrityError as exc:
                await session.rollback()

                if is_unique_violation(
                    exc
                ):
                    raise (
                        UserAlreadyExistsError(
                            "Username is already "
                            "registered."
                        )
                    ) from exc

                raise

        return record_to_stored_user(
            record
        )

    async def get_by_username(
        self,
        username: str,
    ) -> StoredUser | None:
        normalized_username = (
            normalize_username(
                username
            )
        )

        statement = (
            select(
                UserRecord
            )
            .where(
                UserRecord.username
                == normalized_username
            )
        )

        async with (
            self._session_factory()
            as session
        ):
            result = await session.execute(
                statement
            )

            record = (
                result.scalar_one_or_none()
            )

        if record is None:
            return None

        return record_to_stored_user(
            record
        )

    async def update_password_hash(
        self,
        *,
        username: str,
        hashed_password: str,
    ) -> StoredUser:
        normalized_username = (
            normalize_username(
                username
            )
        )

        if not hashed_password.strip():
            raise ValueError(
                "Hashed password cannot be empty."
            )

        statement = (
            select(
                UserRecord
            )
            .where(
                UserRecord.username
                == normalized_username
            )
        )

        async with (
            self._session_factory()
            as session
        ):
            result = await session.execute(
                statement
            )

            record = (
                result.scalar_one_or_none()
            )

            if record is None:
                raise UserNotFoundError(
                    "User not found."
                )

            record.hashed_password = (
                hashed_password
            )

            await session.commit()

        return record_to_stored_user(
            record
        )

    async def count(
        self,
    ) -> int:
        statement = (
            select(
                func.count()
            )
            .select_from(
                UserRecord
            )
        )

        async with (
            self._session_factory()
            as session
        ):
            result = await session.execute(
                statement
            )

            return int(
                result.scalar_one()
            )

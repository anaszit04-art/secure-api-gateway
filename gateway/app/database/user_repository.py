from __future__ import annotations

from datetime import (
    datetime,
    timezone,
)
from typing import Any
from uuid import uuid4

from sqlalchemy import (
    func,
    select,
)
from sqlalchemy.exc import (
    IntegrityError,
    SQLAlchemyError,
)

from gateway.app.auth.models import (
    StoredUser,
    normalize_username,
)
from gateway.app.auth.repository import (
    UserAlreadyExistsError,
    UserNotFoundError,
    UserRepositoryBackendError,
)
from gateway.app.database.client import (
    DatabaseSessionFactory,
)
from gateway.app.database.models import (
    UserRecord,
)


UNIQUE_VIOLATION_SQLSTATE = "23505"

BACKEND_ERROR_MESSAGE = (
    "User persistence backend is unavailable."
)


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
    Detect a PostgreSQL unique violation through the
    SQLAlchemy / asyncpg exception chain.
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


async def rollback_quietly(
    session: Any,
) -> None:
    """
    Best-effort rollback.

    A broken database connection must not replace the
    original persistence exception with a rollback error.
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
) -> UserRepositoryBackendError:
    """
    Convert infrastructure failures into the stable
    authentication repository error contract.
    """

    return UserRepositoryBackendError(
        BACKEND_ERROR_MESSAGE
    )


class PostgreSQLUserRepository:
    """
    Asynchronous PostgreSQL-backed user repository.

    Database implementation exceptions never cross this
    persistence boundary.
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

                except IntegrityError as exc:
                    await rollback_quietly(
                        session
                    )

                    if is_unique_violation(
                        exc
                    ):
                        raise (
                            UserAlreadyExistsError(
                                "Username is already "
                                "registered."
                            )
                        ) from exc

                    raise backend_error(
                        exc
                    ) from exc

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

        except (
            UserAlreadyExistsError,
            UserRepositoryBackendError,
        ):
            raise

        except (
            SQLAlchemyError,
            OSError,
        ) as exc:
            raise backend_error(
                exc
            ) from exc

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

        try:
            async with (
                self._session_factory()
                as session
            ):
                result = (
                    await session.execute(
                        statement
                    )
                )

                record = (
                    result.scalar_one_or_none()
                )

        except (
            SQLAlchemyError,
            OSError,
        ) as exc:
            raise backend_error(
                exc
            ) from exc

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

        try:
            async with (
                self._session_factory()
                as session
            ):
                result = (
                    await session.execute(
                        statement
                    )
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

        except (
            UserNotFoundError,
            UserRepositoryBackendError,
        ):
            raise

        except (
            SQLAlchemyError,
            OSError,
        ) as exc:
            raise backend_error(
                exc
            ) from exc

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

        try:
            async with (
                self._session_factory()
                as session
            ):
                result = (
                    await session.execute(
                        statement
                    )
                )

                return int(
                    result.scalar_one()
                )

        except (
            SQLAlchemyError,
            OSError,
        ) as exc:
            raise backend_error(
                exc
            ) from exc

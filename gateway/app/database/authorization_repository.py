from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import (
    delete,
    exists,
    select,
)
from sqlalchemy.dialects.postgresql import (
    insert as postgresql_insert,
)
from sqlalchemy.exc import (
    SQLAlchemyError,
)

from gateway.app.authorization.models import (
    normalize_permission_code,
    normalize_role_name,
)
from gateway.app.authorization.repository import (
    AuthorizationRepositoryBackendError,
    RoleNotFoundError,
    UserAuthorizationNotFoundError,
)
from gateway.app.database.client import (
    DatabaseSessionFactory,
)
from gateway.app.database.models import (
    PermissionRecord,
    RolePermissionRecord,
    RoleRecord,
    UserRecord,
    UserRoleRecord,
)


BACKEND_ERROR_MESSAGE = (
    "Authorization persistence backend "
    "is unavailable."
)


async def rollback_quietly(
    session: Any,
) -> None:
    """
    Best-effort rollback without replacing the
    original persistence error.
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
) -> AuthorizationRepositoryBackendError:
    """
    Translate infrastructure failures into the stable
    authorization repository error contract.
    """

    return AuthorizationRepositoryBackendError(
        BACKEND_ERROR_MESSAGE
    )


class PostgreSQLAuthorizationRepository:
    """
    PostgreSQL-backed RBAC repository.

    All operations are asynchronous and SQLAlchemy /
    asyncpg implementation errors remain hidden behind
    the authorization persistence boundary.
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

    async def get_role_names_for_user(
        self,
        user_id: UUID,
    ) -> frozenset[str]:
        statement = (
            select(
                RoleRecord.name
            )
            .join(
                UserRoleRecord,
                UserRoleRecord.role_id
                == RoleRecord.id,
            )
            .where(
                UserRoleRecord.user_id
                == user_id
            )
            .order_by(
                RoleRecord.name
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

                return frozenset(
                    result.scalars().all()
                )

        except (
            SQLAlchemyError,
            OSError,
        ) as exc:
            raise backend_error(
                exc
            ) from exc

    async def get_permission_codes_for_user(
        self,
        user_id: UUID,
    ) -> frozenset[str]:
        statement = (
            select(
                PermissionRecord.code
            )
            .select_from(
                UserRoleRecord
            )
            .join(
                RolePermissionRecord,
                RolePermissionRecord.role_id
                == UserRoleRecord.role_id,
            )
            .join(
                PermissionRecord,
                PermissionRecord.id
                == (
                    RolePermissionRecord
                    .permission_id
                ),
            )
            .where(
                UserRoleRecord.user_id
                == user_id
            )
            .distinct()
            .order_by(
                PermissionRecord.code
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

                return frozenset(
                    result.scalars().all()
                )

        except (
            SQLAlchemyError,
            OSError,
        ) as exc:
            raise backend_error(
                exc
            ) from exc

    async def has_permission(
        self,
        *,
        user_id: UUID,
        permission_code: str,
    ) -> bool:
        normalized_permission = (
            normalize_permission_code(
                permission_code
            )
        )

        permission_exists = (
            exists()
            .where(
                UserRoleRecord.user_id
                == user_id
            )
            .where(
                RolePermissionRecord.role_id
                == UserRoleRecord.role_id
            )
            .where(
                PermissionRecord.id
                == (
                    RolePermissionRecord
                    .permission_id
                )
            )
            .where(
                PermissionRecord.code
                == normalized_permission
            )
        )

        statement = select(
            permission_exists
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

                return bool(
                    result.scalar_one()
                )

        except (
            SQLAlchemyError,
            OSError,
        ) as exc:
            raise backend_error(
                exc
            ) from exc

    async def _get_role_id(
        self,
        *,
        session: Any,
        role_name: str,
    ) -> UUID:
        normalized_role = (
            normalize_role_name(
                role_name
            )
        )

        result = await session.execute(
            select(
                RoleRecord.id
            ).where(
                RoleRecord.name
                == normalized_role
            )
        )

        role_id = (
            result.scalar_one_or_none()
        )

        if role_id is None:
            raise RoleNotFoundError(
                "Authorization role not found."
            )

        return role_id

    async def _require_user(
        self,
        *,
        session: Any,
        user_id: UUID,
    ) -> None:
        result = await session.execute(
            select(
                UserRecord.id
            ).where(
                UserRecord.id
                == user_id
            )
        )

        existing_user_id = (
            result.scalar_one_or_none()
        )

        if existing_user_id is None:
            raise (
                UserAuthorizationNotFoundError(
                    "User not found."
                )
            )

    async def assign_role(
        self,
        *,
        user_id: UUID,
        role_name: str,
    ) -> bool:
        try:
            async with (
                self._session_factory()
                as session
            ):
                role_id = (
                    await self._get_role_id(
                        session=session,
                        role_name=role_name,
                    )
                )

                await self._require_user(
                    session=session,
                    user_id=user_id,
                )

                statement = (
                    postgresql_insert(
                        UserRoleRecord
                    )
                    .values(
                        user_id=user_id,
                        role_id=role_id,
                    )
                    .on_conflict_do_nothing(
                        index_elements=[
                            "user_id",
                            "role_id",
                        ]
                    )
                )

                result = (
                    await session.execute(
                        statement
                    )
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

                return bool(
                    result.rowcount
                )

        except (
            RoleNotFoundError,
            UserAuthorizationNotFoundError,
            AuthorizationRepositoryBackendError,
        ):
            raise

        except (
            SQLAlchemyError,
            OSError,
        ) as exc:
            raise backend_error(
                exc
            ) from exc

    async def remove_role(
        self,
        *,
        user_id: UUID,
        role_name: str,
    ) -> bool:
        try:
            async with (
                self._session_factory()
                as session
            ):
                role_id = (
                    await self._get_role_id(
                        session=session,
                        role_name=role_name,
                    )
                )

                await self._require_user(
                    session=session,
                    user_id=user_id,
                )

                statement = (
                    delete(
                        UserRoleRecord
                    )
                    .where(
                        UserRoleRecord.user_id
                        == user_id
                    )
                    .where(
                        UserRoleRecord.role_id
                        == role_id
                    )
                )

                result = (
                    await session.execute(
                        statement
                    )
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

                return bool(
                    result.rowcount
                )

        except (
            RoleNotFoundError,
            UserAuthorizationNotFoundError,
            AuthorizationRepositoryBackendError,
        ):
            raise

        except (
            SQLAlchemyError,
            OSError,
        ) as exc:
            raise backend_error(
                exc
            ) from exc

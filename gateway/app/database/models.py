from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    SmallInteger,
    String,
    Text,
    Uuid,
    func,
    true,
)
from sqlalchemy.orm import (
    Mapped,
    mapped_column,
)

from gateway.app.audit.models import (
    MAXIMUM_AUDIT_CODE_LENGTH,
    MAXIMUM_AUDIT_EVENT_TYPE_LENGTH,
    MAXIMUM_AUDIT_METHOD_LENGTH,
    MAXIMUM_AUDIT_OUTCOME_LENGTH,
)
from gateway.app.auth.models import (
    MAXIMUM_USERNAME_LENGTH,
)
from gateway.app.authorization.models import (
    MAXIMUM_PERMISSION_CODE_LENGTH,
    MAXIMUM_ROLE_NAME_LENGTH,
)
from gateway.app.database.base import Base


class UserRecord(Base):
    """
    Persistent PostgreSQL representation of a user.

    Password hashes are stored internally and this model
    must never be returned directly by an API endpoint.
    """

    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(
        Uuid(
            as_uuid=True,
        ),
        primary_key=True,
        default=uuid4,
    )

    username: Mapped[str] = mapped_column(
        String(
            MAXIMUM_USERNAME_LENGTH
        ),
        nullable=False,
        unique=True,
    )

    hashed_password: Mapped[str] = (
        mapped_column(
            Text,
            nullable=False,
        )
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=true(),
    )

    created_at: Mapped[datetime] = (
        mapped_column(
            DateTime(
                timezone=True,
            ),
            nullable=False,
            server_default=func.now(),
        )
    )

    updated_at: Mapped[datetime] = (
        mapped_column(
            DateTime(
                timezone=True,
            ),
            nullable=False,
            server_default=func.now(),
            onupdate=func.now(),
        )
    )


class RoleRecord(Base):
    """
    Persistent authorization role.

    System roles are created and maintained by
    migrations and cannot be treated as arbitrary
    user-controlled strings.
    """

    __tablename__ = "roles"

    id: Mapped[UUID] = mapped_column(
        Uuid(
            as_uuid=True,
        ),
        primary_key=True,
        default=uuid4,
    )

    name: Mapped[str] = mapped_column(
        String(
            MAXIMUM_ROLE_NAME_LENGTH
        ),
        nullable=False,
        unique=True,
    )

    description: Mapped[str] = (
        mapped_column(
            Text,
            nullable=False,
        )
    )

    is_system: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=true(),
    )

    created_at: Mapped[datetime] = (
        mapped_column(
            DateTime(
                timezone=True,
            ),
            nullable=False,
            server_default=func.now(),
        )
    )


class PermissionRecord(Base):
    """
    Persistent fine-grained permission.

    Permission codes are stable identifiers such as:

        proxy:service-a:read
    """

    __tablename__ = "permissions"

    id: Mapped[UUID] = mapped_column(
        Uuid(
            as_uuid=True,
        ),
        primary_key=True,
        default=uuid4,
    )

    code: Mapped[str] = mapped_column(
        String(
            MAXIMUM_PERMISSION_CODE_LENGTH
        ),
        nullable=False,
        unique=True,
    )

    description: Mapped[str] = (
        mapped_column(
            Text,
            nullable=False,
        )
    )

    created_at: Mapped[datetime] = (
        mapped_column(
            DateTime(
                timezone=True,
            ),
            nullable=False,
            server_default=func.now(),
        )
    )


class UserRoleRecord(Base):
    """
    Many-to-many assignment between users and roles.
    """

    __tablename__ = "user_roles"

    user_id: Mapped[UUID] = mapped_column(
        Uuid(
            as_uuid=True,
        ),
        ForeignKey(
            "users.id",
            ondelete="CASCADE",
        ),
        primary_key=True,
    )

    role_id: Mapped[UUID] = mapped_column(
        Uuid(
            as_uuid=True,
        ),
        ForeignKey(
            "roles.id",
            ondelete="CASCADE",
        ),
        primary_key=True,
    )

    assigned_at: Mapped[datetime] = (
        mapped_column(
            DateTime(
                timezone=True,
            ),
            nullable=False,
            server_default=func.now(),
        )
    )


class RolePermissionRecord(Base):
    """
    Many-to-many assignment between roles and
    permissions.
    """

    __tablename__ = "role_permissions"

    role_id: Mapped[UUID] = mapped_column(
        Uuid(
            as_uuid=True,
        ),
        ForeignKey(
            "roles.id",
            ondelete="CASCADE",
        ),
        primary_key=True,
    )

    permission_id: Mapped[UUID] = (
        mapped_column(
            Uuid(
                as_uuid=True,
            ),
            ForeignKey(
                "permissions.id",
                ondelete="CASCADE",
            ),
            primary_key=True,
        )
    )


class AuditEventRecord(Base):
    """
    Append-oriented persistent security audit event.

    actor_user_id and target_user_id intentionally
    remain UUID values without foreign keys so that
    audit history survives future account deletion.
    """

    __tablename__ = "audit_events"

    __table_args__ = (
        CheckConstraint(
            (
                "status_code IS NULL OR "
                "(status_code >= 100 "
                "AND status_code <= 599)"
            ),
            name=(
                "ck_audit_events_"
                "status_code_range"
            ),
        ),
    )

    id: Mapped[UUID] = mapped_column(
        Uuid(
            as_uuid=True,
        ),
        primary_key=True,
        default=uuid4,
    )

    occurred_at: Mapped[datetime] = (
        mapped_column(
            DateTime(
                timezone=True,
            ),
            nullable=False,
            index=True,
        )
    )

    event_type: Mapped[str] = (
        mapped_column(
            String(
                MAXIMUM_AUDIT_EVENT_TYPE_LENGTH
            ),
            nullable=False,
            index=True,
        )
    )

    outcome: Mapped[str] = mapped_column(
        String(
            MAXIMUM_AUDIT_OUTCOME_LENGTH
        ),
        nullable=False,
    )

    request_id: Mapped[UUID] = (
        mapped_column(
            Uuid(
                as_uuid=True,
            ),
            nullable=False,
            index=True,
        )
    )

    actor_user_id: Mapped[
        UUID | None
    ] = mapped_column(
        Uuid(
            as_uuid=True,
        ),
        nullable=True,
        index=True,
    )

    target_user_id: Mapped[
        UUID | None
    ] = mapped_column(
        Uuid(
            as_uuid=True,
        ),
        nullable=True,
        index=True,
    )

    permission_code: Mapped[
        str | None
    ] = mapped_column(
        String(
            MAXIMUM_AUDIT_CODE_LENGTH
        ),
        nullable=True,
    )

    role_name: Mapped[
        str | None
    ] = mapped_column(
        String(
            MAXIMUM_AUDIT_CODE_LENGTH
        ),
        nullable=True,
    )

    service_name: Mapped[
        str | None
    ] = mapped_column(
        String(
            MAXIMUM_AUDIT_CODE_LENGTH
        ),
        nullable=True,
    )

    method: Mapped[
        str | None
    ] = mapped_column(
        String(
            MAXIMUM_AUDIT_METHOD_LENGTH
        ),
        nullable=True,
    )

    status_code: Mapped[
        int | None
    ] = mapped_column(
        SmallInteger,
        nullable=True,
    )

    reason_code: Mapped[
        str | None
    ] = mapped_column(
        String(
            MAXIMUM_AUDIT_CODE_LENGTH
        ),
        nullable=True,
    )

    created_at: Mapped[datetime] = (
        mapped_column(
            DateTime(
                timezone=True,
            ),
            nullable=False,
            server_default=func.now(),
        )
    )

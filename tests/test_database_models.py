from __future__ import annotations

from sqlalchemy import (
    Boolean,
    DateTime,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.dialects import (
    postgresql,
)
from sqlalchemy.schema import (
    CreateTable,
)

from gateway.app.auth.models import (
    MAXIMUM_USERNAME_LENGTH,
)
from gateway.app.database.base import (
    Base,
)
from gateway.app.database.models import (
    UserRecord,
)


EXPECTED_COLUMNS = [
    "id",
    "username",
    "hashed_password",
    "is_active",
    "created_at",
    "updated_at",
]


def test_user_record_is_registered_in_metadata() -> None:
    assert (
        UserRecord.__tablename__
        == "users"
    )

    assert (
        Base.metadata.tables["users"]
        is UserRecord.__table__
    )


def test_user_record_has_expected_columns() -> None:
    assert [
        column.name
        for column
        in UserRecord.__table__.columns
    ] == EXPECTED_COLUMNS


def test_user_id_is_native_uuid_primary_key() -> None:
    column = (
        UserRecord.__table__.c.id
    )

    assert isinstance(
        column.type,
        Uuid,
    )

    assert (
        column.type.as_uuid
        is True
    )

    assert (
        column.primary_key
        is True
    )

    assert (
        column.nullable
        is False
    )

    assert (
        column.default
        is not None
    )


def test_username_has_expected_policy_length() -> None:
    column = (
        UserRecord.__table__.c.username
    )

    assert isinstance(
        column.type,
        String,
    )

    assert (
        column.type.length
        == MAXIMUM_USERNAME_LENGTH
    )

    assert (
        column.nullable
        is False
    )


def test_username_has_unique_constraint() -> None:
    constraints = [
        constraint
        for constraint
        in UserRecord.__table__.constraints
        if isinstance(
            constraint,
            UniqueConstraint,
        )
    ]

    assert len(
        constraints
    ) == 1

    constraint = constraints[0]

    assert (
        constraint.name
        == "uq_users_username"
    )

    assert [
        column.name
        for column
        in constraint.columns
    ] == [
        "username",
    ]


def test_password_hash_is_required_text() -> None:
    column = (
        UserRecord.__table__
        .c.hashed_password
    )

    assert isinstance(
        column.type,
        Text,
    )

    assert (
        column.nullable
        is False
    )

    assert (
        column.default
        is None
    )

    assert (
        column.server_default
        is None
    )


def test_is_active_has_secure_default() -> None:
    column = (
        UserRecord.__table__.c.is_active
    )

    assert isinstance(
        column.type,
        Boolean,
    )

    assert (
        column.nullable
        is False
    )

    assert (
        column.default
        is not None
    )

    assert (
        column.server_default
        is not None
    )


def test_user_timestamps_are_timezone_aware() -> None:
    created_at = (
        UserRecord.__table__.c.created_at
    )

    updated_at = (
        UserRecord.__table__.c.updated_at
    )

    for column in (
        created_at,
        updated_at,
    ):
        assert isinstance(
            column.type,
            DateTime,
        )

        assert (
            column.type.timezone
            is True
        )

        assert (
            column.nullable
            is False
        )

        assert (
            column.server_default
            is not None
        )

    assert (
        updated_at.onupdate
        is not None
    )


def test_primary_key_uses_naming_convention() -> None:
    primary_key = (
        UserRecord.__table__
        .primary_key
    )

    assert (
        primary_key.name
        == "pk_users"
    )


def test_user_table_compiles_for_postgresql() -> None:
    ddl = str(
        CreateTable(
            UserRecord.__table__
        ).compile(
            dialect=(
                postgresql.dialect()
            )
        )
    )

    normalized = " ".join(
        ddl.split()
    )

    assert (
        "CREATE TABLE users"
        in normalized
    )

    assert (
        "id UUID NOT NULL"
        in normalized
    )

    assert (
        "username VARCHAR(64) "
        "NOT NULL"
        in normalized
    )

    assert (
        "hashed_password TEXT "
        "NOT NULL"
        in normalized
    )

    assert (
        "created_at "
        "TIMESTAMP WITH TIME ZONE "
        "DEFAULT now() NOT NULL"
        in normalized
    )

    assert (
        "updated_at "
        "TIMESTAMP WITH TIME ZONE "
        "DEFAULT now() NOT NULL"
        in normalized
    )

    assert (
        "CONSTRAINT pk_users "
        "PRIMARY KEY (id)"
        in normalized
    )

    assert (
        "CONSTRAINT "
        "uq_users_username "
        "UNIQUE (username)"
        in normalized
    )

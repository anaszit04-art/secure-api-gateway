from sqlalchemy import (
    CheckConstraint,
    DateTime,
    SmallInteger,
    String,
    Uuid,
)
from sqlalchemy.dialects import (
    postgresql,
)
from sqlalchemy.schema import (
    CreateTable,
)

from gateway.app.audit.models import (
    MAXIMUM_AUDIT_CODE_LENGTH,
    MAXIMUM_AUDIT_EVENT_TYPE_LENGTH,
    MAXIMUM_AUDIT_METHOD_LENGTH,
    MAXIMUM_AUDIT_OUTCOME_LENGTH,
)
from gateway.app.database.base import (
    Base,
)
from gateway.app.database.models import (
    AuditEventRecord,
)


EXPECTED_COLUMNS = [
    "id",
    "occurred_at",
    "event_type",
    "outcome",
    "request_id",
    "actor_user_id",
    "target_user_id",
    "permission_code",
    "role_name",
    "service_name",
    "method",
    "status_code",
    "reason_code",
    "created_at",
]


def test_audit_event_table_is_registered() -> None:
    assert (
        AuditEventRecord.__tablename__
        == "audit_events"
    )

    assert (
        Base.metadata.tables[
            "audit_events"
        ]
        is AuditEventRecord.__table__
    )


def test_audit_event_has_expected_columns() -> None:
    assert [
        column.name
        for column
        in AuditEventRecord
        .__table__
        .columns
    ] == EXPECTED_COLUMNS


def test_audit_identifiers_use_native_uuid() -> None:
    for column_name in (
        "id",
        "request_id",
        "actor_user_id",
        "target_user_id",
    ):
        column = (
            AuditEventRecord
            .__table__
            .c[column_name]
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
        AuditEventRecord
        .__table__
        .c.id
        .primary_key
        is True
    )


def test_audit_required_columns_are_not_nullable() -> None:
    for column_name in (
        "id",
        "occurred_at",
        "event_type",
        "outcome",
        "request_id",
        "created_at",
    ):
        assert (
            AuditEventRecord
            .__table__
            .c[column_name]
            .nullable
            is False
        )


def test_audit_timestamps_are_timezone_aware() -> None:
    occurred_at = (
        AuditEventRecord
        .__table__
        .c.occurred_at
    )

    created_at = (
        AuditEventRecord
        .__table__
        .c.created_at
    )

    for column in (
        occurred_at,
        created_at,
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
        occurred_at.server_default
        is None
    )

    assert (
        created_at.server_default
        is not None
    )


def test_audit_string_lengths_match_domain_contract() -> None:
    expected_lengths = {
        "event_type": (
            MAXIMUM_AUDIT_EVENT_TYPE_LENGTH
        ),
        "outcome": (
            MAXIMUM_AUDIT_OUTCOME_LENGTH
        ),
        "permission_code": (
            MAXIMUM_AUDIT_CODE_LENGTH
        ),
        "role_name": (
            MAXIMUM_AUDIT_CODE_LENGTH
        ),
        "service_name": (
            MAXIMUM_AUDIT_CODE_LENGTH
        ),
        "method": (
            MAXIMUM_AUDIT_METHOD_LENGTH
        ),
        "reason_code": (
            MAXIMUM_AUDIT_CODE_LENGTH
        ),
    }

    for (
        column_name,
        expected_length,
    ) in expected_lengths.items():
        column = (
            AuditEventRecord
            .__table__
            .c[column_name]
        )

        assert isinstance(
            column.type,
            String,
        )

        assert (
            column.type.length
            == expected_length
        )


def test_audit_status_code_is_small_integer() -> None:
    column = (
        AuditEventRecord
        .__table__
        .c.status_code
    )

    assert isinstance(
        column.type,
        SmallInteger,
    )

    assert (
        column.nullable
        is True
    )


def test_audit_status_code_has_database_constraint() -> None:
    names = {
        constraint.name
        for constraint
        in AuditEventRecord
        .__table__
        .constraints
        if isinstance(
            constraint,
            CheckConstraint,
        )
    }

    assert (
        "ck_audit_events_status_code_range"
        in names
    )


def test_audit_actor_and_target_have_no_foreign_keys() -> None:
    assert not (
        AuditEventRecord
        .__table__
        .c.actor_user_id
        .foreign_keys
    )

    assert not (
        AuditEventRecord
        .__table__
        .c.target_user_id
        .foreign_keys
    )


def test_audit_has_expected_query_indexes() -> None:
    names = {
        index.name
        for index
        in AuditEventRecord
        .__table__
        .indexes
    }

    assert names == {
        "ix_audit_events_occurred_at",
        "ix_audit_events_event_type",
        "ix_audit_events_request_id",
        "ix_audit_events_actor_user_id",
        "ix_audit_events_target_user_id",
    }


def test_audit_table_compiles_for_postgresql() -> None:
    ddl = str(
        CreateTable(
            AuditEventRecord.__table__
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
        "CREATE TABLE audit_events"
        in normalized
    )

    assert (
        "occurred_at "
        "TIMESTAMP WITH TIME ZONE "
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
        "CONSTRAINT pk_audit_events "
        "PRIMARY KEY (id)"
        in normalized
    )

    assert (
        "ck_audit_events_status_code_range"
        in normalized
    )

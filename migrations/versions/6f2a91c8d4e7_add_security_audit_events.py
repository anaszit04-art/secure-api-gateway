"""add security audit events

Revision ID: 6f2a91c8d4e7
Revises: b04e170d1c97
Create Date: Phase 6
"""

from typing import (
    Sequence,
    Union,
)

from alembic import op
import sqlalchemy as sa


revision: str = "6f2a91c8d4e7"

down_revision: Union[
    str,
    Sequence[str],
    None,
] = "b04e170d1c97"

branch_labels: Union[
    str,
    Sequence[str],
    None,
] = None

depends_on: Union[
    str,
    Sequence[str],
    None,
] = None


def upgrade() -> None:
    op.create_table(
        "audit_events",
        sa.Column(
            "id",
            sa.Uuid(),
            nullable=False,
        ),
        sa.Column(
            "occurred_at",
            sa.DateTime(
                timezone=True,
            ),
            nullable=False,
        ),
        sa.Column(
            "event_type",
            sa.String(
                length=64,
            ),
            nullable=False,
        ),
        sa.Column(
            "outcome",
            sa.String(
                length=32,
            ),
            nullable=False,
        ),
        sa.Column(
            "request_id",
            sa.Uuid(),
            nullable=False,
        ),
        sa.Column(
            "actor_user_id",
            sa.Uuid(),
            nullable=True,
        ),
        sa.Column(
            "target_user_id",
            sa.Uuid(),
            nullable=True,
        ),
        sa.Column(
            "permission_code",
            sa.String(
                length=160,
            ),
            nullable=True,
        ),
        sa.Column(
            "role_name",
            sa.String(
                length=160,
            ),
            nullable=True,
        ),
        sa.Column(
            "service_name",
            sa.String(
                length=160,
            ),
            nullable=True,
        ),
        sa.Column(
            "method",
            sa.String(
                length=16,
            ),
            nullable=True,
        ),
        sa.Column(
            "status_code",
            sa.SmallInteger(),
            nullable=True,
        ),
        sa.Column(
            "reason_code",
            sa.String(
                length=160,
            ),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(
                timezone=True,
            ),
            server_default=sa.text(
                "now()"
            ),
            nullable=False,
        ),
        sa.CheckConstraint(
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
        sa.PrimaryKeyConstraint(
            "id",
            name="pk_audit_events",
        ),
    )

    op.create_index(
        "ix_audit_events_occurred_at",
        "audit_events",
        [
            "occurred_at",
        ],
        unique=False,
    )

    op.create_index(
        "ix_audit_events_event_type",
        "audit_events",
        [
            "event_type",
        ],
        unique=False,
    )

    op.create_index(
        "ix_audit_events_request_id",
        "audit_events",
        [
            "request_id",
        ],
        unique=False,
    )

    op.create_index(
        "ix_audit_events_actor_user_id",
        "audit_events",
        [
            "actor_user_id",
        ],
        unique=False,
    )

    op.create_index(
        "ix_audit_events_target_user_id",
        "audit_events",
        [
            "target_user_id",
        ],
        unique=False,
    )


def downgrade() -> None:
    op.drop_table(
        "audit_events"
    )

"""create users table

Revision ID: 1cc279e452ed
Revises:
Create Date: generated during Phase 4
"""

from typing import (
    Sequence,
    Union,
)

from alembic import op
import sqlalchemy as sa


revision: str = "1cc279e452ed"

down_revision: Union[
    str,
    Sequence[str],
    None,
] = None

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
        "users",
        sa.Column(
            "id",
            sa.Uuid(),
            nullable=False,
        ),
        sa.Column(
            "username",
            sa.String(
                length=64,
            ),
            nullable=False,
        ),
        sa.Column(
            "hashed_password",
            sa.Text(),
            nullable=False,
        ),
        sa.Column(
            "is_active",
            sa.Boolean(),
            server_default=sa.text(
                "true"
            ),
            nullable=False,
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
        sa.Column(
            "updated_at",
            sa.DateTime(
                timezone=True,
            ),
            server_default=sa.text(
                "now()"
            ),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint(
            "id",
            name="pk_users",
        ),
        sa.UniqueConstraint(
            "username",
            name="uq_users_username",
        ),
    )


def downgrade() -> None:
    op.drop_table(
        "users"
    )

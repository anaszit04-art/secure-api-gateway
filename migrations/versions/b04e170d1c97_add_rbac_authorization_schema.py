"""add rbac authorization schema

Revision ID: b04e170d1c97
Revises: 1cc279e452ed
Create Date: Phase 5
"""

from typing import (
    Sequence,
    Union,
)
from uuid import UUID

from alembic import op
import sqlalchemy as sa


revision: str = "b04e170d1c97"

down_revision: Union[
    str,
    Sequence[str],
    None,
] = "1cc279e452ed"

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


USER_ROLE_ID = UUID(
    "10000000-0000-0000-0000-000000000001"
)

OPERATOR_ROLE_ID = UUID(
    "10000000-0000-0000-0000-000000000002"
)

ADMIN_ROLE_ID = UUID(
    "10000000-0000-0000-0000-000000000003"
)


SERVICE_A_READ_ID = UUID(
    "20000000-0000-0000-0000-000000000001"
)

SERVICE_A_WRITE_ID = UUID(
    "20000000-0000-0000-0000-000000000002"
)

SERVICE_B_READ_ID = UUID(
    "20000000-0000-0000-0000-000000000003"
)

SERVICE_B_WRITE_ID = UUID(
    "20000000-0000-0000-0000-000000000004"
)

ROLES_READ_ID = UUID(
    "20000000-0000-0000-0000-000000000005"
)

ROLES_MANAGE_ID = UUID(
    "20000000-0000-0000-0000-000000000006"
)


def upgrade() -> None:
    op.create_table(
        "roles",
        sa.Column(
            "id",
            sa.Uuid(),
            nullable=False,
        ),
        sa.Column(
            "name",
            sa.String(
                length=64,
            ),
            nullable=False,
        ),
        sa.Column(
            "description",
            sa.Text(),
            nullable=False,
        ),
        sa.Column(
            "is_system",
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
        sa.PrimaryKeyConstraint(
            "id",
            name="pk_roles",
        ),
        sa.UniqueConstraint(
            "name",
            name="uq_roles_name",
        ),
    )

    op.create_table(
        "permissions",
        sa.Column(
            "id",
            sa.Uuid(),
            nullable=False,
        ),
        sa.Column(
            "code",
            sa.String(
                length=128,
            ),
            nullable=False,
        ),
        sa.Column(
            "description",
            sa.Text(),
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
        sa.PrimaryKeyConstraint(
            "id",
            name="pk_permissions",
        ),
        sa.UniqueConstraint(
            "code",
            name="uq_permissions_code",
        ),
    )

    op.create_table(
        "user_roles",
        sa.Column(
            "user_id",
            sa.Uuid(),
            nullable=False,
        ),
        sa.Column(
            "role_id",
            sa.Uuid(),
            nullable=False,
        ),
        sa.Column(
            "assigned_at",
            sa.DateTime(
                timezone=True,
            ),
            server_default=sa.text(
                "now()"
            ),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=(
                "fk_user_roles_user_id_users"
            ),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["roles.id"],
            name=(
                "fk_user_roles_role_id_roles"
            ),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "user_id",
            "role_id",
            name="pk_user_roles",
        ),
    )

    op.create_table(
        "role_permissions",
        sa.Column(
            "role_id",
            sa.Uuid(),
            nullable=False,
        ),
        sa.Column(
            "permission_id",
            sa.Uuid(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["roles.id"],
            name=(
                "fk_role_permissions_role_id_roles"
            ),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["permission_id"],
            ["permissions.id"],
            name=(
                "fk_role_permissions_"
                "permission_id_permissions"
            ),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "role_id",
            "permission_id",
            name="pk_role_permissions",
        ),
    )

    roles_table = sa.table(
        "roles",
        sa.column(
            "id",
            sa.Uuid(),
        ),
        sa.column(
            "name",
            sa.String(),
        ),
        sa.column(
            "description",
            sa.Text(),
        ),
        sa.column(
            "is_system",
            sa.Boolean(),
        ),
    )

    permissions_table = sa.table(
        "permissions",
        sa.column(
            "id",
            sa.Uuid(),
        ),
        sa.column(
            "code",
            sa.String(),
        ),
        sa.column(
            "description",
            sa.Text(),
        ),
    )

    role_permissions_table = sa.table(
        "role_permissions",
        sa.column(
            "role_id",
            sa.Uuid(),
        ),
        sa.column(
            "permission_id",
            sa.Uuid(),
        ),
    )

    op.bulk_insert(
        roles_table,
        [
            {
                "id": USER_ROLE_ID,
                "name": "user",
                "description": (
                    "Default application user."
                ),
                "is_system": True,
            },
            {
                "id": OPERATOR_ROLE_ID,
                "name": "operator",
                "description": (
                    "Operator allowed to perform "
                    "proxy read and write actions."
                ),
                "is_system": True,
            },
            {
                "id": ADMIN_ROLE_ID,
                "name": "admin",
                "description": (
                    "Administrator with full system "
                    "authorization permissions."
                ),
                "is_system": True,
            },
        ],
    )

    op.bulk_insert(
        permissions_table,
        [
            {
                "id": SERVICE_A_READ_ID,
                "code": (
                    "proxy:service-a:read"
                ),
                "description": (
                    "Read access to Service A."
                ),
            },
            {
                "id": SERVICE_A_WRITE_ID,
                "code": (
                    "proxy:service-a:write"
                ),
                "description": (
                    "Write access to Service A."
                ),
            },
            {
                "id": SERVICE_B_READ_ID,
                "code": (
                    "proxy:service-b:read"
                ),
                "description": (
                    "Read access to Service B."
                ),
            },
            {
                "id": SERVICE_B_WRITE_ID,
                "code": (
                    "proxy:service-b:write"
                ),
                "description": (
                    "Write access to Service B."
                ),
            },
            {
                "id": ROLES_READ_ID,
                "code": (
                    "authorization:roles:read"
                ),
                "description": (
                    "Read authorization roles."
                ),
            },
            {
                "id": ROLES_MANAGE_ID,
                "code": (
                    "authorization:roles:manage"
                ),
                "description": (
                    "Manage authorization roles."
                ),
            },
        ],
    )

    op.bulk_insert(
        role_permissions_table,
        [
            # user
            {
                "role_id": USER_ROLE_ID,
                "permission_id": (
                    SERVICE_A_READ_ID
                ),
            },
            {
                "role_id": USER_ROLE_ID,
                "permission_id": (
                    SERVICE_B_READ_ID
                ),
            },

            # operator
            {
                "role_id": OPERATOR_ROLE_ID,
                "permission_id": (
                    SERVICE_A_READ_ID
                ),
            },
            {
                "role_id": OPERATOR_ROLE_ID,
                "permission_id": (
                    SERVICE_A_WRITE_ID
                ),
            },
            {
                "role_id": OPERATOR_ROLE_ID,
                "permission_id": (
                    SERVICE_B_READ_ID
                ),
            },
            {
                "role_id": OPERATOR_ROLE_ID,
                "permission_id": (
                    SERVICE_B_WRITE_ID
                ),
            },

            # admin
            {
                "role_id": ADMIN_ROLE_ID,
                "permission_id": (
                    SERVICE_A_READ_ID
                ),
            },
            {
                "role_id": ADMIN_ROLE_ID,
                "permission_id": (
                    SERVICE_A_WRITE_ID
                ),
            },
            {
                "role_id": ADMIN_ROLE_ID,
                "permission_id": (
                    SERVICE_B_READ_ID
                ),
            },
            {
                "role_id": ADMIN_ROLE_ID,
                "permission_id": (
                    SERVICE_B_WRITE_ID
                ),
            },
            {
                "role_id": ADMIN_ROLE_ID,
                "permission_id": (
                    ROLES_READ_ID
                ),
            },
            {
                "role_id": ADMIN_ROLE_ID,
                "permission_id": (
                    ROLES_MANAGE_ID
                ),
            },
        ],
    )

    # Backfill every user that existed before RBAC.
    op.execute(
        sa.text(
            """
            INSERT INTO user_roles (
                user_id,
                role_id
            )
            SELECT
                id,
                CAST(:role_id AS uuid)
            FROM users
            ON CONFLICT DO NOTHING
            """
        ).bindparams(
            role_id=str(
                USER_ROLE_ID
            )
        )
    )


def downgrade() -> None:
    op.drop_table(
        "role_permissions"
    )

    op.drop_table(
        "user_roles"
    )

    op.drop_table(
        "permissions"
    )

    op.drop_table(
        "roles"
    )

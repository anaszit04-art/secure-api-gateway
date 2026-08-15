from gateway.app.database.models import (
    PermissionRecord,
    RolePermissionRecord,
    RoleRecord,
    UserRoleRecord,
)


def test_role_table_name() -> None:
    assert (
        RoleRecord.__tablename__
        == "roles"
    )


def test_permission_table_name() -> None:
    assert (
        PermissionRecord.__tablename__
        == "permissions"
    )


def test_user_role_table_name() -> None:
    assert (
        UserRoleRecord.__tablename__
        == "user_roles"
    )


def test_role_permission_table_name() -> None:
    assert (
        RolePermissionRecord.__tablename__
        == "role_permissions"
    )


def test_role_name_is_unique() -> None:
    column = (
        RoleRecord.__table__.c.name
    )

    assert column.nullable is False
    assert column.unique is True


def test_permission_code_is_unique() -> None:
    column = (
        PermissionRecord.__table__.c.code
    )

    assert column.nullable is False
    assert column.unique is True


def test_user_roles_has_composite_primary_key() -> None:
    primary_key_columns = {
        column.name
        for column
        in UserRoleRecord
        .__table__
        .primary_key
        .columns
    }

    assert primary_key_columns == {
        "user_id",
        "role_id",
    }


def test_role_permissions_has_composite_primary_key() -> None:
    primary_key_columns = {
        column.name
        for column
        in RolePermissionRecord
        .__table__
        .primary_key
        .columns
    }

    assert primary_key_columns == {
        "role_id",
        "permission_id",
    }


def test_user_role_user_fk_cascades() -> None:
    foreign_key = next(
        iter(
            UserRoleRecord
            .__table__
            .c.user_id
            .foreign_keys
        )
    )

    assert (
        foreign_key.target_fullname
        == "users.id"
    )

    assert (
        foreign_key.ondelete
        == "CASCADE"
    )


def test_user_role_role_fk_cascades() -> None:
    foreign_key = next(
        iter(
            UserRoleRecord
            .__table__
            .c.role_id
            .foreign_keys
        )
    )

    assert (
        foreign_key.target_fullname
        == "roles.id"
    )

    assert (
        foreign_key.ondelete
        == "CASCADE"
    )


def test_role_permission_role_fk_cascades() -> None:
    foreign_key = next(
        iter(
            RolePermissionRecord
            .__table__
            .c.role_id
            .foreign_keys
        )
    )

    assert (
        foreign_key.target_fullname
        == "roles.id"
    )

    assert (
        foreign_key.ondelete
        == "CASCADE"
    )


def test_role_permission_permission_fk_cascades() -> None:
    foreign_key = next(
        iter(
            RolePermissionRecord
            .__table__
            .c.permission_id
            .foreign_keys
        )
    )

    assert (
        foreign_key.target_fullname
        == "permissions.id"
    )

    assert (
        foreign_key.ondelete
        == "CASCADE"
    )

from __future__ import annotations

from alembic.config import Config
from alembic.script import ScriptDirectory

from gateway.app.database.base import (
    Base,
)
from gateway.app.database.models import (
    UserRecord,
)


def load_scripts() -> ScriptDirectory:
    config = Config(
        "alembic.ini"
    )

    return ScriptDirectory.from_config(
        config
    )


def test_alembic_has_single_initial_head() -> None:
    scripts = load_scripts()

    heads = scripts.get_heads()

    assert len(heads) == 1


def test_initial_revision_has_no_parent() -> None:
    scripts = load_scripts()

    base_revisions = [
        revision
        for revision
        in scripts.walk_revisions()
        if revision.down_revision is None
    ]

    assert len(base_revisions) == 1

    initial_revision = (
        base_revisions[0]
    )

    assert (
        initial_revision.revision
        == "1cc279e452ed"
    )


def test_rbac_revision_follows_initial_revision() -> None:
    scripts = load_scripts()

    revision = scripts.get_revision(
        "b04e170d1c97"
    )

    assert revision is not None

    assert (
        revision.down_revision
        == "1cc279e452ed"
    )


def test_audit_revision_follows_rbac_revision() -> None:
    scripts = load_scripts()

    head = scripts.get_current_head()

    assert head == "6f2a91c8d4e7"

    revision = scripts.get_revision(
        head
    )

    assert revision is not None

    assert (
        revision.down_revision
        == "b04e170d1c97"
    )


def test_alembic_metadata_contains_users() -> None:
    assert (
        "users"
        in Base.metadata.tables
    )

    assert (
        Base.metadata.tables[
            "users"
        ]
        is UserRecord.__table__
    )


def test_users_constraints_have_stable_names() -> None:
    table = (
        Base.metadata.tables[
            "users"
        ]
    )

    assert (
        table.primary_key.name
        == "pk_users"
    )

    unique_names = {
        constraint.name
        for constraint
        in table.constraints
        if (
            constraint.__class__.__name__
            == "UniqueConstraint"
        )
    }

    assert (
        "uq_users_username"
        in unique_names
    )

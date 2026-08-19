from __future__ import annotations

from datetime import (
    datetime,
    timezone,
)
from uuid import uuid4

import pytest

from sqlalchemy.exc import (
    IntegrityError,
)

from gateway.app.authorization.constants import (
    DEFAULT_ROLE_ID,
)
from gateway.app.auth.repository import (
    UserAlreadyExistsError,
    UserNotFoundError,
    UserRepositoryBackendError,
)
from gateway.app.database.models import (
    UserRecord,
    UserRoleRecord,
)
from gateway.app.database.user_repository import (
    PostgreSQLUserRepository,
    is_unique_violation,
    record_to_stored_user,
)


VALID_HASH = "argon2-test-hash"


def make_record(
    *,
    username: str = "anas",
    hashed_password: str = VALID_HASH,
) -> UserRecord:
    now = datetime.now(
        timezone.utc
    )

    return UserRecord(
        id=uuid4(),
        username=username,
        hashed_password=(
            hashed_password
        ),
        is_active=True,
        created_at=now,
        updated_at=now,
    )


class FakeResult:
    def __init__(
        self,
        *,
        record: UserRecord | None = None,
        scalar: int = 0,
    ) -> None:
        self.record = record
        self.scalar = scalar

    def scalar_one_or_none(
        self,
    ) -> UserRecord | None:
        return self.record

    def scalar_one(
        self,
    ) -> int:
        return self.scalar


class FakeSession:
    def __init__(
        self,
        *,
        record: UserRecord | None = None,
        scalar: int = 0,
        commit_error: (
            Exception | None
        ) = None,
    ) -> None:
        self.record = record
        self.scalar = scalar
        self.commit_error = (
            commit_error
        )

        self.added: list[
            object
        ] = []

        self.statements: list[
            object
        ] = []

        self.committed = False
        self.rolled_back = False

    async def __aenter__(
        self,
    ) -> FakeSession:
        return self

    async def __aexit__(
        self,
        exc_type: object,
        exc: object,
        traceback: object,
    ) -> None:
        return None

    def add(
        self,
        value: object,
    ) -> None:
        self.added.append(
            value
        )

    async def execute(
        self,
        statement: object,
    ) -> FakeResult:
        self.statements.append(
            statement
        )

        return FakeResult(
            record=self.record,
            scalar=self.scalar,
        )

    async def commit(
        self,
    ) -> None:
        if (
            self.commit_error
            is not None
        ):
            raise self.commit_error

        self.committed = True

    async def rollback(
        self,
    ) -> None:
        self.rolled_back = True


class FakeSessionFactory:
    def __init__(
        self,
        session: FakeSession,
    ) -> None:
        self.session = session
        self.calls = 0

    def __call__(
        self,
    ) -> FakeSession:
        self.calls += 1
        return self.session


class FakePostgresError(
    Exception
):
    def __init__(
        self,
        sqlstate: str,
    ) -> None:
        super().__init__(
            "database error"
        )

        self.sqlstate = sqlstate


def make_integrity_error(
    sqlstate: str,
) -> IntegrityError:
    return IntegrityError(
        "statement",
        {},
        FakePostgresError(
            sqlstate
        ),
    )


def test_record_to_stored_user() -> None:
    record = make_record()

    stored = record_to_stored_user(
        record
    )

    assert stored.id == record.id
    assert stored.username == "anas"

    assert (
        stored.hashed_password
        == VALID_HASH
    )

    assert stored.is_active is True

    assert (
        stored.created_at
        == record.created_at
    )


def test_unique_violation_detection() -> None:
    assert is_unique_violation(
        make_integrity_error(
            "23505"
        )
    ) is True

    assert is_unique_violation(
        make_integrity_error(
            "23502"
        )
    ) is False


@pytest.mark.anyio
async def test_create_user_normalizes_and_commits() -> None:
    session = FakeSession()

    factory = FakeSessionFactory(
        session
    )

    repository = (
        PostgreSQLUserRepository(
            factory
        )
    )

    created = await repository.create_user(
        username=" ANAS ",
        hashed_password=VALID_HASH,
    )

    assert factory.calls == 1
    assert len(session.added) == 2
    assert session.committed is True
    assert session.rolled_back is False

    record = session.added[0]
    assignment = session.added[1]

    assert isinstance(
        record,
        UserRecord,
    )

    assert isinstance(
        assignment,
        UserRoleRecord,
    )

    assert (
        assignment.user_id
        == record.id
    )

    assert (
        assignment.role_id
        == DEFAULT_ROLE_ID
    )

    assert record.username == "anas"

    assert created.username == "anas"

    assert (
        created.hashed_password
        == VALID_HASH
    )


@pytest.mark.anyio
async def test_create_user_rejects_empty_hash() -> None:
    session = FakeSession()

    factory = FakeSessionFactory(
        session
    )

    repository = (
        PostgreSQLUserRepository(
            factory
        )
    )

    with pytest.raises(
        ValueError,
        match=(
            "Hashed password "
            "cannot be empty"
        ),
    ):
        await repository.create_user(
            username="anas",
            hashed_password="   ",
        )

    assert factory.calls == 0


@pytest.mark.anyio
async def test_create_user_rolls_back_duplicate() -> None:
    session = FakeSession(
        commit_error=(
            make_integrity_error(
                "23505"
            )
        )
    )

    repository = (
        PostgreSQLUserRepository(
            FakeSessionFactory(
                session
            )
        )
    )

    with pytest.raises(
        UserAlreadyExistsError,
    ):
        await repository.create_user(
            username="anas",
            hashed_password=VALID_HASH,
        )

    assert session.rolled_back is True


@pytest.mark.anyio
async def test_create_user_translates_other_integrity_errors() -> None:
    error = make_integrity_error(
        "23502"
    )

    session = FakeSession(
        commit_error=error
    )

    repository = (
        PostgreSQLUserRepository(
            FakeSessionFactory(
                session
            )
        )
    )

    with pytest.raises(
        UserRepositoryBackendError,
        match=(
            "User persistence backend "
            "is unavailable"
        ),
    ) as captured:
        await repository.create_user(
            username="anas",
            hashed_password=VALID_HASH,
        )

    assert session.rolled_back is True

    assert (
        captured.value.__cause__
        is error
    )


@pytest.mark.anyio
async def test_get_by_username_returns_user() -> None:
    record = make_record()

    session = FakeSession(
        record=record
    )

    repository = (
        PostgreSQLUserRepository(
            FakeSessionFactory(
                session
            )
        )
    )

    found = (
        await repository.get_by_username(
            " ANAS "
        )
    )

    assert found is not None
    assert found.username == "anas"

    params = (
        session.statements[0]
        .compile()
        .params
    )

    assert "anas" in params.values()


@pytest.mark.anyio
async def test_get_by_username_returns_none() -> None:
    session = FakeSession(
        record=None
    )

    repository = (
        PostgreSQLUserRepository(
            FakeSessionFactory(
                session
            )
        )
    )

    assert (
        await repository.get_by_username(
            "unknown-user"
        )
        is None
    )


@pytest.mark.anyio
async def test_update_password_hash() -> None:
    record = make_record()

    session = FakeSession(
        record=record
    )

    repository = (
        PostgreSQLUserRepository(
            FakeSessionFactory(
                session
            )
        )
    )

    updated = (
        await repository
        .update_password_hash(
            username="ANAS",
            hashed_password=(
                "replacement-hash"
            ),
        )
    )

    assert (
        record.hashed_password
        == "replacement-hash"
    )

    assert (
        updated.hashed_password
        == "replacement-hash"
    )

    assert session.committed is True


@pytest.mark.anyio
async def test_update_unknown_user() -> None:
    session = FakeSession(
        record=None
    )

    repository = (
        PostgreSQLUserRepository(
            FakeSessionFactory(
                session
            )
        )
    )

    with pytest.raises(
        UserNotFoundError,
        match="User not found",
    ):
        await repository.update_password_hash(
            username="unknown-user",
            hashed_password=(
                "replacement-hash"
            ),
        )

    assert session.committed is False


@pytest.mark.anyio
async def test_repository_count() -> None:
    session = FakeSession(
        scalar=7
    )

    repository = (
        PostgreSQLUserRepository(
            FakeSessionFactory(
                session
            )
        )
    )

    assert (
        await repository.count()
        == 7
    )

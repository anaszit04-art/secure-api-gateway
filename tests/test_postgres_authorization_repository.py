from __future__ import annotations

from uuid import (
    UUID,
    uuid4,
)

import pytest

from sqlalchemy.exc import (
    SQLAlchemyError,
)

from gateway.app.authorization.repository import (
    AuthorizationRepositoryBackendError,
    RoleNotFoundError,
    UserAuthorizationNotFoundError,
)
from gateway.app.database.authorization_repository import (
    PostgreSQLAuthorizationRepository,
)


class FakeResult:
    def __init__(
        self,
        *,
        scalar: object = None,
        values: list[object] | None = None,
        rowcount: int = 0,
    ) -> None:
        self.scalar = scalar
        self.values = (
            values
            if values is not None
            else []
        )
        self.rowcount = rowcount

    def scalar_one(
        self,
    ) -> object:
        return self.scalar

    def scalar_one_or_none(
        self,
    ) -> object:
        return self.scalar

    def scalars(
        self,
    ) -> FakeResult:
        return self

    def all(
        self,
    ) -> list[object]:
        return self.values


class FakeSession:
    def __init__(
        self,
        *,
        results: list[FakeResult] | None = None,
        execute_error: Exception | None = None,
        commit_error: Exception | None = None,
    ) -> None:
        self.results = list(
            results or []
        )

        self.execute_error = (
            execute_error
        )

        self.commit_error = (
            commit_error
        )

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

    async def execute(
        self,
        statement: object,
    ) -> FakeResult:
        self.statements.append(
            statement
        )

        if (
            self.execute_error
            is not None
        ):
            raise self.execute_error

        if not self.results:
            raise AssertionError(
                "No FakeResult configured."
            )

        return self.results.pop(0)

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


@pytest.mark.anyio
async def test_get_role_names_for_user() -> None:
    session = FakeSession(
        results=[
            FakeResult(
                values=[
                    "admin",
                    "user",
                ]
            )
        ]
    )

    repository = (
        PostgreSQLAuthorizationRepository(
            FakeSessionFactory(
                session
            )
        )
    )

    roles = (
        await repository
        .get_role_names_for_user(
            uuid4()
        )
    )

    assert roles == frozenset(
        {
            "admin",
            "user",
        }
    )


@pytest.mark.anyio
async def test_get_permission_codes_for_user() -> None:
    session = FakeSession(
        results=[
            FakeResult(
                values=[
                    "proxy:service-a:read",
                    "proxy:service-b:read",
                ]
            )
        ]
    )

    repository = (
        PostgreSQLAuthorizationRepository(
            FakeSessionFactory(
                session
            )
        )
    )

    permissions = (
        await repository
        .get_permission_codes_for_user(
            uuid4()
        )
    )

    assert permissions == frozenset(
        {
            "proxy:service-a:read",
            "proxy:service-b:read",
        }
    )


@pytest.mark.anyio
async def test_has_permission_returns_true() -> None:
    session = FakeSession(
        results=[
            FakeResult(
                scalar=True
            )
        ]
    )

    repository = (
        PostgreSQLAuthorizationRepository(
            FakeSessionFactory(
                session
            )
        )
    )

    assert (
        await repository.has_permission(
            user_id=uuid4(),
            permission_code=(
                "PROXY:SERVICE-A:READ"
            ),
        )
        is True
    )

    parameters = (
        session.statements[0]
        .compile()
        .params
    )

    assert (
        "proxy:service-a:read"
        in parameters.values()
    )


@pytest.mark.anyio
async def test_has_permission_returns_false() -> None:
    repository = (
        PostgreSQLAuthorizationRepository(
            FakeSessionFactory(
                FakeSession(
                    results=[
                        FakeResult(
                            scalar=False
                        )
                    ]
                )
            )
        )
    )

    assert (
        await repository.has_permission(
            user_id=uuid4(),
            permission_code=(
                "proxy:service-a:write"
            ),
        )
        is False
    )


@pytest.mark.anyio
async def test_assign_role_creates_assignment() -> None:
    user_id = uuid4()
    role_id = uuid4()

    session = FakeSession(
        results=[
            FakeResult(
                scalar=role_id
            ),
            FakeResult(
                scalar=user_id
            ),
            FakeResult(
                rowcount=1
            ),
        ]
    )

    repository = (
        PostgreSQLAuthorizationRepository(
            FakeSessionFactory(
                session
            )
        )
    )

    created = await repository.assign_role(
        user_id=user_id,
        role_name="OPERATOR",
    )

    assert created is True
    assert session.committed is True
    assert session.rolled_back is False


@pytest.mark.anyio
async def test_assign_existing_role_is_idempotent() -> None:
    user_id = uuid4()
    role_id = uuid4()

    session = FakeSession(
        results=[
            FakeResult(
                scalar=role_id
            ),
            FakeResult(
                scalar=user_id
            ),
            FakeResult(
                rowcount=0
            ),
        ]
    )

    repository = (
        PostgreSQLAuthorizationRepository(
            FakeSessionFactory(
                session
            )
        )
    )

    created = await repository.assign_role(
        user_id=user_id,
        role_name="operator",
    )

    assert created is False
    assert session.committed is True


@pytest.mark.anyio
async def test_assign_unknown_role_is_rejected() -> None:
    session = FakeSession(
        results=[
            FakeResult(
                scalar=None
            )
        ]
    )

    repository = (
        PostgreSQLAuthorizationRepository(
            FakeSessionFactory(
                session
            )
        )
    )

    with pytest.raises(
        RoleNotFoundError,
    ):
        await repository.assign_role(
            user_id=uuid4(),
            role_name="operator",
        )

    assert session.committed is False


@pytest.mark.anyio
async def test_assign_unknown_user_is_rejected() -> None:
    role_id = uuid4()

    session = FakeSession(
        results=[
            FakeResult(
                scalar=role_id
            ),
            FakeResult(
                scalar=None
            ),
        ]
    )

    repository = (
        PostgreSQLAuthorizationRepository(
            FakeSessionFactory(
                session
            )
        )
    )

    with pytest.raises(
        UserAuthorizationNotFoundError,
    ):
        await repository.assign_role(
            user_id=uuid4(),
            role_name="operator",
        )

    assert session.committed is False


@pytest.mark.anyio
async def test_remove_role_deletes_assignment() -> None:
    user_id = uuid4()
    role_id = uuid4()

    session = FakeSession(
        results=[
            FakeResult(
                scalar=role_id
            ),
            FakeResult(
                scalar=user_id
            ),
            FakeResult(
                rowcount=1
            ),
        ]
    )

    repository = (
        PostgreSQLAuthorizationRepository(
            FakeSessionFactory(
                session
            )
        )
    )

    removed = await repository.remove_role(
        user_id=user_id,
        role_name="operator",
    )

    assert removed is True
    assert session.committed is True


@pytest.mark.anyio
async def test_remove_missing_assignment_is_idempotent() -> None:
    user_id = uuid4()
    role_id = uuid4()

    session = FakeSession(
        results=[
            FakeResult(
                scalar=role_id
            ),
            FakeResult(
                scalar=user_id
            ),
            FakeResult(
                rowcount=0
            ),
        ]
    )

    repository = (
        PostgreSQLAuthorizationRepository(
            FakeSessionFactory(
                session
            )
        )
    )

    removed = await repository.remove_role(
        user_id=user_id,
        role_name="operator",
    )

    assert removed is False
    assert session.committed is True


@pytest.mark.anyio
async def test_backend_failure_is_translated() -> None:
    error = SQLAlchemyError(
        "database unavailable"
    )

    repository = (
        PostgreSQLAuthorizationRepository(
            FakeSessionFactory(
                FakeSession(
                    execute_error=error
                )
            )
        )
    )

    with pytest.raises(
        AuthorizationRepositoryBackendError,
        match=(
            "Authorization persistence "
            "backend is unavailable"
        ),
    ) as captured:
        await repository.has_permission(
            user_id=uuid4(),
            permission_code=(
                "proxy:service-a:read"
            ),
        )

    assert (
        captured.value.__cause__
        is error
    )


@pytest.mark.anyio
async def test_commit_failure_rolls_back() -> None:
    user_id = uuid4()
    role_id = uuid4()

    error = SQLAlchemyError(
        "commit failed"
    )

    session = FakeSession(
        results=[
            FakeResult(
                scalar=role_id
            ),
            FakeResult(
                scalar=user_id
            ),
            FakeResult(
                rowcount=1
            ),
        ],
        commit_error=error,
    )

    repository = (
        PostgreSQLAuthorizationRepository(
            FakeSessionFactory(
                session
            )
        )
    )

    with pytest.raises(
        AuthorizationRepositoryBackendError,
    ):
        await repository.assign_role(
            user_id=user_id,
            role_name="operator",
        )

    assert session.rolled_back is True

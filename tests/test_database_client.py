from __future__ import annotations

from typing import Any

import pytest

from gateway.app.database import client
from gateway.app.database.config import (
    DatabaseSettings,
)


VALID_URL = (
    "postgresql+asyncpg://"
    "gateway:secret-value@"
    "postgres:5432/gateway"
)


def create_settings() -> DatabaseSettings:
    return DatabaseSettings(
        url=VALID_URL,
        pool_size=7,
        max_overflow=14,
        pool_timeout_seconds=6.5,
        connect_timeout_seconds=3.5,
        verify_on_startup=True,
        application_name="gateway-tests",
    )


def test_create_database_engine_uses_secure_options(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = create_settings()

    captured: dict[str, Any] = {}
    fake_engine = object()

    def fake_create_async_engine(
        url: str,
        **kwargs: Any,
    ) -> object:
        captured["url"] = url
        captured.update(kwargs)

        return fake_engine

    monkeypatch.setattr(
        client,
        "create_async_engine",
        fake_create_async_engine,
    )

    result = client.create_database_engine(
        settings
    )

    assert result is fake_engine
    assert captured["url"] == VALID_URL
    assert captured["echo"] is False
    assert captured["pool_pre_ping"] is True
    assert captured["pool_size"] == 7

    assert (
        captured["max_overflow"]
        == 14
    )

    assert (
        captured["pool_timeout"]
        == 6.5
    )

    assert captured["connect_args"] == {
        "timeout": 3.5,
        "server_settings": {
            "application_name": (
                "gateway-tests"
            )
        },
    }


def test_create_database_session_factory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    fake_engine = object()
    fake_factory = object()

    def fake_async_sessionmaker(
        **kwargs: Any,
    ) -> object:
        captured.update(kwargs)

        return fake_factory

    monkeypatch.setattr(
        client,
        "async_sessionmaker",
        fake_async_sessionmaker,
    )

    result = (
        client.create_database_session_factory(
            fake_engine
        )
    )

    assert result is fake_factory

    assert (
        captured["bind"]
        is fake_engine
    )

    assert (
        captured["class_"]
        is client.AsyncSession
    )

    assert (
        captured["expire_on_commit"]
        is False
    )

    assert (
        captured["autoflush"]
        is False
    )


class FakeResult:
    def scalar_one(
        self,
    ) -> int:
        return 1


class FakeConnection:
    def __init__(
        self,
    ) -> None:
        self.executed_statement = None

    async def execute(
        self,
        statement: object,
    ) -> FakeResult:
        self.executed_statement = (
            statement
        )

        return FakeResult()


class FakeConnectionContext:
    def __init__(
        self,
        connection: FakeConnection,
    ) -> None:
        self.connection = connection

    async def __aenter__(
        self,
    ) -> FakeConnection:
        return self.connection

    async def __aexit__(
        self,
        exc_type: object,
        exc: object,
        traceback: object,
    ) -> None:
        return None


class FakeEngine:
    def __init__(
        self,
    ) -> None:
        self.connection = FakeConnection()
        self.disposed = False

    def connect(
        self,
    ) -> FakeConnectionContext:
        return FakeConnectionContext(
            self.connection
        )

    async def dispose(
        self,
    ) -> None:
        self.disposed = True


@pytest.mark.anyio
async def test_verify_database_connection_executes_probe() -> None:
    engine = FakeEngine()

    await client.verify_database_connection(
        engine
    )

    assert (
        str(
            engine.connection.executed_statement
        )
        == "SELECT 1"
    )


class FakeUnexpectedResult:
    def scalar_one(
        self,
    ) -> int:
        return 2


class FakeUnexpectedConnection(
    FakeConnection
):
    async def execute(
        self,
        statement: object,
    ) -> FakeUnexpectedResult:
        self.executed_statement = statement

        return FakeUnexpectedResult()


class FakeUnexpectedEngine(
    FakeEngine
):
    def __init__(
        self,
    ) -> None:
        super().__init__()

        self.connection = (
            FakeUnexpectedConnection()
        )


@pytest.mark.anyio
async def test_verify_database_connection_rejects_unexpected_result() -> None:
    engine = FakeUnexpectedEngine()

    with pytest.raises(
        RuntimeError,
        match=(
            "Unexpected PostgreSQL "
            "verification result"
        ),
    ):
        await (
            client.verify_database_connection(
                engine
            )
        )


@pytest.mark.anyio
async def test_close_database_engine_disposes_pool() -> None:
    engine = FakeEngine()

    await client.close_database_engine(
        engine
    )

    assert engine.disposed is True

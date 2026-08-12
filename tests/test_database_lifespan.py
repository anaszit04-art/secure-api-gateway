from __future__ import annotations

from typing import Any

import pytest

from fastapi.testclient import TestClient

import gateway.app.main as main_module


DATABASE_URL = (
    "postgresql+asyncpg://"
    "gateway:test-password@"
    "postgres:5432/gateway"
)


class FakeDatabaseEngine:
    pass


def configure_database_environment(
    monkeypatch: pytest.MonkeyPatch,
    *,
    verify: bool,
) -> None:
    monkeypatch.setenv(
        "DATABASE_URL",
        DATABASE_URL,
    )

    monkeypatch.setenv(
        "DATABASE_VERIFY_ON_STARTUP",
        (
            "true"
            if verify
            else "false"
        ),
    )

    # Prevent Redis network verification from being
    # involved in database lifecycle unit tests.
    monkeypatch.setenv(
        "REDIS_VERIFY_ON_STARTUP",
        "false",
    )


def test_database_is_not_created_when_unconfigured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(
        "DATABASE_URL",
        raising=False,
    )

    monkeypatch.setenv(
        "REDIS_VERIFY_ON_STARTUP",
        "false",
    )

    def unexpected_engine_creation(
        *_: Any,
        **__: Any,
    ) -> object:
        raise AssertionError(
            "Database engine should not "
            "be created."
        )

    monkeypatch.setattr(
        main_module,
        "create_database_engine",
        unexpected_engine_creation,
    )

    with TestClient(
        main_module.app
    ) as client:
        response = client.get(
            "/health"
        )

        assert response.status_code == 200

        assert (
            main_module.app.state
            .database_engine
            is None
        )

        assert (
            main_module.app.state
            .database_session_factory
            is None
        )


def test_database_lifecycle_creates_and_closes_engine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_database_environment(
        monkeypatch,
        verify=False,
    )

    fake_engine = FakeDatabaseEngine()
    fake_factory = object()

    closed_engines: list[
        object
    ] = []

    monkeypatch.setattr(
        main_module,
        "create_database_engine",
        lambda settings: fake_engine,
    )

    monkeypatch.setattr(
        main_module,
        "create_database_session_factory",
        lambda engine: fake_factory,
    )

    async def fake_close_database_engine(
        engine: object,
    ) -> None:
        closed_engines.append(
            engine
        )

    monkeypatch.setattr(
        main_module,
        "close_database_engine",
        fake_close_database_engine,
    )

    with TestClient(
        main_module.app
    ) as client:
        assert (
            client.get(
                "/health"
            ).status_code
            == 200
        )

        assert (
            main_module.app.state
            .database_engine
            is fake_engine
        )

        assert (
            main_module.app.state
            .database_session_factory
            is fake_factory
        )

        assert closed_engines == []

    assert closed_engines == [
        fake_engine
    ]


def test_database_connection_is_verified_on_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_database_environment(
        monkeypatch,
        verify=True,
    )

    fake_engine = FakeDatabaseEngine()
    fake_factory = object()

    verified_engines: list[
        object
    ] = []

    closed_engines: list[
        object
    ] = []

    monkeypatch.setattr(
        main_module,
        "create_database_engine",
        lambda settings: fake_engine,
    )

    monkeypatch.setattr(
        main_module,
        "create_database_session_factory",
        lambda engine: fake_factory,
    )

    async def fake_verify_database_connection(
        engine: object,
    ) -> None:
        verified_engines.append(
            engine
        )

    async def fake_close_database_engine(
        engine: object,
    ) -> None:
        closed_engines.append(
            engine
        )

    monkeypatch.setattr(
        main_module,
        "verify_database_connection",
        fake_verify_database_connection,
    )

    monkeypatch.setattr(
        main_module,
        "close_database_engine",
        fake_close_database_engine,
    )

    with TestClient(
        main_module.app
    ) as client:
        assert (
            client.get(
                "/health"
            ).status_code
            == 200
        )

        assert verified_engines == [
            fake_engine
        ]

    assert closed_engines == [
        fake_engine
    ]


def test_database_engine_is_closed_when_startup_verification_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_database_environment(
        monkeypatch,
        verify=True,
    )

    fake_engine = FakeDatabaseEngine()
    fake_factory = object()

    closed_engines: list[
        object
    ] = []

    monkeypatch.setattr(
        main_module,
        "create_database_engine",
        lambda settings: fake_engine,
    )

    monkeypatch.setattr(
        main_module,
        "create_database_session_factory",
        lambda engine: fake_factory,
    )

    async def failing_verification(
        engine: object,
    ) -> None:
        raise RuntimeError(
            "database unavailable"
        )

    async def fake_close_database_engine(
        engine: object,
    ) -> None:
        closed_engines.append(
            engine
        )

    monkeypatch.setattr(
        main_module,
        "verify_database_connection",
        failing_verification,
    )

    monkeypatch.setattr(
        main_module,
        "close_database_engine",
        fake_close_database_engine,
    )

    with pytest.raises(
        RuntimeError,
        match="database unavailable",
    ):
        with TestClient(
            main_module.app
        ):
            pass

    assert closed_engines == [
        fake_engine
    ]

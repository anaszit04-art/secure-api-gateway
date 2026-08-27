from __future__ import annotations

import asyncio

from uuid import UUID

import pytest

from fastapi.testclient import TestClient

import gateway.app.main as main_module
import gateway.app.readiness as readiness_module


def configure_test_runtime(
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

    monkeypatch.setenv(
        "METRICS_ENABLED",
        "false",
    )


def assert_valid_request_id(
    value: str,
) -> None:
    parsed = UUID(value)

    assert str(parsed) == value
    assert parsed.version == 4


def install_runtime_dependencies() -> None:
    main_module.app.state.database_engine = (
        object()
    )

    main_module.app.state.redis_client = (
        object()
    )


def test_ready_when_critical_dependencies_are_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_test_runtime(
        monkeypatch
    )

    async def database_ok(
        _: object,
    ) -> None:
        return None

    async def redis_ok(
        _: object,
    ) -> None:
        return None

    monkeypatch.setattr(
        readiness_module,
        "verify_database_connection",
        database_ok,
    )

    monkeypatch.setattr(
        readiness_module,
        "verify_redis_connection",
        redis_ok,
    )

    with TestClient(
        main_module.app
    ) as client:
        install_runtime_dependencies()

        response = client.get(
            "/ready"
        )

    assert response.status_code == 200

    assert response.json() == {
        "status": "ready",
        "checks": {
            "database": "ok",
            "redis": "ok",
        },
    }


def test_ready_fails_closed_when_database_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_test_runtime(
        monkeypatch
    )

    async def database_failure(
        _: object,
    ) -> None:
        raise RuntimeError(
            "private-postgres-host"
        )

    async def redis_ok(
        _: object,
    ) -> None:
        return None

    monkeypatch.setattr(
        readiness_module,
        "verify_database_connection",
        database_failure,
    )

    monkeypatch.setattr(
        readiness_module,
        "verify_redis_connection",
        redis_ok,
    )

    with TestClient(
        main_module.app
    ) as client:
        install_runtime_dependencies()

        response = client.get(
            "/ready"
        )

    assert response.status_code == 503

    assert response.json() == {
        "status": "not_ready",
        "checks": {
            "database": "unavailable",
            "redis": "ok",
        },
    }

    assert (
        "private-postgres-host"
        not in response.text
    )


def test_ready_fails_closed_when_redis_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_test_runtime(
        monkeypatch
    )

    async def database_ok(
        _: object,
    ) -> None:
        return None

    async def redis_failure(
        _: object,
    ) -> None:
        raise RuntimeError(
            "private-redis-host"
        )

    monkeypatch.setattr(
        readiness_module,
        "verify_database_connection",
        database_ok,
    )

    monkeypatch.setattr(
        readiness_module,
        "verify_redis_connection",
        redis_failure,
    )

    with TestClient(
        main_module.app
    ) as client:
        install_runtime_dependencies()

        response = client.get(
            "/ready"
        )

    assert response.status_code == 503

    assert response.json() == {
        "status": "not_ready",
        "checks": {
            "database": "ok",
            "redis": "unavailable",
        },
    }

    assert (
        "private-redis-host"
        not in response.text
    )


def test_ready_reports_both_dependencies_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_test_runtime(
        monkeypatch
    )

    async def failure(
        _: object,
    ) -> None:
        raise RuntimeError(
            "dependency unavailable"
        )

    monkeypatch.setattr(
        readiness_module,
        "verify_database_connection",
        failure,
    )

    monkeypatch.setattr(
        readiness_module,
        "verify_redis_connection",
        failure,
    )

    with TestClient(
        main_module.app
    ) as client:
        install_runtime_dependencies()

        response = client.get(
            "/ready"
        )

    assert response.status_code == 503

    assert response.json() == {
        "status": "not_ready",
        "checks": {
            "database": "unavailable",
            "redis": "unavailable",
        },
    }


def test_ready_fails_when_database_is_not_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_test_runtime(
        monkeypatch
    )

    async def redis_ok(
        _: object,
    ) -> None:
        return None

    monkeypatch.setattr(
        readiness_module,
        "verify_redis_connection",
        redis_ok,
    )

    with TestClient(
        main_module.app
    ) as client:
        main_module.app.state.database_engine = (
            None
        )

        main_module.app.state.redis_client = (
            object()
        )

        response = client.get(
            "/ready"
        )

    assert response.status_code == 503

    assert response.json() == {
        "status": "not_ready",
        "checks": {
            "database": "unavailable",
            "redis": "ok",
        },
    }


def test_ready_fails_when_redis_client_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_test_runtime(
        monkeypatch
    )

    async def database_ok(
        _: object,
    ) -> None:
        return None

    monkeypatch.setattr(
        readiness_module,
        "verify_database_connection",
        database_ok,
    )

    with TestClient(
        main_module.app
    ) as client:
        main_module.app.state.database_engine = (
            object()
        )

        main_module.app.state.redis_client = (
            None
        )

        response = client.get(
            "/ready"
        )

    assert response.status_code == 503

    assert response.json() == {
        "status": "not_ready",
        "checks": {
            "database": "ok",
            "redis": "unavailable",
        },
    }


def test_health_does_not_probe_dependencies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_test_runtime(
        monkeypatch
    )

    async def unexpected_probe(
        _: object,
    ) -> None:
        raise AssertionError(
            "Liveness must not probe "
            "critical dependencies."
        )

    monkeypatch.setattr(
        readiness_module,
        "verify_database_connection",
        unexpected_probe,
    )

    monkeypatch.setattr(
        readiness_module,
        "verify_redis_connection",
        unexpected_probe,
    )

    with TestClient(
        main_module.app
    ) as client:
        install_runtime_dependencies()

        response = client.get(
            "/health"
        )

    assert response.status_code == 200

    assert response.json() == {
        "status": "ok",
    }


def test_client_cannot_control_ready_request_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_test_runtime(
        monkeypatch
    )

    async def database_ok(
        _: object,
    ) -> None:
        return None

    async def redis_ok(
        _: object,
    ) -> None:
        return None

    monkeypatch.setattr(
        readiness_module,
        "verify_database_connection",
        database_ok,
    )

    monkeypatch.setattr(
        readiness_module,
        "verify_redis_connection",
        redis_ok,
    )

    client_request_id = (
        "client-controlled-request-id"
    )

    with TestClient(
        main_module.app
    ) as client:
        install_runtime_dependencies()

        response = client.get(
            "/ready",
            headers={
                "X-Request-ID": (
                    client_request_id
                ),
            },
        )

    assert response.status_code == 200

    gateway_request_id = (
        response.headers[
            "x-request-id"
        ]
    )

    assert (
        gateway_request_id
        != client_request_id
    )

    assert_valid_request_id(
        gateway_request_id
    )



def test_readiness_checks_run_concurrently(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        readiness_module,
        "READINESS_CHECK_TIMEOUT_SECONDS",
        0.5,
    )

    database_started = asyncio.Event()
    redis_started = asyncio.Event()

    async def database_check(
        _: object,
    ) -> None:
        database_started.set()

        await asyncio.wait_for(
            redis_started.wait(),
            timeout=0.2,
        )

    async def redis_check(
        _: object,
    ) -> None:
        redis_started.set()

        await asyncio.wait_for(
            database_started.wait(),
            timeout=0.2,
        )

    monkeypatch.setattr(
        readiness_module,
        "verify_database_connection",
        database_check,
    )

    monkeypatch.setattr(
        readiness_module,
        "verify_redis_connection",
        redis_check,
    )

    report = asyncio.run(
        readiness_module.evaluate_readiness(
            database_engine=object(),
            redis_client=object(),
        )
    )

    assert report.ready is True
    assert report.database == "ok"
    assert report.redis == "ok"


def test_readiness_dependency_check_is_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        readiness_module,
        "READINESS_CHECK_TIMEOUT_SECONDS",
        0.02,
    )

    async def database_never_returns(
        _: object,
    ) -> None:
        await asyncio.Event().wait()

    async def redis_ok(
        _: object,
    ) -> None:
        return None

    monkeypatch.setattr(
        readiness_module,
        "verify_database_connection",
        database_never_returns,
    )

    monkeypatch.setattr(
        readiness_module,
        "verify_redis_connection",
        redis_ok,
    )

    async def run_bounded_check():
        return await asyncio.wait_for(
            readiness_module.evaluate_readiness(
                database_engine=object(),
                redis_client=object(),
            ),
            timeout=0.5,
        )

    report = asyncio.run(
        run_bounded_check()
    )

    assert report.ready is False
    assert (
        report.database
        == "unavailable"
    )
    assert report.redis == "ok"

from __future__ import annotations

from uuid import UUID

import pytest

from fastapi import FastAPI
from fastapi.testclient import TestClient

from gateway.app.observability.metrics import (
    GatewayMetrics,
)
from gateway.app.observability.middleware import (
    RequestContextMiddleware,
)


class FailingHTTPMetrics(
    GatewayMetrics
):
    def record_http_request(
        self,
        *,
        method: str,
        route: str,
        status_code: int,
        duration_seconds: float,
    ) -> None:
        del (
            method,
            route,
            status_code,
            duration_seconds,
        )

        raise RuntimeError(
            "metrics backend failure"
        )


def build_test_app() -> FastAPI:
    test_app = FastAPI()

    test_app.state.metrics = (
        FailingHTTPMetrics()
    )

    test_app.add_middleware(
        RequestContextMiddleware
    )

    @test_app.get(
        "/ok"
    )
    async def ok() -> dict[
        str,
        str,
    ]:
        return {
            "status": "ok",
        }

    @test_app.get(
        "/explode"
    )
    async def explode() -> None:
        raise RuntimeError(
            "business failure"
        )

    return test_app


def test_http_metrics_failure_does_not_change_success_response() -> None:
    test_app = build_test_app()

    with TestClient(
        test_app
    ) as client:
        response = client.get(
            "/ok"
        )

    assert response.status_code == 200

    assert response.json() == {
        "status": "ok",
    }

    request_id = response.headers[
        "x-request-id"
    ]

    UUID(
        request_id
    )


def test_http_metrics_failure_does_not_mask_application_exception() -> None:
    test_app = build_test_app()

    with TestClient(
        test_app
    ) as client:
        with pytest.raises(
            RuntimeError,
            match="business failure",
        ):
            client.get(
                "/explode"
            )


def test_arbitrary_method_is_bounded_through_real_middleware() -> None:
    test_app = FastAPI()

    metrics = GatewayMetrics()

    test_app.state.metrics = metrics

    test_app.add_middleware(
        RequestContextMiddleware
    )

    with TestClient(
        test_app
    ) as client:
        response = client.request(
            "X-ATTACK-METHOD-12345",
            "/does-not-exist",
        )

    assert response.status_code in {
        404,
        405,
    }

    from prometheus_client import (
        generate_latest,
    )

    rendered = generate_latest(
        metrics.registry
    ).decode(
        "utf-8"
    )

    assert (
        'method="OTHER"'
        in rendered
    )

    assert (
        "X-ATTACK-METHOD-12345"
        not in rendered
    )


def test_logger_construction_failure_does_not_change_success_response(
    monkeypatch,
) -> None:
    test_app = FastAPI()

    test_app.state.metrics = (
        GatewayMetrics()
    )

    test_app.add_middleware(
        RequestContextMiddleware
    )

    @test_app.get(
        "/ok"
    )
    async def ok() -> dict[
        str,
        str,
    ]:
        return {
            "status": "ok",
        }

    def broken_logger_factory():
        raise RuntimeError(
            "logging unavailable"
        )

    monkeypatch.setattr(
        (
            "gateway.app.observability."
            "middleware.get_request_logger"
        ),
        broken_logger_factory,
    )

    with TestClient(
        test_app
    ) as client:
        response = client.get(
            "/ok"
        )

    assert response.status_code == 200

    assert response.json() == {
        "status": "ok",
    }

    UUID(
        response.headers[
            "x-request-id"
        ]
    )


def test_logger_emit_failure_does_not_mask_business_exception(
    monkeypatch,
) -> None:
    test_app = FastAPI()

    test_app.state.metrics = (
        GatewayMetrics()
    )

    test_app.add_middleware(
        RequestContextMiddleware
    )

    @test_app.get(
        "/explode"
    )
    async def explode() -> None:
        raise RuntimeError(
            "original business failure"
        )

    class BrokenLogger:
        def info(
            self,
            *args,
            **kwargs,
        ) -> None:
            del args, kwargs

            raise RuntimeError(
                "logging output failed"
            )

    monkeypatch.setattr(
        (
            "gateway.app.observability."
            "middleware.get_request_logger"
        ),
        lambda: BrokenLogger(),
    )

    with TestClient(
        test_app
    ) as client:
        with pytest.raises(
            RuntimeError,
            match=(
                "original business failure"
            ),
        ):
            client.get(
                "/explode"
            )

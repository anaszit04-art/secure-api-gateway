from __future__ import annotations

import os

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import (
    FastAPI,
    Request,
    status,
)
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncEngine

from gateway.app.auth.router import (
    router as auth_router,
)
from gateway.app.authorization.router import (
    router as authorization_router,
)
from gateway.app.database.client import (
    close_database_engine,
    create_database_engine,
    create_database_session_factory,
    verify_database_connection,
)
from gateway.app.database.config import (
    DatabaseSettings,
)
from gateway.app.observability.logging import (
    emit_readiness_dependency_log_best_effort,
)
from gateway.app.observability.metrics import (
    GatewayMetrics,
    MetricsServerHandle,
    MetricsSettings,
    start_metrics_server,
)
from gateway.app.observability.middleware import (
    RequestContextMiddleware,
)
from gateway.app.proxy.client import (
    create_http_client,
)
from gateway.app.proxy.registry import (
    SERVICE_DEFINITIONS,
)
from gateway.app.proxy.resilience import (
    CircuitBreakerRegistry,
    UpstreamResilienceSettings,
)
from gateway.app.proxy.router import (
    router as proxy_router,
)
from gateway.app.readiness import (
    evaluate_readiness,
)
from gateway.app.rate_limit.client import (
    close_redis_client,
    create_redis_client,
    verify_redis_connection,
)
from gateway.app.rate_limit.config import (
    RedisSettings,
)
from gateway.app.rate_limit.login import (
    RedisLoginProtection,
)
from gateway.app.rate_limit.service import (
    RedisRateLimiter,
)


def database_is_configured() -> bool:
    """
    Return whether PostgreSQL configuration is present.

    PostgreSQL remains optional for isolated tests so that
    they can continue running without a real database.

    Docker always supplies DATABASE_URL.
    """
    database_url = os.environ.get(
        "DATABASE_URL"
    )

    return bool(
        database_url
        and database_url.strip()
    )


@asynccontextmanager
async def lifespan(
    app: FastAPI,
) -> AsyncIterator[None]:
    metrics_settings = (
        MetricsSettings.from_environment()
    )

    upstream_resilience_settings = (
        UpstreamResilienceSettings
        .from_environment()
    )

    upstream_circuit_breakers = (
        CircuitBreakerRegistry(
            service_names=(
                SERVICE_DEFINITIONS.keys()
            ),
            settings=(
                upstream_resilience_settings
            ),
        )
    )

    app.state.upstream_resilience_settings = (
        upstream_resilience_settings
    )

    app.state.upstream_circuit_breakers = (
        upstream_circuit_breakers
    )

    metrics = GatewayMetrics()

    app.state.metrics = metrics
    app.state.metrics_server = None

    metrics_server: (
        MetricsServerHandle | None
    ) = None

    redis_settings = (
        RedisSettings.from_environment()
    )

    redis_client = create_redis_client(
        redis_settings
    )

    app.state.redis_client = redis_client

    app.state.rate_limiter = RedisRateLimiter(
        client=redis_client,
        settings=redis_settings,
    )

    app.state.login_protection = (
        RedisLoginProtection(
            client=redis_client,
            key_prefix=(
                redis_settings.key_prefix
            ),
        )
    )

    database_engine: (
        AsyncEngine | None
    ) = None

    app.state.database_settings = None
    app.state.database_engine = None
    app.state.database_session_factory = None

    try:
        if metrics_settings.enabled:
            metrics_server = (
                start_metrics_server(
                    metrics=metrics,
                    settings=(
                        metrics_settings
                    ),
                )
            )

            app.state.metrics_server = (
                metrics_server
            )

        if database_is_configured():
            database_settings = (
                DatabaseSettings.from_environment()
            )

            database_engine = (
                create_database_engine(
                    database_settings
                )
            )

            database_session_factory = (
                create_database_session_factory(
                    database_engine
                )
            )

            app.state.database_settings = (
                database_settings
            )

            app.state.database_engine = (
                database_engine
            )

            app.state.database_session_factory = (
                database_session_factory
            )

            if (
                database_settings
                .verify_on_startup
            ):
                await verify_database_connection(
                    database_engine
                )

        if redis_settings.verify_on_startup:
            await verify_redis_connection(
                redis_client
            )

        async with (
            create_http_client()
            as http_client
        ):
            app.state.http_client = http_client

            yield
    finally:
        if metrics_server is not None:
            metrics_server.close()

            app.state.metrics_server = None

        if database_engine is not None:
            await close_database_engine(
                database_engine
            )

        await close_redis_client(
            redis_client
        )


app = FastAPI(
    title="Secure API Gateway",
    description=(
        "API Gateway Zero Trust avec JWT, "
        "rate limiting, RBAC, audit de sécurité, "
        "observabilité et reverse proxy résilient."
    ),
    version="0.7.0",
    lifespan=lifespan,
)

app.add_middleware(
    RequestContextMiddleware
)

app.include_router(auth_router)
app.include_router(authorization_router)
app.include_router(proxy_router)


@app.get(
    "/health",
    tags=["System"],
)
async def health() -> dict[str, str]:
    return {
        "status": "ok",
    }


@app.get(
    "/ready",
    tags=["System"],
    responses={
        503: {
            "description": (
                "Gateway dependencies "
                "are unavailable."
            ),
        },
    },
)
async def ready(
    request: Request,
) -> JSONResponse:
    report = await evaluate_readiness(
        database_engine=getattr(
            request.app.state,
            "database_engine",
            None,
        ),
        redis_client=getattr(
            request.app.state,
            "redis_client",
            None,
        ),
    )

    if not report.ready:
        request_id = getattr(
            request.state,
            "request_id",
            None,
        )

        if isinstance(
            request_id,
            str,
        ):
            for (
                dependency,
                dependency_status,
            ) in (
                (
                    "database",
                    report.database,
                ),
                (
                    "redis",
                    report.redis,
                ),
            ):
                if (
                    dependency_status
                    == "unavailable"
                ):
                    (
                        emit_readiness_dependency_log_best_effort(
                            request_id=request_id,
                            dependency=dependency,
                        )
                    )

    return JSONResponse(
        status_code=(
            status.HTTP_200_OK
            if report.ready
            else (
                status
                .HTTP_503_SERVICE_UNAVAILABLE
            )
        ),
        content=report.as_payload(),
    )

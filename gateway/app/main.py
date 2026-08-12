from __future__ import annotations

import os

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncEngine

from gateway.app.auth.router import (
    router as auth_router,
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
from gateway.app.proxy.client import (
    create_http_client,
)
from gateway.app.proxy.router import (
    router as proxy_router,
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

    PostgreSQL remains optional during the staged Phase 4
    migration so that existing isolated tests can continue
    running without a real database.

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
        "API Gateway avec JWT, rate limiting "
        "et reverse proxy."
    ),
    version="0.3.0",
    lifespan=lifespan,
)

app.include_router(auth_router)
app.include_router(proxy_router)


@app.get(
    "/health",
    tags=["System"],
)
async def health() -> dict[str, str]:
    return {
        "status": "ok",
    }

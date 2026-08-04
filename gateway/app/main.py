from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from gateway.app.auth.router import (
    router as auth_router,
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

    try:
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


@app.get("/health", tags=["System"])
async def health() -> dict[str, str]:
    return {"status": "ok"}

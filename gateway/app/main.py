from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from gateway.app.proxy.client import (
    create_http_client,
)
from gateway.app.proxy.router import (
    router as proxy_router,
)
from gateway.app.auth.router import (
    router as auth_router,
)


@asynccontextmanager
async def lifespan(
    app: FastAPI,
) -> AsyncIterator[None]:
    async with create_http_client() as http_client:
        app.state.http_client = http_client

        yield


app = FastAPI(
    title="Secure API Gateway",
    description=(
        "API Gateway avec JWT, rate limiting "
        "et reverse proxy."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(auth_router)

app.include_router(proxy_router)


@app.get("/health", tags=["System"])
async def health() -> dict[str, str]:
    return {"status": "ok"}

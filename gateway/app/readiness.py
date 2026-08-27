from __future__ import annotations

import asyncio

from collections.abc import (
    Awaitable,
    Callable,
)
from dataclasses import dataclass
from typing import Any, Literal

from gateway.app.database.client import (
    verify_database_connection,
)
from gateway.app.rate_limit.client import (
    verify_redis_connection,
)


DependencyStatus = Literal[
    "ok",
    "unavailable",
]

DependencyCheck = Callable[
    [],
    Awaitable[None],
]


READINESS_CHECK_TIMEOUT_SECONDS = 2.0


@dataclass(
    frozen=True,
    slots=True,
)
class ReadinessReport:
    database: DependencyStatus
    redis: DependencyStatus

    @property
    def ready(self) -> bool:
        return (
            self.database == "ok"
            and self.redis == "ok"
        )

    def as_payload(
        self,
    ) -> dict[str, object]:
        return {
            "status": (
                "ready"
                if self.ready
                else "not_ready"
            ),
            "checks": {
                "database": self.database,
                "redis": self.redis,
            },
        }


async def _run_dependency_check(
    check: DependencyCheck | None,
) -> DependencyStatus:
    """
    Execute one bounded readiness probe.

    Missing dependencies and any runtime failure are
    deliberately normalized to "unavailable".

    Infrastructure exception details must never be
    returned to the client.
    """
    if check is None:
        return "unavailable"

    try:
        async with asyncio.timeout(
            READINESS_CHECK_TIMEOUT_SECONDS
        ):
            await check()

    except Exception:
        return "unavailable"

    return "ok"


async def evaluate_readiness(
    *,
    database_engine: Any | None,
    redis_client: Any | None,
) -> ReadinessReport:
    """
    Evaluate dependencies that are mandatory for
    accepting production traffic.

    PostgreSQL and Redis are checked concurrently to
    keep the readiness probe bounded.

    Upstream business services and observability
    components are intentionally excluded.
    """
    database_check: (
        DependencyCheck | None
    ) = None

    redis_check: (
        DependencyCheck | None
    ) = None

    if database_engine is not None:

        async def database_check() -> None:
            await verify_database_connection(
                database_engine
            )

    if redis_client is not None:

        async def redis_check() -> None:
            await verify_redis_connection(
                redis_client
            )

    (
        database_status,
        redis_status,
    ) = await asyncio.gather(
        _run_dependency_check(
            database_check
        ),
        _run_dependency_check(
            redis_check
        ),
    )

    return ReadinessReport(
        database=database_status,
        redis=redis_status,
    )

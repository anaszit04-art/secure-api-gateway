from __future__ import annotations

import logging

from time import perf_counter
from uuid import uuid4

from fastapi import Request
from starlette.middleware.base import (
    BaseHTTPMiddleware,
    RequestResponseEndpoint,
)
from starlette.responses import Response

from gateway.app.observability.logging import (
    get_request_logger,
)


REQUEST_ID_HEADER = "X-Request-ID"


def resolve_route_template(
    request: Request,
) -> str:
    """
    Return the matched route template without logging
    raw request paths that may contain identifiers.

    Examples:

        /health
        /auth/token
        /authorization/users/{username}/roles
        /api/{service_name}/{path:path}

    Unknown routes deliberately use a fixed placeholder.
    """

    route = request.scope.get(
        "route"
    )

    route_path = getattr(
        route,
        "path",
        None,
    )

    if (
        isinstance(route_path, str)
        and route_path
    ):
        return route_path

    return "<unmatched>"


def emit_request_log(
    *,
    logger: logging.Logger,
    event: str,
    request_id: str,
    method: str,
    route: str,
    status_code: int,
    duration_ms: float,
) -> None:
    """
    Emit one bounded operational request event.

    Passwords, JWTs, request bodies, query strings,
    Authorization headers and database URLs are never
    included in this event.
    """

    logger.info(
        event,
        extra={
            "event": event,
            "request_id": request_id,
            "method": method,
            "route": route,
            "status_code": status_code,
            "duration_ms": duration_ms,
        },
    )


class RequestContextMiddleware(
    BaseHTTPMiddleware
):
    """
    Generate a Gateway-owned request identifier and
    emit one structured operational log per request.

    A client-supplied X-Request-ID is intentionally
    ignored. The Gateway therefore remains the trust
    authority for correlation identifiers.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        request_id = str(
            uuid4()
        )

        request.state.request_id = (
            request_id
        )

        started_at = perf_counter()

        logger = get_request_logger()

        try:
            response = await call_next(
                request
            )

        except Exception:
            duration_ms = round(
                (
                    perf_counter()
                    - started_at
                )
                * 1000,
                3,
            )

            emit_request_log(
                logger=logger,
                event="request_failed",
                request_id=request_id,
                method=request.method,
                route=(
                    resolve_route_template(
                        request
                    )
                ),
                status_code=500,
                duration_ms=duration_ms,
            )

            raise

        response.headers[
            REQUEST_ID_HEADER
        ] = request_id

        duration_ms = round(
            (
                perf_counter()
                - started_at
            )
            * 1000,
            3,
        )

        emit_request_log(
            logger=logger,
            event="request_completed",
            request_id=request_id,
            method=request.method,
            route=(
                resolve_route_template(
                    request
                )
            ),
            status_code=(
                response.status_code
            ),
            duration_ms=duration_ms,
        )

        return response

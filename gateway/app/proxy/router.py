from time import perf_counter
from typing import Annotated

import httpx

from gateway.app.authorization.dependencies import (
    enforce_proxy_authorization,
)

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Request,
    Response,
)

from gateway.app.observability.metrics import (
    record_upstream_metric_best_effort,
    status_class,
)
from gateway.app.proxy.headers import (
    filter_request_headers,
    filter_response_headers,
)
from gateway.app.proxy.registry import (
    UnknownServiceError,
    get_service_base_url,
)
from gateway.app.rate_limit.dependencies import (
    build_rate_limit_headers,
    enforce_proxy_rate_limit,
)
from gateway.app.rate_limit.models import (
    RateLimitDecision,
)


router = APIRouter(
    prefix="/api",
    tags=["Proxy"],
)


PROXY_METHODS = [
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "OPTIONS",
    "HEAD",
]


@router.api_route(
    "/{service_name}",
    include_in_schema=False,
    methods=PROXY_METHODS,
)
@router.api_route(
    "/{service_name}/{path:path}",
    include_in_schema=False,
    methods=PROXY_METHODS,
)
async def proxy_request(
    request: Request,
    service_name: str,
    rate_limit_decision: Annotated[
        RateLimitDecision,
        Depends(enforce_proxy_rate_limit),
    ],
    authorization_check: Annotated[
        None,
        Depends(
            enforce_proxy_authorization
        ),
    ],
    path: str = "",
) -> Response:
    try:
        base_url = get_service_base_url(
            service_name
        )
    except UnknownServiceError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc

    target_url = (
        f"{base_url.rstrip('/')}/"
        f"{path.lstrip('/')}"
    )

    request_body = await request.body()

    outgoing_headers = filter_request_headers(
        request.headers
    )

    request_id = getattr(
        request.state,
        "request_id",
        None,
    )

    if request_id is not None:
        outgoing_headers[
            "x-request-id"
        ] = request_id

    if request.client is not None:
        outgoing_headers["x-forwarded-for"] = (
            request.client.host
        )

    outgoing_headers["x-forwarded-proto"] = (
        request.url.scheme
    )

    original_host = request.headers.get(
        "host"
    )

    if original_host:
        outgoing_headers["x-forwarded-host"] = (
            original_host
        )

    http_client: httpx.AsyncClient = (
        request.app.state.http_client
    )

    upstream_started_at = (
        perf_counter()
    )

    try:
        upstream_response = (
            await http_client.request(
                method=request.method,
                url=target_url,
                params=list(
                    request.query_params.multi_items()
                ),
                headers=outgoing_headers,
                content=request_body,
            )
        )

    except httpx.TimeoutException as exc:
        record_upstream_metric_best_effort(
            request=request,
            service=service_name,
            outcome="timeout",
            duration_seconds=(
                perf_counter()
                - upstream_started_at
            ),
        )

        raise HTTPException(
            status_code=504,
            detail="Upstream service timeout",
        ) from exc

    except httpx.RequestError as exc:
        record_upstream_metric_best_effort(
            request=request,
            service=service_name,
            outcome="unavailable",
            duration_seconds=(
                perf_counter()
                - upstream_started_at
            ),
        )

        raise HTTPException(
            status_code=502,
            detail=(
                "Upstream service unavailable"
            ),
        ) from exc

    record_upstream_metric_best_effort(
        request=request,
        service=service_name,
        outcome=status_class(
            upstream_response.status_code
        ),
        duration_seconds=(
            perf_counter()
            - upstream_started_at
        ),
    )

    response_headers = (
        filter_response_headers(
            upstream_response.headers
        )
    )

    response_headers.update(
        build_rate_limit_headers(
            rate_limit_decision
        )
    )

    return Response(
        content=upstream_response.content,
        status_code=(
            upstream_response.status_code
        ),
        headers=response_headers,
    )

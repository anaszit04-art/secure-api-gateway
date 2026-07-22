import httpx

from fastapi import APIRouter, HTTPException, Request, Response

from gateway.app.proxy.headers import (
    filter_request_headers,
    filter_response_headers,
)
from gateway.app.proxy.registry import (
    UnknownServiceError,
    get_service_base_url,
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
    methods=PROXY_METHODS,
)
@router.api_route(
    "/{service_name}/{path:path}",
    methods=PROXY_METHODS,
)
async def proxy_request(
    request: Request,
    service_name: str,
    path: str = "",
) -> Response:
    try:
        base_url = get_service_base_url(service_name)
    except UnknownServiceError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc

    target_url = (
        f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    )

    request_body = await request.body()

    outgoing_headers = filter_request_headers(
        request.headers
    )

    if request.client is not None:
        outgoing_headers["x-forwarded-for"] = (
            request.client.host
        )

    outgoing_headers["x-forwarded-proto"] = (
        request.url.scheme
    )

    original_host = request.headers.get("host")

    if original_host:
        outgoing_headers["x-forwarded-host"] = (
            original_host
        )

    http_client: httpx.AsyncClient = (
        request.app.state.http_client
    )

    try:
        upstream_response = await http_client.request(
            method=request.method,
            url=target_url,
            params=list(
                request.query_params.multi_items()
            ),
            headers=outgoing_headers,
            content=request_body,
        )

    except httpx.TimeoutException as exc:
        raise HTTPException(
            status_code=504,
            detail="Upstream service timeout",
        ) from exc

    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=502,
            detail="Upstream service unavailable",
        ) from exc

    return Response(
        content=upstream_response.content,
        status_code=upstream_response.status_code,
        headers=filter_response_headers(
            upstream_response.headers
        ),
    )

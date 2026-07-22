import httpx


def create_http_client() -> httpx.AsyncClient:
    timeout = httpx.Timeout(
        connect=2.0,
        read=5.0,
        write=5.0,
        pool=2.0,
    )

    return httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=False,
        headers={
            "Accept-Encoding": "identity",
        },
    )

from gateway.app.proxy.headers import (
    filter_request_headers,
    filter_response_headers,
)


def test_request_header_filter_removes_unsafe_headers() -> None:
    incoming_headers = {
        "Host": "127.0.0.1:8000",
        "Connection": "keep-alive, X-Temporary",
        "X-Temporary": "remove-me",
        "Content-Length": "42",
        "Accept-Encoding": "gzip",
        "Forwarded": "for=attacker",
        "X-Forwarded-For": "203.0.113.10",
        "X-Forwarded-Host": "evil.example",
        "X-Forwarded-Proto": "https",
        "X-Real-IP": "203.0.113.10",
        "X-Role": "admin",
        "X-User-Role": "admin",
        "X-Permission": "proxy:service-a:write",
        "X-Authorization-Role": "admin",
        "X-Request-ID": "client-controlled-id",
        "Authorization": "Bearer example-token",
        "Content-Type": "application/json",
    }

    filtered_headers = filter_request_headers(
        incoming_headers
    )

    filtered_names = {
        name.lower()
        for name in filtered_headers
    }

    assert "host" not in filtered_names
    assert "connection" not in filtered_names
    assert "x-temporary" not in filtered_names
    assert "content-length" not in filtered_names
    assert "accept-encoding" not in filtered_names
    assert "forwarded" not in filtered_names
    assert "x-forwarded-for" not in filtered_names
    assert "x-forwarded-host" not in filtered_names
    assert "x-forwarded-proto" not in filtered_names
    assert "x-real-ip" not in filtered_names

    assert "x-role" not in filtered_names
    assert "x-user-role" not in filtered_names
    assert "x-permission" not in filtered_names
    assert (
        "x-authorization-role"
        not in filtered_names
    )

    assert "x-request-id" not in filtered_names

    assert filtered_headers["Authorization"] == (
        "Bearer example-token"
    )
    assert filtered_headers["Content-Type"] == (
        "application/json"
    )


def test_response_header_filter_removes_proxy_headers() -> None:
    upstream_headers = {
        "Connection": "keep-alive, X-Temporary",
        "X-Temporary": "remove-me",
        "Transfer-Encoding": "chunked",
        "Content-Length": "100",
        "Content-Encoding": "gzip",
        "Date": "Tue, 21 Jul 2026 11:00:00 GMT",
        "Server": "upstream-server",
        "Content-Type": "application/json",
        "X-Request-ID": "request-123",
    }

    filtered_headers = filter_response_headers(
        upstream_headers
    )

    filtered_names = {
        name.lower()
        for name in filtered_headers
    }

    assert "connection" not in filtered_names
    assert "x-temporary" not in filtered_names
    assert "transfer-encoding" not in filtered_names
    assert "content-length" not in filtered_names
    assert "content-encoding" not in filtered_names
    assert "date" not in filtered_names
    assert "server" not in filtered_names

    assert filtered_headers["Content-Type"] == (
        "application/json"
    )
    assert "x-request-id" not in filtered_names

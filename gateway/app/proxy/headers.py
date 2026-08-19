from collections.abc import Mapping


HOP_BY_HOP_HEADERS = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)


SPOOFABLE_FORWARDING_HEADERS = frozenset(
    {
        "forwarded",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-real-ip",
    }
)


SPOOFABLE_AUTHORIZATION_HEADERS = frozenset(
    {
        "x-role",
        "x-user-role",
        "x-permission",
        "x-authorization-role",
    }
)


def get_connection_header_tokens(
    headers: Mapping[str, str],
) -> set[str]:
    """
    Return the header names declared inside the Connection header.

    HTTP header names are case-insensitive. The function therefore
    compares every name in lowercase instead of using headers.get()
    with a fixed casing.
    """
    connection_values = [
        value
        for name, value in headers.items()
        if name.lower() == "connection"
    ]

    tokens: set[str] = set()

    for connection_value in connection_values:
        tokens.update(
            token.strip().lower()
            for token in connection_value.split(",")
            if token.strip()
        )

    return tokens


def filter_request_headers(
    headers: Mapping[str, str],
) -> dict[str, str]:
    blocked_headers = (
        set(HOP_BY_HOP_HEADERS)
        | set(SPOOFABLE_FORWARDING_HEADERS)
        | set(SPOOFABLE_AUTHORIZATION_HEADERS)
        | get_connection_header_tokens(headers)
        | {
            "host",
            "content-length",
            "accept-encoding",
        }
    )

    return {
        name: value
        for name, value in headers.items()
        if name.lower() not in blocked_headers
    }


def filter_response_headers(
    headers: Mapping[str, str],
) -> dict[str, str]:
    blocked_headers = (
        set(HOP_BY_HOP_HEADERS)
        | get_connection_header_tokens(headers)
        | {
            "content-length",
            "content-encoding",
            "date",
            "server",
        }
    )

    return {
        name: value
        for name, value in headers.items()
        if name.lower() not in blocked_headers
    }

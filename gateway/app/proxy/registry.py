from __future__ import annotations

import os

from typing import Final
from urllib.parse import urlsplit


SERVICE_DEFINITIONS: Final[
    dict[str, tuple[str, str]]
] = {
    "service-a": (
        "SERVICE_A_URL",
        "http://127.0.0.1:8001",
    ),
    "service-b": (
        "SERVICE_B_URL",
        "http://127.0.0.1:8002",
    ),
}


ALLOWED_UPSTREAM_SCHEMES: Final[
    frozenset[str]
] = frozenset(
    {
        "http",
        "https",
    }
)


class UnknownServiceError(LookupError):
    """Raised when a requested service is not registered."""


class InvalidServiceConfigurationError(
    RuntimeError
):
    """
    Raised when a registered upstream URL is invalid.
    """


def _validate_service_base_url(
    *,
    service_name: str,
    value: str,
) -> str:
    normalized = value.strip()

    if not normalized:
        raise InvalidServiceConfigurationError(
            "Empty URL configured for service: "
            f"{service_name}"
        )

    if any(
        character.isspace()
        for character in normalized
    ):
        raise InvalidServiceConfigurationError(
            "Invalid URL configured for service: "
            f"{service_name}"
        )

    try:
        parsed = urlsplit(
            normalized
        )

        # Accessing port also validates malformed
        # numeric/out-of-range port values.
        _ = parsed.port

    except ValueError as exc:
        raise InvalidServiceConfigurationError(
            "Invalid URL configured for service: "
            f"{service_name}"
        ) from exc

    if (
        parsed.scheme
        not in ALLOWED_UPSTREAM_SCHEMES
    ):
        raise InvalidServiceConfigurationError(
            "Unsupported URL scheme configured "
            f"for service: {service_name}"
        )

    if not parsed.hostname:
        raise InvalidServiceConfigurationError(
            "Missing hostname configured for "
            f"service: {service_name}"
        )

    if (
        parsed.username is not None
        or parsed.password is not None
    ):
        raise InvalidServiceConfigurationError(
            "Upstream credentials are not allowed "
            f"for service: {service_name}"
        )

    if parsed.query:
        raise InvalidServiceConfigurationError(
            "Upstream query strings are not allowed "
            f"for service: {service_name}"
        )

    if parsed.fragment:
        raise InvalidServiceConfigurationError(
            "Upstream fragments are not allowed "
            f"for service: {service_name}"
        )

    return normalized.rstrip("/")


def get_service_base_url(
    service_name: str,
) -> str:
    try:
        (
            environment_variable,
            default_url,
        ) = SERVICE_DEFINITIONS[
            service_name
        ]

    except KeyError as exc:
        raise UnknownServiceError(
            f"Unknown service: {service_name}"
        ) from exc

    configured_url = os.getenv(
        environment_variable,
        default_url,
    )

    return _validate_service_base_url(
        service_name=service_name,
        value=configured_url,
    )


def is_registered_service(
    service_name: str,
) -> bool:
    """
    Return whether a service name belongs to the
    Gateway's explicit upstream allow-list.
    """

    return (
        service_name
        in SERVICE_DEFINITIONS
    )

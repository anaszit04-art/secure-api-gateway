import os
from typing import Final


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


class UnknownServiceError(LookupError):
    """Raised when a requested service is not registered."""


class InvalidServiceConfigurationError(RuntimeError):
    """Raised when a registered service has an invalid URL."""


def get_service_base_url(service_name: str) -> str:
    try:
        environment_variable, default_url = (
            SERVICE_DEFINITIONS[service_name]
        )
    except KeyError as exc:
        raise UnknownServiceError(
            f"Unknown service: {service_name}"
        ) from exc

    configured_url = os.getenv(
        environment_variable,
        default_url,
    ).strip()

    if not configured_url:
        raise InvalidServiceConfigurationError(
            f"Empty URL configured for service: {service_name}"
        )

    return configured_url.rstrip("/")

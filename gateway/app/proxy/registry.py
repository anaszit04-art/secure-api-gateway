from typing import Final


SERVICE_REGISTRY: Final[dict[str, str]] = {
    "service-a": "http://127.0.0.1:8001",
    "service-b": "http://127.0.0.1:8002",
}


class UnknownServiceError(LookupError):
    """Raised when a requested service is not registered."""


def get_service_base_url(service_name: str) -> str:
    try:
        return SERVICE_REGISTRY[service_name]
    except KeyError as exc:
        raise UnknownServiceError(
            f"Unknown service: {service_name}"
        ) from exc

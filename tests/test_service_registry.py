import pytest

from gateway.app.proxy.registry import (
    UnknownServiceError,
    get_service_base_url,
)


def test_registry_resolves_service_a() -> None:
    result = get_service_base_url("service-a")

    assert result == "http://127.0.0.1:8001"


def test_registry_resolves_service_b() -> None:
    result = get_service_base_url("service-b")

    assert result == "http://127.0.0.1:8002"


def test_registry_rejects_unknown_service() -> None:
    with pytest.raises(
        UnknownServiceError,
        match="Unknown service: service-c",
    ):
        get_service_base_url("service-c")

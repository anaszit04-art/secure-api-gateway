import pytest

from gateway.app.proxy.registry import (
    InvalidServiceConfigurationError,
    UnknownServiceError,
    get_service_base_url,
)


def test_registry_resolves_service_a_with_default_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(
        "SERVICE_A_URL",
        raising=False,
    )

    result = get_service_base_url("service-a")

    assert result == "http://127.0.0.1:8001"


def test_registry_resolves_service_b_with_default_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(
        "SERVICE_B_URL",
        raising=False,
    )

    result = get_service_base_url("service-b")

    assert result == "http://127.0.0.1:8002"


def test_registry_uses_service_a_environment_variable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "SERVICE_A_URL",
        "http://service-a:8001",
    )

    result = get_service_base_url("service-a")

    assert result == "http://service-a:8001"


def test_registry_uses_service_b_environment_variable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "SERVICE_B_URL",
        "http://service-b:8002",
    )

    result = get_service_base_url("service-b")

    assert result == "http://service-b:8002"


def test_registry_removes_trailing_slash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "SERVICE_A_URL",
        "http://service-a:8001/",
    )

    result = get_service_base_url("service-a")

    assert result == "http://service-a:8001"


def test_registry_rejects_empty_service_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "SERVICE_A_URL",
        "   ",
    )

    with pytest.raises(
        InvalidServiceConfigurationError,
        match="Empty URL configured for service: service-a",
    ):
        get_service_base_url("service-a")


def test_registry_rejects_unknown_service() -> None:
    with pytest.raises(
        UnknownServiceError,
        match="Unknown service: service-c",
    ):
        get_service_base_url("service-c")

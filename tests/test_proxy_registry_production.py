from __future__ import annotations

import pytest

from gateway.app.proxy.registry import (
    InvalidServiceConfigurationError,
    get_service_base_url,
)


def test_upstream_uses_default_when_environment_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(
        "SERVICE_A_URL",
        raising=False,
    )

    assert get_service_base_url(
        "service-a"
    ) == "http://127.0.0.1:8001"


def test_valid_upstream_override_is_normalized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "SERVICE_A_URL",
        "https://service-a.internal:8443/",
    )

    assert get_service_base_url(
        "service-a"
    ) == "https://service-a.internal:8443"


@pytest.mark.parametrize(
    "value",
    [
        "",
        "ftp://service-a:8001",
        "service-a:8001",
        "http://user:password@service-a:8001",
        "http://service-a:8001?debug=true",
        "http://service-a:8001#fragment",
        "http://bad host:8001",
    ],
)
def test_invalid_upstream_configuration_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    value: str,
) -> None:
    monkeypatch.setenv(
        "SERVICE_A_URL",
        value,
    )

    with pytest.raises(
        InvalidServiceConfigurationError
    ):
        get_service_base_url(
            "service-a"
        )

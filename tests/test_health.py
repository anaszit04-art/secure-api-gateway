from uuid import UUID

from fastapi.testclient import TestClient

from gateway.app.main import app


client = TestClient(app)


def assert_valid_request_id(
    request_id: str,
) -> None:
    parsed = UUID(
        request_id
    )

    assert str(parsed) == request_id
    assert parsed.version == 4


def test_health_returns_status_ok() -> None:
    response = client.get(
        "/health"
    )

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
    }

    request_id = response.headers[
        "x-request-id"
    ]

    assert_valid_request_id(
        request_id
    )


def test_client_cannot_control_request_id() -> None:
    client_request_id = (
        "client-controlled-request-id"
    )

    response = client.get(
        "/health",
        headers={
            "X-Request-ID": (
                client_request_id
            ),
        },
    )

    assert response.status_code == 200

    gateway_request_id = (
        response.headers[
            "x-request-id"
        ]
    )

    assert gateway_request_id != (
        client_request_id
    )

    assert_valid_request_id(
        gateway_request_id
    )

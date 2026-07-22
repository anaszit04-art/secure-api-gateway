from fastapi.testclient import TestClient

from microservices.service_a.app.main import app


client = TestClient(app)


def test_service_a_health_returns_ok() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "service-a",
    }


def test_service_a_ping_returns_pong() -> None:
    response = client.get("/ping")

    assert response.status_code == 200
    assert response.json() == {
        "message": "pong",
        "service": "service-a",
    }


def test_service_a_info_returns_public_information() -> None:
    response = client.get("/info")

    assert response.status_code == 200
    assert response.json() == {
        "name": "service-a",
        "version": "0.1.0",
        "purpose": "Microservice fictif de démonstration",
    }


def test_service_a_echo_returns_received_payload() -> None:
    payload = {
        "message": "Bonjour Service A",
        "priority": 2,
        "enabled": True,
    }

    response = client.post("/echo", json=payload)

    assert response.status_code == 200
    assert response.json() == {
        "service": "service-a",
        "received": payload,
    }


def test_service_a_echo_rejects_missing_body() -> None:
    response = client.post("/echo")

    assert response.status_code == 422

from fastapi.testclient import TestClient

from microservices.service_b.app.main import app


client = TestClient(app)


def test_service_b_health_returns_ok() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "service-b",
    }


def test_service_b_ping_returns_pong() -> None:
    response = client.get("/ping")

    assert response.status_code == 200
    assert response.json() == {
        "message": "pong",
        "service": "service-b",
    }


def test_service_b_products_respect_limit() -> None:
    response = client.get("/products", params={"limit": 2})

    assert response.status_code == 200

    body = response.json()

    assert body["service"] == "service-b"
    assert body["count"] == 2
    assert len(body["products"]) == 2


def test_service_b_rejects_invalid_limit() -> None:
    response = client.get("/products", params={"limit": 0})

    assert response.status_code == 422


def test_service_b_returns_product_by_id() -> None:
    response = client.get("/products/2")

    assert response.status_code == 200
    assert response.json() == {
        "service": "service-b",
        "product": {
            "id": 2,
            "name": "Souris sans fil",
            "price": 350.0,
            "available": True,
        },
    }


def test_service_b_returns_404_for_unknown_product() -> None:
    response = client.get("/products/999")

    assert response.status_code == 404
    assert response.json() == {
        "detail": "Product not found",
    }


def test_service_b_echo_returns_received_payload() -> None:
    payload = {
        "action": "proxy-test",
        "enabled": True,
    }

    response = client.post("/echo", json=payload)

    assert response.status_code == 200
    assert response.json() == {
        "service": "service-b",
        "received": payload,
    }

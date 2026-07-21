from typing import Any

from fastapi import Body, FastAPI


app = FastAPI(
    title="Service A",
    description=(
        "Premier microservice fictif utilisé pour tester "
        "le routage de l'API Gateway."
    ),
    version="0.1.0",
)


@app.get("/health", tags=["System"])
async def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "service-a",
    }


@app.get("/ping", tags=["Diagnostic"])
async def ping() -> dict[str, str]:
    return {
        "message": "pong",
        "service": "service-a",
    }


@app.get("/info", tags=["Service"])
async def get_service_info() -> dict[str, str]:
    return {
        "name": "service-a",
        "version": "0.1.0",
        "purpose": "Microservice fictif de démonstration",
    }


@app.post("/echo", tags=["Service"])
async def echo_payload(
    payload: dict[str, Any] = Body(...),
) -> dict[str, Any]:
    return {
        "service": "service-a",
        "received": payload,
    }

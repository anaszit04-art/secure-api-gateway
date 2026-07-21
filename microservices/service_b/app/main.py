from typing import Any

from fastapi import Body, FastAPI, HTTPException, Query


app = FastAPI(
    title="Service B",
    description=(
        "Deuxième microservice fictif utilisé pour tester "
        "le routage et la transmission des paramètres."
    ),
    version="0.1.0",
)


PRODUCTS: list[dict[str, Any]] = [
    {
        "id": 1,
        "name": "Clavier mécanique",
        "price": 790.0,
        "available": True,
    },
    {
        "id": 2,
        "name": "Souris sans fil",
        "price": 350.0,
        "available": True,
    },
    {
        "id": 3,
        "name": "Écran 27 pouces",
        "price": 2400.0,
        "available": False,
    },
]


@app.get("/health", tags=["System"])
async def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "service-b",
    }


@app.get("/ping", tags=["Diagnostic"])
async def ping() -> dict[str, str]:
    return {
        "message": "pong",
        "service": "service-b",
    }


@app.get("/products", tags=["Products"])
async def list_products(
    limit: int = Query(default=10, ge=1, le=100),
) -> dict[str, Any]:
    selected_products = PRODUCTS[:limit]

    return {
        "service": "service-b",
        "count": len(selected_products),
        "products": selected_products,
    }


@app.get("/products/{product_id}", tags=["Products"])
async def get_product(product_id: int) -> dict[str, Any]:
    for product in PRODUCTS:
        if product["id"] == product_id:
            return {
                "service": "service-b",
                "product": product,
            }

    raise HTTPException(
        status_code=404,
        detail="Product not found",
    )


@app.post("/echo", tags=["Service"])
async def echo_payload(
    payload: dict[str, Any] = Body(...),
) -> dict[str, Any]:
    return {
        "service": "service-b",
        "received": payload,
    }

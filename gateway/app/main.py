from fastapi import FastAPI


app = FastAPI(
    title="Secure API Gateway",
    description="API Gateway avec JWT, rate limiting et reverse proxy.",
    version="0.1.0",
)


@app.get("/health", tags=["System"])
async def health() -> dict[str, str]:
    return {"status": "ok"}

from fastapi import FastAPI, HTTPException

from app.api.v1.endpoints.health import router as health_router
from app.api.v1.endpoints.metrics import router as metrics_router
from app.gateway.router import router as gateway_router
from app.core.middleware import MetricsMiddleware

app = FastAPI(
    title="API Gateway",
    description="A FastAPI-based API Gateway service",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add metrics middleware
app.add_middleware(MetricsMiddleware)

# Include health endpoints
app.include_router(health_router, prefix="/api/v1")

# Include metrics endpoints  
app.include_router(metrics_router, prefix="/api/v1")

# Include gateway router (should be last to catch all remaining routes)
app.include_router(gateway_router)


@app.get("/")
async def read_root():
    return {"message": "Welcome to the API Gateway"}


@app.get("/items/{item_id}")
async def read_item(item_id: int):
    if item_id < 0:
        raise HTTPException(status_code=400, detail="Invalid item ID")
    return {"item_id": item_id}
import logging
from fastapi import FastAPI, HTTPException

from app.api.v1.endpoints.health import router as health_router
from app.api.v1.endpoints.metrics import router as metrics_router
from app.gateway.router import router as gateway_router
from app.core.middleware import MetricsMiddleware
from app.config import get_config, get_services_config
from app.services.registry import ServiceRegistry
from app.models.service import ServiceDefinition, ServiceInstance

logger = logging.getLogger(__name__)

async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Load configuration
    config = get_config()
    app.state.config = config
    
    # Load services configuration
    services_config = get_services_config()
    
    # Initialize service registry with services from config
    registry = ServiceRegistry()
    if "services" in services_config:
        for service_name, service_data in services_config["services"].items():
            try:
                # Create service definition from YAML config
                service = ServiceDefinition(
                    name=service_data["name"],
                    description=service_data.get("description", ""),
                    version=service_data.get("version", "1.0.0"),
                    load_balancer=service_data.get("load_balancer", "round_robin"),
                    health_check=service_data.get("health_check", {}),
                    timeouts=service_data.get("timeouts", {}),
                    headers=service_data.get("headers", {}),
                    retry=service_data.get("retry", {}),
                    circuit_breaker=service_data.get("circuit_breaker", {})
                )
                
                # Register service instances
                for instance_data in service_data.get("instances", []):
                    instance = ServiceInstance(
                        id=instance_data["id"],
                        url=instance_data["url"],
                        weight=instance_data.get("weight", 1),
                        metadata=instance_data.get("metadata", {})
                    )
                    registry.register_service(service, instance)
                    
            except Exception as e:
                logger.error(f"Failed to register service {service_name}: {e}")
    
    app.state.service_registry = registry
    
    # Start health checking
    await registry.start_health_checking()
    
    yield
    
    # Cleanup
    await registry.stop_health_checking()


app = FastAPI(
    title="GCA API Gateway",
    description="A high-performance API Gateway for microservices",
    version="0.1.0",
    lifespan=lifespan,
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
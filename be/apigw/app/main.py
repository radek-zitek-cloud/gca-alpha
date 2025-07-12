"""
Main FastAPI application entry point.

This module initializes the API Gateway with proper configuration,
middleware, routing, and service registry setup.
"""

import logging
from fastapi import FastAPI, HTTPException

from app.api.v1.router import api_router
from app.core.rbac import rbac_admin, rbac_engine
from app.gateway.router_new import router as gateway_router, proxy_router
from app.core.middleware import MetricsMiddleware
from app.middleware.jwt_middleware import JWTAuthMiddleware, RoleBasedAccessMiddleware
from app.middleware.api_key_middleware import APIKeyAuthMiddleware, create_api_key_middleware_config
from app.middleware.auth import AuthConfig
from app.config.jwt_config import validate_jwt_config
from app.config.settings import ConfigLoader, get_services_config
from app.config.logging import setup_logging
from app.services.registry import ServiceRegistry
from app.models.service import ServiceDefinition, ServiceInstance, LoadBalancerType

logger = logging.getLogger(__name__)


async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Load configuration using new config system
    config_loader = ConfigLoader()
    config = config_loader.load_config()
    app.state.config = config
    
    # Setup logging using new logging system
    setup_logging(
        log_level=config.server.log_level.upper(),
        log_format="text",  # Could be made configurable
        enable_access_log=config.server.access_log
    )
    
    # Load services configuration
    services_config = get_services_config()
    
    # Initialize service registry with services from config
    registry = ServiceRegistry()
    if "services" in services_config:
        for service_name, service_data in services_config["services"].items():
            try:
                # Create service instances from YAML config
                instances = []
                for instance_data in service_data.get("instances", []):
                    instance = ServiceInstance(
                        id=instance_data["id"],
                        url=instance_data["url"],
                        weight=instance_data.get("weight", 1),
                        metadata=instance_data.get("metadata", {})
                    )
                    instances.append(instance)
                
                # Create service definition from YAML config
                load_balancer_str = service_data.get("load_balancer", "round_robin")
                # Convert string to enum if needed
                if isinstance(load_balancer_str, str):
                    load_balancer_type = LoadBalancerType(load_balancer_str)
                else:
                    load_balancer_type = load_balancer_str
                
                service = ServiceDefinition(
                    name=service_data["name"],
                    description=service_data.get("description", ""),
                    version=service_data.get("version", "1.0.0"),
                    instances=instances,
                    load_balancer_type=load_balancer_type,
                    health_check=service_data.get("health_check", {}),
                    timeout_config=service_data.get("timeouts", {}),
                    headers=service_data.get("headers", {}),
                    retry_config=service_data.get("retry", {}),
                    circuit_breaker=service_data.get("circuit_breaker", {})
                )
                
                # Register the complete service
                await registry.register_service(service)
                    
            except Exception as e:
                logger.error(f"Failed to register service {service_name}: {e}")
    
    app.state.service_registry = registry
    
    # Initialize RBAC system with existing roles and policies
    try:
        # The system is already initialized with default roles
        roles = rbac_engine.role_manager.list_roles()
        policies = rbac_engine.policy_manager.list_policies()
        logger.info(f"RBAC system initialized with {len(roles)} roles and {len(policies)} policies")
    except Exception as e:
        logger.error(f"Failed to check RBAC system status: {e}")
    
    yield
    
    # Cleanup
    await registry.cleanup()


app = FastAPI(
    title="GCA API Gateway",
    description="A high-performance API Gateway for microservices with JWT Authentication",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configure authentication
auth_config = AuthConfig.from_jwt_settings()

# Validate JWT configuration
if not validate_jwt_config():
    logger.warning("JWT configuration has issues - please review for production use")

# Configure API key middleware
api_key_config = create_api_key_middleware_config(
    enable_for_all_api_routes=True,
    require_for_gateway=True,
    require_for_weather=True,
    require_for_metrics=True,
    require_for_admin=True
)

# Add authentication middleware (order matters!)
app.add_middleware(RoleBasedAccessMiddleware)
app.add_middleware(JWTAuthMiddleware, config=auth_config)
app.add_middleware(APIKeyAuthMiddleware, **api_key_config)

# Add metrics middleware
app.add_middleware(MetricsMiddleware)

# Include all API endpoints via main router
app.include_router(api_router)

# Include gateway management endpoints
app.include_router(gateway_router)

# Include proxy router (should be last to catch all remaining routes)
app.include_router(proxy_router)


@app.get("/")
async def read_root():
    return {"message": "Welcome to the API Gateway"}


@app.get("/items/{item_id}")
async def read_item(item_id: int):
    if item_id < 0:
        raise HTTPException(status_code=400, detail="Invalid item ID")
    return {"item_id": item_id}
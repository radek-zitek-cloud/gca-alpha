"""
Main gateway router implementation.

This module provides the main routing logic for the API Gateway,
utilizing the modular proxy, routing, and plugin components.
"""

import time
from typing import Dict, Any, Optional
from fastapi import APIRouter, Request, Response, HTTPException, status, Depends

from app.models.service import ServiceDefinition, ServiceInstance
from app.services.registry import ServiceRegistry
from app.gateway.proxy import UpstreamHTTPClient
from app.gateway.proxy.load_balancer import load_balancer
from app.gateway.routing.path_matcher import path_matcher, ServicePathExtractor
from app.config import get_logger, StructuredLogger

logger = StructuredLogger(__name__)


# Router for gateway management endpoints (with /gateway prefix)
router = APIRouter(prefix="/gateway", tags=["gateway"])

# Router for proxy functionality (no prefix, catch-all)
proxy_router = APIRouter(tags=["proxy"])

# HTTP client for upstream requests
http_client = UpstreamHTTPClient()


def get_service_registry(request: Request) -> ServiceRegistry:
    """Dependency to get the service registry from app state."""
    return request.app.state.service_registry


# Gateway management endpoints

@router.get(
    "/services",
    summary="List available services",
    description="Returns a list of all registered services and their status"
)
async def list_services(service_registry: ServiceRegistry = Depends(get_service_registry)) -> Dict[str, Any]:
    """List all registered services and their current status."""
    services = await service_registry.list_services()
    service_status = {}
    
    for service_name, service in services.items():
        health_status = await service_registry.get_service_health(service_name)
        service_status[service_name] = {
            "name": service.name,
            "description": service.description,
            "version": service.version,
            "instances": len(service.instances),
            "healthy_instances": len([i for i in service.instances if i.healthy]),
            "load_balancer": service.load_balancer_type,
            "health": health_status.dict() if health_status else None
        }
    
    return {
        "total_services": len(services),
        "services": service_status
    }


@router.get(
    "/routing-rules",
    summary="Get routing rules",
    description="Returns current routing rules and configuration"
)
async def get_routing_rules(service_registry: ServiceRegistry = Depends(get_service_registry)) -> Dict[str, Any]:
    """Get current routing rules and configuration."""
    rules = await service_registry.get_routing_rules()
    return {
        "routing_rules": rules,
        "timestamp": time.time()
    }


@router.get(
    "/services/{service_name}",
    summary="Get service details",
    description="Returns detailed information about a specific service"
)
async def get_service_details(service_name: str, service_registry: ServiceRegistry = Depends(get_service_registry)) -> Dict[str, Any]:
    """Get detailed information about a specific service."""
    service = await service_registry.get_service(service_name)
    if not service:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Service '{service_name}' not found"
        )
    
    health_status = await service_registry.get_service_health(service_name)
    
    return {
        "name": service.name,
        "description": service.description,
        "version": service.version,
        "instances": [
            {
                "id": instance.id,
                "url": instance.url,
                "healthy": instance.healthy,
                "weight": instance.weight,
                "metadata": instance.metadata,
                "last_health_check": instance.last_health_check.isoformat() if instance.last_health_check else None
            }
            for instance in service.instances
        ],
        "load_balancer": service.load_balancer_type,
        "health_check": service.health_check,
        "timeout_config": service.timeout_config,
        "headers": service.headers,
        "retry_config": service.retry_config,
        "circuit_breaker": service.circuit_breaker,
        "health": health_status.dict() if health_status else None
    }


@router.post(
    "/services/{service_name}/health-check",
    summary="Trigger health check",
    description="Manually trigger a health check for a specific service"
)
async def trigger_health_check(service_name: str, service_registry: ServiceRegistry = Depends(get_service_registry)) -> Dict[str, Any]:
    """Manually trigger a health check for a specific service."""
    service = await service_registry.get_service(service_name)
    if not service:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Service '{service_name}' not found"
        )
    
    # Trigger health check
    health_results = await service_registry.check_service_health(service_name)
    
    return {
        "service_name": service_name,
        "health_check_timestamp": time.time(),
        "results": health_results
    }


# Main proxy endpoint

@proxy_router.api_route(
    "/{service_path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
    summary="Gateway proxy endpoint",
    description="Forwards requests to upstream services based on routing rules"
)
async def gateway_proxy(request: Request, service_path: str, service_registry: ServiceRegistry = Depends(get_service_registry)) -> Response:
    """
    Main gateway proxy endpoint that forwards requests to upstream services.
    
    This endpoint handles the core gateway functionality:
    1. Extract service name from request path
    2. Find healthy service instance using load balancing
    3. Forward request to upstream service
    4. Return response to client
    """
    start_time = time.time()
    
    try:
        # Extract service name and remaining path
        service_name, remaining_path = ServicePathExtractor.extract_from_path(service_path)
        
        if not service_name:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Could not determine service from path"
            )
        
        # Get service definition
        service = await service_registry.get_service(service_name)
        if not service:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Service '{service_name}' not found"
            )
        
        # Check if service is healthy
        if not await service_registry.is_service_healthy(service_name):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Service '{service_name}' is currently unavailable"
            )
        
        # Select instance using load balancing
        request_context = {
            "client_ip": request.client.host if request.client else "unknown",
            "path": f"/{service_path}",
            "method": request.method
        }
        
        instance = await load_balancer.select_instance(
            service.instances,
            service.load_balancer_type,
            request_context
        )
        
        if not instance:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"No healthy instances available for service '{service_name}'"
            )
        
        # Build upstream URL
        upstream_path = ServicePathExtractor.build_upstream_path("/", remaining_path)
        upstream_url = f"{instance.url.rstrip('/')}{upstream_path}"
        
        # Add query parameters if present
        if request.url.query:
            upstream_url += f"?{request.url.query}"
        
        logger.info(
            f"Proxying request to upstream service",
            service_name=service_name,
            instance_id=instance.id,
            upstream_url=upstream_url,
            method=request.method,
            client_ip=request_context["client_ip"]
        )
        
        # Forward request to upstream service
        response = await http_client.forward_request(request, upstream_url, service, instance)
        
        # Calculate response time
        response_time = (time.time() - start_time) * 1000
        
        # Log successful request
        logger.log_request(
            method=request.method,
            path=f"/{service_path}",
            status_code=response.status_code,
            response_time=response_time,
            client_ip=request_context["client_ip"],
            service_name=service_name,
            instance_id=instance.id
        )
        
        return response
        
    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except Exception as e:
        response_time = (time.time() - start_time) * 1000
        
        logger.error(
            f"Unexpected error in gateway proxy",
            error=str(e),
            path=f"/{service_path}",
            method=request.method,
            response_time_ms=response_time
        )
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal gateway error"
        )


# Background task to periodically check service health
async def periodic_health_check(service_registry: ServiceRegistry):
    """Background task to periodically check the health of all services."""
    import asyncio
    
    while True:
        try:
            services = await service_registry.list_services()
            for service_name in services.keys():
                await service_registry.check_service_health(service_name)
        except Exception as e:
            logger.error(f"Error during periodic health check: {e}")
        
        # Wait before next check (configurable)
        await asyncio.sleep(30)  # Check every 30 seconds


# Health check endpoint for the gateway itself
@router.get("/health", summary="Gateway health check")
async def gateway_health() -> Dict[str, Any]:
    """Check the health of the gateway itself."""
    return {
        "status": "healthy",
        "timestamp": time.time(),
        "version": "0.1.0"
    }


# Metrics endpoint
@router.get("/metrics", summary="Gateway metrics")
async def gateway_metrics(service_registry: ServiceRegistry = Depends(get_service_registry)) -> Dict[str, Any]:
    """Get basic gateway metrics."""
    services = await service_registry.list_services()
    
    total_instances = sum(len(service.instances) for service in services.values())
    healthy_instances = sum(
        len([i for i in service.instances if i.healthy]) 
        for service in services.values()
    )
    
    return {
        "timestamp": time.time(),
        "services": {
            "total": len(services),
            "instances": {
                "total": total_instances,
                "healthy": healthy_instances,
                "unhealthy": total_instances - healthy_instances
            }
        }
    }

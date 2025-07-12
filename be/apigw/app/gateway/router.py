"""
Gateway router for request forwarding and routing logic.

This module contains the core API gateway functionality including
request routing, load balancing, and proxying to upstream services.
"""

import asyncio
import time
from typing import Dict, Any, Optional, List
from urllib.parse import urljoin, urlparse

import httpx
from fastapi import APIRouter, Request, Response, HTTPException, status, Depends
from fastapi.responses import StreamingResponse
from starlette.background import BackgroundTask

from app.models.service import ServiceDefinition, ServiceHealth
from app.services.registry import ServiceRegistry
from app.utils.helpers import extract_service_from_path, build_upstream_url


# Router for gateway management endpoints (with /gateway prefix)
router = APIRouter(prefix="/gateway", tags=["gateway"])

# Router for proxy functionality (no prefix, catch-all)
proxy_router = APIRouter(tags=["proxy"])


def get_service_registry(request: Request) -> ServiceRegistry:
    """Dependency to get the service registry from app state."""
    return request.app.state.service_registry


# Gateway management endpoints - these must come BEFORE the catch-all proxy route

@router.get(
    "/services",
    summary="List available services",
    description="Returns a list of all registered services and their status"
)
async def list_services(service_registry: ServiceRegistry = Depends(get_service_registry)) -> Dict[str, Any]:
    """
    List all registered services and their current status.
    
    Returns:
        Dict: Dictionary of services with their health status
    """
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
    """
    Get current routing rules and configuration.
    
    Returns:
        Dict: Current routing rules
    """
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
    """
    Get detailed information about a specific service.
    
    Args:
        service_name: Name of the service
        
    Returns:
        Dict: Detailed service information
        
    Raises:
        HTTPException: If service is not found
    """
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
    """
    Manually trigger a health check for a specific service.
    
    Args:
        service_name: Name of the service to check
        
    Returns:
        Dict: Health check results
        
    Raises:
        HTTPException: If service is not found
    """
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


# Catch-all proxy route - on the proxy router without prefix


@proxy_router.api_route(
    "/{service_name:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
    summary="Gateway proxy endpoint",
    description="Forwards requests to upstream services based on routing rules"
)
async def gateway_proxy(request: Request, service_name: str, service_registry: ServiceRegistry = Depends(get_service_registry)) -> Response:
    """
    Main gateway proxy endpoint that forwards requests to upstream services.
    
    Args:
        request: The incoming HTTP request
        service_name: The service name extracted from the path
        
    Returns:
        Response: The response from the upstream service
        
    Raises:
        HTTPException: If service is not found or unavailable
    """
    # Extract the actual service name and remaining path
    path_parts = service_name.split('/', 1)
    actual_service_name = path_parts[0]
    remaining_path = path_parts[1] if len(path_parts) > 1 else ""
    
    # Get service definition from registry
    service = await service_registry.get_service(actual_service_name)
    if not service:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Service '{actual_service_name}' not found"
        )
    
    # Check if service is healthy
    if not await service_registry.is_service_healthy(actual_service_name):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Service '{actual_service_name}' is currently unavailable"
        )
    
    # Get the best available instance (load balancing)
    instance = await service_registry.get_best_instance(actual_service_name)
    if not instance:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"No healthy instances available for service '{actual_service_name}'"
        )
    
    # Build the upstream URL
    upstream_url = build_upstream_url(instance["url"], remaining_path, request.url.query)
    
    # Forward the request
    try:
        response = await _forward_request(request, upstream_url, service)
        return response
    except httpx.RequestError as e:
        # Mark instance as potentially unhealthy
        await service_registry.mark_instance_unhealthy(actual_service_name, instance["id"])
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to connect to upstream service: {str(e)}"
        )
    except httpx.TimeoutException:
        await service_registry.mark_instance_unhealthy(actual_service_name, instance["id"])
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Request to upstream service timed out"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal gateway error: {str(e)}"
        )


async def _forward_request(request: Request, upstream_url: str, service: ServiceDefinition) -> Response:
    """
    Forward the HTTP request to the upstream service.
    
    Args:
        request: The original request
        upstream_url: The URL of the upstream service
        service: Service definition with configuration
        
    Returns:
        Response: The response from the upstream service
    """
    # Prepare headers
    headers = dict(request.headers)
    
    # Remove hop-by-hop headers
    hop_by_hop_headers = {
        'connection', 'keep-alive', 'proxy-authenticate',
        'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade'
    }
    headers = {k: v for k, v in headers.items() if k.lower() not in hop_by_hop_headers}
    
    # Add forwarding headers
    headers['X-Forwarded-For'] = request.client.host if request.client else 'unknown'
    headers['X-Forwarded-Proto'] = request.url.scheme
    headers['X-Forwarded-Host'] = request.headers.get('host', 'unknown')
    
    # Add custom service headers if configured
    if service.headers:
        headers.update(service.headers)
    
    # Get request body
    body = await request.body()
    
    # Configure timeout from service definition
    timeout = httpx.Timeout(
        connect=service.timeout_config.get("connect", 5.0),
        read=service.timeout_config.get("read", 30.0),
        write=service.timeout_config.get("write", 5.0),
        pool=service.timeout_config.get("pool", 5.0)
    )
    
    # Make the request to upstream service
    async with httpx.AsyncClient(timeout=timeout) as client:
        upstream_response = await client.request(
            method=request.method,
            url=upstream_url,
            headers=headers,
            content=body,
            params=request.query_params
        )
    
    # Prepare response headers
    response_headers = dict(upstream_response.headers)
    
    # Remove hop-by-hop headers from response
    response_headers = {
        k: v for k, v in response_headers.items() 
        if k.lower() not in hop_by_hop_headers
    }
    
    # Add gateway headers
    response_headers['X-Gateway-Service'] = service.name
    response_headers['X-Gateway-Instance'] = upstream_url
    response_headers['X-Gateway-Timestamp'] = str(int(time.time()))
    
    # Create the response
    return Response(
        content=upstream_response.content,
        status_code=upstream_response.status_code,
        headers=response_headers,
        media_type=upstream_response.headers.get('content-type')
    )


# Background task to periodically check service health
async def periodic_health_check(service_registry: ServiceRegistry):
    """Background task to periodically check the health of all services."""
    while True:
        try:
            services = await service_registry.list_services()
            for service_name in services.keys():
                await service_registry.check_service_health(service_name)
        except Exception as e:
            # Log error but continue
            print(f"Error during periodic health check: {e}")
        
        # Wait before next check (configurable)
        await asyncio.sleep(30)  # Check every 30 seconds


# Note: Router startup/shutdown events are deprecated in FastAPI
# These should be handled in main.py app startup/shutdown events
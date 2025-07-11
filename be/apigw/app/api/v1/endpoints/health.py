"""
Health check endpoint for the API Gateway.

This module provides health check functionality to monitor the status
of the API Gateway service and its dependencies.
"""

import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel


class HealthStatus(BaseModel):
    """Health status response model."""
    status: str
    timestamp: datetime
    version: str
    uptime_seconds: float
    environment: str
    dependencies: Optional[Dict[str, Dict[str, Any]]] = None


class DetailedHealthStatus(HealthStatus):
    """Detailed health status response model."""
    service_name: str
    build_info: Optional[Dict[str, str]] = None
    system_info: Optional[Dict[str, Any]] = None


# Track service start time for uptime calculation
_start_time = time.time()

# Router for health endpoints
router = APIRouter(prefix="/health", tags=["health"])


@router.get(
    "/",
    response_model=HealthStatus,
    summary="Basic health check",
    description="Returns basic health status of the API Gateway service"
)
async def health_check() -> HealthStatus:
    """
    Basic health check endpoint.
    
    Returns:
        HealthStatus: Basic health information including status, timestamp, and uptime.
    """
    current_time = time.time()
    uptime = current_time - _start_time
    
    return HealthStatus(
        status="healthy",
        timestamp=datetime.now(timezone.utc),
        version="1.0.0",  # This should be dynamically set from config/environment
        uptime_seconds=uptime,
        environment="development"  # This should be dynamically set from config
    )


@router.get(
    "/detailed",
    response_model=DetailedHealthStatus,
    summary="Detailed health check",
    description="Returns detailed health status including system and dependency information"
)
async def detailed_health_check() -> DetailedHealthStatus:
    """
    Detailed health check endpoint.
    
    Returns:
        DetailedHealthStatus: Comprehensive health information including system details.
    """
    import platform
    import psutil
    
    current_time = time.time()
    uptime = current_time - _start_time
    
    # System information
    system_info = {
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "cpu_usage_percent": psutil.cpu_percent(interval=1),
        "memory_usage_percent": psutil.virtual_memory().percent,
        "disk_usage_percent": psutil.disk_usage('/').percent,
    }
    
    # Build information (would typically come from CI/CD or version file)
    build_info = {
        "build_date": "2025-07-11",  # This should be set during build
        "commit_hash": "unknown",    # This should be set from git during build
        "branch": "main"             # This should be set during build
    }
    
    # Check dependencies (extend this based on your actual dependencies)
    dependencies = await _check_dependencies()
    
    return DetailedHealthStatus(
        status="healthy" if _all_dependencies_healthy(dependencies) else "degraded",
        timestamp=datetime.now(timezone.utc),
        version="1.0.0",
        uptime_seconds=uptime,
        environment="development",
        service_name="API Gateway",
        build_info=build_info,
        system_info=system_info,
        dependencies=dependencies
    )


@router.get(
    "/ready",
    summary="Readiness check",
    description="Returns 200 if service is ready to handle requests"
)
async def readiness_check() -> Dict[str, str]:
    """
    Readiness check endpoint for Kubernetes readiness probes.
    
    Returns:
        Dict: Simple ready status.
        
    Raises:
        HTTPException: 503 if service is not ready.
    """
    # Check if service is ready (all critical dependencies are available)
    dependencies = await _check_dependencies()
    
    if not _critical_dependencies_healthy(dependencies):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service not ready - critical dependencies unavailable"
        )
    
    return {"status": "ready"}


@router.get(
    "/live",
    summary="Liveness check", 
    description="Returns 200 if service is alive"
)
async def liveness_check() -> Dict[str, str]:
    """
    Liveness check endpoint for Kubernetes liveness probes.
    
    Returns:
        Dict: Simple alive status.
    """
    return {"status": "alive"}


async def _check_dependencies() -> Dict[str, Dict[str, Any]]:
    """
    Check the health of service dependencies.
    
    Returns:
        Dict: Health status of each dependency.
    """
    dependencies = {}
    
    # Example database check (replace with actual database)
    dependencies["database"] = await _check_database()
    
    # Example external service check
    dependencies["external_api"] = await _check_external_api()
    
    # Add more dependency checks as needed
    
    return dependencies


async def _check_database() -> Dict[str, Any]:
    """
    Check database connectivity and health.
    
    Returns:
        Dict: Database health status.
    """
    try:
        # Replace with actual database health check
        # For example: await database.execute("SELECT 1")
        
        return {
            "status": "healthy",
            "response_time_ms": 5.2,
            "message": "Database connection successful"
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "message": "Database connection failed"
        }


async def _check_external_api() -> Dict[str, Any]:
    """
    Check external API connectivity and health.
    
    Returns:
        Dict: External API health status.
    """
    try:
        # Replace with actual external API health check
        # For example: async with httpx.AsyncClient() as client:
        #                 response = await client.get("https://api.example.com/health")
        
        return {
            "status": "healthy", 
            "response_time_ms": 150.0,
            "message": "External API reachable"
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "message": "External API unreachable"
        }


def _all_dependencies_healthy(dependencies: Dict[str, Dict[str, Any]]) -> bool:
    """
    Check if all dependencies are healthy.
    
    Args:
        dependencies: Dictionary of dependency health statuses.
        
    Returns:
        bool: True if all dependencies are healthy.
    """
    return all(dep.get("status") == "healthy" for dep in dependencies.values())


def _critical_dependencies_healthy(dependencies: Dict[str, Dict[str, Any]]) -> bool:
    """
    Check if critical dependencies are healthy.
    
    Args:
        dependencies: Dictionary of dependency health statuses.
        
    Returns:
        bool: True if critical dependencies are healthy.
    """
    critical_deps = ["database"]  # Add your critical dependencies here
    
    for dep_name in critical_deps:
        if dep_name in dependencies:
            if dependencies[dep_name].get("status") != "healthy":
                return False
    
    return True

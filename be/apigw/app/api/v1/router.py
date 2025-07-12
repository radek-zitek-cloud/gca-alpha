"""
API v1 Router Configuration.

This module configures and organizes all API v1 endpoints including:
- Authentication and authorization
- RBAC management
- API key management
- Health checks and metrics
- Service routing
- Administrative functions

All endpoints are properly secured with authentication and RBAC controls.
"""

from fastapi import APIRouter

from app.api.v1.endpoints import (
    auth,
    oauth,
    rbac,
    api_keys,
    admin,
    health,
    metrics,
    weather
)

# Create main v1 router
api_router = APIRouter(prefix="/api/v1")

# Include all endpoint routers
api_router.include_router(
    auth.router,
    tags=["Authentication"]
)

api_router.include_router(
    oauth.router,
    tags=["OAuth Authentication"]
)

api_router.include_router(
    rbac.router,
    tags=["RBAC Management"]
)

api_router.include_router(
    api_keys.router,
    tags=["API Keys"]
)

api_router.include_router(
    admin.router,
    tags=["Administration"]
)

api_router.include_router(
    health.router,
    tags=["Health"]
)

api_router.include_router(
    metrics.router,
    tags=["Metrics"]
)

api_router.include_router(
    weather.router,
    tags=["Weather Service"]
)

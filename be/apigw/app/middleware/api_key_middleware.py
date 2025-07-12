"""
API Key Authentication Middleware.

This middleware integrates the API key system with the FastAPI request pipeline,
providing automatic API key validation for protected routes.

Features:
- Automatic API key extraction from headers
- Route-based API key requirement configuration
- Integration with existing JWT authentication
- Rate limiting enforcement
- Security headers injection
- Usage tracking and analytics
"""

import logging
from typing import Optional, Callable, Set, List
from datetime import datetime

from fastapi import Request, Response, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.services.api_keys import (
    api_key_manager,
    APIKeyScope,
    APIKeyMetadata,
    get_client_ip
)

logger = logging.getLogger(__name__)


class APIKeyAuthMiddleware(BaseHTTPMiddleware):
    """
    Middleware for API key authentication and rate limiting.
    
    This middleware automatically validates API keys for configured routes
    and enforces rate limiting policies.
    """
    
    def __init__(
        self,
        app,
        protected_paths: Optional[Set[str]] = None,
        excluded_paths: Optional[Set[str]] = None,
        require_api_key_paths: Optional[Set[str]] = None,
        admin_paths: Optional[Set[str]] = None
    ):
        """
        Initialize API key middleware.
        
        Args:
            app: FastAPI application
            protected_paths: Paths that support API key auth (optional)
            excluded_paths: Paths to exclude from API key processing
            require_api_key_paths: Paths that require API key auth
            admin_paths: Paths that require admin API key scope
        """
        super().__init__(app)
        
        # Default path configurations
        self.protected_paths = protected_paths or {
            "/api/v1/gateway/",
            "/api/v1/weather/",
            "/api/v1/metrics/",
            "/api/v1/admin/"
        }
        
        self.excluded_paths = excluded_paths or {
            "/health",
            "/docs",
            "/openapi.json",
            "/api/v1/auth/",
            "/api/v1/keys/health",
            "/api/v1/keys/scopes"
        }
        
        self.require_api_key_paths = require_api_key_paths or {
            "/api/v1/gateway/services",
            "/api/v1/weather/",
            "/api/v1/metrics/"
        }
        
        self.admin_paths = admin_paths or {
            "/api/v1/admin/"
        }
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request through API key middleware."""
        
        # Skip processing for excluded paths
        if self._is_excluded_path(request.url.path):
            return await call_next(request)
        
        # Check if this path requires API key authentication
        requires_api_key = self._requires_api_key(request.url.path)
        requires_admin = self._requires_admin_scope(request.url.path)
        
        # Extract API key from request
        api_key = self._extract_api_key(request)
        
        # If API key is required but not provided
        if requires_api_key and not api_key:
            return self._create_error_response(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key required for this endpoint",
                headers={"WWW-Authenticate": "ApiKey"}
            )
        
        # If API key is provided, validate it
        api_key_metadata = None
        if api_key:
            try:
                client_ip = get_client_ip(request)
                user_agent = request.headers.get("User-Agent")
                
                # Determine required scope
                required_scope = None
                if requires_admin:
                    required_scope = APIKeyScope.ADMIN
                elif "/weather/" in request.url.path:
                    required_scope = APIKeyScope.WEATHER
                elif "/metrics/" in request.url.path:
                    required_scope = APIKeyScope.METRICS
                elif "/gateway/" in request.url.path:
                    required_scope = APIKeyScope.GATEWAY_MANAGEMENT
                
                # Validate API key with rate limiting
                api_key_metadata = await api_key_manager.validate_key_with_rate_limit(
                    api_key=api_key,
                    client_ip=client_ip,
                    user_agent=user_agent,
                    required_scope=required_scope
                )
                
                # Add API key metadata to request state
                request.state.api_key_metadata = api_key_metadata
                request.state.authenticated_via = "api_key"
                
                logger.info(
                    f"API key authenticated: {api_key_metadata.key_id} "
                    f"for {request.method} {request.url.path}"
                )
                
            except HTTPException as e:
                # Return the HTTP exception as JSON response
                return self._create_error_response(
                    status_code=e.status_code,
                    detail=e.detail,
                    headers=getattr(e, 'headers', None)
                )
            except Exception as e:
                logger.error(f"API key validation error: {e}")
                return self._create_error_response(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Internal authentication error"
                )
        
        # Process the request
        response = await call_next(request)
        
        # Add security headers and API key info to response
        if api_key_metadata:
            self._add_api_key_headers(response, api_key_metadata)
        
        return response
    
    def _extract_api_key(self, request: Request) -> Optional[str]:
        """Extract API key from request headers."""
        # Try X-API-Key header first
        api_key = request.headers.get("X-API-Key")
        if api_key:
            return api_key
        
        # Try Authorization header with ApiKey scheme
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("ApiKey "):
            return auth_header[7:]  # Remove "ApiKey " prefix
        
        # Try query parameter (less secure, for testing only)
        if "api_key" in request.query_params:
            logger.warning("API key provided via query parameter - not recommended for production")
            return request.query_params["api_key"]
        
        return None
    
    def _is_excluded_path(self, path: str) -> bool:
        """Check if path is excluded from API key processing."""
        for excluded_path in self.excluded_paths:
            if path.startswith(excluded_path):
                return True
        return False
    
    def _requires_api_key(self, path: str) -> bool:
        """Check if path requires API key authentication."""
        for required_path in self.require_api_key_paths:
            if path.startswith(required_path):
                return True
        return False
    
    def _requires_admin_scope(self, path: str) -> bool:
        """Check if path requires admin scope."""
        for admin_path in self.admin_paths:
            if path.startswith(admin_path):
                return True
        return False
    
    def _create_error_response(self, status_code: int, detail: str, headers: Optional[dict] = None) -> JSONResponse:
        """Create standardized error response."""
        content = {
            "detail": detail,
            "timestamp": datetime.utcnow().isoformat(),
            "path": getattr(self, '_current_path', 'unknown')
        }
        
        return JSONResponse(
            status_code=status_code,
            content=content,
            headers=headers
        )
    
    def _add_api_key_headers(self, response: Response, metadata: APIKeyMetadata):
        """Add API key information to response headers."""
        # Add rate limit headers
        response.headers["X-RateLimit-Limit"] = str(metadata.rate_limit_rpm)
        response.headers["X-RateLimit-Remaining"] = str(max(0, metadata.rate_limit_rpm - metadata.usage.requests_today))
        
        # Add API key info (without exposing sensitive data)
        response.headers["X-API-Key-ID"] = metadata.key_id
        response.headers["X-API-Key-Scopes"] = ",".join([scope.value for scope in metadata.scopes])
        
        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"


class APIKeyRateLimitMiddleware(BaseHTTPMiddleware):
    """
    Dedicated rate limiting middleware for API keys.
    
    This middleware can be used independently or in combination with
    the main API key auth middleware for specialized rate limiting.
    """
    
    def __init__(self, app, paths_to_limit: Optional[Set[str]] = None):
        super().__init__(app)
        self.paths_to_limit = paths_to_limit or {
            "/api/v1/"
        }
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Apply rate limiting based on API key."""
        
        # Check if this path should be rate limited
        should_limit = any(request.url.path.startswith(path) for path in self.paths_to_limit)
        
        if not should_limit:
            return await call_next(request)
        
        # Check if we have API key metadata from previous middleware
        api_key_metadata = getattr(request.state, 'api_key_metadata', None)
        
        if api_key_metadata:
            try:
                # Check rate limit
                rate_ok = await api_key_manager.rate_limiter.check_rate_limit(
                    api_key_metadata.key_id, 
                    api_key_metadata
                )
                
                if not rate_ok:
                    # Get rate limit info
                    rate_info = await api_key_manager.rate_limiter.get_rate_limit_status(
                        api_key_metadata.key_id
                    )
                    
                    return JSONResponse(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        content={
                            "detail": "Rate limit exceeded",
                            "rate_limit": {
                                "limit": api_key_metadata.rate_limit_rpm,
                                "reset_in_seconds": rate_info["reset_in_seconds"]
                            }
                        },
                        headers={
                            "X-RateLimit-Limit": str(api_key_metadata.rate_limit_rpm),
                            "X-RateLimit-Remaining": "0",
                            "X-RateLimit-Reset": str(rate_info["reset_in_seconds"]),
                            "Retry-After": str(rate_info["reset_in_seconds"])
                        }
                    )
                
            except Exception as e:
                logger.error(f"Rate limiting error: {e}")
                # Continue with request if rate limiting fails
        
        return await call_next(request)


# Utility functions for integration

def get_api_key_metadata(request: Request) -> Optional[APIKeyMetadata]:
    """
    Get API key metadata from request state.
    
    This function can be used in route handlers to access
    API key information for the current request.
    """
    return getattr(request.state, 'api_key_metadata', None)


def is_authenticated_via_api_key(request: Request) -> bool:
    """Check if request was authenticated via API key."""
    return getattr(request.state, 'authenticated_via', None) == "api_key"


def require_api_key_scope(required_scope: APIKeyScope):
    """
    Route dependency to require specific API key scope.
    
    Usage:
        @app.get("/admin/endpoint", dependencies=[Depends(require_api_key_scope(APIKeyScope.ADMIN))])
    """
    async def check_scope(request: Request):
        metadata = get_api_key_metadata(request)
        
        if not metadata:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key authentication required"
            )
        
        if required_scope not in metadata.scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Required scope '{required_scope.value}' not granted"
            )
        
        return metadata
    
    return check_scope


# Configuration helpers

def create_api_key_middleware_config(
    enable_for_all_api_routes: bool = True,
    require_for_gateway: bool = True,
    require_for_weather: bool = True,
    require_for_metrics: bool = True,
    require_for_admin: bool = True
) -> dict:
    """
    Create API key middleware configuration.
    
    Args:
        enable_for_all_api_routes: Enable API key support for all /api/ routes
        require_for_gateway: Require API key for gateway routes
        require_for_weather: Require API key for weather routes
        require_for_metrics: Require API key for metrics routes
        require_for_admin: Require API key for admin routes
    
    Returns:
        Configuration dictionary for middleware
    """
    config = {
        "protected_paths": set(),
        "excluded_paths": {
            "/health",
            "/docs", 
            "/openapi.json",
            "/api/v1/auth/",
            "/api/v1/keys/health",
            "/api/v1/keys/scopes"
        },
        "require_api_key_paths": set(),
        "admin_paths": set()
    }
    
    if enable_for_all_api_routes:
        config["protected_paths"].add("/api/v1/")
    
    if require_for_gateway:
        config["require_api_key_paths"].add("/api/v1/gateway/")
    
    if require_for_weather:
        config["require_api_key_paths"].add("/api/v1/weather/")
    
    if require_for_metrics:
        config["require_api_key_paths"].add("/api/v1/metrics/")
    
    if require_for_admin:
        config["require_api_key_paths"].add("/api/v1/admin/")
        config["admin_paths"].add("/api/v1/admin/")
    
    return config


# Integration with existing auth system

async def get_current_user_or_api_key(request: Request):
    """
    FastAPI dependency that supports both JWT and API key authentication.
    
    This dependency can be used in routes that should accept either
    JWT tokens or API keys for authentication.
    """
    # Check for API key authentication first
    api_key_metadata = get_api_key_metadata(request)
    if api_key_metadata:
        return {
            "user_id": api_key_metadata.owner_id,
            "email": api_key_metadata.owner_email,
            "auth_type": "api_key",
            "api_key_id": api_key_metadata.key_id,
            "scopes": [scope.value for scope in api_key_metadata.scopes]
        }
    
    # Fall back to JWT authentication
    from app.middleware.auth import get_current_user
    try:
        jwt_user = await get_current_user(request)
        jwt_user["auth_type"] = "jwt"
        return jwt_user
    except HTTPException:
        pass
    
    # No authentication found
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required (JWT token or API key)",
        headers={"WWW-Authenticate": "Bearer, ApiKey"}
    )


# Logging helpers

def log_api_key_usage(metadata: APIKeyMetadata, request: Request, response: Response):
    """Log API key usage for analytics and monitoring."""
    logger.info(
        f"API Key Usage: {metadata.key_id} | "
        f"Method: {request.method} | "
        f"Path: {request.url.path} | "
        f"Status: {response.status_code} | "
        f"IP: {get_client_ip(request)} | "
        f"UA: {request.headers.get('User-Agent', 'Unknown')[:100]}"
    )


# Metrics collection (placeholder for Prometheus integration)

class APIKeyMetricsCollector:
    """Collect metrics for API key usage."""
    
    def __init__(self):
        # In production, integrate with Prometheus metrics
        self.request_count = {}
        self.error_count = {}
        self.rate_limit_hits = {}
    
    def record_request(self, key_id: str, method: str, path: str, status_code: int):
        """Record API key request metrics."""
        key = f"{key_id}:{method}:{path}"
        self.request_count[key] = self.request_count.get(key, 0) + 1
        
        if status_code >= 400:
            self.error_count[key] = self.error_count.get(key, 0) + 1
    
    def record_rate_limit_hit(self, key_id: str):
        """Record rate limit hit."""
        self.rate_limit_hits[key_id] = self.rate_limit_hits.get(key_id, 0) + 1
    
    def get_metrics_summary(self) -> dict:
        """Get metrics summary."""
        return {
            "total_requests": sum(self.request_count.values()),
            "total_errors": sum(self.error_count.values()),
            "total_rate_limit_hits": sum(self.rate_limit_hits.values()),
            "unique_keys": len(set(key.split(':')[0] for key in self.request_count.keys()))
        }


# Global metrics collector instance
api_key_metrics = APIKeyMetricsCollector()

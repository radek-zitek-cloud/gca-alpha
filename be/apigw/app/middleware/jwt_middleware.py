"""
Authentication Middleware for automatic JWT token validation.

This middleware automatically validates JWT tokens for protected routes
and adds user context to requests. It implements the security requirements
from the implementation roadmap.
"""

import logging
from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response, JSONResponse

from app.middleware.auth import (
    authenticator,
    audit_logger,
    check_path_requires_auth,
    AuthConfig,
    get_client_ip,
    get_user_agent,
    UserContext,
    RBACManager
)

logger = logging.getLogger(__name__)


class JWTAuthMiddleware(BaseHTTPMiddleware):
    """
    JWT Authentication Middleware.
    
    Automatically validates JWT tokens for protected routes and adds
    user context to the request state.
    """
    
    def __init__(self, app, config: AuthConfig = None):
        """
        Initialize JWT authentication middleware.
        
        Args:
            app: FastAPI application instance
            config: Authentication configuration
        """
        super().__init__(app)
        self.config = config or AuthConfig()
        
    async def dispatch(self, request: Request, call_next):
        """
        Process request with JWT authentication.
        
        Args:
            request: The incoming HTTP request
            call_next: The next middleware/handler in the chain
            
        Returns:
            Response: The HTTP response
        """
        # Initialize user context
        request.state.user = None
        request.state.authenticated = False
        
        # Extract client information for logging
        client_ip = get_client_ip(request)
        user_agent = get_user_agent(request)
        path = request.url.path
        
        try:
            # Check if path requires authentication
            requires_auth = check_path_requires_auth(path, self.config)
            
            # Extract token from Authorization header
            auth_header = request.headers.get("Authorization")
            token = None
            
            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header[7:]  # Remove "Bearer " prefix
            
            # If token is provided, validate it
            if token:
                try:
                    token_data = authenticator.verify_token(token)
                    
                    # Create user context
                    user_permissions = token_data.permissions or RBACManager.get_effective_permissions(token_data.roles)
                    user_context = UserContext(
                        user_id=token_data.user_id,
                        username=token_data.username,
                        email=token_data.email,
                        roles=token_data.roles,
                        permissions=user_permissions,
                        token_jti=token_data.jti
                    )
                    
                    # Set user context in request state
                    request.state.user = user_context
                    request.state.authenticated = True
                    
                    # Add user headers to downstream services
                    request.headers.__dict__["_list"].extend([
                        (b"x-user-id", token_data.user_id.encode()),
                        (b"x-username", token_data.username.encode()),
                        (b"x-user-roles", ",".join(token_data.roles).encode()),
                        (b"x-user-permissions", ",".join(user_permissions).encode())
                    ])
                    
                except HTTPException as e:
                    # Token validation failed
                    if requires_auth:
                        # Log authentication failure
                        await audit_logger.log_authentication_failure(
                            username="unknown",
                            ip_address=client_ip,
                            user_agent=user_agent,
                            reason=f"Invalid token: {e.detail}"
                        )
                        
                        return JSONResponse(
                            status_code=e.status_code,
                            content={"detail": e.detail},
                            headers=e.headers or {}
                        )
                    else:
                        # Optional auth - continue without user context
                        logger.warning(f"Invalid token for optional auth path {path}: {e.detail}")
            
            elif requires_auth:
                # No token provided for protected route
                await audit_logger.log_authentication_failure(
                    username="unknown",
                    ip_address=client_ip,
                    user_agent=user_agent,
                    reason="No token provided"
                )
                
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"detail": "Authorization token required"},
                    headers={"WWW-Authenticate": "Bearer"}
                )
            
            # Process the request
            response = await call_next(request)
            
            # Add security headers to response
            self._add_security_headers(response)
            
            return response
            
        except Exception as e:
            logger.error(f"Authentication middleware error: {e}")
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": "Internal authentication error"}
            )
    
    def _add_security_headers(self, response: Response):
        """Add security headers to response."""
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Add CORS headers if not already present
        if "Access-Control-Allow-Origin" not in response.headers:
            response.headers["Access-Control-Allow-Origin"] = "*"  # Configure appropriately for production
        
        # Cache control for auth-related responses
        if response.status_code in [401, 403]:
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"


class RoleBasedAccessMiddleware(BaseHTTPMiddleware):
    """
    Role-based access control middleware.
    
    Checks user roles and permissions for protected resources.
    """
    
    def __init__(self, app, role_mappings: dict = None):
        """
        Initialize RBAC middleware.
        
        Args:
            app: FastAPI application instance
            role_mappings: Dictionary mapping paths to required roles/permissions
        """
        super().__init__(app)
        
        # Default role mappings
        self.role_mappings = role_mappings or {
            "/gateway/admin": {"roles": ["admin"]},
            "/gateway/services": {"roles": ["admin", "moderator"]},
            "/api/v1/admin": {"roles": ["admin"]},
            "/api/v1/metrics": {"permissions": ["metrics:read"]},
        }
    
    async def dispatch(self, request: Request, call_next):
        """
        Process request with role-based access control.
        
        Args:
            request: The incoming HTTP request
            call_next: The next middleware/handler in the chain
            
        Returns:
            Response: The HTTP response
        """
        path = request.url.path
        user = getattr(request.state, "user", None)
        
        # Check if path has role/permission requirements
        access_requirements = self._get_access_requirements(path)
        
        if access_requirements and user:
            # Check role requirements
            required_roles = access_requirements.get("roles", [])
            if required_roles and not any(RBACManager.has_role(user.roles, role) for role in required_roles):
                client_ip = get_client_ip(request)
                
                # Log authorization failure
                await audit_logger.log_authorization_failure(
                    user_id=user.user_id,
                    resource=path,
                    action=request.method,
                    ip_address=client_ip
                )
                
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"detail": f"Insufficient privileges. Required roles: {required_roles}"}
                )
            
            # Check permission requirements
            required_permissions = access_requirements.get("permissions", [])
            if required_permissions and not any(RBACManager.has_permission(user.permissions, perm) for perm in required_permissions):
                client_ip = get_client_ip(request)
                
                # Log authorization failure
                await audit_logger.log_authorization_failure(
                    user_id=user.user_id,
                    resource=path,
                    action=request.method,
                    ip_address=client_ip
                )
                
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"detail": f"Insufficient permissions. Required: {required_permissions}"}
                )
        
        # Process the request
        return await call_next(request)
    
    def _get_access_requirements(self, path: str) -> dict | None:
        """
        Get access requirements for a given path.
        
        Args:
            path: Request path
            
        Returns:
            Dictionary with role/permission requirements or None
        """
        for pattern, requirements in self.role_mappings.items():
            if path.startswith(pattern):
                return requirements
        return None

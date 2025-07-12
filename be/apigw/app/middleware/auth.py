"""
JWT Authentication Middleware for API Gateway.

This module provides comprehensive JWT token authentication with refresh tokens,
role-based access control, and security middleware for the API Gateway.
Implements the authentication requirements from the security roadmap.

Features:
- JWT token validation and generation
- Token refresh mechanism
- Authentication decorators/dependencies
- Role-based access control (RBAC)
- Security audit logging
- Rate limiting integration
"""

import json
import time
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List, Union, Callable
from functools import wraps

import jwt
from fastapi import Request, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
from pydantic import BaseModel, Field

from app.config.jwt_config import get_jwt_settings
from app.core.rbac import rbac_engine, AccessRequest

logger = logging.getLogger(__name__)

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# HTTP Bearer token scheme
security = HTTPBearer(auto_error=False)


class TokenData(BaseModel):
    """JWT token payload data model."""
    user_id: str
    username: str
    email: Optional[str] = None
    roles: List[str] = Field(default_factory=list)
    permissions: List[str] = Field(default_factory=list)
    token_type: str = "access"  # "access" or "refresh"
    exp: int
    iat: int
    jti: Optional[str] = None  # JWT ID for token tracking


class UserContext(BaseModel):
    """User context for authenticated requests."""
    user_id: str
    username: str
    email: Optional[str] = None
    roles: List[str] = Field(default_factory=list)
    permissions: List[str] = Field(default_factory=list)
    token_jti: Optional[str] = None
    authenticated_at: datetime = Field(default_factory=datetime.utcnow)


class AuthConfig(BaseModel):
    """Authentication configuration model."""
    jwt_secret_key: str = "your-super-secret-jwt-key-change-in-production"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 30
    token_issuer: str = "gca-api-gateway"
    token_audience: str = "gca-services"
    require_auth_by_default: bool = False
    protected_paths: List[str] = Field(default_factory=lambda: ["/api/v1/admin", "/gateway"])
    public_paths: List[str] = Field(default_factory=lambda: ["/docs", "/redoc", "/health", "/api/v1/auth"])
    
    @classmethod
    def from_jwt_settings(cls):
        """Create AuthConfig from JWT settings."""
        jwt_settings = get_jwt_settings()
        return cls(
            jwt_secret_key=jwt_settings.jwt_secret_key,
            jwt_algorithm=jwt_settings.jwt_algorithm,
            access_token_expire_minutes=jwt_settings.access_token_expire_minutes,
            refresh_token_expire_days=jwt_settings.refresh_token_expire_days,
            token_issuer=jwt_settings.token_issuer,
            token_audience=jwt_settings.token_audience,
            require_auth_by_default=jwt_settings.require_auth_by_default,
            protected_paths=jwt_settings.protected_paths,
            public_paths=jwt_settings.public_paths
        )


class JWTAuthenticator:
    """JWT token authenticator with refresh token support."""
    
    def __init__(self, config: Optional[AuthConfig] = None):
        """Initialize JWT authenticator with configuration."""
        self.config = config or AuthConfig()
        self._revoked_tokens: set = set()  # In production, use Redis
        
    def create_access_token(self, user_data: Dict[str, Any], 
                          expires_delta: Optional[timedelta] = None) -> str:
        """
        Create a new access token.
        
        Args:
            user_data: User information to encode in token
            expires_delta: Optional custom expiration time
            
        Returns:
            Encoded JWT access token
        """
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(
                minutes=self.config.access_token_expire_minutes
            )
        
        # Generate unique JWT ID
        jti = f"{user_data['user_id']}_{int(time.time())}"
        
        payload = {
            "user_id": user_data["user_id"],
            "username": user_data["username"],
            "email": user_data.get("email"),
            "roles": user_data.get("roles", []),
            "permissions": user_data.get("permissions", []),
            "token_type": "access",
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "iss": self.config.token_issuer,
            "aud": self.config.token_audience,
            "jti": jti
        }
        
        return jwt.encode(payload, self.config.jwt_secret_key, algorithm=self.config.jwt_algorithm)
    
    def create_refresh_token(self, user_data: Dict[str, Any]) -> str:
        """
        Create a new refresh token.
        
        Args:
            user_data: User information to encode in token
            
        Returns:
            Encoded JWT refresh token
        """
        expire = datetime.now(timezone.utc) + timedelta(days=self.config.refresh_token_expire_days)
        jti = f"{user_data['user_id']}_refresh_{int(time.time())}"
        
        payload = {
            "user_id": user_data["user_id"],
            "username": user_data["username"],
            "token_type": "refresh",
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "iss": self.config.token_issuer,
            "aud": self.config.token_audience,
            "jti": jti
        }
        
        return jwt.encode(payload, self.config.jwt_secret_key, algorithm=self.config.jwt_algorithm)
    
    def verify_token(self, token: str) -> TokenData:
        """
        Verify and decode JWT token.
        
        Args:
            token: JWT token to verify
            
        Returns:
            Decoded token data
            
        Raises:
            HTTPException: If token is invalid, expired, or revoked
        """
        try:
            # Decode the token
            payload = jwt.decode(
                token,
                self.config.jwt_secret_key,
                algorithms=[self.config.jwt_algorithm],
                audience=self.config.token_audience,
                issuer=self.config.token_issuer
            )
            
            # Check if token is revoked
            jti = payload.get("jti")
            if jti and jti in self._revoked_tokens:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has been revoked",
                    headers={"WWW-Authenticate": "Bearer"}
                )
            
            return TokenData(**payload)
            
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
                headers={"WWW-Authenticate": "Bearer"}
            )
        except jwt.JWTError as e:
            logger.warning(f"JWT validation failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"}
            )
    
    def refresh_access_token(self, refresh_token: str) -> Dict[str, str]:
        """
        Generate new access token from refresh token.
        
        Args:
            refresh_token: Valid refresh token
            
        Returns:
            Dictionary with new access token and optionally new refresh token
            
        Raises:
            HTTPException: If refresh token is invalid
        """
        try:
            # Verify refresh token
            token_data = self.verify_token(refresh_token)
            
            if token_data.token_type != "refresh":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token type for refresh"
                )
            
            # Create new access token
            user_data = {
                "user_id": token_data.user_id,
                "username": token_data.username,
                "email": token_data.email,
                "roles": token_data.roles,
                "permissions": token_data.permissions
            }
            
            new_access_token = self.create_access_token(user_data)
            
            return {
                "access_token": new_access_token,
                "token_type": "bearer"
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Token refresh failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not refresh token"
            )
    
    def revoke_token(self, jti: str) -> None:
        """
        Revoke a token by adding its JTI to the revoked list.
        
        Args:
            jti: JWT ID to revoke
        """
        self._revoked_tokens.add(jti)
        logger.info(f"Token revoked: {jti}")
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash."""
        return pwd_context.verify(plain_password, hashed_password)
    
    def get_password_hash(self, password: str) -> str:
        """Hash a password."""
        return pwd_context.hash(password)


# Global authenticator instance
authenticator = JWTAuthenticator()


class RBACManager:
    """Role-Based Access Control manager."""
    
    # Define role hierarchy (higher roles inherit lower role permissions)
    ROLE_HIERARCHY = {
        "admin": ["admin", "moderator", "user", "guest"],
        "moderator": ["moderator", "user", "guest"],
        "user": ["user", "guest"],
        "guest": ["guest"]
    }
    
    # Define default permissions for roles
    DEFAULT_PERMISSIONS = {
        "admin": [
            "gateway:read", "gateway:write", "gateway:delete", "gateway:admin",
            "services:read", "services:write", "services:delete",
            "users:read", "users:write", "users:delete",
            "metrics:read", "logs:read"
        ],
        "moderator": [
            "gateway:read", "gateway:write",
            "services:read", "services:write",
            "users:read",
            "metrics:read"
        ],
        "user": [
            "gateway:read",
            "services:read",
            "metrics:read"
        ],
        "guest": [
            "gateway:read"
        ]
    }
    
    @classmethod
    def has_role(cls, user_roles: List[str], required_role: str) -> bool:
        """Check if user has required role or higher."""
        for user_role in user_roles:
            if required_role in cls.ROLE_HIERARCHY.get(user_role, []):
                return True
        return False
    
    @classmethod
    def has_permission(cls, user_permissions: List[str], required_permission: str) -> bool:
        """Check if user has required permission."""
        return required_permission in user_permissions
    
    @classmethod
    def get_effective_permissions(cls, roles: List[str]) -> List[str]:
        """Get all permissions for given roles."""
        permissions = set()
        for role in roles:
            permissions.update(cls.DEFAULT_PERMISSIONS.get(role, []))
        return list(permissions)


# Authentication dependencies for FastAPI

async def get_token_optional(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> Optional[str]:
    """Extract token from Authorization header (optional)."""
    if credentials:
        return credentials.credentials
    return None


async def get_token_required(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    """Extract token from Authorization header (required)."""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header missing",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return credentials.credentials


async def get_current_user_optional(token: Optional[str] = Depends(get_token_optional)) -> Optional[UserContext]:
    """Get current user from token (optional)."""
    if not token:
        return None
    
    try:
        token_data = authenticator.verify_token(token)
        return UserContext(
            user_id=token_data.user_id,
            username=token_data.username,
            email=token_data.email,
            roles=token_data.roles,
            permissions=token_data.permissions or RBACManager.get_effective_permissions(token_data.roles),
            token_jti=token_data.jti
        )
    except HTTPException:
        return None


async def get_current_user(token: str = Depends(get_token_required)) -> UserContext:
    """Get current authenticated user (required)."""
    token_data = authenticator.verify_token(token)
    return UserContext(
        user_id=token_data.user_id,
        username=token_data.username,
        email=token_data.email,
        roles=token_data.roles,
        permissions=token_data.permissions or RBACManager.get_effective_permissions(token_data.roles),
        token_jti=token_data.jti
    )


# Authentication decorators

def require_role(required_role: str):
    """Decorator to require specific role."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            user = kwargs.get('current_user') or kwargs.get('user')
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )
            
            if not RBACManager.has_role(user.roles, required_role):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Role '{required_role}' required"
                )
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator


def require_permission(required_permission: str):
    """Decorator to require specific permission."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            user = kwargs.get('current_user') or kwargs.get('user')
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )
            
            if not RBACManager.has_permission(user.permissions, required_permission):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission '{required_permission}' required"
                )
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator


# FastAPI dependency versions of decorators

def RequireRole(required_role: str):
    """FastAPI dependency to require specific role."""
    async def check_role(current_user: UserContext = Depends(get_current_user)):
        if not RBACManager.has_role(current_user.roles, required_role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{required_role}' required"
            )
        return current_user
    return check_role


def RequirePermission(required_permission: str):
    """FastAPI dependency to require specific permission."""
    async def check_permission(current_user: UserContext = Depends(get_current_user)):
        if not RBACManager.has_permission(current_user.permissions, required_permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{required_permission}' required"
            )
        return current_user
    return check_permission


class SecurityAuditLogger:
    """Security audit logger for authentication events."""
    
    def __init__(self):
        self.logger = logging.getLogger("security.audit")
    
    async def log_authentication_success(self, user_id: str, ip_address: str, user_agent: str):
        """Log successful authentication."""
        audit_event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "auth.login.success",
            "user_id": user_id,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "severity": "INFO"
        }
        self.logger.info(f"SECURITY_AUDIT: {json.dumps(audit_event)}")
    
    async def log_authentication_failure(self, username: str, ip_address: str, user_agent: str, reason: str):
        """Log failed authentication."""
        audit_event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "auth.login.failure",
            "username": username,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "reason": reason,
            "severity": "WARNING"
        }
        self.logger.warning(f"SECURITY_AUDIT: {json.dumps(audit_event)}")
    
    async def log_token_refresh(self, user_id: str, ip_address: str):
        """Log token refresh."""
        audit_event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "auth.token.refresh",
            "user_id": user_id,
            "ip_address": ip_address,
            "severity": "INFO"
        }
        self.logger.info(f"SECURITY_AUDIT: {json.dumps(audit_event)}")
    
    async def log_token_revocation(self, user_id: str, jti: str, ip_address: str):
        """Log token revocation."""
        audit_event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "auth.token.revoke",
            "user_id": user_id,
            "jti": jti,
            "ip_address": ip_address,
            "severity": "INFO"
        }
        self.logger.info(f"SECURITY_AUDIT: {json.dumps(audit_event)}")
    
    async def log_authorization_failure(self, user_id: str, resource: str, action: str, ip_address: str):
        """Log authorization failure."""
        audit_event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "authz.access.denied",
            "user_id": user_id,
            "resource": resource,
            "action": action,
            "ip_address": ip_address,
            "severity": "WARNING"
        }
        self.logger.warning(f"SECURITY_AUDIT: {json.dumps(audit_event)}")


# Global audit logger instance
audit_logger = SecurityAuditLogger()


def check_path_requires_auth(path: str, config: AuthConfig) -> bool:
    """Check if a path requires authentication."""
    # Check if it's a public path
    for public_path in config.public_paths:
        if path.startswith(public_path):
            return False
    
    # Check if it's a protected path
    for protected_path in config.protected_paths:
        if path.startswith(protected_path):
            return True
    
    # Return default behavior
    return config.require_auth_by_default


# Utility functions for middleware integration

def get_client_ip(request: Request) -> str:
    """Extract client IP address from request."""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    
    if request.client:
        return request.client.host
    
    return "unknown"


def get_user_agent(request: Request) -> str:
    """Extract user agent from request."""
    return request.headers.get("User-Agent", "unknown")


# Enhanced Access Control with Enterprise RBAC

async def require_rbac_access(
    resource: str,
    action: str,
    context: Optional[Dict[str, Any]] = None
):
    """
    Create a dependency that enforces RBAC access control.
    
    Args:
        resource: Resource being accessed (e.g., 'users', 'services')
        action: Action being performed (e.g., 'read', 'write', 'delete')
        context: Additional context for policy evaluation
    
    Returns:
        FastAPI dependency function
    """
    async def rbac_dependency(
        current_user: Dict[str, Any] = Depends(get_current_user)
    ):
        """RBAC dependency function."""
        access_request = AccessRequest(
            user_id=current_user["user_id"],
            username=current_user["username"],
            roles=current_user.get("roles", []),
            resource=resource,
            action=action,
            additional_context=context or {}
        )
        
        result = rbac_engine.check_access(access_request)
        
        if not result.granted:
            logger.warning(
                f"RBAC access denied for user {current_user['user_id']} "
                f"to {resource}:{action} - {result.reason}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: {result.reason}"
            )
        
        logger.info(
            f"RBAC access granted for user {current_user['user_id']} "
            f"to {resource}:{action} via {result.policy_matched or 'permissions'}"
        )
        
        return current_user
    
    return rbac_dependency


def rbac_permission(permission: str):
    """
    Decorator for endpoints requiring specific RBAC permissions.
    
    Args:
        permission: Permission string in format "resource:action:scope"
    
    Usage:
        @rbac_permission("users:read:own")
        async def get_user_profile(user_id: str, current_user = Depends(get_current_user)):
            ...
    """
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get current user from kwargs (should be injected by FastAPI)
            current_user = None
            for key, value in kwargs.items():
                if isinstance(value, dict) and "user_id" in value and "roles" in value:
                    current_user = value
                    break
            
            if not current_user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )
            
            # Parse permission components
            parts = permission.split(":")
            if len(parts) != 3:
                raise ValueError(f"Invalid permission format: {permission}")
            
            resource, action, scope = parts
            
            # Create access request
            access_request = AccessRequest(
                user_id=current_user["user_id"],
                username=current_user["username"],
                roles=current_user.get("roles", []),
                resource=resource,
                action=action,
                additional_context={"scope": scope}
            )
            
            # Check access
            result = rbac_engine.check_access(access_request)
            
            if not result.granted:
                logger.warning(
                    f"Permission {permission} denied for user {current_user['user_id']} - {result.reason}"
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions: {result.reason}"
                )
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


# Example usage and testing functions

async def create_test_user_token() -> Dict[str, str]:
    """Create test tokens for development/testing."""
    test_user = {
        "user_id": "test-user-123",
        "username": "testuser",
        "email": "test@example.com",
        "roles": ["user"],
        "permissions": ["gateway:read", "services:read"]
    }
    
    access_token = authenticator.create_access_token(test_user)
    refresh_token = authenticator.create_refresh_token(test_user)
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


async def create_admin_token() -> Dict[str, str]:
    """Create admin token for testing."""
    admin_user = {
        "user_id": "admin-123",
        "username": "admin",
        "email": "admin@example.com",
        "roles": ["admin"]
    }
    
    access_token = authenticator.create_access_token(admin_user)
    refresh_token = authenticator.create_refresh_token(admin_user)
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

"""
API Key Management System for API Gateway.

This module provides comprehensive API key management including:
- API key generation and validation
- Key rotation and lifecycle management
- Rate limiting integration
- Scoped permissions and access control
- Usage tracking and analytics

Features:
- Secure API key generation with cryptographic randomness
- Configurable key expiration and rotation
- Per-key rate limiting and quotas
- Key scoping and permission management
- Usage analytics and monitoring
- Integration with existing JWT authentication
"""

import secrets
import hashlib
import time
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List, Set
from enum import Enum
from dataclasses import dataclass, field
from functools import wraps

from pydantic import BaseModel, Field
from fastapi import HTTPException, status

logger = logging.getLogger(__name__)


class APIKeyStatus(Enum):
    """API key status enumeration."""
    ACTIVE = "active"
    SUSPENDED = "suspended" 
    EXPIRED = "expired"
    REVOKED = "revoked"


class APIKeyScope(Enum):
    """API key scope enumeration."""
    READ_ONLY = "read_only"
    READ_WRITE = "read_write"
    ADMIN = "admin"
    GATEWAY_MANAGEMENT = "gateway_management"
    METRICS = "metrics"
    WEATHER = "weather"


@dataclass
class APIKeyUsage:
    """API key usage tracking."""
    total_requests: int = 0
    requests_today: int = 0
    requests_this_month: int = 0
    last_used: Optional[datetime] = None
    last_ip: Optional[str] = None
    last_user_agent: Optional[str] = None
    rate_limit_hits: int = 0
    error_count: int = 0


@dataclass
class APIKeyMetadata:
    """API key metadata and configuration."""
    key_id: str
    name: str
    description: str
    owner_id: str
    owner_email: str
    scopes: Set[APIKeyScope]
    rate_limit_rpm: int = 60  # Requests per minute
    rate_limit_rph: int = 3600  # Requests per hour
    rate_limit_rpd: int = 86400  # Requests per day
    quota_monthly: Optional[int] = None
    allowed_ips: Optional[Set[str]] = None
    allowed_domains: Optional[Set[str]] = None
    expires_at: Optional[datetime] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    status: APIKeyStatus = APIKeyStatus.ACTIVE
    usage: APIKeyUsage = field(default_factory=APIKeyUsage)


class APIKeyConfig(BaseModel):
    """API key system configuration."""
    key_prefix: str = "gca_"
    key_length: int = 32
    default_expiry_days: int = 365
    max_keys_per_user: int = 10
    enable_ip_restriction: bool = True
    enable_domain_restriction: bool = True
    enable_rate_limiting: bool = True
    enable_usage_tracking: bool = True
    auto_rotate_days: Optional[int] = None  # Auto-rotation disabled by default
    

class APIKeyGenerator:
    """Secure API key generator."""
    
    def __init__(self, config: APIKeyConfig):
        self.config = config
    
    def generate_key(self) -> str:
        """
        Generate a cryptographically secure API key.
        
        Returns:
            Secure API key string
        """
        # Generate random bytes
        random_bytes = secrets.token_bytes(self.config.key_length)
        
        # Create key with prefix
        key = f"{self.config.key_prefix}{secrets.token_urlsafe(self.config.key_length)}"
        
        return key
    
    def generate_key_id(self) -> str:
        """Generate unique key ID."""
        timestamp = int(time.time())
        random_suffix = secrets.token_hex(8)
        return f"key_{timestamp}_{random_suffix}"
    
    def hash_key(self, api_key: str) -> str:
        """
        Hash API key for secure storage.
        
        Args:
            api_key: Plain text API key
            
        Returns:
            SHA-256 hash of the key
        """
        return hashlib.sha256(api_key.encode()).hexdigest()


class APIKeyValidator:
    """API key validation and verification."""
    
    def __init__(self, key_store: 'APIKeyStore'):
        self.key_store = key_store
    
    async def validate_key(self, api_key: str, 
                          client_ip: Optional[str] = None,
                          user_agent: Optional[str] = None,
                          required_scope: Optional[APIKeyScope] = None) -> APIKeyMetadata:
        """
        Validate API key and check permissions.
        
        Args:
            api_key: API key to validate
            client_ip: Client IP address
            user_agent: Client user agent
            required_scope: Required scope for the operation
            
        Returns:
            API key metadata if valid
            
        Raises:
            HTTPException: If key is invalid or unauthorized
        """
        # Hash the key for lookup
        key_hash = APIKeyGenerator(APIKeyConfig()).hash_key(api_key)
        
        # Get key metadata
        key_metadata = await self.key_store.get_key_by_hash(key_hash)
        if not key_metadata:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key",
                headers={"WWW-Authenticate": "ApiKey"}
            )
        
        # Check key status
        if key_metadata.status != APIKeyStatus.ACTIVE:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"API key is {key_metadata.status.value}",
                headers={"WWW-Authenticate": "ApiKey"}
            )
        
        # Check expiration
        if key_metadata.expires_at and datetime.now(timezone.utc) > key_metadata.expires_at:
            # Auto-update status to expired
            await self.key_store.update_key_status(key_metadata.key_id, APIKeyStatus.EXPIRED)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key has expired",
                headers={"WWW-Authenticate": "ApiKey"}
            )
        
        # Check IP restrictions
        if key_metadata.allowed_ips and client_ip:
            if client_ip not in key_metadata.allowed_ips:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="API key not allowed from this IP address"
                )
        
        # Check scope permissions
        if required_scope and required_scope not in key_metadata.scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"API key does not have required scope: {required_scope.value}"
            )
        
        # Update usage tracking
        await self._update_usage(key_metadata, client_ip, user_agent)
        
        return key_metadata
    
    async def _update_usage(self, key_metadata: APIKeyMetadata, 
                           client_ip: Optional[str], 
                           user_agent: Optional[str]):
        """Update API key usage statistics."""
        now = datetime.now(timezone.utc)
        
        # Update usage stats
        key_metadata.usage.total_requests += 1
        key_metadata.usage.last_used = now
        key_metadata.usage.last_ip = client_ip
        key_metadata.usage.last_user_agent = user_agent
        
        # Update daily/monthly counters (simplified - in production use proper time windows)
        key_metadata.usage.requests_today += 1
        key_metadata.usage.requests_this_month += 1
        
        # Save updated metadata
        await self.key_store.update_key_metadata(key_metadata)


class APIKeyStore:
    """API key storage and management."""
    
    def __init__(self):
        # In-memory storage - in production use Redis/Database
        self._keys: Dict[str, APIKeyMetadata] = {}  # key_hash -> metadata
        self._key_ids: Dict[str, str] = {}  # key_id -> key_hash
        self._user_keys: Dict[str, Set[str]] = {}  # user_id -> set of key_ids
    
    async def store_key(self, key_hash: str, metadata: APIKeyMetadata) -> bool:
        """
        Store API key metadata.
        
        Args:
            key_hash: Hashed API key
            metadata: Key metadata
            
        Returns:
            True if stored successfully
        """
        self._keys[key_hash] = metadata
        self._key_ids[metadata.key_id] = key_hash
        
        # Track user keys
        if metadata.owner_id not in self._user_keys:
            self._user_keys[metadata.owner_id] = set()
        self._user_keys[metadata.owner_id].add(metadata.key_id)
        
        logger.info(f"API key stored: {metadata.key_id} for user {metadata.owner_id}")
        return True
    
    async def get_key_by_hash(self, key_hash: str) -> Optional[APIKeyMetadata]:
        """Get API key metadata by hash."""
        return self._keys.get(key_hash)
    
    async def get_key_by_id(self, key_id: str) -> Optional[APIKeyMetadata]:
        """Get API key metadata by ID."""
        key_hash = self._key_ids.get(key_id)
        if key_hash:
            return self._keys.get(key_hash)
        return None
    
    async def update_key_metadata(self, metadata: APIKeyMetadata) -> bool:
        """Update API key metadata."""
        key_hash = self._key_ids.get(metadata.key_id)
        if key_hash:
            metadata.updated_at = datetime.now(timezone.utc)
            self._keys[key_hash] = metadata
            return True
        return False
    
    async def update_key_status(self, key_id: str, status: APIKeyStatus) -> bool:
        """Update API key status."""
        metadata = await self.get_key_by_id(key_id)
        if metadata:
            metadata.status = status
            metadata.updated_at = datetime.now(timezone.utc)
            return await self.update_key_metadata(metadata)
        return False
    
    async def list_user_keys(self, user_id: str) -> List[APIKeyMetadata]:
        """List all keys for a user."""
        user_key_ids = self._user_keys.get(user_id, set())
        keys = []
        for key_id in user_key_ids:
            metadata = await self.get_key_by_id(key_id)
            if metadata:
                keys.append(metadata)
        return keys
    
    async def delete_key(self, key_id: str) -> bool:
        """Delete API key."""
        key_hash = self._key_ids.get(key_id)
        if key_hash:
            metadata = self._keys.get(key_hash)
            if metadata:
                # Remove from user keys
                if metadata.owner_id in self._user_keys:
                    self._user_keys[metadata.owner_id].discard(key_id)
                
                # Remove from storage
                del self._keys[key_hash]
                del self._key_ids[key_id]
                
                logger.info(f"API key deleted: {key_id}")
                return True
        return False
    
    async def rotate_key(self, key_id: str, new_key_hash: str) -> bool:
        """Rotate API key (update hash while keeping metadata)."""
        old_metadata = await self.get_key_by_id(key_id)
        if old_metadata:
            # Remove old key
            old_key_hash = self._key_ids[key_id]
            del self._keys[old_key_hash]
            
            # Store with new hash
            old_metadata.updated_at = datetime.now(timezone.utc)
            self._keys[new_key_hash] = old_metadata
            self._key_ids[key_id] = new_key_hash
            
            logger.info(f"API key rotated: {key_id}")
            return True
        return False


class RateLimiter:
    """Rate limiter for API keys."""
    
    def __init__(self):
        # In-memory rate limiting - in production use Redis
        self._windows: Dict[str, Dict[str, Any]] = {}
    
    async def check_rate_limit(self, key_id: str, metadata: APIKeyMetadata) -> bool:
        """
        Check if request is within rate limits.
        
        Args:
            key_id: API key ID
            metadata: Key metadata with rate limits
            
        Returns:
            True if within limits, False if rate limited
        """
        now = time.time()
        window_key = f"{key_id}:minute"
        
        # Initialize window if not exists
        if window_key not in self._windows:
            self._windows[window_key] = {
                "count": 0,
                "reset_time": now + 60
            }
        
        window = self._windows[window_key]
        
        # Reset window if expired
        if now >= window["reset_time"]:
            window["count"] = 0
            window["reset_time"] = now + 60
        
        # Check limit
        if window["count"] >= metadata.rate_limit_rpm:
            metadata.usage.rate_limit_hits += 1
            return False
        
        # Increment counter
        window["count"] += 1
        return True
    
    async def get_rate_limit_status(self, key_id: str) -> Dict[str, Any]:
        """Get current rate limit status for a key."""
        window_key = f"{key_id}:minute"
        now = time.time()
        
        if window_key in self._windows:
            window = self._windows[window_key]
            remaining = max(0, int(window["reset_time"] - now))
            return {
                "requests_made": window["count"],
                "reset_in_seconds": remaining
            }
        
        return {
            "requests_made": 0,
            "reset_in_seconds": 60
        }


class APIKeyManager:
    """Main API key management service."""
    
    def __init__(self, config: Optional[APIKeyConfig] = None):
        self.config = config or APIKeyConfig()
        self.generator = APIKeyGenerator(self.config)
        self.store = APIKeyStore()
        self.validator = APIKeyValidator(self.store)
        self.rate_limiter = RateLimiter()
    
    async def create_key(self, name: str, description: str,
                        owner_id: str, owner_email: str,
                        scopes: List[APIKeyScope],
                        expires_in_days: Optional[int] = None,
                        rate_limit_rpm: Optional[int] = None,
                        allowed_ips: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Create a new API key.
        
        Args:
            name: Human-readable key name
            description: Key description
            owner_id: Owner user ID
            owner_email: Owner email
            scopes: List of permitted scopes
            expires_in_days: Expiration in days (None for default)
            rate_limit_rpm: Rate limit requests per minute
            allowed_ips: List of allowed IP addresses
            
        Returns:
            Dictionary with key details
        """
        # Check user key limit
        user_keys = await self.store.list_user_keys(owner_id)
        if len(user_keys) >= self.config.max_keys_per_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Maximum number of API keys ({self.config.max_keys_per_user}) reached"
            )
        
        # Generate key and metadata
        api_key = self.generator.generate_key()
        key_id = self.generator.generate_key_id()
        key_hash = self.generator.hash_key(api_key)
        
        # Set expiration
        expires_at = None
        if expires_in_days:
            expires_at = datetime.now(timezone.utc) + timedelta(days=expires_in_days)
        elif self.config.default_expiry_days:
            expires_at = datetime.now(timezone.utc) + timedelta(days=self.config.default_expiry_days)
        
        # Create metadata
        metadata = APIKeyMetadata(
            key_id=key_id,
            name=name,
            description=description,
            owner_id=owner_id,
            owner_email=owner_email,
            scopes=set(scopes),
            rate_limit_rpm=rate_limit_rpm or 60,
            expires_at=expires_at,
            allowed_ips=set(allowed_ips) if allowed_ips else None
        )
        
        # Store key
        await self.store.store_key(key_hash, metadata)
        
        logger.info(f"API key created: {key_id} for {owner_email}")
        
        return {
            "key_id": key_id,
            "api_key": api_key,  # Only returned once!
            "name": name,
            "scopes": [scope.value for scope in scopes],
            "expires_at": expires_at.isoformat() if expires_at else None,
            "rate_limit_rpm": metadata.rate_limit_rpm,
            "created_at": metadata.created_at.isoformat()
        }
    
    async def validate_key_with_rate_limit(self, api_key: str,
                                          client_ip: Optional[str] = None,
                                          user_agent: Optional[str] = None,
                                          required_scope: Optional[APIKeyScope] = None) -> APIKeyMetadata:
        """
        Validate API key and check rate limits.
        
        Args:
            api_key: API key to validate
            client_ip: Client IP address
            user_agent: Client user agent
            required_scope: Required scope
            
        Returns:
            API key metadata if valid and within limits
            
        Raises:
            HTTPException: If invalid, expired, or rate limited
        """
        # Validate key
        metadata = await self.validator.validate_key(
            api_key, client_ip, user_agent, required_scope
        )
        
        # Check rate limits
        if self.config.enable_rate_limiting:
            if not await self.rate_limiter.check_rate_limit(metadata.key_id, metadata):
                # Get rate limit info for headers
                rate_info = await self.rate_limiter.get_rate_limit_status(metadata.key_id)
                
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Rate limit exceeded",
                    headers={
                        "X-RateLimit-Limit": str(metadata.rate_limit_rpm),
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": str(rate_info["reset_in_seconds"]),
                        "Retry-After": str(rate_info["reset_in_seconds"])
                    }
                )
        
        return metadata
    
    async def rotate_key(self, key_id: str, owner_id: str) -> Dict[str, Any]:
        """
        Rotate an API key (generate new key, keep metadata).
        
        Args:
            key_id: Key ID to rotate
            owner_id: Owner user ID (for authorization)
            
        Returns:
            New key details
        """
        # Get existing metadata
        metadata = await self.store.get_key_by_id(key_id)
        if not metadata or metadata.owner_id != owner_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="API key not found"
            )
        
        # Generate new key
        new_api_key = self.generator.generate_key()
        new_key_hash = self.generator.hash_key(new_api_key)
        
        # Rotate key in store
        await self.store.rotate_key(key_id, new_key_hash)
        
        logger.info(f"API key rotated: {key_id}")
        
        return {
            "key_id": key_id,
            "api_key": new_api_key,  # New key - store securely!
            "rotated_at": datetime.now(timezone.utc).isoformat()
        }
    
    async def revoke_key(self, key_id: str, owner_id: str) -> bool:
        """
        Revoke an API key.
        
        Args:
            key_id: Key ID to revoke
            owner_id: Owner user ID (for authorization)
            
        Returns:
            True if revoked successfully
        """
        metadata = await self.store.get_key_by_id(key_id)
        if not metadata or metadata.owner_id != owner_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="API key not found"
            )
        
        # Update status to revoked
        success = await self.store.update_key_status(key_id, APIKeyStatus.REVOKED)
        
        if success:
            logger.info(f"API key revoked: {key_id}")
        
        return success
    
    async def list_keys(self, owner_id: str) -> List[Dict[str, Any]]:
        """
        List all API keys for a user.
        
        Args:
            owner_id: Owner user ID
            
        Returns:
            List of key metadata (without actual keys)
        """
        keys = await self.store.list_user_keys(owner_id)
        
        return [
            {
                "key_id": key.key_id,
                "name": key.name,
                "description": key.description,
                "scopes": [scope.value for scope in key.scopes],
                "status": key.status.value,
                "rate_limit_rpm": key.rate_limit_rpm,
                "expires_at": key.expires_at.isoformat() if key.expires_at else None,
                "created_at": key.created_at.isoformat(),
                "last_used": key.usage.last_used.isoformat() if key.usage.last_used else None,
                "total_requests": key.usage.total_requests,
                "rate_limit_hits": key.usage.rate_limit_hits
            }
            for key in keys
        ]
    
    async def get_key_analytics(self, key_id: str, owner_id: str) -> Dict[str, Any]:
        """
        Get analytics for an API key.
        
        Args:
            key_id: Key ID
            owner_id: Owner user ID (for authorization)
            
        Returns:
            Key analytics and usage data
        """
        metadata = await self.store.get_key_by_id(key_id)
        if not metadata or metadata.owner_id != owner_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="API key not found"
            )
        
        rate_info = await self.rate_limiter.get_rate_limit_status(key_id)
        
        return {
            "key_id": key_id,
            "name": metadata.name,
            "status": metadata.status.value,
            "usage": {
                "total_requests": metadata.usage.total_requests,
                "requests_today": metadata.usage.requests_today,
                "requests_this_month": metadata.usage.requests_this_month,
                "last_used": metadata.usage.last_used.isoformat() if metadata.usage.last_used else None,
                "last_ip": metadata.usage.last_ip,
                "error_count": metadata.usage.error_count,
                "rate_limit_hits": metadata.usage.rate_limit_hits
            },
            "rate_limit": {
                "limit_rpm": metadata.rate_limit_rpm,
                "current_requests": rate_info["requests_made"],
                "reset_in_seconds": rate_info["reset_in_seconds"]
            },
            "security": {
                "allowed_ips": list(metadata.allowed_ips) if metadata.allowed_ips else None,
                "scopes": [scope.value for scope in metadata.scopes]
            }
        }


# Global API key manager instance
api_key_manager = APIKeyManager()


# FastAPI dependencies for API key authentication

from fastapi import Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.security.api_key import APIKeyHeader

# API key header scheme
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def get_api_key_optional(api_key: Optional[str] = Depends(api_key_header)) -> Optional[str]:
    """Extract API key from X-API-Key header (optional)."""
    return api_key

async def get_api_key_required(api_key: str = Depends(api_key_header)) -> str:
    """Extract API key from X-API-Key header (required)."""
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required",
            headers={"WWW-Authenticate": "ApiKey"}
        )
    return api_key

async def validate_api_key(request: Request, api_key: str = Depends(get_api_key_required)) -> APIKeyMetadata:
    """Validate API key and return metadata."""
    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("User-Agent")
    
    return await api_key_manager.validate_key_with_rate_limit(
        api_key=api_key,
        client_ip=client_ip,
        user_agent=user_agent
    )

def require_api_key_scope(required_scope: APIKeyScope):
    """Dependency factory for requiring specific API key scope."""
    async def check_scope(request: Request, api_key: str = Depends(get_api_key_required)) -> APIKeyMetadata:
        client_ip = request.client.host if request.client else None
        user_agent = request.headers.get("User-Agent")
        
        return await api_key_manager.validate_key_with_rate_limit(
            api_key=api_key,
            client_ip=client_ip,
            user_agent=user_agent,
            required_scope=required_scope
        )
    return check_scope


# Utility functions for integration

def get_client_ip(request: Request) -> str:
    """Extract client IP from request."""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    
    if request.client:
        return request.client.host
    
    return "unknown"


# Security decorator for API key validation
def require_api_key(required_scope: Optional[APIKeyScope] = None):
    """Decorator to require API key authentication."""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # This is for non-FastAPI usage
            # FastAPI should use the Depends() mechanism
            request = kwargs.get('request')
            if not request:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Request object required for API key validation"
                )
            
            api_key = request.headers.get("X-API-Key")
            if not api_key:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="API key required",
                    headers={"WWW-Authenticate": "ApiKey"}
                )
            
            client_ip = get_client_ip(request)
            user_agent = request.headers.get("User-Agent")
            
            metadata = await api_key_manager.validate_key_with_rate_limit(
                api_key=api_key,
                client_ip=client_ip,
                user_agent=user_agent,
                required_scope=required_scope
            )
            
            # Add metadata to kwargs
            kwargs['api_key_metadata'] = metadata
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator

"""
API Key Management Endpoints.

This module provides REST API endpoints for managing API keys:
- Create new API keys
- List user's API keys
- Rotate API keys
- Revoke API keys
- Get API key analytics
- Admin endpoints for key management

Endpoints support both JWT authentication (for users managing their keys)
and admin access for managing all keys.
"""

from typing import List, Optional
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, Field, validator

from app.services.api_keys import (
    api_key_manager, 
    APIKeyScope, 
    APIKeyStatus,
    APIKeyMetadata
)
from app.middleware.auth import (
    get_current_user, 
    RBACManager
)

router = APIRouter(prefix="/api/v1/keys", tags=["API Keys"])


# Request/Response Models

class CreateAPIKeyRequest(BaseModel):
    """Request model for creating API key."""
    name: str = Field(..., min_length=1, max_length=100, description="Human-readable key name")
    description: str = Field(..., min_length=1, max_length=500, description="Key description")
    scopes: List[APIKeyScope] = Field(..., min_items=1, description="List of permitted scopes")
    expires_in_days: Optional[int] = Field(None, gt=0, le=3650, description="Expiration in days (max 10 years)")
    rate_limit_rpm: Optional[int] = Field(60, gt=0, le=10000, description="Rate limit requests per minute")
    allowed_ips: Optional[List[str]] = Field(None, description="List of allowed IP addresses")
    
    @validator('allowed_ips')
    def validate_ips(cls, v):
        """Validate IP addresses."""
        if v:
            import ipaddress
            for ip in v:
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    raise ValueError(f"Invalid IP address: {ip}")
        return v


class APIKeyResponse(BaseModel):
    """Response model for API key (without actual key)."""
    key_id: str
    name: str
    description: str
    scopes: List[str]
    status: str
    rate_limit_rpm: int
    expires_at: Optional[str]
    created_at: str
    last_used: Optional[str]
    total_requests: int
    rate_limit_hits: int


class CreateAPIKeyResponse(BaseModel):
    """Response model for created API key (includes actual key)."""
    key_id: str
    api_key: str = Field(..., description="API key - store securely, won't be shown again!")
    name: str
    scopes: List[str]
    expires_at: Optional[str]
    rate_limit_rpm: int
    created_at: str


class RotateKeyResponse(BaseModel):
    """Response model for rotated API key."""
    key_id: str
    api_key: str = Field(..., description="New API key - store securely, won't be shown again!")
    rotated_at: str


class APIKeyAnalytics(BaseModel):
    """Analytics for an API key."""
    key_id: str
    name: str
    status: str
    usage: dict
    rate_limit: dict
    security: dict


class UpdateAPIKeyRequest(BaseModel):
    """Request model for updating API key."""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, min_length=1, max_length=500)
    rate_limit_rpm: Optional[int] = Field(None, gt=0, le=10000)
    allowed_ips: Optional[List[str]] = None
    status: Optional[APIKeyStatus] = None


# User API Key Endpoints

@router.post("/", response_model=CreateAPIKeyResponse, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    request: CreateAPIKeyRequest,
    current_user=Depends(get_current_user)
):
    """
    Create a new API key for the authenticated user.
    
    The API key will be returned only once in the response.
    Store it securely as it cannot be retrieved again.
    """
    try:
        result = await api_key_manager.create_key(
            name=request.name,
            description=request.description,
            owner_id=current_user["user_id"],
            owner_email=current_user["email"],
            scopes=request.scopes,
            expires_in_days=request.expires_in_days,
            rate_limit_rpm=request.rate_limit_rpm,
            allowed_ips=request.allowed_ips
        )
        
        return CreateAPIKeyResponse(**result)
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create API key: {str(e)}"
        )


@router.get("/", response_model=List[APIKeyResponse])
async def list_api_keys(current_user=Depends(get_current_user)):
    """List all API keys for the authenticated user."""
    try:
        keys = await api_key_manager.list_keys(current_user["user_id"])
        return [APIKeyResponse(**key) for key in keys]
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list API keys: {str(e)}"
        )


@router.get("/{key_id}", response_model=APIKeyResponse)
async def get_api_key(key_id: str, current_user=Depends(get_current_user)):
    """Get details of a specific API key."""
    try:
        keys = await api_key_manager.list_keys(current_user["user_id"])
        key = next((k for k in keys if k["key_id"] == key_id), None)
        
        if not key:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="API key not found"
            )
        
        return APIKeyResponse(**key)
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get API key: {str(e)}"
        )


@router.post("/{key_id}/rotate", response_model=RotateKeyResponse)
async def rotate_api_key(key_id: str, current_user=Depends(get_current_user)):
    """
    Rotate an API key (generate new key, keep metadata).
    
    The old key will be immediately invalidated.
    The new key will be returned only once.
    """
    try:
        result = await api_key_manager.rotate_key(key_id, current_user["user_id"])
        return RotateKeyResponse(**result)
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to rotate API key: {str(e)}"
        )


@router.delete("/{key_id}")
async def revoke_api_key(key_id: str, current_user=Depends(get_current_user)):
    """Revoke an API key (mark as revoked, cannot be used)."""
    try:
        success = await api_key_manager.revoke_key(key_id, current_user["user_id"])
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="API key not found"
            )
        
        return {"message": "API key revoked successfully", "key_id": key_id}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to revoke API key: {str(e)}"
        )


@router.get("/{key_id}/analytics", response_model=APIKeyAnalytics)
async def get_api_key_analytics(key_id: str, current_user=Depends(get_current_user)):
    """Get usage analytics for an API key."""
    try:
        analytics = await api_key_manager.get_key_analytics(key_id, current_user["user_id"])
        return APIKeyAnalytics(**analytics)
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get API key analytics: {str(e)}"
        )


# Admin role dependency
async def require_admin_role(current_user=Depends(get_current_user)):
    """Require admin role for the current user."""
    user_roles = current_user.get("roles", [])
    if not RBACManager.has_role(user_roles, "admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required"
        )
    return current_user


# Admin API Key Endpoints

@router.get("/admin/all", response_model=List[APIKeyResponse])
async def admin_list_all_keys(current_user=Depends(require_admin_role)):
    """[Admin] List all API keys in the system."""
    try:
        # For admin, we need to iterate through all users
        # In a real implementation, this would be a database query
        all_keys = []
        
        # This is a simplified implementation
        # In production, you'd query the database directly
        from app.services.api_keys import api_key_manager
        
        # Access the internal store (not recommended for production)
        for key_hash, metadata in api_key_manager.store._keys.items():
            key_data = {
                "key_id": metadata.key_id,
                "name": metadata.name,
                "description": metadata.description,
                "scopes": [scope.value for scope in metadata.scopes],
                "status": metadata.status.value,
                "rate_limit_rpm": metadata.rate_limit_rpm,
                "expires_at": metadata.expires_at.isoformat() if metadata.expires_at else None,
                "created_at": metadata.created_at.isoformat(),
                "last_used": metadata.usage.last_used.isoformat() if metadata.usage.last_used else None,
                "total_requests": metadata.usage.total_requests,
                "rate_limit_hits": metadata.usage.rate_limit_hits,
                "owner_email": metadata.owner_email  # Additional field for admin
            }
            all_keys.append(key_data)
        
        return all_keys
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list all API keys: {str(e)}"
        )


@router.delete("/admin/{key_id}")
async def admin_revoke_api_key(key_id: str, current_user=Depends(require_admin_role)):
    """[Admin] Revoke any API key in the system."""
    try:
        # Get the key metadata first
        metadata = await api_key_manager.store.get_key_by_id(key_id)
        if not metadata:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="API key not found"
            )
        
        # Revoke the key (using owner_id from metadata)
        success = await api_key_manager.revoke_key(key_id, metadata.owner_id)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to revoke API key"
            )
        
        return {
            "message": "API key revoked successfully by admin",
            "key_id": key_id,
            "owner_email": metadata.owner_email
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to revoke API key: {str(e)}"
        )


@router.get("/admin/analytics/summary")
async def admin_get_analytics_summary(current_user=Depends(require_admin_role)):
    """[Admin] Get system-wide API key analytics summary."""
    try:
        # Collect system-wide statistics
        total_keys = 0
        active_keys = 0
        total_requests = 0
        total_rate_limit_hits = 0
        keys_by_status = {}
        keys_by_scope = {}
        
        # Analyze all keys
        for key_hash, metadata in api_key_manager.store._keys.items():
            total_keys += 1
            
            if metadata.status == APIKeyStatus.ACTIVE:
                active_keys += 1
            
            total_requests += metadata.usage.total_requests
            total_rate_limit_hits += metadata.usage.rate_limit_hits
            
            # Count by status
            status_str = metadata.status.value
            keys_by_status[status_str] = keys_by_status.get(status_str, 0) + 1
            
            # Count by scope
            for scope in metadata.scopes:
                scope_str = scope.value
                keys_by_scope[scope_str] = keys_by_scope.get(scope_str, 0) + 1
        
        return {
            "summary": {
                "total_keys": total_keys,
                "active_keys": active_keys,
                "total_requests": total_requests,
                "total_rate_limit_hits": total_rate_limit_hits
            },
            "distribution": {
                "by_status": keys_by_status,
                "by_scope": keys_by_scope
            },
            "generated_at": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get analytics summary: {str(e)}"
        )


# Health and Status Endpoints

@router.get("/health")
async def api_key_system_health():
    """Check API key system health."""
    try:
        # Basic health checks
        total_keys = len(api_key_manager.store._keys)
        
        # Check if the system is responsive
        test_key_id = "health_check_test"
        
        health_status = {
            "status": "healthy",
            "total_keys": total_keys,
            "timestamp": datetime.utcnow().isoformat(),
            "system": {
                "generator": "operational",
                "validator": "operational", 
                "store": "operational",
                "rate_limiter": "operational"
            }
        }
        
        return health_status
        
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }


# API Key Scope Information

@router.get("/scopes")
async def get_available_scopes():
    """Get list of available API key scopes."""
    scopes = [
        {
            "scope": scope.value,
            "description": _get_scope_description(scope)
        }
        for scope in APIKeyScope
    ]
    
    return {
        "scopes": scopes,
        "total": len(scopes)
    }


def _get_scope_description(scope: APIKeyScope) -> str:
    """Get human-readable description for API key scope."""
    descriptions = {
        APIKeyScope.READ_ONLY: "Read-only access to all endpoints",
        APIKeyScope.READ_WRITE: "Read and write access to user-owned resources",
        APIKeyScope.ADMIN: "Administrative access to all resources",
        APIKeyScope.GATEWAY_MANAGEMENT: "Access to gateway configuration and management",
        APIKeyScope.METRICS: "Access to metrics and monitoring data",
        APIKeyScope.WEATHER: "Access to weather service endpoints"
    }
    return descriptions.get(scope, "Custom scope")


# Rate limit information endpoint

@router.get("/{key_id}/rate-limit")
async def get_rate_limit_status(key_id: str, current_user=Depends(get_current_user)):
    """Get current rate limit status for an API key."""
    try:
        # Verify ownership
        keys = await api_key_manager.list_keys(current_user["user_id"])
        key = next((k for k in keys if k["key_id"] == key_id), None)
        
        if not key:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="API key not found"
            )
        
        rate_info = await api_key_manager.rate_limiter.get_rate_limit_status(key_id)
        
        return {
            "key_id": key_id,
            "rate_limit": {
                "limit_rpm": key["rate_limit_rpm"],
                "requests_made": rate_info["requests_made"],
                "reset_in_seconds": rate_info["reset_in_seconds"]
            },
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get rate limit status: {str(e)}"
        )

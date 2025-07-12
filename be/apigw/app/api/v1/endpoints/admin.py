"""
Admin endpoints protected by JWT authentication.

These endpoints demonstrate the JWT authentication middleware in action
and provide administrative functionality for the API Gateway.
"""

from typing import Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException, status

from app.middleware.auth import (
    get_current_user,
    RequireRole,
    RequirePermission,
    UserContext,
    RBACManager
)

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/users")
async def list_users(current_user: UserContext = Depends(RequireRole("admin"))) -> Dict[str, Any]:
    """
    List all users (admin only).
    
    Requires admin role.
    """
    from app.api.v1.endpoints.auth import MOCK_USERS
    
    users = []
    for username, user_data in MOCK_USERS.items():
        users.append({
            "user_id": user_data["user_id"],
            "username": user_data["username"],
            "email": user_data["email"],
            "roles": user_data["roles"],
            "active": user_data["active"]
        })
    
    return {
        "total_users": len(users),
        "users": users,
        "requested_by": current_user.username
    }


@router.get("/system-info")
async def get_system_info(current_user: UserContext = Depends(RequirePermission("gateway:admin"))) -> Dict[str, Any]:
    """
    Get system information (requires gateway:admin permission).
    
    This endpoint demonstrates permission-based access control.
    """
    import psutil
    import time
    
    return {
        "system": {
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_usage": psutil.disk_usage('/').percent,
            "uptime": time.time() - psutil.boot_time()
        },
        "gateway": {
            "version": "0.1.0",
            "authentication": "enabled",
            "protected_endpoints": True
        },
        "requested_by": {
            "user_id": current_user.user_id,
            "username": current_user.username,
            "roles": current_user.roles,
            "permissions": current_user.permissions
        }
    }


@router.post("/user/{user_id}/roles")
async def assign_roles(
    user_id: str,
    roles: List[str],
    current_user: UserContext = Depends(RequireRole("admin"))
) -> Dict[str, Any]:
    """
    Assign roles to a user (admin only).
    
    Demonstrates role-based access control for user management.
    """
    from app.api.v1.endpoints.auth import MOCK_USERS
    
    # Find user by user_id
    target_user = None
    target_username = None
    for username, user_data in MOCK_USERS.items():
        if user_data["user_id"] == user_id:
            target_user = user_data
            target_username = username
            break
    
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found"
        )
    
    # Validate roles
    valid_roles = ["guest", "user", "moderator", "admin"]
    invalid_roles = [role for role in roles if role not in valid_roles]
    if invalid_roles:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid roles: {invalid_roles}. Valid roles: {valid_roles}"
        )
    
    # Update user roles
    target_user["roles"] = roles
    
    return {
        "message": f"Roles updated for user {target_username}",
        "user_id": user_id,
        "username": target_username,
        "new_roles": roles,
        "new_permissions": RBACManager.get_effective_permissions(roles),
        "updated_by": current_user.username
    }


@router.get("/permissions")
async def list_permissions(current_user: UserContext = Depends(RequireRole("admin"))) -> Dict[str, Any]:
    """
    List all available permissions and role mappings (admin only).
    """
    return {
        "role_hierarchy": RBACManager.ROLE_HIERARCHY,
        "default_permissions": RBACManager.DEFAULT_PERMISSIONS,
        "current_user": {
            "username": current_user.username,
            "roles": current_user.roles,
            "permissions": current_user.permissions
        }
    }


@router.get("/audit-log")
async def get_audit_log(current_user: UserContext = Depends(RequireRole("admin"))) -> Dict[str, Any]:
    """
    Get recent security audit events (admin only).
    
    In production, this would query a proper audit log storage.
    """
    # This is a mock response - in production you'd query actual audit logs
    return {
        "message": "Audit log endpoint - in production this would return actual security events",
        "note": "Check application logs for SECURITY_AUDIT entries",
        "log_location": "Application logs with 'SECURITY_AUDIT' prefix",
        "requested_by": current_user.username,
        "sample_events": [
            {
                "timestamp": "2025-07-12T10:30:00Z",
                "event_type": "auth.login.success",
                "user_id": "user-456",
                "ip_address": "192.168.1.100"
            },
            {
                "timestamp": "2025-07-12T10:25:00Z", 
                "event_type": "auth.login.failure",
                "username": "unknown",
                "ip_address": "192.168.1.200",
                "reason": "Invalid credentials"
            }
        ]
    }

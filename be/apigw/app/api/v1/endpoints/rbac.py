"""
RBAC Management API Endpoints.

This module provides REST API endpoints for managing the RBAC system:
- Role management (create, update, delete, list roles)
- Permission management
- Policy management
- User role assignments
- Access auditing and reporting
- System health and diagnostics

Endpoints support administrative access control and comprehensive
audit logging for security compliance.
"""

from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, Field, validator

from app.core.rbac import (
    rbac_engine,
    rbac_admin,
    RBACAdmin,
    Role,
    Permission,
    AccessPolicy,
    AccessRequest,
    AccessResult,
    ResourceType,
    Action,
    AccessEffect,
    create_permission_from_string,
    permission_to_string
)
from app.middleware.auth import get_current_user

router = APIRouter(prefix="/api/v1/rbac", tags=["RBAC Management"])


# Request/Response Models

class CreateRoleRequest(BaseModel):
    """Request model for creating a role."""
    name: str = Field(..., min_length=1, max_length=50, description="Role name")
    display_name: str = Field(..., min_length=1, max_length=100, description="Display name")
    description: str = Field(..., min_length=1, max_length=500, description="Role description")
    permissions: List[str] = Field(default_factory=list, description="List of permissions")
    parent_roles: List[str] = Field(default_factory=list, description="Parent roles for inheritance")
    
    @validator('name')
    def validate_name(cls, v):
        """Validate role name format."""
        if not v.replace('_', '').replace('-', '').isalnum():
            raise ValueError("Role name must contain only alphanumeric characters, hyphens, and underscores")
        return v.lower()


class UpdateRoleRequest(BaseModel):
    """Request model for updating a role."""
    display_name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, min_length=1, max_length=500)
    permissions: Optional[List[str]] = None
    parent_roles: Optional[List[str]] = None


class RoleResponse(BaseModel):
    """Response model for role information."""
    name: str
    display_name: str
    description: str
    permissions: List[str]
    parent_roles: List[str]
    is_system_role: bool
    created_at: str
    updated_at: str


class CreatePolicyRequest(BaseModel):
    """Request model for creating an access policy."""
    id: str = Field(..., min_length=1, max_length=100, description="Policy ID")
    name: str = Field(..., min_length=1, max_length=100, description="Policy name")
    description: str = Field(..., min_length=1, max_length=500, description="Policy description")
    effect: AccessEffect = Field(..., description="Allow or deny effect")
    subjects: List[str] = Field(..., min_items=1, description="Subjects (users, roles)")
    resources: List[str] = Field(..., min_items=1, description="Resource patterns")
    actions: List[str] = Field(..., min_items=1, description="Action patterns")
    conditions: Optional[Dict[str, Any]] = Field(None, description="Policy conditions")
    priority: int = Field(0, ge=0, le=1000, description="Policy priority")
    duration_hours: Optional[int] = Field(None, gt=0, description="Policy duration in hours")


class PolicyResponse(BaseModel):
    """Response model for policy information."""
    id: str
    name: str
    description: str
    effect: str
    subjects: List[str]
    resources: List[str]
    actions: List[str]
    conditions: Optional[Dict[str, Any]]
    priority: int
    enabled: bool
    created_at: str
    expires_at: Optional[str]


class AccessCheckRequest(BaseModel):
    """Request model for access checking."""
    user_id: str = Field(..., description="User ID")
    roles: List[str] = Field(..., min_items=1, description="User roles")
    resource: str = Field(..., description="Resource being accessed")
    action: str = Field(..., description="Action being performed")
    additional_context: Optional[Dict[str, Any]] = None


class AccessCheckResponse(BaseModel):
    """Response model for access check result."""
    granted: bool
    reason: str
    policy_matched: Optional[str]
    permissions_used: Optional[List[str]]
    timestamp: str


class UserRoleAssignmentRequest(BaseModel):
    """Request model for user role assignment."""
    user_id: str = Field(..., description="User ID")
    roles: List[str] = Field(..., min_items=1, description="Roles to assign")


class PermissionInfo(BaseModel):
    """Information about a permission."""
    resource: str
    action: str
    scope: str
    description: str


class RoleHierarchyResponse(BaseModel):
    """Response model for role hierarchy."""
    roles: Dict[str, Any]
    total_roles: int
    system_roles: int
    custom_roles: int


# Admin role dependency
async def require_rbac_admin(current_user=Depends(get_current_user)):
    """Require RBAC admin permissions."""
    user_roles = current_user.get("roles", [])
    
    # Check if user has admin or super_admin role
    if not any(role in ["admin", "super_admin"] for role in user_roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="RBAC administration privileges required"
        )
    
    return current_user


# Role Management Endpoints

@router.post("/roles", response_model=RoleResponse, status_code=status.HTTP_201_CREATED)
async def create_role(
    request: CreateRoleRequest,
    current_user=Depends(require_rbac_admin)
):
    """Create a new role with specified permissions."""
    try:
        role = rbac_admin.create_custom_role(
            name=request.name,
            display_name=request.display_name,
            description=request.description,
            permissions=request.permissions,
            parent_roles=request.parent_roles
        )
        
        return RoleResponse(
            name=role.name,
            display_name=role.display_name,
            description=role.description,
            permissions=[str(p) for p in role.permissions],
            parent_roles=list(role.parent_roles),
            is_system_role=role.is_system_role,
            created_at=role.created_at.isoformat(),
            updated_at=role.updated_at.isoformat()
        )
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create role: {str(e)}"
        )


@router.get("/roles", response_model=List[RoleResponse])
async def list_roles(current_user=Depends(require_rbac_admin)):
    """List all roles in the system."""
    try:
        roles = rbac_engine.role_manager.list_roles()
        
        return [
            RoleResponse(
                name=role.name,
                display_name=role.display_name,
                description=role.description,
                permissions=[str(p) for p in role.permissions],
                parent_roles=list(role.parent_roles),
                is_system_role=role.is_system_role,
                created_at=role.created_at.isoformat(),
                updated_at=role.updated_at.isoformat()
            )
            for role in roles
        ]
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list roles: {str(e)}"
        )


@router.get("/roles/{role_name}", response_model=RoleResponse)
async def get_role(role_name: str, current_user=Depends(require_rbac_admin)):
    """Get details of a specific role."""
    try:
        role = rbac_engine.role_manager.get_role(role_name)
        
        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Role '{role_name}' not found"
            )
        
        return RoleResponse(
            name=role.name,
            display_name=role.display_name,
            description=role.description,
            permissions=[str(p) for p in role.permissions],
            parent_roles=list(role.parent_roles),
            is_system_role=role.is_system_role,
            created_at=role.created_at.isoformat(),
            updated_at=role.updated_at.isoformat()
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get role: {str(e)}"
        )


@router.put("/roles/{role_name}", response_model=RoleResponse)
async def update_role(
    role_name: str,
    request: UpdateRoleRequest,
    current_user=Depends(require_rbac_admin)
):
    """Update an existing role."""
    try:
        # Convert permissions to Permission objects if provided
        update_data = {}
        for field, value in request.dict(exclude_unset=True).items():
            if field == "permissions" and value is not None:
                update_data[field] = {create_permission_from_string(p) for p in value}
            elif field == "parent_roles" and value is not None:
                update_data[field] = set(value)
            else:
                update_data[field] = value
        
        role = rbac_engine.role_manager.update_role(role_name, **update_data)
        
        return RoleResponse(
            name=role.name,
            display_name=role.display_name,
            description=role.description,
            permissions=[str(p) for p in role.permissions],
            parent_roles=list(role.parent_roles),
            is_system_role=role.is_system_role,
            created_at=role.created_at.isoformat(),
            updated_at=role.updated_at.isoformat()
        )
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update role: {str(e)}"
        )


@router.delete("/roles/{role_name}")
async def delete_role(role_name: str, current_user=Depends(require_rbac_admin)):
    """Delete a role."""
    try:
        success = rbac_engine.role_manager.delete_role(role_name)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Role '{role_name}' not found"
            )
        
        return {"message": f"Role '{role_name}' deleted successfully"}
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete role: {str(e)}"
        )


# Policy Management Endpoints

@router.post("/policies", response_model=PolicyResponse, status_code=status.HTTP_201_CREATED)
async def create_policy(
    request: CreatePolicyRequest,
    current_user=Depends(require_rbac_admin)
):
    """Create a new access control policy."""
    try:
        if request.duration_hours:
            # Create time-limited policy
            policy = rbac_admin.create_time_limited_policy(
                policy_id=request.id,
                name=request.name,
                description=request.description,
                effect=request.effect,
                subjects=request.subjects,
                resources=request.resources,
                actions=request.actions,
                duration_hours=request.duration_hours
            )
        else:
            # Create permanent policy
            policy = AccessPolicy(
                id=request.id,
                name=request.name,
                description=request.description,
                effect=request.effect,
                subjects=request.subjects,
                resources=request.resources,
                actions=request.actions,
                conditions=request.conditions,
                priority=request.priority
            )
            policy = rbac_engine.policy_manager.create_policy(policy)
        
        return PolicyResponse(
            id=policy.id,
            name=policy.name,
            description=policy.description,
            effect=policy.effect.value,
            subjects=policy.subjects,
            resources=policy.resources,
            actions=policy.actions,
            conditions=policy.conditions,
            priority=policy.priority,
            enabled=policy.enabled,
            created_at=policy.created_at.isoformat(),
            expires_at=policy.expires_at.isoformat() if policy.expires_at else None
        )
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create policy: {str(e)}"
        )


@router.get("/policies", response_model=List[PolicyResponse])
async def list_policies(current_user=Depends(require_rbac_admin)):
    """List all access control policies."""
    try:
        policies = rbac_engine.policy_manager.list_policies()
        
        return [
            PolicyResponse(
                id=policy.id,
                name=policy.name,
                description=policy.description,
                effect=policy.effect.value,
                subjects=policy.subjects,
                resources=policy.resources,
                actions=policy.actions,
                conditions=policy.conditions,
                priority=policy.priority,
                enabled=policy.enabled,
                created_at=policy.created_at.isoformat(),
                expires_at=policy.expires_at.isoformat() if policy.expires_at else None
            )
            for policy in policies
        ]
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list policies: {str(e)}"
        )


@router.delete("/policies/{policy_id}")
async def delete_policy(policy_id: str, current_user=Depends(require_rbac_admin)):
    """Delete an access control policy."""
    try:
        success = rbac_engine.policy_manager.delete_policy(policy_id)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Policy '{policy_id}' not found"
            )
        
        return {"message": f"Policy '{policy_id}' deleted successfully"}
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete policy: {str(e)}"
        )


# Access Control Endpoints

@router.post("/check-access", response_model=AccessCheckResponse)
async def check_access(
    request: AccessCheckRequest,
    current_user=Depends(require_rbac_admin)
):
    """Check if a user has access to a resource/action."""
    try:
        access_request = AccessRequest(
            user_id=request.user_id,
            username=f"user_{request.user_id}",  # Simplified username
            roles=request.roles,
            resource=request.resource,
            action=request.action,
            additional_context=request.additional_context
        )
        
        result = rbac_engine.check_access(access_request)
        
        return AccessCheckResponse(
            granted=result.granted,
            reason=result.reason,
            policy_matched=result.policy_matched,
            permissions_used=result.permissions_used,
            timestamp=result.timestamp.isoformat()
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to check access: {str(e)}"
        )


@router.get("/permissions/available", response_model=List[PermissionInfo])
async def get_available_permissions(current_user=Depends(require_rbac_admin)):
    """Get list of all available permissions."""
    try:
        permissions = []
        
        # Generate permissions for all resource types and actions
        for resource_type in ResourceType:
            for action in Action:
                permissions.append(PermissionInfo(
                    resource=resource_type.value,
                    action=action.value,
                    scope="*",
                    description=f"{action.value.title()} access to {resource_type.value} resources"
                ))
        
        return permissions
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get available permissions: {str(e)}"
        )


@router.get("/hierarchy", response_model=RoleHierarchyResponse)
async def get_role_hierarchy(current_user=Depends(require_rbac_admin)):
    """Get complete role hierarchy for visualization."""
    try:
        hierarchy = rbac_admin.get_role_hierarchy()
        
        total_roles = len(hierarchy)
        system_roles = sum(1 for role_info in hierarchy.values() if role_info["is_system_role"])
        custom_roles = total_roles - system_roles
        
        return RoleHierarchyResponse(
            roles=hierarchy,
            total_roles=total_roles,
            system_roles=system_roles,
            custom_roles=custom_roles
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get role hierarchy: {str(e)}"
        )


# User Management Endpoints (Integration points)

@router.get("/users/{user_id}/audit")
async def audit_user_access(user_id: str, current_user=Depends(require_rbac_admin)):
    """Audit user's current access rights."""
    try:
        # In a real implementation, you'd get user roles from the user service
        # For now, we'll use the current user's roles as an example
        user_roles = current_user.get("roles", ["user"])
        
        audit_result = rbac_admin.audit_user_access(user_id, user_roles)
        
        return audit_result
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to audit user access: {str(e)}"
        )


@router.get("/users/{user_id}/permissions")
async def get_user_permissions(user_id: str, current_user=Depends(require_rbac_admin)):
    """Get effective permissions for a user."""
    try:
        # In a real implementation, you'd get user roles from the user service
        user_roles = current_user.get("roles", ["user"])
        
        effective_permissions = rbac_engine.get_user_effective_permissions(user_roles)
        
        return {
            "user_id": user_id,
            "roles": user_roles,
            "effective_permissions": effective_permissions,
            "permission_count": len(effective_permissions),
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get user permissions: {str(e)}"
        )


@router.get("/health")
async def rbac_system_health():
    """Check RBAC system health and status."""
    try:
        roles = rbac_engine.role_manager.list_roles()
        policies = rbac_engine.policy_manager.list_policies()
        
        # Check for potential issues
        issues = []
        
        # Check for roles without permissions
        roles_without_permissions = [r.name for r in roles if not r.permissions and not r.parent_roles]
        if roles_without_permissions:
            issues.append(f"Roles without permissions: {', '.join(roles_without_permissions)}")
        
        # Check for expired policies
        now = datetime.utcnow()
        expired_policies = [p.id for p in policies if p.expires_at and p.expires_at < now]
        if expired_policies:
            issues.append(f"Expired policies: {', '.join(expired_policies)}")
        
        return {
            "status": "healthy" if not issues else "warning",
            "timestamp": datetime.utcnow().isoformat(),
            "statistics": {
                "total_roles": len(roles),
                "system_roles": sum(1 for r in roles if r.is_system_role),
                "custom_roles": sum(1 for r in roles if not r.is_system_role),
                "total_policies": len(policies),
                "active_policies": sum(1 for p in policies if p.enabled),
                "expired_policies": len(expired_policies)
            },
            "issues": issues
        }
        
    except Exception as e:
        return {
            "status": "unhealthy",
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }


@router.get("/metrics")
async def rbac_metrics(current_user=Depends(require_rbac_admin)):
    """Get RBAC system metrics."""
    try:
        roles = rbac_engine.role_manager.list_roles()
        policies = rbac_engine.policy_manager.list_policies()
        
        # Calculate metrics
        total_permissions = sum(len(role.permissions) for role in roles)
        avg_permissions_per_role = total_permissions / len(roles) if roles else 0
        
        role_distribution = {}
        for role in roles:
            category = "system" if role.is_system_role else "custom"
            role_distribution[category] = role_distribution.get(category, 0) + 1
        
        policy_distribution = {}
        for policy in policies:
            effect = policy.effect.value
            policy_distribution[effect] = policy_distribution.get(effect, 0) + 1
        
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "role_metrics": {
                "total_roles": len(roles),
                "total_permissions": total_permissions,
                "avg_permissions_per_role": round(avg_permissions_per_role, 2),
                "role_distribution": role_distribution
            },
            "policy_metrics": {
                "total_policies": len(policies),
                "active_policies": sum(1 for p in policies if p.enabled),
                "policy_distribution": policy_distribution
            }
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get RBAC metrics: {str(e)}"
        )

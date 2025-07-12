"""
Enterprise-Grade Role-Based Access Control (RBAC) System.

This module provides a comprehensive RBAC implementation for the API Gateway with:
- Hierarchical role system with inheritance
- Fine-grained permission management
- Dynamic role and permission assignment
- Resource-based access control
- Policy-driven authorization
- Audit logging for access control events
- Performance-optimized permission checking

Features:
- Role hierarchy with automatic inheritance
- Resource-specific permissions
- Dynamic policy evaluation
- Time-based access control
- IP-based restrictions
- Contextual authorization
- Comprehensive audit trail
"""

import logging
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Set, Optional, Any, Tuple, Union
from enum import Enum
from dataclasses import dataclass, field
from functools import wraps, lru_cache
import json
import fnmatch

from pydantic import BaseModel, Field, validator
from fastapi import HTTPException, status, Request, Depends

logger = logging.getLogger(__name__)


class AccessEffect(Enum):
    """Access control effect enumeration."""
    ALLOW = "allow"
    DENY = "deny"


class ResourceType(Enum):
    """Resource type enumeration for RBAC."""
    GATEWAY = "gateway"
    SERVICE = "service"
    USER = "user"
    ROLE = "role"
    PERMISSION = "permission"
    METRIC = "metric"
    LOG = "log"
    API_KEY = "api_key"
    CONFIG = "config"
    AUDIT = "audit"


class Action(Enum):
    """Action enumeration for RBAC."""
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    EXECUTE = "execute"
    ADMIN = "admin"
    LIST = "list"
    SEARCH = "search"


@dataclass
class Permission:
    """Permission definition with resource and action scope."""
    resource: ResourceType
    action: Action
    scope: Optional[str] = "*"  # Resource scope (e.g., specific service ID, "*" for all)
    conditions: Optional[Dict[str, Any]] = None  # Additional conditions
    
    def __str__(self) -> str:
        """String representation of permission."""
        if self.scope and self.scope != "*":
            return f"{self.resource.value}:{self.scope}:{self.action.value}"
        return f"{self.resource.value}:{self.action.value}"
    
    def __hash__(self) -> int:
        """Hash for use in sets."""
        return hash((self.resource, self.action, self.scope, str(self.conditions)))
    
    def matches(self, other: 'Permission') -> bool:
        """Check if this permission matches another permission request."""
        # Resource must match
        if self.resource != other.resource:
            return False
        
        # Action must match
        if self.action != other.action:
            return False
        
        # Scope matching with wildcard support
        if self.scope == "*":
            return True
        
        if self.scope == other.scope:
            return True
        
        # Pattern matching for scope
        if self.scope and other.scope:
            return fnmatch.fnmatch(other.scope, self.scope)
        
        return False


@dataclass
class Role:
    """Role definition with permissions and metadata."""
    name: str
    display_name: str
    description: str
    permissions: Set[Permission] = field(default_factory=set)
    parent_roles: Set[str] = field(default_factory=set)  # Role inheritance
    metadata: Dict[str, Any] = field(default_factory=dict)
    is_system_role: bool = False  # System roles cannot be deleted
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def add_permission(self, permission: Permission):
        """Add permission to role."""
        self.permissions.add(permission)
        self.updated_at = datetime.now(timezone.utc)
    
    def remove_permission(self, permission: Permission):
        """Remove permission from role."""
        self.permissions.discard(permission)
        self.updated_at = datetime.now(timezone.utc)
    
    def get_all_permissions(self, role_manager: 'RoleManager') -> Set[Permission]:
        """Get all permissions including inherited ones."""
        all_permissions = set(self.permissions)
        
        # Add permissions from parent roles
        for parent_role_name in self.parent_roles:
            parent_role = role_manager.get_role(parent_role_name)
            if parent_role:
                all_permissions.update(parent_role.get_all_permissions(role_manager))
        
        return all_permissions


@dataclass
class AccessPolicy:
    """Access control policy definition."""
    id: str
    name: str
    description: str
    effect: AccessEffect
    subjects: List[str]  # Users, roles, or groups
    resources: List[str]  # Resource patterns
    actions: List[str]  # Action patterns
    conditions: Optional[Dict[str, Any]] = None  # Policy conditions
    priority: int = 0  # Higher priority policies evaluated first
    enabled: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    
    def matches_request(self, subject: str, resource: str, action: str, context: Optional[Dict[str, Any]] = None) -> bool:
        """Check if policy matches the access request."""
        if not self.enabled:
            return False
        
        # Check expiration
        if self.expires_at and datetime.now(timezone.utc) > self.expires_at:
            return False
        
        # Check subject
        if not any(fnmatch.fnmatch(subject, pattern) for pattern in self.subjects):
            return False
        
        # Check resource
        if not any(fnmatch.fnmatch(resource, pattern) for pattern in self.resources):
            return False
        
        # Check action
        if not any(fnmatch.fnmatch(action, pattern) for pattern in self.actions):
            return False
        
        # Check conditions
        if self.conditions and context:
            if not self._evaluate_conditions(self.conditions, context):
                return False
        
        return True
    
    def _evaluate_conditions(self, conditions: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Evaluate policy conditions against request context."""
        for key, expected_value in conditions.items():
            if key not in context:
                return False
            
            actual_value = context[key]
            
            # Handle different condition types
            if isinstance(expected_value, dict):
                # Complex condition evaluation
                if "$in" in expected_value:
                    if actual_value not in expected_value["$in"]:
                        return False
                elif "$not" in expected_value:
                    if actual_value == expected_value["$not"]:
                        return False
                elif "$regex" in expected_value:
                    import re
                    if not re.match(expected_value["$regex"], str(actual_value)):
                        return False
            else:
                # Simple equality check
                if actual_value != expected_value:
                    return False
        
        return True


class RoleManager:
    """Manages roles and their permissions."""
    
    def __init__(self):
        self._roles: Dict[str, Role] = {}
        self._initialize_system_roles()
    
    def _initialize_system_roles(self):
        """Initialize system-defined roles."""
        # Super Admin role
        super_admin_permissions = {
            Permission(ResourceType.GATEWAY, Action.ADMIN),
            Permission(ResourceType.SERVICE, Action.ADMIN),
            Permission(ResourceType.USER, Action.ADMIN),
            Permission(ResourceType.ROLE, Action.ADMIN),
            Permission(ResourceType.PERMISSION, Action.ADMIN),
            Permission(ResourceType.METRIC, Action.ADMIN),
            Permission(ResourceType.LOG, Action.ADMIN),
            Permission(ResourceType.API_KEY, Action.ADMIN),
            Permission(ResourceType.CONFIG, Action.ADMIN),
            Permission(ResourceType.AUDIT, Action.ADMIN),
        }
        
        super_admin = Role(
            name="super_admin",
            display_name="Super Administrator",
            description="Full system access with all permissions",
            permissions=super_admin_permissions,
            is_system_role=True
        )
        
        # Admin role
        admin_permissions = {
            Permission(ResourceType.GATEWAY, Action.READ),
            Permission(ResourceType.GATEWAY, Action.UPDATE),
            Permission(ResourceType.GATEWAY, Action.ADMIN),
            Permission(ResourceType.SERVICE, Action.READ),
            Permission(ResourceType.SERVICE, Action.CREATE),
            Permission(ResourceType.SERVICE, Action.UPDATE),
            Permission(ResourceType.SERVICE, Action.DELETE),
            Permission(ResourceType.USER, Action.READ),
            Permission(ResourceType.USER, Action.UPDATE),
            Permission(ResourceType.METRIC, Action.READ),
            Permission(ResourceType.API_KEY, Action.READ),
            Permission(ResourceType.API_KEY, Action.CREATE),
            Permission(ResourceType.CONFIG, Action.READ),
            Permission(ResourceType.CONFIG, Action.UPDATE),
        }
        
        admin = Role(
            name="admin",
            display_name="Administrator",
            description="Administrative access to most system functions",
            permissions=admin_permissions,
            is_system_role=True
        )
        
        # Moderator role
        moderator_permissions = {
            Permission(ResourceType.GATEWAY, Action.READ),
            Permission(ResourceType.SERVICE, Action.READ),
            Permission(ResourceType.SERVICE, Action.UPDATE),
            Permission(ResourceType.USER, Action.READ),
            Permission(ResourceType.METRIC, Action.READ),
            Permission(ResourceType.API_KEY, Action.READ),
        }
        
        moderator = Role(
            name="moderator",
            display_name="Moderator",
            description="Limited administrative access",
            permissions=moderator_permissions,
            parent_roles={"user"},
            is_system_role=True
        )
        
        # User role
        user_permissions = {
            Permission(ResourceType.GATEWAY, Action.READ),
            Permission(ResourceType.SERVICE, Action.READ),
            Permission(ResourceType.METRIC, Action.READ),
        }
        
        user = Role(
            name="user",
            display_name="User",
            description="Standard user access",
            permissions=user_permissions,
            parent_roles={"guest"},
            is_system_role=True
        )
        
        # Guest role
        guest_permissions = {
            Permission(ResourceType.GATEWAY, Action.READ, scope="public"),
        }
        
        guest = Role(
            name="guest",
            display_name="Guest",
            description="Minimal read-only access",
            permissions=guest_permissions,
            is_system_role=True
        )
        
        # Service Account role
        service_account_permissions = {
            Permission(ResourceType.GATEWAY, Action.READ),
            Permission(ResourceType.SERVICE, Action.READ),
            Permission(ResourceType.METRIC, Action.CREATE),
            Permission(ResourceType.METRIC, Action.READ),
        }
        
        service_account = Role(
            name="service_account",
            display_name="Service Account",
            description="Automated service access",
            permissions=service_account_permissions,
            is_system_role=True
        )
        
        # Store system roles
        for role in [super_admin, admin, moderator, user, guest, service_account]:
            self._roles[role.name] = role
    
    def create_role(self, name: str, display_name: str, description: str, 
                   permissions: Optional[Set[Permission]] = None,
                   parent_roles: Optional[Set[str]] = None) -> Role:
        """Create a new role."""
        if name in self._roles:
            raise ValueError(f"Role '{name}' already exists")
        
        role = Role(
            name=name,
            display_name=display_name,
            description=description,
            permissions=permissions or set(),
            parent_roles=parent_roles or set()
        )
        
        self._roles[name] = role
        logger.info(f"Created role: {name}")
        return role
    
    def get_role(self, name: str) -> Optional[Role]:
        """Get role by name."""
        return self._roles.get(name)
    
    def list_roles(self) -> List[Role]:
        """List all roles."""
        return list(self._roles.values())
    
    def update_role(self, name: str, **kwargs) -> Role:
        """Update role properties."""
        role = self.get_role(name)
        if not role:
            raise ValueError(f"Role '{name}' not found")
        
        if role.is_system_role:
            raise ValueError(f"Cannot modify system role '{name}'")
        
        for key, value in kwargs.items():
            if hasattr(role, key):
                setattr(role, key, value)
        
        role.updated_at = datetime.now(timezone.utc)
        logger.info(f"Updated role: {name}")
        return role
    
    def delete_role(self, name: str) -> bool:
        """Delete a role."""
        role = self.get_role(name)
        if not role:
            return False
        
        if role.is_system_role:
            raise ValueError(f"Cannot delete system role '{name}'")
        
        del self._roles[name]
        logger.info(f"Deleted role: {name}")
        return True
    
    def add_permission_to_role(self, role_name: str, permission: Permission) -> bool:
        """Add permission to role."""
        role = self.get_role(role_name)
        if not role:
            return False
        
        role.add_permission(permission)
        logger.info(f"Added permission {permission} to role {role_name}")
        return True
    
    def remove_permission_from_role(self, role_name: str, permission: Permission) -> bool:
        """Remove permission from role."""
        role = self.get_role(role_name)
        if not role:
            return False
        
        role.remove_permission(permission)
        logger.info(f"Removed permission {permission} from role {role_name}")
        return True


class PolicyManager:
    """Manages access control policies."""
    
    def __init__(self):
        self._policies: Dict[str, AccessPolicy] = {}
        self._initialize_default_policies()
    
    def _initialize_default_policies(self):
        """Initialize default access policies."""
        # Allow admins full access
        admin_policy = AccessPolicy(
            id="admin_full_access",
            name="Admin Full Access",
            description="Allow administrators full access to all resources",
            effect=AccessEffect.ALLOW,
            subjects=["role:admin", "role:super_admin"],
            resources=["*"],
            actions=["*"],
            priority=100
        )
        
        # Deny guests write access
        guest_deny_policy = AccessPolicy(
            id="guest_deny_write",
            name="Guest Deny Write",
            description="Deny guests write access to all resources",
            effect=AccessEffect.DENY,
            subjects=["role:guest"],
            resources=["*"],
            actions=["create", "update", "delete", "admin"],
            priority=90
        )
        
        # Allow users read access to their own resources
        user_self_access = AccessPolicy(
            id="user_self_access",
            name="User Self Access",
            description="Allow users access to their own resources",
            effect=AccessEffect.ALLOW,
            subjects=["role:user"],
            resources=["user:${user_id}", "api_key:${user_id}/*"],
            actions=["read", "update"],
            priority=80
        )
        
        for policy in [admin_policy, guest_deny_policy, user_self_access]:
            self._policies[policy.id] = policy
    
    def create_policy(self, policy: AccessPolicy) -> AccessPolicy:
        """Create a new access policy."""
        if policy.id in self._policies:
            raise ValueError(f"Policy '{policy.id}' already exists")
        
        self._policies[policy.id] = policy
        logger.info(f"Created policy: {policy.id}")
        return policy
    
    def get_policy(self, policy_id: str) -> Optional[AccessPolicy]:
        """Get policy by ID."""
        return self._policies.get(policy_id)
    
    def list_policies(self) -> List[AccessPolicy]:
        """List all policies."""
        return sorted(self._policies.values(), key=lambda p: p.priority, reverse=True)
    
    def update_policy(self, policy_id: str, **kwargs) -> AccessPolicy:
        """Update policy properties."""
        policy = self.get_policy(policy_id)
        if not policy:
            raise ValueError(f"Policy '{policy_id}' not found")
        
        for key, value in kwargs.items():
            if hasattr(policy, key):
                setattr(policy, key, value)
        
        logger.info(f"Updated policy: {policy_id}")
        return policy
    
    def delete_policy(self, policy_id: str) -> bool:
        """Delete a policy."""
        if policy_id in self._policies:
            del self._policies[policy_id]
            logger.info(f"Deleted policy: {policy_id}")
            return True
        return False
    
    def evaluate_policies(self, subject: str, resource: str, action: str, 
                         context: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        """Evaluate all applicable policies for an access request."""
        applicable_policies = []
        
        # Find applicable policies
        for policy in self.list_policies():  # Already sorted by priority
            if policy.matches_request(subject, resource, action, context):
                applicable_policies.append(policy)
        
        # Evaluate policies (DENY takes precedence)
        for policy in applicable_policies:
            if policy.effect == AccessEffect.DENY:
                return False, f"Access denied by policy: {policy.name}"
        
        # Check for ALLOW policies
        for policy in applicable_policies:
            if policy.effect == AccessEffect.ALLOW:
                return True, f"Access granted by policy: {policy.name}"
        
        # Default deny if no policies match
        return False, "No applicable policies found - default deny"


@dataclass
class AccessRequest:
    """Access control request context."""
    user_id: str
    username: str
    roles: List[str]
    resource: str
    action: str
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    additional_context: Optional[Dict[str, Any]] = None


@dataclass
class AccessResult:
    """Access control decision result."""
    granted: bool
    reason: str
    policy_matched: Optional[str] = None
    permissions_used: Optional[List[str]] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class RBACEngine:
    """Main RBAC engine that combines roles, permissions, and policies."""
    
    def __init__(self):
        self.role_manager = RoleManager()
        self.policy_manager = PolicyManager()
        self._permission_cache: Dict[str, Set[Permission]] = {}
        self._cache_ttl = 300  # 5 minutes
        self._cache_timestamps: Dict[str, float] = {}
    
    @lru_cache(maxsize=1000)
    def _get_user_permissions(self, user_roles_tuple: Tuple[str, ...]) -> Set[Permission]:
        """Get all permissions for user roles (cached)."""
        user_roles = list(user_roles_tuple)
        all_permissions = set()
        
        for role_name in user_roles:
            role = self.role_manager.get_role(role_name)
            if role:
                all_permissions.update(role.get_all_permissions(self.role_manager))
        
        return all_permissions
    
    def check_permission(self, user_roles: List[str], required_permission: Permission) -> bool:
        """Check if user has required permission."""
        user_permissions = self._get_user_permissions(tuple(user_roles))
        
        for permission in user_permissions:
            if permission.matches(required_permission):
                return True
        
        return False
    
    def check_access(self, request: AccessRequest) -> AccessResult:
        """Comprehensive access control check."""
        start_time = time.time()
        
        # Create context for policy evaluation
        context = {
            "user_id": request.user_id,
            "username": request.username,
            "client_ip": request.client_ip,
            "user_agent": request.user_agent,
            "timestamp": request.timestamp.isoformat(),
        }
        
        if request.additional_context:
            context.update(request.additional_context)
        
        # Check policies first (they can override permissions)
        policy_subjects = [f"user:{request.user_id}"] + [f"role:{role}" for role in request.roles]
        
        for subject in policy_subjects:
            policy_granted, policy_reason = self.policy_manager.evaluate_policies(
                subject=subject,
                resource=request.resource,
                action=request.action,
                context=context
            )
            
            # If any policy explicitly grants or denies, use that result
            if "Access denied by policy" in policy_reason:
                return AccessResult(
                    granted=False,
                    reason=policy_reason,
                    policy_matched=policy_reason.split(": ")[-1]
                )
            elif "Access granted by policy" in policy_reason:
                return AccessResult(
                    granted=True,
                    reason=policy_reason,
                    policy_matched=policy_reason.split(": ")[-1]
                )
        
        # Fallback to permission-based check
        resource_type, action = self._parse_resource_action(request.resource, request.action)
        if resource_type and action:
            required_permission = Permission(resource_type, action, scope=request.resource)
            
            if self.check_permission(request.roles, required_permission):
                return AccessResult(
                    granted=True,
                    reason="Permission granted",
                    permissions_used=[str(required_permission)]
                )
        
        # Default deny
        return AccessResult(
            granted=False,
            reason="No applicable permissions or policies found"
        )
    
    def _parse_resource_action(self, resource: str, action: str) -> Tuple[Optional[ResourceType], Optional[Action]]:
        """Parse resource and action strings into enums."""
        try:
            # Extract resource type from resource string
            if ":" in resource:
                resource_type_str = resource.split(":")[0]
            else:
                resource_type_str = resource
            
            resource_type = ResourceType(resource_type_str.lower())
            action_enum = Action(action.lower())
            
            return resource_type, action_enum
        except ValueError:
            logger.warning(f"Failed to parse resource '{resource}' or action '{action}'")
            return None, None
    
    def get_user_effective_permissions(self, user_roles: List[str]) -> List[str]:
        """Get all effective permissions for user."""
        permissions = self._get_user_permissions(tuple(user_roles))
        return [str(p) for p in permissions]
    
    def grant_role_to_user(self, user_id: str, role_name: str) -> bool:
        """Grant role to user (this would integrate with user management)."""
        # This is a placeholder - actual implementation would update user storage
        logger.info(f"Granted role '{role_name}' to user '{user_id}'")
        return True
    
    def revoke_role_from_user(self, user_id: str, role_name: str) -> bool:
        """Revoke role from user (this would integrate with user management)."""
        # This is a placeholder - actual implementation would update user storage
        logger.info(f"Revoked role '{role_name}' from user '{user_id}'")
        return True


# Global RBAC engine instance
rbac_engine = RBACEngine()


# FastAPI Dependencies

def require_permission(resource_type: ResourceType, action: Action, scope: str = "*"):
    """Dependency factory for requiring specific permission."""
    async def check_permission_dependency(request: Request) -> AccessResult:
        # Get current user from request state (set by auth middleware)
        user_context = getattr(request.state, 'user_context', None)
        api_key_metadata = getattr(request.state, 'api_key_metadata', None)
        
        if not user_context and not api_key_metadata:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required"
            )
        
        # Create access request
        if user_context:
            access_request = AccessRequest(
                user_id=user_context.user_id,
                username=user_context.username,
                roles=user_context.roles,
                resource=f"{resource_type.value}:{scope}",
                action=action.value,
                client_ip=getattr(request.client, 'host', None),
                user_agent=request.headers.get("User-Agent")
            )
        else:
            # API key authentication
            access_request = AccessRequest(
                user_id=api_key_metadata.owner_id,
                username=api_key_metadata.owner_email,
                roles=["service_account"],  # API keys get service account role
                resource=f"{resource_type.value}:{scope}",
                action=action.value,
                client_ip=getattr(request.client, 'host', None),
                user_agent=request.headers.get("User-Agent")
            )
        
        # Check access
        result = rbac_engine.check_access(access_request)
        
        if not result.granted:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: {result.reason}"
            )
        
        return result
    
    return check_permission_dependency


def require_role(role_name: str):
    """Dependency factory for requiring specific role."""
    async def check_role_dependency(request: Request) -> bool:
        user_context = getattr(request.state, 'user_context', None)
        
        if not user_context:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required"
            )
        
        if role_name not in user_context.roles:
            # Check role hierarchy
            has_role = False
            for user_role in user_context.roles:
                role = rbac_engine.role_manager.get_role(user_role)
                if role and role_name in role.parent_roles:
                    has_role = True
                    break
            
            if not has_role:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Role '{role_name}' required"
                )
        
        return True
    
    return check_role_dependency


def get_current_user_permissions(request: Request) -> List[str]:
    """Get current user's effective permissions."""
    user_context = getattr(request.state, 'user_context', None)
    
    if not user_context:
        return []
    
    return rbac_engine.get_user_effective_permissions(user_context.roles)


# Utility functions

def create_permission_from_string(permission_str: str) -> Permission:
    """Create Permission object from string representation."""
    parts = permission_str.split(":")
    
    if len(parts) < 2:
        raise ValueError(f"Invalid permission string: {permission_str}")
    
    resource = ResourceType(parts[0])
    
    if len(parts) == 2:
        action = Action(parts[1])
        scope = "*"
    else:
        scope = parts[1]
        action = Action(parts[2])
    
    return Permission(resource=resource, action=action, scope=scope)


def permission_to_string(permission: Permission) -> str:
    """Convert Permission object to string representation."""
    return str(permission)


# Administrative functions

class RBACAdmin:
    """Administrative interface for RBAC management."""
    
    @staticmethod
    def create_custom_role(name: str, display_name: str, description: str, 
                          permissions: List[str], parent_roles: Optional[List[str]] = None) -> Role:
        """Create a custom role with permissions."""
        permission_objects = {create_permission_from_string(p) for p in permissions}
        parent_role_set = set(parent_roles) if parent_roles else set()
        
        return rbac_engine.role_manager.create_role(
            name=name,
            display_name=display_name,
            description=description,
            permissions=permission_objects,
            parent_roles=parent_role_set
        )
    
    @staticmethod
    def create_time_limited_policy(policy_id: str, name: str, description: str,
                                  effect: AccessEffect, subjects: List[str],
                                  resources: List[str], actions: List[str],
                                  duration_hours: int) -> AccessPolicy:
        """Create a time-limited access policy."""
        expires_at = datetime.now(timezone.utc) + timedelta(hours=duration_hours)
        
        policy = AccessPolicy(
            id=policy_id,
            name=name,
            description=description,
            effect=effect,
            subjects=subjects,
            resources=resources,
            actions=actions,
            expires_at=expires_at
        )
        
        return rbac_engine.policy_manager.create_policy(policy)
    
    @staticmethod
    def get_role_hierarchy() -> Dict[str, Any]:
        """Get complete role hierarchy for visualization."""
        roles = rbac_engine.role_manager.list_roles()
        hierarchy = {}
        
        for role in roles:
            hierarchy[role.name] = {
                "display_name": role.display_name,
                "description": role.description,
                "parent_roles": list(role.parent_roles),
                "permissions": [str(p) for p in role.permissions],
                "is_system_role": role.is_system_role
            }
        
        return hierarchy
    
    @staticmethod
    def audit_user_access(user_id: str, roles: List[str]) -> Dict[str, Any]:
        """Audit user's current access rights."""
        effective_permissions = rbac_engine.get_user_effective_permissions(roles)
        role_details = []
        
        for role_name in roles:
            role = rbac_engine.role_manager.get_role(role_name)
            if role:
                role_details.append({
                    "name": role.name,
                    "display_name": role.display_name,
                    "permissions": [str(p) for p in role.permissions],
                    "parent_roles": list(role.parent_roles)
                })
        
        return {
            "user_id": user_id,
            "roles": role_details,
            "effective_permissions": effective_permissions,
            "audit_timestamp": datetime.now(timezone.utc).isoformat()
        }


# Global admin interface
rbac_admin = RBACAdmin()

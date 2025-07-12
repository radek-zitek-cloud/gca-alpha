# RBAC Implementation Guide

## Overview

The Role-Based Access Control (RBAC) system provides enterprise-grade authorization and access control for the API Gateway. This implementation supports hierarchical roles, fine-grained permissions, policy-driven authorization, and comprehensive audit capabilities.

## Architecture

### Core Components

1. **Role Manager** (`app/core/rbac.py`)
   - Manages role definitions and hierarchies
   - Supports role inheritance and composition
   - Handles custom and system roles

2. **Permission System**
   - Resource-based permissions (e.g., `services:read:*`)
   - Action-based control (read, write, delete, admin)
   - Scope-based restrictions (own, team, all)

3. **Policy Engine**
   - Time-based policies with expiration
   - Condition-based access control
   - Priority-based policy evaluation

4. **Access Control Engine**
   - Fast permission checking
   - Policy evaluation
   - Audit logging

### System Roles

The system includes the following default roles:

- **super_admin**: Full system access
- **admin**: Administrative access (cannot manage super admins)
- **moderator**: Content and user moderation
- **user**: Basic authenticated user access
- **guest**: Limited read-only access

### Permission Format

Permissions follow the format: `resource:action:scope`

- **Resource**: `users`, `services`, `gateway`, `admin`, `metrics`
- **Action**: `read`, `write`, `delete`, `admin`
- **Scope**: `own`, `team`, `all`, `*` (wildcard)

Examples:
- `users:read:own` - Read own user profile
- `services:write:all` - Write access to all services
- `admin:*:*` - Full administrative access

## API Endpoints

### Role Management

#### Create Role
```bash
POST /api/v1/rbac/roles
```

Request:
```json
{
  "name": "developer",
  "display_name": "Developer",
  "description": "Software developer role",
  "permissions": ["services:read:*", "services:write:own"],
  "parent_roles": ["user"]
}
```

#### List Roles
```bash
GET /api/v1/rbac/roles
```

#### Get Role Details
```bash
GET /api/v1/rbac/roles/{role_name}
```

#### Update Role
```bash
PUT /api/v1/rbac/roles/{role_name}
```

#### Delete Role
```bash
DELETE /api/v1/rbac/roles/{role_name}
```

### Policy Management

#### Create Policy
```bash
POST /api/v1/rbac/policies
```

Request:
```json
{
  "id": "dev_hours_policy",
  "name": "Development Hours Policy",
  "description": "Allow development access during business hours",
  "effect": "allow",
  "subjects": ["role:developer"],
  "resources": ["services:development:*"],
  "actions": ["read", "write"],
  "conditions": {
    "time_range": {
      "start": "09:00",
      "end": "17:00"
    }
  },
  "priority": 100
}
```

#### Create Time-Limited Policy
```json
{
  "id": "temp_admin_policy",
  "name": "Temporary Admin Access",
  "description": "24-hour admin access",
  "effect": "allow",
  "subjects": ["user:john.doe"],
  "resources": ["admin:*"],
  "actions": ["read", "write"],
  "duration_hours": 24,
  "priority": 200
}
```

#### List Policies
```bash
GET /api/v1/rbac/policies
```

#### Delete Policy
```bash
DELETE /api/v1/rbac/policies/{policy_id}
```

### Access Control

#### Check Access
```bash
POST /api/v1/rbac/check-access
```

Request:
```json
{
  "user_id": "user123",
  "roles": ["developer", "user"],
  "resource": "services",
  "action": "write",
  "additional_context": {
    "service_name": "auth-service",
    "environment": "development"
  }
}
```

Response:
```json
{
  "granted": true,
  "reason": "Permission granted via role 'developer'",
  "policy_matched": null,
  "permissions_used": ["services:write:*"],
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### Get Available Permissions
```bash
GET /api/v1/rbac/permissions/available
```

#### Get Role Hierarchy
```bash
GET /api/v1/rbac/hierarchy
```

#### Get User Permissions
```bash
GET /api/v1/rbac/users/{user_id}/permissions
```

#### Audit User Access
```bash
GET /api/v1/rbac/users/{user_id}/audit
```

### System Health

#### Health Check
```bash
GET /api/v1/rbac/health
```

#### System Metrics
```bash
GET /api/v1/rbac/metrics
```

## Integration with FastAPI

### Using RBAC Dependencies

```python
from app.middleware.auth import require_rbac_access, rbac_permission

# Method 1: Using dependency
@app.get("/protected-endpoint")
async def protected_endpoint(
    current_user = Depends(require_rbac_access("services", "read"))
):
    return {"message": "Access granted"}

# Method 2: Using decorator
@rbac_permission("users:write:own")
async def update_user_profile(
    user_id: str,
    current_user = Depends(get_current_user)
):
    return {"message": "Profile updated"}
```

### Custom Permission Checking

```python
from app.core.rbac import rbac_engine, AccessRequest

async def check_custom_access(user_id: str, roles: List[str]):
    request = AccessRequest(
        user_id=user_id,
        username=f"user_{user_id}",
        roles=roles,
        resource="custom_resource",
        action="special_action",
        additional_context={"context": "value"}
    )
    
    result = rbac_engine.check_access(request)
    return result.granted
```

## Configuration

### Default Policies

The system creates default policies during initialization:

1. **Admin Full Access**: Allows admins access to all resources
2. **User Basic Access**: Allows users basic read access
3. **Service Access**: Controls service-to-service communication

### Custom Role Creation

```python
from app.core.rbac import rbac_admin

# Create custom role
role = rbac_admin.create_custom_role(
    name="data_scientist",
    display_name="Data Scientist",
    description="Access to data analysis tools",
    permissions=[
        "metrics:read:*",
        "analytics:read:*",
        "analytics:write:own"
    ],
    parent_roles=["user"]
)
```

### Time-Limited Policies

```python
# Create temporary elevated access
policy = rbac_admin.create_time_limited_policy(
    policy_id="emergency_access",
    name="Emergency Access",
    description="Emergency admin access",
    effect=AccessEffect.ALLOW,
    subjects=["user:emergency.user"],
    resources=["admin:*"],
    actions=["*"],
    duration_hours=4
)
```

## Security Features

### Audit Logging

All access decisions are logged with:
- User identification
- Resource and action requested
- Decision (granted/denied)
- Reason for decision
- Timestamp
- Policy or permission used

### Policy Conditions

Policies support conditions for advanced access control:

```json
{
  "conditions": {
    "time_range": {
      "start": "09:00",
      "end": "17:00",
      "timezone": "UTC"
    },
    "ip_whitelist": ["192.168.1.0/24"],
    "user_attributes": {
      "department": "engineering"
    }
  }
}
```

### Role Hierarchy

Roles inherit permissions from parent roles:

```
super_admin
├── admin
│   ├── moderator
│   │   └── user
│   │       └── guest
│   └── service_admin
└── system
```

## Performance Considerations

### Caching

- Role definitions are cached in memory
- Permission calculations are cached per user session
- Policy evaluations use optimized lookup tables

### Optimization

- Fast path for simple permission checks
- Lazy loading of complex policies
- Efficient role hierarchy traversal

## Testing

### Unit Tests

```python
from app.core.rbac import rbac_engine

def test_permission_check():
    result = rbac_engine.check_permission(
        roles=["user"],
        permission="services:read:*"
    )
    assert result.granted
```

### Integration Tests

Run the comprehensive test suite:

```bash
python -m pytest tests/test_rbac_integration.py -v
```

### Load Testing

The system is tested for:
- 1000+ concurrent access checks
- Role hierarchies with 100+ roles
- Policy sets with 500+ policies

## Troubleshooting

### Common Issues

1. **Access Denied Unexpectedly**
   - Check user roles assignment
   - Verify permission format
   - Review policy conditions

2. **Performance Issues**
   - Monitor cache hit rates
   - Check for role hierarchy depth
   - Review policy complexity

3. **Policy Not Applied**
   - Verify policy is enabled
   - Check expiration date
   - Review priority settings

### Debug Endpoints

```bash
# Check user effective permissions
GET /api/v1/rbac/users/{user_id}/permissions

# Audit specific user
GET /api/v1/rbac/users/{user_id}/audit

# System health
GET /api/v1/rbac/health
```

## Migration from Basic RBAC

For existing systems using the basic RBAC in `auth.py`:

1. Roles are automatically migrated
2. Permissions are converted to new format
3. Custom roles need manual recreation
4. Update middleware imports

```python
# Old
from app.middleware.auth import RBACManager

# New
from app.core.rbac import rbac_engine
from app.middleware.auth import require_rbac_access
```

## Future Enhancements

Planned features:
- Attribute-based access control (ABAC)
- External policy providers
- Real-time policy updates
- Advanced analytics dashboard
- Multi-tenant support

## API Reference

For complete API documentation, visit `/docs` when the server is running to see the interactive OpenAPI documentation with all RBAC endpoints.

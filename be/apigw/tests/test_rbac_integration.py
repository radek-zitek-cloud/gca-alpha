"""
Integration tests for RBAC system endpoints.

Tests the complete RBAC flow including:
- Role management
- Policy management
- Access control enforcement
- User permissions
- Administrative functions
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any

from fastapi.testclient import TestClient
from fastapi import status

from app.main import app
from app.core.rbac import rbac_engine, rbac_admin, AccessEffect
from app.middleware.auth import create_admin_token, create_test_user_token


@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app)


@pytest.fixture
async def admin_token():
    """Create admin token for testing."""
    token_data = await create_admin_token()
    return token_data["access_token"]


@pytest.fixture
async def user_token():
    """Create user token for testing."""
    token_data = await create_test_user_token()
    return token_data["access_token"]


class TestRBACRoleManagement:
    """Test role management endpoints."""
    
    def test_create_role(self, client: TestClient, admin_token: str):
        """Test creating a new role."""
        role_data = {
            "name": "test_role",
            "display_name": "Test Role",
            "description": "A test role for integration testing",
            "permissions": ["services:read:*", "gateway:read:*"],
            "parent_roles": ["user"]
        }
        
        response = client.post(
            "/api/v1/rbac/roles",
            json=role_data,
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        
        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert data["name"] == "test_role"
        assert data["display_name"] == "Test Role"
        assert len(data["permissions"]) >= 2
        assert "user" in data["parent_roles"]
    
    def test_create_role_unauthorized(self, client: TestClient, user_token: str):
        """Test creating role without admin permissions."""
        role_data = {
            "name": "unauthorized_role",
            "display_name": "Unauthorized Role",
            "description": "Should fail",
            "permissions": []
        }
        
        response = client.post(
            "/api/v1/rbac/roles",
            json=role_data,
            headers={"Authorization": f"Bearer {user_token}"}
        )
        
        assert response.status_code == status.HTTP_403_FORBIDDEN
    
    def test_list_roles(self, client: TestClient, admin_token: str):
        """Test listing all roles."""
        response = client.get(
            "/api/v1/rbac/roles",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert isinstance(data, list)
        
        # Should include default system roles
        role_names = [role["name"] for role in data]
        assert "admin" in role_names
        assert "user" in role_names
    
    def test_get_role(self, client: TestClient, admin_token: str):
        """Test getting specific role details."""
        response = client.get(
            "/api/v1/rbac/roles/admin",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["name"] == "admin"
        assert data["is_system_role"] is True
        assert len(data["permissions"]) > 0
    
    def test_get_nonexistent_role(self, client: TestClient, admin_token: str):
        """Test getting non-existent role."""
        response = client.get(
            "/api/v1/rbac/roles/nonexistent",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        
        assert response.status_code == status.HTTP_404_NOT_FOUND
    
    def test_update_role(self, client: TestClient, admin_token: str):
        """Test updating a role."""
        # First create a role
        role_data = {
            "name": "updatable_role",
            "display_name": "Updatable Role",
            "description": "Original description",
            "permissions": ["services:read:*"]
        }
        
        create_response = client.post(
            "/api/v1/rbac/roles",
            json=role_data,
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert create_response.status_code == status.HTTP_201_CREATED
        
        # Update the role
        update_data = {
            "description": "Updated description",
            "permissions": ["services:read:*", "services:write:*"]
        }
        
        response = client.put(
            "/api/v1/rbac/roles/updatable_role",
            json=update_data,
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["description"] == "Updated description"
        assert len(data["permissions"]) == 2
    
    def test_delete_role(self, client: TestClient, admin_token: str):
        """Test deleting a role."""
        # First create a role
        role_data = {
            "name": "deletable_role",
            "display_name": "Deletable Role",
            "description": "Will be deleted",
            "permissions": []
        }
        
        create_response = client.post(
            "/api/v1/rbac/roles",
            json=role_data,
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert create_response.status_code == status.HTTP_201_CREATED
        
        # Delete the role
        response = client.delete(
            "/api/v1/rbac/roles/deletable_role",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        
        assert response.status_code == status.HTTP_200_OK
        assert "deleted successfully" in response.json()["message"]
        
        # Verify role is gone
        get_response = client.get(
            "/api/v1/rbac/roles/deletable_role",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert get_response.status_code == status.HTTP_404_NOT_FOUND


class TestRBACPolicyManagement:
    """Test policy management endpoints."""
    
    def test_create_policy(self, client: TestClient, admin_token: str):
        """Test creating a new policy."""
        policy_data = {
            "id": "test_policy_123",
            "name": "Test Policy",
            "description": "A test policy",
            "effect": "allow",
            "subjects": ["role:test_role"],
            "resources": ["services:*"],
            "actions": ["read", "write"],
            "priority": 100
        }
        
        response = client.post(
            "/api/v1/rbac/policies",
            json=policy_data,
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        
        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert data["id"] == "test_policy_123"
        assert data["name"] == "Test Policy"
        assert data["effect"] == "allow"
        assert data["priority"] == 100
    
    def test_create_time_limited_policy(self, client: TestClient, admin_token: str):
        """Test creating a time-limited policy."""
        policy_data = {
            "id": "temp_policy_123",
            "name": "Temporary Policy",
            "description": "A temporary policy",
            "effect": "allow",
            "subjects": ["user:test_user"],
            "resources": ["admin:*"],
            "actions": ["read"],
            "duration_hours": 24,
            "priority": 200
        }
        
        response = client.post(
            "/api/v1/rbac/policies",
            json=policy_data,
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        
        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert data["expires_at"] is not None
        assert data["enabled"] is True
    
    def test_list_policies(self, client: TestClient, admin_token: str):
        """Test listing all policies."""
        response = client.get(
            "/api/v1/rbac/policies",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert isinstance(data, list)
    
    def test_delete_policy(self, client: TestClient, admin_token: str):
        """Test deleting a policy."""
        # First create a policy
        policy_data = {
            "id": "deletable_policy",
            "name": "Deletable Policy",
            "description": "Will be deleted",
            "effect": "deny",
            "subjects": ["role:test"],
            "resources": ["test:*"],
            "actions": ["delete"]
        }
        
        create_response = client.post(
            "/api/v1/rbac/policies",
            json=policy_data,
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert create_response.status_code == status.HTTP_201_CREATED
        
        # Delete the policy
        response = client.delete(
            "/api/v1/rbac/policies/deletable_policy",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        
        assert response.status_code == status.HTTP_200_OK
        assert "deleted successfully" in response.json()["message"]


class TestRBACAccessControl:
    """Test access control enforcement."""
    
    def test_check_access_granted(self, client: TestClient, admin_token: str):
        """Test access check that should be granted."""
        access_data = {
            "user_id": "test_user",
            "roles": ["admin"],
            "resource": "services",
            "action": "read"
        }
        
        response = client.post(
            "/api/v1/rbac/check-access",
            json=access_data,
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["granted"] is True
        assert "reason" in data
    
    def test_check_access_denied(self, client: TestClient, admin_token: str):
        """Test access check that should be denied."""
        access_data = {
            "user_id": "test_user",
            "roles": ["guest"],
            "resource": "admin",
            "action": "delete"
        }
        
        response = client.post(
            "/api/v1/rbac/check-access",
            json=access_data,
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["granted"] is False
        assert "reason" in data
    
    def test_get_available_permissions(self, client: TestClient, admin_token: str):
        """Test getting list of available permissions."""
        response = client.get(
            "/api/v1/rbac/permissions/available",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert isinstance(data, list)
        assert len(data) > 0
        
        # Check permission structure
        permission = data[0]
        assert "resource" in permission
        assert "action" in permission
        assert "scope" in permission
        assert "description" in permission
    
    def test_get_role_hierarchy(self, client: TestClient, admin_token: str):
        """Test getting role hierarchy."""
        response = client.get(
            "/api/v1/rbac/hierarchy",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "roles" in data
        assert "total_roles" in data
        assert "system_roles" in data
        assert "custom_roles" in data
        assert data["total_roles"] > 0
    
    def test_get_user_permissions(self, client: TestClient, admin_token: str):
        """Test getting user effective permissions."""
        response = client.get(
            "/api/v1/rbac/users/test_user/permissions",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "user_id" in data
        assert "roles" in data
        assert "effective_permissions" in data
        assert "permission_count" in data
    
    def test_audit_user_access(self, client: TestClient, admin_token: str):
        """Test auditing user access."""
        response = client.get(
            "/api/v1/rbac/users/test_user/audit",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        # Response format depends on audit implementation
        assert isinstance(data, dict)


class TestRBACSystemHealth:
    """Test RBAC system health and diagnostics."""
    
    def test_rbac_health_check(self, client: TestClient):
        """Test RBAC system health check."""
        response = client.get("/api/v1/rbac/health")
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "status" in data
        assert "timestamp" in data
        assert "statistics" in data
        assert data["status"] in ["healthy", "warning", "unhealthy"]
    
    def test_rbac_metrics(self, client: TestClient, admin_token: str):
        """Test RBAC system metrics."""
        response = client.get(
            "/api/v1/rbac/metrics",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "timestamp" in data
        assert "role_metrics" in data
        assert "policy_metrics" in data
        
        role_metrics = data["role_metrics"]
        assert "total_roles" in role_metrics
        assert "total_permissions" in role_metrics
        assert "avg_permissions_per_role" in role_metrics


class TestRBACIntegration:
    """Test RBAC integration with existing auth system."""
    
    def test_rbac_with_jwt_auth(self, client: TestClient, admin_token: str):
        """Test RBAC working with JWT authentication."""
        # This test verifies that RBAC endpoints properly validate JWT tokens
        response = client.get(
            "/api/v1/rbac/roles",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        
        assert response.status_code == status.HTTP_200_OK
    
    def test_rbac_without_auth(self, client: TestClient):
        """Test RBAC endpoints without authentication."""
        response = client.get("/api/v1/rbac/roles")
        
        # Should require authentication
        assert response.status_code in [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN]
    
    def test_rbac_with_invalid_token(self, client: TestClient):
        """Test RBAC endpoints with invalid token."""
        response = client.get(
            "/api/v1/rbac/roles",
            headers={"Authorization": "Bearer invalid_token"}
        )
        
        assert response.status_code in [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN]


# Performance and load tests

class TestRBACPerformance:
    """Test RBAC system performance."""
    
    def test_access_check_performance(self, client: TestClient, admin_token: str):
        """Test performance of access checks."""
        import time
        
        access_data = {
            "user_id": "perf_test_user",
            "roles": ["user"],
            "resource": "services",
            "action": "read"
        }
        
        # Run multiple access checks and measure time
        start_time = time.time()
        iterations = 100
        
        for _ in range(iterations):
            response = client.post(
                "/api/v1/rbac/check-access",
                json=access_data,
                headers={"Authorization": f"Bearer {admin_token}"}
            )
            assert response.status_code == status.HTTP_200_OK
        
        end_time = time.time()
        avg_time = (end_time - start_time) / iterations
        
        # Access check should be fast (< 50ms average)
        assert avg_time < 0.05, f"Access check too slow: {avg_time:.3f}s average"
    
    def test_bulk_role_operations(self, client: TestClient, admin_token: str):
        """Test bulk role creation and deletion."""
        # Create multiple roles
        role_names = []
        for i in range(10):
            role_data = {
                "name": f"bulk_role_{i}",
                "display_name": f"Bulk Role {i}",
                "description": f"Bulk test role {i}",
                "permissions": ["services:read:*"]
            }
            
            response = client.post(
                "/api/v1/rbac/roles",
                json=role_data,
                headers={"Authorization": f"Bearer {admin_token}"}
            )
            assert response.status_code == status.HTTP_201_CREATED
            role_names.append(f"bulk_role_{i}")
        
        # Clean up
        for role_name in role_names:
            response = client.delete(
                f"/api/v1/rbac/roles/{role_name}",
                headers={"Authorization": f"Bearer {admin_token}"}
            )
            assert response.status_code == status.HTTP_200_OK


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"])

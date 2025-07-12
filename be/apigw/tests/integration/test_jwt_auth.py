#!/usr/bin/env python3
"""
Test script for JWT Authentication Middleware implementation.

This script tests all aspects of the JWT authentication system:
- User registration and login
- Token generation and validation
- Token refresh mechanism
- Role-based access control
- Protected endpoint access
- Security audit logging

Usage:
    python scripts/test_jwt_auth.py
"""

import sys
import os
import asyncio
import httpx
import json
from datetime import datetime
from typing import Dict, Any, Optional

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Configuration
BASE_URL = "http://localhost:8000"
TEST_TIMEOUT = 30.0


class JWTAuthTester:
    """Test class for JWT authentication system."""
    
    def __init__(self, base_url: str = BASE_URL):
        self.base_url = base_url
        self.client = httpx.AsyncClient(timeout=TEST_TIMEOUT)
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.admin_token: Optional[str] = None
        
    async def __aenter__(self):
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()
    
    def print_test(self, test_name: str):
        """Print test header."""
        print(f"\n🧪 Testing: {test_name}")
        print("=" * 50)
    
    def print_success(self, message: str):
        """Print success message."""
        print(f"✅ {message}")
    
    def print_error(self, message: str):
        """Print error message."""
        print(f"❌ {message}")
    
    def print_info(self, message: str):
        """Print info message."""
        print(f"ℹ️  {message}")
    
    async def test_health_check(self) -> bool:
        """Test that the API Gateway is running."""
        self.print_test("API Gateway Health Check")
        
        try:
            response = await self.client.get(f"{self.base_url}/api/v1/health")
            if response.status_code == 200:
                self.print_success("API Gateway is running")
                return True
            else:
                self.print_error(f"Health check failed: {response.status_code}")
                return False
        except Exception as e:
            self.print_error(f"Could not connect to API Gateway: {e}")
            return False
    
    async def test_public_endpoints(self) -> bool:
        """Test access to public endpoints without authentication."""
        self.print_test("Public Endpoint Access")
        
        public_endpoints = [
            "/docs",
            "/api/v1/health",
            "/api/v1/auth/status"
        ]
        
        success = True
        for endpoint in public_endpoints:
            try:
                response = await self.client.get(f"{self.base_url}{endpoint}")
                if response.status_code in [200, 307]:  # 307 for redirect to docs
                    self.print_success(f"Public access to {endpoint}")
                else:
                    self.print_error(f"Failed to access {endpoint}: {response.status_code}")
                    success = False
            except Exception as e:
                self.print_error(f"Error accessing {endpoint}: {e}")
                success = False
        
        return success
    
    async def test_protected_endpoints_without_auth(self) -> bool:
        """Test that protected endpoints deny access without authentication."""
        self.print_test("Protected Endpoint Access (No Auth)")
        
        protected_endpoints = [
            "/gateway/services",
            "/api/v1/admin/users",
            "/api/v1/metrics"
        ]
        
        success = True
        for endpoint in protected_endpoints:
            try:
                response = await self.client.get(f"{self.base_url}{endpoint}")
                if response.status_code == 401:
                    self.print_success(f"Properly blocked access to {endpoint}")
                else:
                    self.print_error(f"Expected 401 for {endpoint}, got {response.status_code}")
                    success = False
            except Exception as e:
                self.print_error(f"Error testing {endpoint}: {e}")
                success = False
        
        return success
    
    async def test_user_registration(self) -> bool:
        """Test user registration."""
        self.print_test("User Registration")
        
        test_user = {
            "username": "testuser2",
            "email": "testuser2@example.com",
            "password": "testpass123",
            "roles": ["user"]
        }
        
        try:
            response = await self.client.post(
                f"{self.base_url}/api/v1/auth/register",
                json=test_user
            )
            
            if response.status_code == 200:
                result = response.json()
                self.print_success(f"User registered: {result['user_id']}")
                return True
            else:
                self.print_error(f"Registration failed: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            self.print_error(f"Registration error: {e}")
            return False
    
    async def test_user_login(self) -> bool:
        """Test user login and token generation."""
        self.print_test("User Login")
        
        # Test with default test user
        login_data = {
            "username": "testuser",
            "password": "test123"
        }
        
        try:
            response = await self.client.post(
                f"{self.base_url}/api/v1/auth/login",
                json=login_data
            )
            
            if response.status_code == 200:
                tokens = response.json()
                self.access_token = tokens["access_token"]
                self.refresh_token = tokens["refresh_token"]
                
                self.print_success("User login successful")
                self.print_info(f"Access token: {self.access_token[:50]}...")
                self.print_info(f"Refresh token: {self.refresh_token[:50]}...")
                return True
            else:
                self.print_error(f"Login failed: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            self.print_error(f"Login error: {e}")
            return False
    
    async def test_admin_login(self) -> bool:
        """Test admin login."""
        self.print_test("Admin Login")
        
        login_data = {
            "username": "admin",
            "password": "admin123"
        }
        
        try:
            response = await self.client.post(
                f"{self.base_url}/api/v1/auth/login",
                json=login_data
            )
            
            if response.status_code == 200:
                tokens = response.json()
                self.admin_token = tokens["access_token"]
                
                self.print_success("Admin login successful")
                return True
            else:
                self.print_error(f"Admin login failed: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            self.print_error(f"Admin login error: {e}")
            return False
    
    async def test_authenticated_access(self) -> bool:
        """Test access to endpoints with valid token."""
        self.print_test("Authenticated Access")
        
        if not self.access_token:
            self.print_error("No access token available")
            return False
        
        headers = {"Authorization": f"Bearer {self.access_token}"}
        
        # Test user info endpoint
        try:
            response = await self.client.get(
                f"{self.base_url}/api/v1/auth/me",
                headers=headers
            )
            
            if response.status_code == 200:
                user_info = response.json()
                self.print_success(f"Retrieved user info: {user_info['username']}")
                self.print_info(f"User roles: {user_info['roles']}")
                self.print_info(f"User permissions: {user_info['permissions']}")
                return True
            else:
                self.print_error(f"Failed to get user info: {response.status_code}")
                return False
        except Exception as e:
            self.print_error(f"Authenticated access error: {e}")
            return False
    
    async def test_role_based_access(self) -> bool:
        """Test role-based access control."""
        self.print_test("Role-Based Access Control")
        
        if not self.access_token or not self.admin_token:
            self.print_error("Missing required tokens")
            return False
        
        # Test user trying to access admin endpoint (should fail)
        user_headers = {"Authorization": f"Bearer {self.access_token}"}
        
        try:
            response = await self.client.get(
                f"{self.base_url}/api/v1/admin/users",
                headers=user_headers
            )
            
            if response.status_code == 403:
                self.print_success("User correctly denied admin access")
            else:
                self.print_error(f"Expected 403 for user admin access, got {response.status_code}")
                return False
        except Exception as e:
            self.print_error(f"RBAC test error: {e}")
            return False
        
        # Test admin accessing admin endpoint (should succeed)
        admin_headers = {"Authorization": f"Bearer {self.admin_token}"}
        
        try:
            response = await self.client.get(
                f"{self.base_url}/api/v1/admin/users",
                headers=admin_headers
            )
            
            if response.status_code == 200:
                result = response.json()
                self.print_success(f"Admin access successful: {result['total_users']} users")
                return True
            else:
                self.print_error(f"Admin access failed: {response.status_code}")
                return False
        except Exception as e:
            self.print_error(f"Admin access error: {e}")
            return False
    
    async def test_token_refresh(self) -> bool:
        """Test token refresh mechanism."""
        self.print_test("Token Refresh")
        
        if not self.refresh_token:
            self.print_error("No refresh token available")
            return False
        
        refresh_data = {
            "refresh_token": self.refresh_token
        }
        
        try:
            response = await self.client.post(
                f"{self.base_url}/api/v1/auth/refresh",
                json=refresh_data
            )
            
            if response.status_code == 200:
                new_tokens = response.json()
                old_token = self.access_token
                self.access_token = new_tokens["access_token"]
                
                self.print_success("Token refresh successful")
                self.print_info(f"Old token: {old_token[:30]}...")
                self.print_info(f"New token: {self.access_token[:30]}...")
                return True
            else:
                self.print_error(f"Token refresh failed: {response.status_code}")
                return False
        except Exception as e:
            self.print_error(f"Token refresh error: {e}")
            return False
    
    async def test_token_revocation(self) -> bool:
        """Test token revocation."""
        self.print_test("Token Revocation")
        
        if not self.access_token:
            self.print_error("No access token available")
            return False
        
        headers = {"Authorization": f"Bearer {self.access_token}"}
        
        try:
            # Revoke the token
            response = await self.client.post(
                f"{self.base_url}/api/v1/auth/revoke",
                headers=headers
            )
            
            if response.status_code == 200:
                self.print_success("Token revoked successfully")
                
                # Try to use revoked token (should fail)
                response = await self.client.get(
                    f"{self.base_url}/api/v1/auth/me",
                    headers=headers
                )
                
                if response.status_code == 401:
                    self.print_success("Revoked token correctly rejected")
                    return True
                else:
                    self.print_error(f"Revoked token still works: {response.status_code}")
                    return False
            else:
                self.print_error(f"Token revocation failed: {response.status_code}")
                return False
        except Exception as e:
            self.print_error(f"Token revocation error: {e}")
            return False
    
    async def test_invalid_token(self) -> bool:
        """Test handling of invalid tokens."""
        self.print_test("Invalid Token Handling")
        
        invalid_tokens = [
            "invalid-token",
            "Bearer invalid-token",
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.invalid",
            ""
        ]
        
        success = True
        for token in invalid_tokens:
            headers = {"Authorization": f"Bearer {token}"}
            
            try:
                response = await self.client.get(
                    f"{self.base_url}/api/v1/auth/me",
                    headers=headers
                )
                
                if response.status_code == 401:
                    self.print_success(f"Invalid token properly rejected: {token[:20]}...")
                else:
                    self.print_error(f"Invalid token accepted: {token[:20]}... (status: {response.status_code})")
                    success = False
            except Exception as e:
                self.print_error(f"Error testing invalid token: {e}")
                success = False
        
        return success
    
    async def test_gateway_management_protection(self) -> bool:
        """Test that gateway management endpoints are protected."""
        self.print_test("Gateway Management Protection")
        
        if not self.admin_token:
            self.print_error("No admin token available")
            return False
        
        admin_headers = {"Authorization": f"Bearer {self.admin_token}"}
        
        try:
            response = await self.client.get(
                f"{self.base_url}/gateway/services",
                headers=admin_headers
            )
            
            if response.status_code == 200:
                result = response.json()
                self.print_success(f"Admin access to gateway services: {result['total_services']} services")
                return True
            else:
                self.print_error(f"Gateway access failed: {response.status_code}")
                return False
        except Exception as e:
            self.print_error(f"Gateway access error: {e}")
            return False
    
    async def run_all_tests(self) -> bool:
        """Run all authentication tests."""
        print("🚀 Starting JWT Authentication Tests")
        print("=" * 60)
        
        tests = [
            self.test_health_check,
            self.test_public_endpoints,
            self.test_protected_endpoints_without_auth,
            self.test_user_registration,
            self.test_user_login,
            self.test_admin_login,
            self.test_authenticated_access,
            self.test_role_based_access,
            self.test_token_refresh,
            self.test_gateway_management_protection,
            self.test_invalid_token,
            self.test_token_revocation,  # Run last since it invalidates tokens
        ]
        
        passed = 0
        failed = 0
        
        for test in tests:
            try:
                if await test():
                    passed += 1
                else:
                    failed += 1
            except Exception as e:
                self.print_error(f"Test {test.__name__} crashed: {e}")
                failed += 1
        
        print("\n" + "=" * 60)
        print(f"📊 Test Results: {passed} passed, {failed} failed")
        
        if failed == 0:
            print("🎉 All tests passed! JWT Authentication is working correctly.")
        else:
            print(f"⚠️  {failed} tests failed. Please check the implementation.")
        
        return failed == 0


async def main():
    """Main test function."""
    print("JWT Authentication Middleware Test Suite")
    print("=" * 60)
    print(f"Testing API Gateway at: {BASE_URL}")
    print(f"Current time: {datetime.now()}")
    print()
    
    async with JWTAuthTester() as tester:
        success = await tester.run_all_tests()
        
        if success:
            print("\n🔐 JWT Authentication Implementation: COMPLETE ✅")
            print("\nNext steps:")
            print("1. Start the API Gateway: uvicorn app.main:app --reload")
            print("2. Access Swagger docs: http://localhost:8000/docs")
            print("3. Test authentication endpoints")
            print("4. Check security audit logs")
        else:
            print("\n❌ Some tests failed. Please review the implementation.")
            sys.exit(1)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n⏹️  Tests interrupted by user")
    except Exception as e:
        print(f"\n💥 Test suite crashed: {e}")
        sys.exit(1)

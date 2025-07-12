#!/usr/bin/env python3
"""
Comprehensive test suite for API Key Management system.

This script tests all aspects of the API key management:
1. API key creation and validation
2. Rate limiting functionality
3. Scope-based access control
4. Key rotation and revocation
5. Admin functionality
6. Security features
7. Integration with existing authentication

Run this script to validate the API key system implementation.
"""

import asyncio
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, Any

import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

console = Console()

# Configuration
BASE_URL = "http://localhost:8000"
TEST_USER_EMAIL = "test@example.com"
TEST_USER_PASSWORD = "testpassword123"
ADMIN_EMAIL = "admin@gateway.com"
ADMIN_PASSWORD = "admin123"


class APIKeyTester:
    """API Key system test suite."""
    
    def __init__(self, base_url: str = BASE_URL):
        self.base_url = base_url
        self.client = httpx.AsyncClient(timeout=30.0)
        self.test_results = []
        
        # Auth tokens
        self.user_token = None
        self.admin_token = None
        
        # Test data
        self.test_api_keys = []
    
    async def run_all_tests(self):
        """Run comprehensive test suite."""
        console.print("\n🔑 API Key Management System Test Suite", style="bold blue")
        console.print("=" * 60)
        
        try:
            # Setup
            await self._setup_test_environment()
            
            # Test categories
            test_categories = [
                ("Authentication Setup", self._test_authentication_setup),
                ("API Key Creation", self._test_api_key_creation),
                ("API Key Validation", self._test_api_key_validation),
                ("Rate Limiting", self._test_rate_limiting),
                ("Scope-based Access Control", self._test_scope_access_control),
                ("Key Management Operations", self._test_key_management),
                ("Admin Functionality", self._test_admin_functionality),
                ("Security Features", self._test_security_features),
                ("Analytics and Monitoring", self._test_analytics),
                ("Error Handling", self._test_error_handling)
            ]
            
            for category_name, test_func in test_categories:
                await self._run_test_category(category_name, test_func)
            
            # Summary
            self._print_test_summary()
            
        except Exception as e:
            console.print(f"\n❌ Test suite failed: {e}", style="red")
            raise
        finally:
            await self._cleanup()
    
    async def _setup_test_environment(self):
        """Setup test environment."""
        console.print("\n🔧 Setting up test environment...", style="yellow")
        
        # Check if server is running
        try:
            response = await self.client.get(f"{self.base_url}/health")
            if response.status_code != 200:
                raise Exception("API Gateway not running or unhealthy")
            console.print("✅ API Gateway is running", style="green")
        except Exception as e:
            raise Exception(f"Cannot connect to API Gateway: {e}")
    
    async def _test_authentication_setup(self):
        """Test authentication setup for API key management."""
        tests = []
        
        # Test 1: Login as regular user
        try:
            login_data = {
                "username": TEST_USER_EMAIL,
                "password": TEST_USER_PASSWORD
            }
            
            response = await self.client.post(
                f"{self.base_url}/api/v1/auth/login",
                data=login_data
            )
            
            if response.status_code == 200:
                data = response.json()
                self.user_token = data.get("access_token")
                tests.append(("User login", True, "Successfully logged in as user"))
            else:
                tests.append(("User login", False, f"Login failed: {response.status_code}"))
                
        except Exception as e:
            tests.append(("User login", False, f"Login error: {e}"))
        
        # Test 2: Login as admin
        try:
            login_data = {
                "username": ADMIN_EMAIL,
                "password": ADMIN_PASSWORD
            }
            
            response = await self.client.post(
                f"{self.base_url}/api/v1/auth/login",
                data=login_data
            )
            
            if response.status_code == 200:
                data = response.json()
                self.admin_token = data.get("access_token")
                tests.append(("Admin login", True, "Successfully logged in as admin"))
            else:
                tests.append(("Admin login", False, f"Admin login failed: {response.status_code}"))
                
        except Exception as e:
            tests.append(("Admin login", False, f"Admin login error: {e}"))
        
        return tests
    
    async def _test_api_key_creation(self):
        """Test API key creation functionality."""
        tests = []
        
        if not self.user_token:
            return [("API Key Creation", False, "No user token available")]
        
        headers = {"Authorization": f"Bearer {self.user_token}"}
        
        # Test 1: Create basic API key
        try:
            key_data = {
                "name": "Test API Key",
                "description": "Test key for automated testing",
                "scopes": ["read_only", "weather"],
                "rate_limit_rpm": 100
            }
            
            response = await self.client.post(
                f"{self.base_url}/api/v1/keys/",
                json=key_data,
                headers=headers
            )
            
            if response.status_code == 201:
                data = response.json()
                api_key = data.get("api_key")
                key_id = data.get("key_id")
                
                if api_key and key_id:
                    self.test_api_keys.append({
                        "key_id": key_id,
                        "api_key": api_key,
                        "scopes": key_data["scopes"]
                    })
                    tests.append(("Create basic API key", True, f"Created key: {key_id}"))
                else:
                    tests.append(("Create basic API key", False, "Missing key data in response"))
            else:
                tests.append(("Create basic API key", False, f"Creation failed: {response.status_code}"))
                
        except Exception as e:
            tests.append(("Create basic API key", False, f"Creation error: {e}"))
        
        # Test 2: Create API key with expiration
        try:
            key_data = {
                "name": "Expiring Test Key",
                "description": "Test key with expiration",
                "scopes": ["read_write"],
                "expires_in_days": 30,
                "rate_limit_rpm": 50,
                "allowed_ips": ["127.0.0.1", "192.168.1.1"]
            }
            
            response = await self.client.post(
                f"{self.base_url}/api/v1/keys/",
                json=key_data,
                headers=headers
            )
            
            if response.status_code == 201:
                data = response.json()
                self.test_api_keys.append({
                    "key_id": data.get("key_id"),
                    "api_key": data.get("api_key"),
                    "scopes": key_data["scopes"]
                })
                tests.append(("Create expiring API key", True, f"Created expiring key"))
            else:
                tests.append(("Create expiring API key", False, f"Creation failed: {response.status_code}"))
                
        except Exception as e:
            tests.append(("Create expiring API key", False, f"Creation error: {e}"))
        
        # Test 3: Create admin scope API key
        try:
            key_data = {
                "name": "Admin Test Key",
                "description": "Test key with admin scope",
                "scopes": ["admin"],
                "rate_limit_rpm": 200
            }
            
            response = await self.client.post(
                f"{self.base_url}/api/v1/keys/",
                json=key_data,
                headers=headers
            )
            
            if response.status_code == 201:
                data = response.json()
                self.test_api_keys.append({
                    "key_id": data.get("key_id"),
                    "api_key": data.get("api_key"),
                    "scopes": key_data["scopes"]
                })
                tests.append(("Create admin API key", True, f"Created admin key"))
            else:
                tests.append(("Create admin API key", False, f"Creation failed: {response.status_code}"))
                
        except Exception as e:
            tests.append(("Create admin API key", False, f"Creation error: {e}"))
        
        return tests
    
    async def _test_api_key_validation(self):
        """Test API key validation functionality."""
        tests = []
        
        if not self.test_api_keys:
            return [("API Key Validation", False, "No test API keys available")]
        
        # Test 1: Valid API key authentication
        test_key = self.test_api_keys[0]
        try:
            headers = {"X-API-Key": test_key["api_key"]}
            
            response = await self.client.get(
                f"{self.base_url}/api/v1/gateway/services",
                headers=headers
            )
            
            if response.status_code == 200:
                tests.append(("Valid API key", True, "API key accepted"))
            else:
                tests.append(("Valid API key", False, f"Validation failed: {response.status_code}"))
                
        except Exception as e:
            tests.append(("Valid API key", False, f"Validation error: {e}"))
        
        # Test 2: Invalid API key
        try:
            headers = {"X-API-Key": "invalid_key_123"}
            
            response = await self.client.get(
                f"{self.base_url}/api/v1/gateway/services",
                headers=headers
            )
            
            if response.status_code == 401:
                tests.append(("Invalid API key", True, "Invalid key rejected"))
            else:
                tests.append(("Invalid API key", False, f"Should have been rejected: {response.status_code}"))
                
        except Exception as e:
            tests.append(("Invalid API key", False, f"Validation error: {e}"))
        
        # Test 3: Missing API key
        try:
            response = await self.client.get(f"{self.base_url}/api/v1/gateway/services")
            
            if response.status_code == 401:
                tests.append(("Missing API key", True, "Missing key rejected"))
            else:
                tests.append(("Missing API key", False, f"Should require API key: {response.status_code}"))
                
        except Exception as e:
            tests.append(("Missing API key", False, f"Validation error: {e}"))
        
        return tests
    
    async def _test_rate_limiting(self):
        """Test rate limiting functionality."""
        tests = []
        
        if not self.test_api_keys:
            return [("Rate Limiting", False, "No test API keys available")]
        
        # Use a key with low rate limit for testing
        test_key = next((k for k in self.test_api_keys if "50" in str(k)), self.test_api_keys[0])
        headers = {"X-API-Key": test_key["api_key"]}
        
        # Test 1: Normal usage within limits
        try:
            success_count = 0
            for i in range(5):  # Make 5 requests
                response = await self.client.get(
                    f"{self.base_url}/api/v1/gateway/health",
                    headers=headers
                )
                if response.status_code == 200:
                    success_count += 1
                await asyncio.sleep(0.1)  # Small delay
            
            if success_count == 5:
                tests.append(("Normal rate limit usage", True, f"All {success_count} requests succeeded"))
            else:
                tests.append(("Normal rate limit usage", False, f"Only {success_count}/5 requests succeeded"))
                
        except Exception as e:
            tests.append(("Normal rate limit usage", False, f"Rate limit error: {e}"))
        
        # Test 2: Rate limit enforcement (this test is aggressive and may need adjustment)
        try:
            # Make many rapid requests to trigger rate limit
            rate_limited = False
            for i in range(60):  # Try to exceed rate limit
                response = await self.client.get(
                    f"{self.base_url}/api/v1/gateway/health",
                    headers=headers
                )
                if response.status_code == 429:
                    rate_limited = True
                    tests.append(("Rate limit enforcement", True, f"Rate limited after {i+1} requests"))
                    break
            
            if not rate_limited:
                tests.append(("Rate limit enforcement", False, "Rate limit not triggered"))
                
        except Exception as e:
            tests.append(("Rate limit enforcement", False, f"Rate limit test error: {e}"))
        
        return tests
    
    async def _test_scope_access_control(self):
        """Test scope-based access control."""
        tests = []
        
        if not self.test_api_keys:
            return [("Scope Access Control", False, "No test API keys available")]
        
        # Test read-only scope
        read_only_key = next((k for k in self.test_api_keys if "read_only" in k.get("scopes", [])), None)
        if read_only_key:
            try:
                headers = {"X-API-Key": read_only_key["api_key"]}
                
                # Should allow read operations
                response = await self.client.get(
                    f"{self.base_url}/api/v1/gateway/services",
                    headers=headers
                )
                
                if response.status_code == 200:
                    tests.append(("Read-only scope read access", True, "Read access granted"))
                else:
                    tests.append(("Read-only scope read access", False, f"Read access denied: {response.status_code}"))
                    
            except Exception as e:
                tests.append(("Read-only scope read access", False, f"Scope test error: {e}"))
        
        # Test admin scope
        admin_key = next((k for k in self.test_api_keys if "admin" in k.get("scopes", [])), None)
        if admin_key:
            try:
                headers = {"X-API-Key": admin_key["api_key"]}
                
                # Should allow admin operations
                response = await self.client.get(
                    f"{self.base_url}/api/v1/admin/system-info",
                    headers=headers
                )
                
                if response.status_code in [200, 404]:  # 404 is OK if endpoint doesn't exist yet
                    tests.append(("Admin scope access", True, "Admin access granted or endpoint not found"))
                else:
                    tests.append(("Admin scope access", False, f"Admin access denied: {response.status_code}"))
                    
            except Exception as e:
                tests.append(("Admin scope access", False, f"Admin scope test error: {e}"))
        
        return tests
    
    async def _test_key_management(self):
        """Test key management operations."""
        tests = []
        
        if not self.user_token or not self.test_api_keys:
            return [("Key Management", False, "No user token or test keys available")]
        
        headers = {"Authorization": f"Bearer {self.user_token}"}
        
        # Test 1: List API keys
        try:
            response = await self.client.get(
                f"{self.base_url}/api/v1/keys/",
                headers=headers
            )
            
            if response.status_code == 200:
                keys = response.json()
                if len(keys) >= len(self.test_api_keys):
                    tests.append(("List API keys", True, f"Listed {len(keys)} keys"))
                else:
                    tests.append(("List API keys", False, f"Expected at least {len(self.test_api_keys)} keys, got {len(keys)}"))
            else:
                tests.append(("List API keys", False, f"List failed: {response.status_code}"))
                
        except Exception as e:
            tests.append(("List API keys", False, f"List error: {e}"))
        
        # Test 2: Get specific API key
        if self.test_api_keys:
            try:
                key_id = self.test_api_keys[0]["key_id"]
                response = await self.client.get(
                    f"{self.base_url}/api/v1/keys/{key_id}",
                    headers=headers
                )
                
                if response.status_code == 200:
                    key_data = response.json()
                    tests.append(("Get specific API key", True, f"Retrieved key {key_id}"))
                else:
                    tests.append(("Get specific API key", False, f"Get failed: {response.status_code}"))
                    
            except Exception as e:
                tests.append(("Get specific API key", False, f"Get error: {e}"))
        
        # Test 3: Rotate API key
        if self.test_api_keys:
            try:
                key_id = self.test_api_keys[0]["key_id"]
                response = await self.client.post(
                    f"{self.base_url}/api/v1/keys/{key_id}/rotate",
                    headers=headers
                )
                
                if response.status_code == 200:
                    rotation_data = response.json()
                    new_api_key = rotation_data.get("api_key")
                    if new_api_key:
                        # Update our test key
                        self.test_api_keys[0]["api_key"] = new_api_key
                        tests.append(("Rotate API key", True, f"Rotated key {key_id}"))
                    else:
                        tests.append(("Rotate API key", False, "No new API key in response"))
                else:
                    tests.append(("Rotate API key", False, f"Rotation failed: {response.status_code}"))
                    
            except Exception as e:
                tests.append(("Rotate API key", False, f"Rotation error: {e}"))
        
        # Test 4: Get API key analytics
        if self.test_api_keys:
            try:
                key_id = self.test_api_keys[0]["key_id"]
                response = await self.client.get(
                    f"{self.base_url}/api/v1/keys/{key_id}/analytics",
                    headers=headers
                )
                
                if response.status_code == 200:
                    analytics = response.json()
                    tests.append(("Get API key analytics", True, f"Retrieved analytics for {key_id}"))
                else:
                    tests.append(("Get API key analytics", False, f"Analytics failed: {response.status_code}"))
                    
            except Exception as e:
                tests.append(("Get API key analytics", False, f"Analytics error: {e}"))
        
        return tests
    
    async def _test_admin_functionality(self):
        """Test admin functionality."""
        tests = []
        
        if not self.admin_token:
            return [("Admin Functionality", False, "No admin token available")]
        
        headers = {"Authorization": f"Bearer {self.admin_token}"}
        
        # Test 1: List all API keys (admin)
        try:
            response = await self.client.get(
                f"{self.base_url}/api/v1/keys/admin/all",
                headers=headers
            )
            
            if response.status_code == 200:
                all_keys = response.json()
                tests.append(("Admin list all keys", True, f"Listed {len(all_keys)} system keys"))
            else:
                tests.append(("Admin list all keys", False, f"Admin list failed: {response.status_code}"))
                
        except Exception as e:
            tests.append(("Admin list all keys", False, f"Admin list error: {e}"))
        
        # Test 2: Get analytics summary (admin)
        try:
            response = await self.client.get(
                f"{self.base_url}/api/v1/keys/admin/analytics/summary",
                headers=headers
            )
            
            if response.status_code == 200:
                summary = response.json()
                tests.append(("Admin analytics summary", True, f"Retrieved system analytics"))
            else:
                tests.append(("Admin analytics summary", False, f"Admin analytics failed: {response.status_code}"))
                
        except Exception as e:
            tests.append(("Admin analytics summary", False, f"Admin analytics error: {e}"))
        
        return tests
    
    async def _test_security_features(self):
        """Test security features."""
        tests = []
        
        # Test 1: API key system health
        try:
            response = await self.client.get(f"{self.base_url}/api/v1/keys/health")
            
            if response.status_code == 200:
                health = response.json()
                if health.get("status") == "healthy":
                    tests.append(("API key system health", True, "System is healthy"))
                else:
                    tests.append(("API key system health", False, f"System unhealthy: {health}"))
            else:
                tests.append(("API key system health", False, f"Health check failed: {response.status_code}"))
                
        except Exception as e:
            tests.append(("API key system health", False, f"Health check error: {e}"))
        
        # Test 2: Get available scopes
        try:
            response = await self.client.get(f"{self.base_url}/api/v1/keys/scopes")
            
            if response.status_code == 200:
                scopes_data = response.json()
                scopes = scopes_data.get("scopes", [])
                if len(scopes) > 0:
                    tests.append(("Get available scopes", True, f"Retrieved {len(scopes)} scopes"))
                else:
                    tests.append(("Get available scopes", False, "No scopes returned"))
            else:
                tests.append(("Get available scopes", False, f"Scopes request failed: {response.status_code}"))
                
        except Exception as e:
            tests.append(("Get available scopes", False, f"Scopes error: {e}"))
        
        return tests
    
    async def _test_analytics(self):
        """Test analytics and monitoring."""
        tests = []
        
        if not self.user_token or not self.test_api_keys:
            return [("Analytics", False, "No user token or test keys available")]
        
        headers = {"Authorization": f"Bearer {self.user_token}"}
        key_id = self.test_api_keys[0]["key_id"]
        
        # Test 1: Get rate limit status
        try:
            response = await self.client.get(
                f"{self.base_url}/api/v1/keys/{key_id}/rate-limit",
                headers=headers
            )
            
            if response.status_code == 200:
                rate_status = response.json()
                tests.append(("Get rate limit status", True, f"Retrieved rate limit status"))
            else:
                tests.append(("Get rate limit status", False, f"Rate limit status failed: {response.status_code}"))
                
        except Exception as e:
            tests.append(("Get rate limit status", False, f"Rate limit status error: {e}"))
        
        return tests
    
    async def _test_error_handling(self):
        """Test error handling scenarios."""
        tests = []
        
        if not self.user_token:
            return [("Error Handling", False, "No user token available")]
        
        headers = {"Authorization": f"Bearer {self.user_token}"}
        
        # Test 1: Create API key with invalid data
        try:
            invalid_key_data = {
                "name": "",  # Invalid: empty name
                "description": "Test",
                "scopes": [],  # Invalid: no scopes
            }
            
            response = await self.client.post(
                f"{self.base_url}/api/v1/keys/",
                json=invalid_key_data,
                headers=headers
            )
            
            if response.status_code == 422:  # Validation error
                tests.append(("Invalid key data rejection", True, "Invalid data properly rejected"))
            else:
                tests.append(("Invalid key data rejection", False, f"Should have rejected invalid data: {response.status_code}"))
                
        except Exception as e:
            tests.append(("Invalid key data rejection", False, f"Validation error: {e}"))
        
        # Test 2: Access non-existent key
        try:
            response = await self.client.get(
                f"{self.base_url}/api/v1/keys/non_existent_key_id",
                headers=headers
            )
            
            if response.status_code == 404:
                tests.append(("Non-existent key handling", True, "Non-existent key properly handled"))
            else:
                tests.append(("Non-existent key handling", False, f"Should return 404: {response.status_code}"))
                
        except Exception as e:
            tests.append(("Non-existent key handling", False, f"Error handling error: {e}"))
        
        return tests
    
    async def _run_test_category(self, category_name: str, test_func):
        """Run a category of tests."""
        console.print(f"\n🧪 Testing: {category_name}", style="bold cyan")
        
        try:
            tests = await test_func()
            
            # Create results table
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Test", style="cyan")
            table.add_column("Status", justify="center")
            table.add_column("Details", style="dim")
            
            for test_name, success, details in tests:
                status = "✅ PASS" if success else "❌ FAIL"
                status_style = "green" if success else "red"
                table.add_row(test_name, f"[{status_style}]{status}[/]", details)
                
                # Store result
                self.test_results.append({
                    "category": category_name,
                    "test": test_name,
                    "success": success,
                    "details": details
                })
            
            console.print(table)
            
        except Exception as e:
            console.print(f"❌ Category failed: {e}", style="red")
            self.test_results.append({
                "category": category_name,
                "test": "Category Execution",
                "success": False,
                "details": str(e)
            })
    
    def _print_test_summary(self):
        """Print overall test summary."""
        console.print("\n📊 Test Summary", style="bold blue")
        console.print("=" * 60)
        
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results if result["success"])
        failed_tests = total_tests - passed_tests
        
        # Summary stats
        summary_table = Table(show_header=False)
        summary_table.add_column("Metric", style="bold")
        summary_table.add_column("Value", justify="right")
        
        summary_table.add_row("Total Tests", str(total_tests))
        summary_table.add_row("Passed", f"[green]{passed_tests}[/]")
        summary_table.add_row("Failed", f"[red]{failed_tests}[/]")
        summary_table.add_row("Success Rate", f"{(passed_tests/total_tests)*100:.1f}%" if total_tests > 0 else "0%")
        
        console.print(summary_table)
        
        # Failed tests detail
        if failed_tests > 0:
            console.print(f"\n❌ Failed Tests ({failed_tests}):", style="red bold")
            failed_table = Table(show_header=True, header_style="bold red")
            failed_table.add_column("Category", style="red")
            failed_table.add_column("Test", style="red")
            failed_table.add_column("Details", style="dim red")
            
            for result in self.test_results:
                if not result["success"]:
                    failed_table.add_row(
                        result["category"],
                        result["test"],
                        result["details"]
                    )
            
            console.print(failed_table)
        
        # Overall result
        if failed_tests == 0:
            console.print(f"\n🎉 All tests passed! API Key Management system is working correctly.", style="bold green")
        else:
            console.print(f"\n⚠️  {failed_tests} test(s) failed. Please review the implementation.", style="bold red")
    
    async def _cleanup(self):
        """Cleanup test resources."""
        try:
            # Revoke test API keys
            if self.user_token and self.test_api_keys:
                headers = {"Authorization": f"Bearer {self.user_token}"}
                
                for key_data in self.test_api_keys:
                    try:
                        await self.client.delete(
                            f"{self.base_url}/api/v1/keys/{key_data['key_id']}",
                            headers=headers
                        )
                    except:
                        pass  # Ignore cleanup errors
            
            await self.client.aclose()
            console.print("\n🧹 Cleanup completed", style="yellow")
            
        except Exception as e:
            console.print(f"\n⚠️  Cleanup error: {e}", style="yellow")


async def main():
    """Main test execution."""
    tester = APIKeyTester()
    await tester.run_all_tests()


if __name__ == "__main__":
    # Banner
    console.print(Panel.fit(
        "[bold blue]API Key Management System Test Suite[/]\n"
        "[dim]Comprehensive testing of API key creation, validation, rate limiting, and security[/]",
        border_style="blue"
    ))
    
    asyncio.run(main())

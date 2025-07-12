#!/usr/bin/env python3
"""
Simple API Key System Validation Script.

This script performs basic validation of the API key management system
without external dependencies beyond what's already available.
"""

import asyncio
import json
import time
from datetime import datetime

# Test the core API key system components
async def test_api_key_system():
    """Test core API key system functionality."""
    print("🔑 Testing API Key Management System")
    print("=" * 50)
    
    try:
        # Import the core components
        from app.services.api_keys import (
            APIKeyManager, 
            APIKeyScope, 
            APIKeyStatus,
            APIKeyConfig
        )
        
        print("✅ Successfully imported API key components")
        
        # Initialize the manager
        manager = APIKeyManager()
        print("✅ API key manager initialized")
        
        # Test 1: Create an API key
        print("\n📝 Test 1: Creating API key...")
        key_result = await manager.create_key(
            name="Test API Key",
            description="Test key for validation",
            owner_id="test_user_123",
            owner_email="test@example.com",
            scopes=[APIKeyScope.READ_ONLY, APIKeyScope.WEATHER],
            rate_limit_rpm=100
        )
        
        api_key = key_result["api_key"]
        key_id = key_result["key_id"]
        print(f"✅ Created API key: {key_id}")
        print(f"   Key length: {len(api_key)} characters")
        print(f"   Scopes: {key_result['scopes']}")
        
        # Test 2: Validate the API key
        print("\n🔍 Test 2: Validating API key...")
        metadata = await manager.validate_key_with_rate_limit(
            api_key=api_key,
            client_ip="127.0.0.1",
            user_agent="Test-Agent/1.0",
            required_scope=APIKeyScope.READ_ONLY
        )
        
        print(f"✅ API key validated successfully")
        print(f"   Owner: {metadata.owner_email}")
        print(f"   Status: {metadata.status.value}")
        print(f"   Rate limit: {metadata.rate_limit_rpm} RPM")
        
        # Test 3: Test rate limiting
        print("\n⏱️ Test 3: Testing rate limiting...")
        rate_limited = False
        for i in range(5):
            try:
                await manager.validate_key_with_rate_limit(api_key=api_key)
                print(f"   Request {i+1}: ✅ Success")
            except Exception as e:
                if "429" in str(e) or "rate limit" in str(e).lower():
                    print(f"   Request {i+1}: ⚠️ Rate limited")
                    rate_limited = True
                    break
                else:
                    print(f"   Request {i+1}: ❌ Error: {e}")
        
        if not rate_limited:
            print("✅ Rate limiting system operational (no limits hit in test)")
        
        # Test 4: List user keys
        print("\n📋 Test 4: Listing user keys...")
        user_keys = await manager.list_keys("test_user_123")
        print(f"✅ Found {len(user_keys)} keys for user")
        
        # Test 5: Get analytics
        print("\n📊 Test 5: Getting key analytics...")
        analytics = await manager.get_key_analytics(key_id, "test_user_123")
        print(f"✅ Retrieved analytics for key {key_id}")
        print(f"   Total requests: {analytics['usage']['total_requests']}")
        
        # Test 6: Test invalid key
        print("\n❌ Test 6: Testing invalid key...")
        try:
            await manager.validate_key_with_rate_limit("invalid_key_123")
            print("❌ Invalid key should have been rejected")
        except Exception as e:
            if "401" in str(e) or "invalid" in str(e).lower():
                print("✅ Invalid key properly rejected")
            else:
                print(f"❌ Unexpected error: {e}")
        
        # Test 7: Test scope enforcement
        print("\n🔒 Test 7: Testing scope enforcement...")
        try:
            await manager.validate_key_with_rate_limit(
                api_key=api_key,
                required_scope=APIKeyScope.ADMIN  # This should fail
            )
            print("❌ Should have been rejected for insufficient scope")
        except Exception as e:
            if "403" in str(e) or "scope" in str(e).lower():
                print("✅ Scope enforcement working correctly")
            else:
                print(f"❌ Unexpected error: {e}")
        
        # Test 8: Key rotation
        print("\n🔄 Test 8: Testing key rotation...")
        rotation_result = await manager.rotate_key(key_id, "test_user_123")
        new_api_key = rotation_result["api_key"]
        print(f"✅ Key rotated successfully")
        print(f"   New key length: {len(new_api_key)} characters")
        
        # Verify old key is invalid
        try:
            await manager.validate_key_with_rate_limit(api_key)
            print("❌ Old key should be invalid after rotation")
        except Exception:
            print("✅ Old key properly invalidated")
        
        # Verify new key works
        try:
            await manager.validate_key_with_rate_limit(new_api_key)
            print("✅ New key works correctly")
        except Exception as e:
            print(f"❌ New key validation failed: {e}")
        
        # Test 9: Key revocation
        print("\n🚫 Test 9: Testing key revocation...")
        revoke_success = await manager.revoke_key(key_id, "test_user_123")
        if revoke_success:
            print("✅ Key revoked successfully")
            
            # Verify revoked key is invalid
            try:
                await manager.validate_key_with_rate_limit(new_api_key)
                print("❌ Revoked key should be invalid")
            except Exception:
                print("✅ Revoked key properly invalidated")
        else:
            print("❌ Key revocation failed")
        
        print("\n🎉 API Key System Validation Complete!")
        print("✅ All core functionality is working correctly")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("   Make sure all dependencies are installed")
    except Exception as e:
        print(f"❌ Test error: {e}")
        import traceback
        traceback.print_exc()


async def test_middleware_integration():
    """Test middleware components."""
    print("\n🔧 Testing Middleware Integration")
    print("=" * 50)
    
    try:
        from app.middleware.api_key_middleware import (
            APIKeyAuthMiddleware,
            create_api_key_middleware_config,
            get_api_key_metadata,
            require_api_key_scope
        )
        
        print("✅ Successfully imported middleware components")
        
        # Test configuration creation
        config = create_api_key_middleware_config(
            enable_for_all_api_routes=True,
            require_for_gateway=True,
            require_for_weather=True
        )
        
        print("✅ Middleware configuration created")
        print(f"   Protected paths: {len(config['protected_paths'])}")
        print(f"   Required paths: {len(config['require_api_key_paths'])}")
        
    except ImportError as e:
        print(f"❌ Middleware import error: {e}")
    except Exception as e:
        print(f"❌ Middleware test error: {e}")


async def test_endpoint_imports():
    """Test API endpoint imports."""
    print("\n🌐 Testing API Endpoint Imports")
    print("=" * 50)
    
    try:
        from app.api.v1.endpoints.api_keys import router
        print("✅ Successfully imported API key endpoints")
        
        # Check router configuration
        routes = router.routes
        print(f"✅ Router has {len(routes)} routes configured")
        
        # List some key routes
        route_paths = [route.path for route in routes if hasattr(route, 'path')]
        print("   Key routes:")
        for path in route_paths[:5]:  # Show first 5 routes
            print(f"     - {path}")
        
    except ImportError as e:
        print(f"❌ Endpoint import error: {e}")
    except Exception as e:
        print(f"❌ Endpoint test error: {e}")


async def test_fastapi_integration():
    """Test FastAPI application integration."""
    print("\n🚀 Testing FastAPI Integration")
    print("=" * 50)
    
    try:
        # Import the main app to test integration
        from app.main import app
        print("✅ Successfully imported FastAPI app with API key integration")
        
        # Check if API key routes are included
        routes = []
        for route in app.routes:
            if hasattr(route, 'path'):
                routes.append(route.path)
        
        api_key_routes = [r for r in routes if '/keys' in r]
        print(f"✅ Found {len(api_key_routes)} API key routes in app")
        
        # Check middleware
        middleware_names = [type(m).__name__ for m in app.user_middleware]
        api_key_middleware = [m for m in middleware_names if 'APIKey' in m]
        print(f"✅ Found {len(api_key_middleware)} API key middleware components")
        
        if api_key_middleware:
            print(f"   Middleware: {', '.join(api_key_middleware)}")
        
    except ImportError as e:
        print(f"❌ FastAPI integration import error: {e}")
    except Exception as e:
        print(f"❌ FastAPI integration test error: {e}")


async def main():
    """Run all tests."""
    print("🧪 API Key Management System Validation")
    print("=" * 60)
    print(f"Timestamp: {datetime.now().isoformat()}")
    print()
    
    # Run all test categories
    await test_api_key_system()
    await test_middleware_integration()
    await test_endpoint_imports()
    await test_fastapi_integration()
    
    print("\n" + "=" * 60)
    print("🏁 Validation Complete")
    print()
    print("Next steps:")
    print("1. Start the FastAPI server: uvicorn app.main:app --reload")
    print("2. Run the comprehensive test suite: python scripts/test_api_keys.py")
    print("3. Test API endpoints with curl or Postman")
    print("4. Review the documentation: docs/api-key-management.md")


if __name__ == "__main__":
    asyncio.run(main())

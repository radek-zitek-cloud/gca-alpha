#!/usr/bin/env python3
"""
Quick test script to verify the API Gateway functionality.
"""

import asyncio
import sys
import os

# Add the app directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.models.service import ServiceDefinition, ServiceInstance
from app.services.registry import ServiceRegistry
from app.utils.helpers import build_upstream_url, extract_service_from_path


async def test_service_registry():
    """Test the service registry functionality."""
    print("🧪 Testing Service Registry...")
    
    registry = ServiceRegistry()
    
    # Create a test service
    service = ServiceDefinition(
        name="test-service",
        description="Test service for demonstration",
        instances=[
            ServiceInstance(
                id="test-1",
                url="http://httpbin.org",
                weight=1
            )
        ]
    )
    
    # Register the service
    await registry.register_service(service)
    
    # Test getting the service
    retrieved_service = await registry.get_service("test-service")
    assert retrieved_service is not None
    assert retrieved_service.name == "test-service"
    
    # Test getting best instance
    instance = await registry.get_best_instance("test-service")
    assert instance is not None
    assert instance["url"] == "http://httpbin.org"
    
    print("✅ Service Registry tests passed!")


def test_helpers():
    """Test utility helper functions."""
    print("🧪 Testing Helper Functions...")
    
    # Test path extraction
    service, path = extract_service_from_path("/api/v1/users/123")
    assert service == "api"
    assert path == "v1/users/123"
    
    # Test URL building
    url = build_upstream_url("http://api.example.com", "users/123", "limit=10")
    assert url == "http://api.example.com/users/123?limit=10"
    
    print("✅ Helper function tests passed!")


async def main():
    """Run all tests."""
    print("🚀 Starting API Gateway Tests...\n")
    
    try:
        test_helpers()
        await test_service_registry()
        
        print("\n🎉 All tests passed! The API Gateway is ready to use.")
        
        # Show example usage
        print("\n📖 Example Usage:")
        print("1. Start the server: uvicorn app.main:app --reload")
        print("2. View docs: http://localhost:8000/docs")
        print("3. Health check: http://localhost:8000/api/v1/health")
        print("4. Gateway services: http://localhost:8000/gateway/services")
        print("5. Proxy request: http://localhost:8000/gateway/example-service/get")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)

"""Test fixtures for API Gateway tests."""

import pytest
import asyncio
from typing import Dict, Any, AsyncGenerator
from unittest.mock import AsyncMock, MagicMock
from fastapi.testclient import TestClient
from httpx import AsyncClient

from app.main import app
from app.services.registry import ServiceRegistry
from app.models.service import ServiceDefinition, ServiceInstance


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def test_client():
    """Create a test client for the FastAPI app."""
    return TestClient(app)


@pytest.fixture
async def async_client() -> AsyncGenerator[AsyncClient, None]:
    """Create an async HTTP client for testing."""
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client


@pytest.fixture
def mock_service_registry():
    """Create a mock service registry for testing."""
    registry = MagicMock(spec=ServiceRegistry)
    registry.get_service = AsyncMock()
    registry.get_best_instance = AsyncMock()
    registry.register_service = AsyncMock()
    registry.deregister_service = AsyncMock()
    registry.start_health_checking = AsyncMock()
    registry.stop_health_checking = AsyncMock()
    registry.get_all_services = MagicMock(return_value={})
    return registry


@pytest.fixture
def sample_service_definition():
    """Create a sample service definition for testing."""
    return ServiceDefinition(
        name="test-service",
        description="Test service for unit tests",
        version="1.0.0",
        load_balancer="round_robin",
        health_check={
            "enabled": True,
            "type": "http",
            "path": "/health",
            "interval_seconds": 30,
            "timeout_seconds": 5
        },
        timeouts={
            "connect": 5.0,
            "read": 30.0,
            "write": 5.0
        },
        headers={
            "X-Service-Version": "1.0.0"
        }
    )


@pytest.fixture
def sample_service_instance():
    """Create a sample service instance for testing."""
    return ServiceInstance(
        id="test-instance-1",
        url="http://test-service:8080",
        weight=1,
        healthy=True,
        metadata={
            "region": "us-east-1",
            "datacenter": "dc1"
        }
    )


@pytest.fixture
def multiple_service_instances():
    """Create multiple service instances for load balancing tests."""
    return [
        ServiceInstance(
            id="test-instance-1",
            url="http://test-service-1:8080",
            weight=1,
            healthy=True,
            metadata={"region": "us-east-1"}
        ),
        ServiceInstance(
            id="test-instance-2",
            url="http://test-service-2:8080",
            weight=2,
            healthy=True,
            metadata={"region": "us-west-2"}
        ),
        ServiceInstance(
            id="test-instance-3",
            url="http://test-service-3:8080",
            weight=1,
            healthy=False,
            metadata={"region": "us-east-1"}
        )
    ]


@pytest.fixture
def sample_gateway_config():
    """Create a sample gateway configuration for testing."""
    return {
        "server": {
            "host": "localhost",
            "port": 8000,
            "workers": 1,
            "debug": True
        },
        "security": {
            "cors": {
                "enabled": True,
                "allow_origins": ["*"]
            },
            "authentication": {
                "enabled": False
            }
        },
        "monitoring": {
            "metrics": {
                "enabled": True,
                "endpoint": "/metrics"
            },
            "health_checks": {
                "enabled": True,
                "endpoint": "/health"
            }
        }
    }


@pytest.fixture
def sample_services_config():
    """Create a sample services configuration for testing."""
    return {
        "services": {
            "user-service": {
                "name": "user-service",
                "description": "User management service",
                "version": "1.0.0",
                "instances": [
                    {
                        "id": "user-service-1",
                        "url": "http://user-service-1:8080",
                        "weight": 1,
                        "metadata": {"region": "us-east-1"}
                    },
                    {
                        "id": "user-service-2",
                        "url": "http://user-service-2:8080",
                        "weight": 1,
                        "metadata": {"region": "us-west-2"}
                    }
                ],
                "load_balancer": "round_robin",
                "health_check": {
                    "enabled": True,
                    "type": "http",
                    "path": "/health",
                    "interval_seconds": 30
                }
            },
            "order-service": {
                "name": "order-service",
                "description": "Order processing service",
                "version": "2.0.0",
                "instances": [
                    {
                        "id": "order-service-1",
                        "url": "http://order-service:8080",
                        "weight": 1
                    }
                ],
                "load_balancer": "weighted_round_robin"
            }
        }
    }


@pytest.fixture
def mock_httpx_response():
    """Create a mock httpx response for testing."""
    response = MagicMock()
    response.status_code = 200
    response.headers = {"content-type": "application/json"}
    response.content = b'{"message": "success"}'
    response.text = '{"message": "success"}'
    response.json.return_value = {"message": "success"}
    return response


@pytest.fixture
def mock_httpx_client():
    """Create a mock httpx async client for testing."""
    client = AsyncMock()
    client.get = AsyncMock()
    client.post = AsyncMock()
    client.put = AsyncMock()
    client.delete = AsyncMock()
    client.patch = AsyncMock()
    client.head = AsyncMock()
    client.options = AsyncMock()
    return client


@pytest.fixture(autouse=True)
def reset_app_state():
    """Reset application state between tests."""
    # Clear any state that might persist between tests
    if hasattr(app.state, 'service_registry'):
        delattr(app.state, 'service_registry')
    if hasattr(app.state, 'config'):
        delattr(app.state, 'config')
    yield
    # Cleanup after test
    if hasattr(app.state, 'service_registry'):
        delattr(app.state, 'service_registry')
    if hasattr(app.state, 'config'):
        delattr(app.state, 'config')


class MockServer:
    """Mock HTTP server for testing upstream services."""
    
    def __init__(self, host: str = "localhost", port: int = 9999):
        self.host = host
        self.port = port
        self.responses = {}
        self.request_history = []
    
    def set_response(self, path: str, response: Dict[str, Any], status_code: int = 200):
        """Set a mock response for a specific path."""
        self.responses[path] = {
            "response": response,
            "status_code": status_code
        }
    
    def get_request_history(self):
        """Get the history of requests made to this mock server."""
        return self.request_history
    
    def clear_history(self):
        """Clear the request history."""
        self.request_history.clear()


@pytest.fixture
def mock_upstream_server():
    """Create a mock upstream server for testing."""
    return MockServer()


@pytest.fixture
def temp_config_dir(tmp_path):
    """Create a temporary directory with test configuration files."""
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    
    # Create test gateway.yaml
    gateway_config = {
        "server": {"host": "localhost", "port": 8000},
        "security": {"cors": {"enabled": True}},
        "monitoring": {"metrics": {"enabled": True}}
    }
    
    gateway_file = config_dir / "gateway.yaml"
    gateway_file.write_text(f"""
server:
  host: localhost
  port: 8000
security:
  cors:
    enabled: true
monitoring:
  metrics:
    enabled: true
""")
    
    # Create test services.yaml
    services_file = config_dir / "services.yaml"
    services_file.write_text(f"""
services:
  test-service:
    name: test-service
    description: Test service
    version: 1.0.0
    instances:
      - id: test-1
        url: http://test:8080
        weight: 1
    load_balancer: round_robin
""")
    
    return config_dir

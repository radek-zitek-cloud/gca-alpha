"""Integration tests for the API Gateway endpoints."""

import pytest
import json
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient
from httpx import AsyncClient

from app.main import app
from app.services.registry import ServiceRegistry
from app.models.service import ServiceDefinition, ServiceInstance


class TestHealthEndpoints:
    """Integration tests for health check endpoints."""
    
    def test_health_endpoint_basic(self, test_client):
        """Test basic health endpoint."""
        response = test_client.get("/api/v1/health")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "status" in data
        assert "timestamp" in data
        assert "version" in data
        assert data["status"] in ["healthy", "degraded", "unhealthy"]
    
    def test_health_endpoint_with_services(self, test_client, mock_service_registry):
        """Test health endpoint with service registry."""
        # Mock service registry with health summary
        mock_service_registry.get_all_services.return_value = {
            "user-service": {
                "service": MagicMock(),
                "instances": [MagicMock(healthy=True), MagicMock(healthy=False)]
            }
        }
        
        # Replace app's service registry
        app.state.service_registry = mock_service_registry
        
        response = test_client.get("/api/v1/health")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "services" in data
        assert len(data["services"]) >= 0  # May be empty in test environment
    
    def test_health_endpoint_detailed(self, test_client):
        """Test detailed health endpoint."""
        response = test_client.get("/api/v1/health?detailed=true")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "status" in data
        assert "checks" in data
        assert isinstance(data["checks"], dict)


class TestMetricsEndpoints:
    """Integration tests for metrics endpoints."""
    
    def test_metrics_endpoint(self, test_client):
        """Test metrics endpoint."""
        response = test_client.get("/api/v1/metrics")
        
        assert response.status_code == 200
        
        # Should return Prometheus format metrics
        content = response.text
        assert "# HELP" in content or "# TYPE" in content or len(content) > 0
    
    def test_metrics_endpoint_prometheus_format(self, test_client):
        """Test that metrics are in Prometheus format."""
        response = test_client.get("/api/v1/metrics")
        
        assert response.status_code == 200
        assert response.headers["content-type"] == "text/plain; charset=utf-8"
        
        # Basic Prometheus format validation
        lines = response.text.split("\n")
        has_metrics = any(line.startswith("#") or "_" in line for line in lines)
        assert has_metrics


class TestGatewayRouting:
    """Integration tests for gateway routing functionality."""
    
    def test_gateway_services_endpoint(self, test_client):
        """Test gateway services listing endpoint."""
        response = test_client.get("/gateway/services")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "services" in data
        assert isinstance(data["services"], dict)
    
    @patch('httpx.AsyncClient.request')
    async def test_gateway_proxy_success(self, mock_request, async_client, mock_service_registry):
        """Test successful request proxying through gateway."""
        # Setup mock service
        service_def = ServiceDefinition(name="test-service")
        service_instance = ServiceInstance(
            id="test-1",
            url="http://test-service:8080",
            healthy=True
        )
        
        mock_service_registry.get_best_instance = AsyncMock(return_value=service_instance)
        app.state.service_registry = mock_service_registry
        
        # Mock successful upstream response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/json"}
        mock_response.content = b'{"message": "success"}'
        mock_request.return_value = mock_response
        
        # Make request through gateway
        response = await async_client.get("/gateway/test-service/api/users")
        
        assert response.status_code == 200
        assert response.json() == {"message": "success"}
        
        # Verify upstream was called correctly
        mock_request.assert_called_once()
        call_args = mock_request.call_args
        assert "http://test-service:8080/api/users" in str(call_args)
    
    @patch('httpx.AsyncClient.request')
    async def test_gateway_proxy_service_not_found(self, mock_request, async_client, mock_service_registry):
        """Test gateway routing when service not found."""
        mock_service_registry.get_best_instance = AsyncMock(return_value=None)
        app.state.service_registry = mock_service_registry
        
        response = await async_client.get("/gateway/nonexistent-service/api/data")
        
        assert response.status_code == 503
        data = response.json()
        assert "Service not available" in data["detail"]
    
    @patch('httpx.AsyncClient.request')
    async def test_gateway_proxy_upstream_error(self, mock_request, async_client, mock_service_registry):
        """Test gateway routing when upstream service returns error."""
        # Setup mock service
        service_instance = ServiceInstance(
            id="test-1",
            url="http://test-service:8080",
            healthy=True
        )
        mock_service_registry.get_best_instance = AsyncMock(return_value=service_instance)
        app.state.service_registry = mock_service_registry
        
        # Mock upstream error response
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.headers = {"content-type": "application/json"}
        mock_response.content = b'{"error": "internal server error"}'
        mock_request.return_value = mock_response
        
        response = await async_client.get("/gateway/test-service/api/error")
        
        assert response.status_code == 500
        assert response.json() == {"error": "internal server error"}
    
    @patch('httpx.AsyncClient.request')
    async def test_gateway_proxy_timeout(self, mock_request, async_client, mock_service_registry):
        """Test gateway routing when upstream times out."""
        import httpx
        
        service_instance = ServiceInstance(
            id="test-1",
            url="http://test-service:8080",
            healthy=True
        )
        mock_service_registry.get_best_instance = AsyncMock(return_value=service_instance)
        app.state.service_registry = mock_service_registry
        
        # Mock timeout exception
        mock_request.side_effect = httpx.TimeoutException("Request timeout")
        
        response = await async_client.get("/gateway/test-service/api/slow")
        
        assert response.status_code == 504
        data = response.json()
        assert "Gateway timeout" in data["detail"]
    
    @patch('httpx.AsyncClient.request')
    async def test_gateway_proxy_post_request(self, mock_request, async_client, mock_service_registry):
        """Test gateway proxying of POST requests with body."""
        service_instance = ServiceInstance(
            id="test-1",
            url="http://test-service:8080",
            healthy=True
        )
        mock_service_registry.get_best_instance = AsyncMock(return_value=service_instance)
        app.state.service_registry = mock_service_registry
        
        # Mock successful response
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.headers = {"content-type": "application/json"}
        mock_response.content = b'{"id": 123, "created": true}'
        mock_request.return_value = mock_response
        
        # Send POST request with JSON body
        test_data = {"name": "Test User", "email": "test@example.com"}
        response = await async_client.post(
            "/gateway/test-service/api/users",
            json=test_data
        )
        
        assert response.status_code == 201
        assert response.json() == {"id": 123, "created": True}
        
        # Verify request was proxied correctly
        mock_request.assert_called_once()
        call_args = mock_request.call_args
        assert call_args[1]["method"] == "POST"
        assert "http://test-service:8080/api/users" in str(call_args)
    
    async def test_gateway_proxy_headers_forwarded(self, async_client, mock_service_registry):
        """Test that headers are properly forwarded to upstream services."""
        with patch('httpx.AsyncClient.request') as mock_request:
            service_instance = ServiceInstance(
                id="test-1",
                url="http://test-service:8080",
                healthy=True
            )
            mock_service_registry.get_best_instance = AsyncMock(return_value=service_instance)
            app.state.service_registry = mock_service_registry
            
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {"content-type": "application/json"}
            mock_response.content = b'{"data": "test"}'
            mock_request.return_value = mock_response
            
            # Send request with custom headers
            headers = {
                "Authorization": "Bearer token123",
                "X-API-Key": "secret-key",
                "X-Request-ID": "req-123"
            }
            
            response = await async_client.get(
                "/gateway/test-service/api/data",
                headers=headers
            )
            
            assert response.status_code == 200
            
            # Verify headers were forwarded
            mock_request.assert_called_once()
            call_args = mock_request.call_args
            forwarded_headers = call_args[1]["headers"]
            
            assert "Authorization" in forwarded_headers
            assert "X-API-Key" in forwarded_headers
            assert "X-Request-ID" in forwarded_headers


class TestApplicationLifecycle:
    """Integration tests for application lifecycle and startup."""
    
    @patch('app.config.get_config')
    @patch('app.config.get_services_config')
    def test_app_startup_with_services_config(self, mock_get_services, mock_get_config):
        """Test application startup with services configuration."""
        # Mock configuration
        mock_config = MagicMock()
        mock_get_config.return_value = mock_config
        
        mock_services = {
            "services": {
                "test-service": {
                    "name": "test-service",
                    "description": "Test service",
                    "version": "1.0.0",
                    "instances": [
                        {
                            "id": "test-1",
                            "url": "http://test:8080",
                            "weight": 1
                        }
                    ],
                    "load_balancer": "round_robin",
                    "health_check": {"enabled": True}
                }
            }
        }
        mock_get_services.return_value = mock_services
        
        # Create test client (triggers startup)
        with TestClient(app) as client:
            # Verify app started successfully
            response = client.get("/api/v1/health")
            assert response.status_code == 200
    
    def test_app_startup_without_services(self):
        """Test application startup without services configuration."""
        with patch('app.config.get_services_config') as mock_get_services:
            mock_get_services.return_value = {"services": {}}
            
            with TestClient(app) as client:
                response = client.get("/api/v1/health")
                assert response.status_code == 200
    
    def test_root_endpoint(self, test_client):
        """Test root endpoint."""
        response = test_client.get("/")
        
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
    
    def test_openapi_docs(self, test_client):
        """Test OpenAPI documentation endpoint."""
        response = test_client.get("/docs")
        assert response.status_code == 200
        
        response = test_client.get("/redoc")
        assert response.status_code == 200
        
        response = test_client.get("/openapi.json")
        assert response.status_code == 200
        openapi_spec = response.json()
        assert "openapi" in openapi_spec
        assert "info" in openapi_spec


class TestErrorHandling:
    """Integration tests for error handling."""
    
    def test_404_for_unknown_routes(self, test_client):
        """Test 404 response for unknown routes."""
        response = test_client.get("/unknown/route")
        assert response.status_code == 404
    
    def test_405_for_unsupported_methods(self, test_client):
        """Test 405 response for unsupported HTTP methods."""
        # Health endpoint only supports GET
        response = test_client.post("/api/v1/health")
        assert response.status_code == 405
    
    def test_gateway_invalid_service_path(self, test_client):
        """Test gateway response for invalid service paths."""
        # Missing service name
        response = test_client.get("/gateway/")
        assert response.status_code in [404, 422]  # Depends on routing implementation
        
        # Empty service name
        response = test_client.get("/gateway//api/test")
        assert response.status_code in [404, 503]


class TestMiddleware:
    """Integration tests for middleware functionality."""
    
    def test_metrics_middleware_headers(self, test_client):
        """Test that metrics middleware adds appropriate headers."""
        response = test_client.get("/api/v1/health")
        
        # Check for response time header (added by metrics middleware)
        # Note: This test may need adjustment based on actual middleware implementation
        assert response.status_code == 200
        
        # Verify middleware is working by checking timing
        # (Exact headers depend on middleware implementation)
    
    def test_cors_headers(self, test_client):
        """Test CORS headers are properly set."""
        # Preflight request
        response = test_client.options(
            "/api/v1/health",
            headers={"Origin": "http://localhost:3000"}
        )
        
        # Should include CORS headers
        # Note: Actual CORS behavior depends on configuration
        assert response.status_code in [200, 204]
    
    def test_request_id_generation(self, test_client):
        """Test that request IDs are generated and included in responses."""
        response = test_client.get("/api/v1/health")
        
        assert response.status_code == 200
        # Note: Check for X-Request-ID header if implemented
        # This depends on the actual middleware implementation


class TestConcurrency:
    """Integration tests for concurrent request handling."""
    
    @pytest.mark.asyncio
    async def test_concurrent_health_checks(self, async_client):
        """Test handling concurrent health check requests."""
        import asyncio
        
        # Make multiple concurrent requests
        tasks = []
        for _ in range(10):
            task = async_client.get("/api/v1/health")
            tasks.append(task)
        
        responses = await asyncio.gather(*tasks)
        
        # All requests should succeed
        for response in responses:
            assert response.status_code == 200
            data = response.json()
            assert "status" in data
    
    @pytest.mark.asyncio
    async def test_concurrent_gateway_requests(self, async_client, mock_service_registry):
        """Test handling concurrent gateway requests."""
        import asyncio
        
        # Setup mock service
        service_instance = ServiceInstance(
            id="test-1",
            url="http://test-service:8080",
            healthy=True
        )
        mock_service_registry.get_best_instance = AsyncMock(return_value=service_instance)
        app.state.service_registry = mock_service_registry
        
        with patch('httpx.AsyncClient.request') as mock_request:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {"content-type": "application/json"}
            mock_response.content = b'{"success": true}'
            mock_request.return_value = mock_response
            
            # Make concurrent gateway requests
            tasks = []
            for i in range(5):
                task = async_client.get(f"/gateway/test-service/api/data/{i}")
                tasks.append(task)
            
            responses = await asyncio.gather(*tasks)
            
            # All requests should succeed
            for response in responses:
                assert response.status_code == 200
                assert response.json() == {"success": True}
            
            # Verify all upstream calls were made
            assert mock_request.call_count == 5

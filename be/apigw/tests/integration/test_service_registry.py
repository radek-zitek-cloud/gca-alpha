"""Integration tests for service registry with real HTTP calls."""

import pytest
import asyncio
import json
from unittest.mock import patch, MagicMock
import httpx

from app.services.registry import ServiceRegistry
from app.models.service import ServiceDefinition, ServiceInstance


@pytest.mark.asyncio
class TestServiceRegistryIntegration:
    """Integration tests for service registry with mock HTTP services."""
    
    async def test_health_check_integration_success(self):
        """Test health check integration with successful HTTP response."""
        registry = ServiceRegistry()
        
        # Create service definition with health check
        service_def = ServiceDefinition(
            name="test-service",
            health_check={
                "enabled": True,
                "type": "http",
                "path": "/health",
                "interval_seconds": 30,
                "timeout_seconds": 5,
                "expected_status_codes": [200]
            }
        )
        
        # Create service instance
        instance = ServiceInstance(
            id="test-1",
            url="http://httpbin.org",  # Using real service for integration test
            healthy=True
        )
        
        registry.register_service(service_def, instance)
        
        # Mock the health check to use a known endpoint
        with patch.object(registry, '_get_health_check_url') as mock_url:
            mock_url.return_value = "http://httpbin.org/status/200"
            
            # Perform health check
            await registry._perform_health_check("test-service", instance)
            
            # Instance should remain healthy
            assert instance.healthy
    
    async def test_health_check_integration_failure(self):
        """Test health check integration with failed HTTP response."""
        registry = ServiceRegistry()
        
        service_def = ServiceDefinition(
            name="test-service",
            health_check={
                "enabled": True,
                "type": "http",
                "path": "/health",
                "expected_status_codes": [200]
            }
        )
        
        instance = ServiceInstance(
            id="test-1",
            url="http://httpbin.org",
            healthy=True
        )
        
        registry.register_service(service_def, instance)
        
        # Mock to return 500 status
        with patch.object(registry, '_get_health_check_url') as mock_url:
            mock_url.return_value = "http://httpbin.org/status/500"
            
            await registry._perform_health_check("test-service", instance)
            
            # Instance should become unhealthy
            assert not instance.healthy
    
    async def test_health_check_integration_timeout(self):
        """Test health check integration with timeout."""
        registry = ServiceRegistry()
        
        service_def = ServiceDefinition(
            name="test-service",
            health_check={
                "enabled": True,
                "type": "http",
                "path": "/health",
                "timeout_seconds": 1  # Very short timeout
            }
        )
        
        instance = ServiceInstance(
            id="test-1",
            url="http://httpbin.org",
            healthy=True
        )
        
        registry.register_service(service_def, instance)
        
        # Mock to use a slow endpoint
        with patch.object(registry, '_get_health_check_url') as mock_url:
            mock_url.return_value = "http://httpbin.org/delay/5"  # 5 second delay
            
            await registry._perform_health_check("test-service", instance)
            
            # Instance should become unhealthy due to timeout
            assert not instance.healthy
    
    async def test_multiple_service_health_checks(self):
        """Test health checks for multiple services concurrently."""
        registry = ServiceRegistry()
        
        # Create multiple services
        services_data = [
            ("service-1", "http://httpbin.org/status/200", True),
            ("service-2", "http://httpbin.org/status/500", False),
            ("service-3", "http://httpbin.org/status/200", True)
        ]
        
        instances = []
        for service_name, mock_url, expected_healthy in services_data:
            service_def = ServiceDefinition(
                name=service_name,
                health_check={
                    "enabled": True,
                    "type": "http",
                    "path": "/health"
                }
            )
            
            instance = ServiceInstance(
                id=f"{service_name}-1",
                url="http://httpbin.org",
                healthy=True
            )
            
            registry.register_service(service_def, instance)
            instances.append((service_name, instance, expected_healthy, mock_url))
        
        # Mock health check URLs for each service
        original_get_url = registry._get_health_check_url
        
        def mock_get_health_url(service_name, instance):
            for svc_name, inst, expected, url in instances:
                if svc_name == service_name and inst.id == instance.id:
                    return url
            return original_get_url(service_name, instance)
        
        with patch.object(registry, '_get_health_check_url', side_effect=mock_get_health_url):
            # Perform health checks for all services
            tasks = []
            for service_name, instance, expected, _ in instances:
                task = registry._perform_health_check(service_name, instance)
                tasks.append(task)
            
            await asyncio.gather(*tasks)
            
            # Verify health states
            for service_name, instance, expected_healthy, _ in instances:
                assert instance.healthy == expected_healthy, f"Health check failed for {service_name}"
    
    async def test_load_balancer_integration(self):
        """Test load balancer integration with multiple instances."""
        registry = ServiceRegistry()
        
        service_def = ServiceDefinition(
            name="web-service",
            load_balancer="weighted_round_robin"
        )
        
        # Create instances with different weights
        instances = [
            ServiceInstance(id="web-1", url="http://web-1:8080", weight=1, healthy=True),
            ServiceInstance(id="web-2", url="http://web-2:8080", weight=2, healthy=True),
            ServiceInstance(id="web-3", url="http://web-3:8080", weight=1, healthy=False)  # Unhealthy
        ]
        
        for instance in instances:
            registry.register_service(service_def, instance)
        
        # Test multiple selections
        selections = []
        for _ in range(10):
            selected = await registry.get_best_instance("web-service")
            if selected:
                selections.append(selected.id)
        
        # Should only select from healthy instances
        assert all(sel_id in ["web-1", "web-2"] for sel_id in selections)
        
        # web-2 should be selected more often due to higher weight
        web2_count = selections.count("web-2")
        web1_count = selections.count("web-1")
        assert web2_count > web1_count
    
    async def test_service_registry_lifecycle(self):
        """Test complete service registry lifecycle."""
        registry = ServiceRegistry()
        
        # Start with empty registry
        assert len(registry.get_all_services()) == 0
        
        # Register a service
        service_def = ServiceDefinition(
            name="lifecycle-service",
            health_check={"enabled": True}
        )
        
        instance = ServiceInstance(
            id="lifecycle-1",
            url="http://httpbin.org",
            healthy=True
        )
        
        registry.register_service(service_def, instance)
        
        # Verify registration
        assert len(registry.get_all_services()) == 1
        service = await registry.get_service("lifecycle-service")
        assert service is not None
        assert service.name == "lifecycle-service"
        
        # Get best instance
        best = await registry.get_best_instance("lifecycle-service")
        assert best is not None
        assert best.id == "lifecycle-1"
        
        # Add another instance
        instance2 = ServiceInstance(
            id="lifecycle-2",
            url="http://httpbin.org",
            healthy=True
        )
        registry.register_service(service_def, instance2)
        
        # Should have 2 instances now
        all_services = registry.get_all_services()
        assert len(all_services["lifecycle-service"]["instances"]) == 2
        
        # Deregister one instance
        registry.deregister_service("lifecycle-service", "lifecycle-1")
        
        # Should have 1 instance left
        all_services = registry.get_all_services()
        assert len(all_services["lifecycle-service"]["instances"]) == 1
        assert all_services["lifecycle-service"]["instances"][0].id == "lifecycle-2"
        
        # Deregister entire service
        registry.deregister_service("lifecycle-service")
        
        # Should be empty again
        assert len(registry.get_all_services()) == 0
        service = await registry.get_service("lifecycle-service")
        assert service is None
    
    @patch('httpx.AsyncClient.get')
    async def test_health_check_with_custom_status_codes(self, mock_get):
        """Test health check with custom expected status codes."""
        registry = ServiceRegistry()
        
        service_def = ServiceDefinition(
            name="custom-service",
            health_check={
                "enabled": True,
                "expected_status_codes": [200, 204, 202]  # Custom codes
            }
        )
        
        instance = ServiceInstance(
            id="custom-1",
            url="http://service:8080",
            healthy=True
        )
        
        registry.register_service(service_def, instance)
        
        # Test with status code 204 (should be healthy)
        mock_response = MagicMock()
        mock_response.status_code = 204
        mock_get.return_value = mock_response
        
        await registry._perform_health_check("custom-service", instance)
        assert instance.healthy
        
        # Test with status code 404 (should be unhealthy)
        mock_response.status_code = 404
        await registry._perform_health_check("custom-service", instance)
        assert not instance.healthy
        
        # Reset and test with 202 (should be healthy)
        instance.healthy = True
        mock_response.status_code = 202
        await registry._perform_health_check("custom-service", instance)
        assert instance.healthy
    
    async def test_service_registry_thread_safety_integration(self):
        """Test service registry thread safety with concurrent operations."""
        registry = ServiceRegistry()
        
        service_def = ServiceDefinition(name="concurrent-service")
        
        # Concurrent registration
        async def register_instance(instance_id):
            instance = ServiceInstance(
                id=f"instance-{instance_id}",
                url=f"http://service-{instance_id}:8080",
                healthy=True
            )
            registry.register_service(service_def, instance)
            return instance
        
        # Register 20 instances concurrently
        tasks = [register_instance(i) for i in range(20)]
        instances = await asyncio.gather(*tasks)
        
        # Verify all instances were registered
        all_services = registry.get_all_services()
        assert "concurrent-service" in all_services
        assert len(all_services["concurrent-service"]["instances"]) == 20
        
        # Concurrent deregistration
        async def deregister_instance(instance_id):
            registry.deregister_service("concurrent-service", f"instance-{instance_id}")
        
        # Deregister 10 instances concurrently
        deregister_tasks = [deregister_instance(i) for i in range(10)]
        await asyncio.gather(*deregister_tasks)
        
        # Should have 10 instances left
        all_services = registry.get_all_services()
        assert len(all_services["concurrent-service"]["instances"]) == 10
        
        # Concurrent instance selection
        async def get_instance():
            return await registry.get_best_instance("concurrent-service")
        
        # Get instances concurrently
        selection_tasks = [get_instance() for _ in range(50)]
        selected_instances = await asyncio.gather(*selection_tasks)
        
        # All selections should return valid instances
        assert all(instance is not None for instance in selected_instances)
        assert all(instance.healthy for instance in selected_instances)
    
    async def test_health_check_recovery(self):
        """Test instance recovery after health check failure."""
        registry = ServiceRegistry()
        
        service_def = ServiceDefinition(
            name="recovery-service",
            health_check={
                "enabled": True,
                "healthy_threshold": 2,  # Need 2 consecutive successful checks
                "unhealthy_threshold": 2  # Need 2 consecutive failed checks
            }
        )
        
        instance = ServiceInstance(
            id="recovery-1",
            url="http://httpbin.org",
            healthy=True
        )
        
        registry.register_service(service_def, instance)
        
        # Simulate health check failures
        with patch.object(registry, '_get_health_check_url') as mock_url:
            # First failure
            mock_url.return_value = "http://httpbin.org/status/500"
            await registry._perform_health_check("recovery-service", instance)
            assert instance.healthy  # Still healthy (need 2 failures)
            
            # Second failure - should become unhealthy
            await registry._perform_health_check("recovery-service", instance)
            assert not instance.healthy
            
            # Now simulate recovery
            mock_url.return_value = "http://httpbin.org/status/200"
            
            # First success
            await registry._perform_health_check("recovery-service", instance)
            assert not instance.healthy  # Still unhealthy (need 2 successes)
            
            # Second success - should become healthy
            await registry._perform_health_check("recovery-service", instance)
            assert instance.healthy

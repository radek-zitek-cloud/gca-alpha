"""Unit tests for service registry functionality."""

import pytest
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch

from app.services.registry import ServiceRegistry
from app.models.service import (
    ServiceDefinition, ServiceInstance, ServiceHealth, HealthCheckConfig,
    LoadBalancerType, ServiceInstanceStatus, RoutingRule
)


@pytest.fixture
def registry():
    """Create a service registry instance for testing."""
    return ServiceRegistry()


@pytest.fixture
def sample_service():
    """Create a sample service definition for testing."""
    health_check = HealthCheckConfig(
        path="/health",
        interval_seconds=30,
        timeout_seconds=5,
        healthy_threshold=2,
        unhealthy_threshold=3,
        enabled=True
    )
    
    instance = ServiceInstance(
        id="inst-1",
        url="http://localhost:8080",
        weight=1,
        healthy=True
    )
    
    return ServiceDefinition(
        name="user-service",
        version="1.0.0",
        instances=[instance],
        load_balancer_type=LoadBalancerType.ROUND_ROBIN,
        health_check=health_check
    )


@pytest.fixture
def sample_routing_rule():
    """Create a sample routing rule for testing."""
    return RoutingRule(
        id="rule-1",
        path_pattern="/api/v1/*",
        service_name="user-service",
        priority=1,
        methods=["GET", "POST"],
        headers={"X-Version": "v1"}
    )


class TestServiceRegistry:
    """Test cases for ServiceRegistry class."""
    
    @pytest.mark.asyncio
    async def test_register_service(self, registry, sample_service):
        """Test service registration."""
        await registry.register_service(sample_service)
        
        # Verify service is registered
        services = await registry.list_services()
        assert "user-service" in services
        assert services["user-service"].name == "user-service"
        assert services["user-service"].version == "1.0.0"
    
    @pytest.mark.asyncio
    async def test_unregister_service(self, registry, sample_service):
        """Test service unregistration."""
        # Register first
        await registry.register_service(sample_service)
        
        # Verify it's registered
        services = await registry.list_services()
        assert "user-service" in services
        
        # Unregister
        result = await registry.unregister_service("user-service")
        assert result is True
        
        # Verify it's removed
        services = await registry.list_services()
        assert "user-service" not in services
        
        # Try to unregister non-existent service
        result = await registry.unregister_service("non-existent")
        assert result is False
    
    @pytest.mark.asyncio
    async def test_get_service(self, registry, sample_service):
        """Test getting service by name."""
        # Test non-existent service
        service = await registry.get_service("non-existent")
        assert service is None
        
        # Register and test existing service
        await registry.register_service(sample_service)
        service = await registry.get_service("user-service")
        assert service is not None
        assert service.name == "user-service"
    
    @pytest.mark.asyncio
    async def test_list_services(self, registry, sample_service):
        """Test listing all services."""
        # Initially empty
        services = await registry.list_services()
        assert len(services) == 0
        
        # Add service
        await registry.register_service(sample_service)
        services = await registry.list_services()
        assert len(services) == 1
        assert "user-service" in services
    
    @pytest.mark.asyncio
    async def test_add_service_instance(self, registry, sample_service):
        """Test adding service instance."""
        await registry.register_service(sample_service)
        
        new_instance = ServiceInstance(
            id="inst-2",
            url="http://localhost:8081",
            weight=2,
            healthy=True
        )
        
        result = await registry.add_service_instance("user-service", new_instance)
        assert result is True
        
        # Verify instance was added
        service = await registry.get_service("user-service")
        assert len(service.instances) == 2
        
        # Test adding to non-existent service
        result = await registry.add_service_instance("non-existent", new_instance)
        assert result is False
    
    @pytest.mark.asyncio
    async def test_remove_service_instance(self, registry, sample_service):
        """Test removing service instance."""
        await registry.register_service(sample_service)
        
        # Remove existing instance
        result = await registry.remove_service_instance("user-service", "inst-1")
        assert result is True
        
        # Verify instance was removed
        service = await registry.get_service("user-service")
        assert len(service.instances) == 0
        
        # Test removing non-existent instance
        result = await registry.remove_service_instance("user-service", "non-existent")
        assert result is False
        
        # Test removing from non-existent service
        result = await registry.remove_service_instance("non-existent", "inst-1")
        assert result is False
    
    @pytest.mark.asyncio
    async def test_get_best_instance(self, registry, sample_service):
        """Test getting best instance for load balancing."""
        await registry.register_service(sample_service)
        
        # Get instance
        instance_info = await registry.get_best_instance("user-service")
        assert instance_info is not None
        assert instance_info["id"] == "inst-1"
        assert instance_info["url"] == "http://localhost:8080"
        
        # Test non-existent service
        instance_info = await registry.get_best_instance("non-existent")
        assert instance_info is None
    
    @pytest.mark.asyncio
    async def test_get_best_instance_multiple_instances(self, registry, sample_service):
        """Test load balancing with multiple instances."""
        # Add another instance
        second_instance = ServiceInstance(
            id="inst-2",
            url="http://localhost:8081",
            weight=1,
            healthy=True
        )
        sample_service.instances.append(second_instance)
        
        await registry.register_service(sample_service)
        
        # Get multiple instances to test round-robin
        instances_selected = []
        for _ in range(4):
            instance_info = await registry.get_best_instance("user-service")
            instances_selected.append(instance_info["id"])
        
        # Should alternate between instances
        assert "inst-1" in instances_selected
        assert "inst-2" in instances_selected
    
    @pytest.mark.asyncio
    async def test_is_service_healthy(self, registry, sample_service):
        """Test service health check."""
        await registry.register_service(sample_service)
        
        # Mock the health check to return healthy
        with patch.object(registry, 'check_service_health') as mock_health_check:
            mock_health_check.return_value = {
                "healthy": True,
                "total_instances": 1,
                "healthy_instances": 1
            }
            
            is_healthy = await registry.is_service_healthy("user-service")
            assert is_healthy is True
        
        # Test non-existent service
        is_healthy = await registry.is_service_healthy("non-existent")
        assert is_healthy is False
    
    @pytest.mark.asyncio
    async def test_check_service_health(self, registry, sample_service):
        """Test detailed service health check."""
        await registry.register_service(sample_service)
        
        # Mock the HTTP health check
        with patch('httpx.AsyncClient.get') as mock_get:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"status": "healthy"}
            mock_response.elapsed.total_seconds.return_value = 0.1
            mock_get.return_value = mock_response
            
            health_info = await registry.check_service_health("user-service")
            
            # The return format is a dict with instance IDs as keys
            assert "inst-1" in health_info
            assert health_info["inst-1"]["healthy"] is True
    
    @pytest.mark.asyncio
    async def test_mark_instance_unhealthy(self, registry, sample_service):
        """Test marking instance as unhealthy."""
        await registry.register_service(sample_service)
        
        # Mark instance as unhealthy
        await registry.mark_instance_unhealthy("user-service", "inst-1")
        
        # Verify instance is marked as unhealthy
        service = await registry.get_service("user-service")
        instance = next(inst for inst in service.instances if inst.id == "inst-1")
        assert instance.healthy is False
    
    @pytest.mark.asyncio
    async def test_routing_rules(self, registry, sample_routing_rule):
        """Test routing rule management."""
        # Initially no rules
        rules = await registry.get_routing_rules()
        assert len(rules) == 0
        
        # Add rule
        await registry.add_routing_rule(sample_routing_rule)
        
        # Verify rule was added
        rules = await registry.get_routing_rules()
        assert len(rules) == 1
        assert rules[0]["path_pattern"] == "/api/v1/*"
        assert rules[0]["service_name"] == "user-service"
    
    @pytest.mark.asyncio
    async def test_cleanup(self, registry):
        """Test registry cleanup."""
        # Add some actual asyncio tasks (not mocks)
        import asyncio
        
        async def dummy_task():
            while True:
                await asyncio.sleep(1)
        
        registry._health_check_tasks["service1"] = asyncio.create_task(dummy_task())
        registry._health_check_tasks["service2"] = asyncio.create_task(dummy_task())
        
        # Call cleanup
        await registry.cleanup()
        
        # Verify tasks were cancelled
        for task in registry._health_check_tasks.values():
            assert task.cancelled()


class TestLoadBalancingMethods:
    """Test cases for load balancing algorithms."""
    
    def test_round_robin_selection(self, registry):
        """Test round-robin load balancing."""
        instances = [
            ServiceInstance(id="inst-1", url="http://host1:8080"),
            ServiceInstance(id="inst-2", url="http://host2:8080"),
            ServiceInstance(id="inst-3", url="http://host3:8080"),
        ]
        
        # Test round-robin selection
        selected = []
        for _ in range(6):  # Two full rounds
            instance = registry._round_robin_selection("test-service", instances)
            selected.append(instance.id)
        
        # Should cycle through instances
        expected = ["inst-1", "inst-2", "inst-3", "inst-1", "inst-2", "inst-3"]
        assert selected == expected
    
    def test_least_connections_selection(self, registry):
        """Test least connections load balancing."""
        instances = [
            ServiceInstance(id="inst-1", url="http://host1:8080"),
            ServiceInstance(id="inst-2", url="http://host2:8080"),
            ServiceInstance(id="inst-3", url="http://host3:8080"),
        ]
        
        # Set up connection counts
        registry._connection_counts["test-service"]["inst-1"] = 5
        registry._connection_counts["test-service"]["inst-2"] = 2
        registry._connection_counts["test-service"]["inst-3"] = 8
        
        # Should select instance with least connections
        selected = registry._least_connections_selection("test-service", instances)
        assert selected.id == "inst-2"
    
    def test_weighted_round_robin_selection(self, registry):
        """Test weighted round-robin load balancing."""
        instances = [
            ServiceInstance(id="inst-1", url="http://host1:8080", weight=1),
            ServiceInstance(id="inst-2", url="http://host2:8080", weight=3),
            ServiceInstance(id="inst-3", url="http://host3:8080", weight=2),
        ]
        
        # Test multiple selections
        selected = []
        for _ in range(12):
            instance = registry._weighted_round_robin_selection("test-service", instances)
            selected.append(instance.id)
        
        # Count selections
        counts = {id: selected.count(id) for id in ["inst-1", "inst-2", "inst-3"]}
        
        # inst-2 should be selected most (weight 3), then inst-3 (weight 2), then inst-1 (weight 1)
        assert counts["inst-2"] > counts["inst-3"] > counts["inst-1"]

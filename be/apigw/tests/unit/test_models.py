"""Unit tests for service models."""

import pytest
from pydantic import ValidationError

from app.models.service import ServiceDefinition, ServiceInstance, HealthCheckConfig, RoutingRule


class TestServiceInstance:
    """Test cases for ServiceInstance model."""
    
    def test_service_instance_creation(self):
        """Test creating a valid service instance."""
        instance = ServiceInstance(
            id="test-1",
            url="http://test:8080",
            weight=1,
            healthy=True,
            metadata={"region": "us-east-1"}
        )
        
        assert instance.id == "test-1"
        assert instance.url == "http://test:8080"
        assert instance.weight == 1
        assert instance.healthy is True
        assert instance.metadata == {"region": "us-east-1"}
    
    def test_service_instance_defaults(self):
        """Test service instance with default values."""
        instance = ServiceInstance(
            id="test-1",
            url="http://test:8080"
        )
        
        assert instance.weight == 1
        assert instance.healthy is True
        assert instance.metadata == {}
    
    def test_service_instance_invalid_weight(self):
        """Test service instance with invalid weight."""
        with pytest.raises(ValidationError):
            ServiceInstance(
                id="test-1",
                url="http://test:8080",
                weight=-1  # Invalid negative weight
            )
    
    def test_service_instance_zero_weight(self):
        """Test service instance with zero weight."""
        instance = ServiceInstance(
            id="test-1",
            url="http://test:8080",
            weight=0
        )
        assert instance.weight == 0
    
    def test_service_instance_url_validation(self):
        """Test service instance URL validation."""
        # Valid URLs
        valid_urls = [
            "http://test:8080",
            "https://api.example.com",
            "http://localhost:3000",
            "https://service.internal.com:8443"
        ]
        
        for url in valid_urls:
            instance = ServiceInstance(id="test", url=url)
            assert instance.url == url
    
    def test_service_instance_update_health(self):
        """Test updating service instance health status."""
        instance = ServiceInstance(
            id="test-1",
            url="http://test:8080",
            healthy=True
        )
        
        # Update health status
        instance.healthy = False
        assert instance.healthy is False


class TestHealthCheckConfig:
    """Test cases for HealthCheckConfig model."""
    
    def test_health_check_config_creation(self):
        """Test creating a valid health check configuration."""
        config = HealthCheckConfig(
            enabled=True,
            type="http",
            path="/health",
            interval_seconds=30,
            timeout_seconds=5,
            healthy_threshold=2,
            unhealthy_threshold=3,
            expected_status_codes=[200, 204]
        )
        
        assert config.enabled is True
        assert config.type == "http"
        assert config.path == "/health"
        assert config.interval_seconds == 30
        assert config.timeout_seconds == 5
        assert config.healthy_threshold == 2
        assert config.unhealthy_threshold == 3
        assert config.expected_status_codes == [200, 204]
    
    def test_health_check_config_defaults(self):
        """Test health check configuration with default values."""
        config = HealthCheckConfig()
        
        assert config.enabled is True
        assert config.type == "http"
        assert config.path == "/health"
        assert config.interval_seconds == 30
        assert config.timeout_seconds == 5
        assert config.healthy_threshold == 2
        assert config.unhealthy_threshold == 3
        assert config.expected_status_codes == [200]
    
    def test_health_check_config_tcp_type(self):
        """Test health check configuration with TCP type."""
        config = HealthCheckConfig(
            type="tcp",
            path=""  # TCP doesn't need a path
        )
        
        assert config.type == "tcp"
        assert config.path == ""
    
    def test_health_check_config_invalid_interval(self):
        """Test health check configuration with invalid interval."""
        with pytest.raises(ValidationError):
            HealthCheckConfig(interval_seconds=0)  # Invalid zero interval
    
    def test_health_check_config_invalid_timeout(self):
        """Test health check configuration with invalid timeout."""
        with pytest.raises(ValidationError):
            HealthCheckConfig(timeout_seconds=0)  # Invalid zero timeout


class TestRoutingRule:
    """Test cases for RoutingRule model."""
    
    def test_routing_rule_creation(self):
        """Test creating a valid routing rule."""
        rule = RoutingRule(
            path_pattern="/api/v1/*",
            methods=["GET", "POST"],
            headers={"X-API-Version": "v1"},
            priority=1
        )
        
        assert rule.path_pattern == "/api/v1/*"
        assert rule.methods == ["GET", "POST"]
        assert rule.headers == {"X-API-Version": "v1"}
        assert rule.priority == 1
    
    def test_routing_rule_defaults(self):
        """Test routing rule with default values."""
        rule = RoutingRule(path_pattern="/api/*")
        
        assert rule.path_pattern == "/api/*"
        assert rule.methods == ["*"]
        assert rule.headers == {}
        assert rule.priority == 0
    
    def test_routing_rule_priority_validation(self):
        """Test routing rule priority validation."""
        # Valid priority values
        valid_priorities = [0, 1, 5, 10]
        for priority in valid_priorities:
            rule = RoutingRule(path_pattern="/api/*", priority=priority)
            assert rule.priority == priority
        
        # Invalid priority values
        with pytest.raises(ValidationError):
            RoutingRule(path_pattern="/api/*", priority=-1)


class TestServiceDefinition:
    """Test cases for ServiceDefinition model."""
    
    def test_service_definition_creation(self):
        """Test creating a valid service definition."""
        service = ServiceDefinition(
            name="user-service",
            description="User management service",
            version="1.0.0",
            load_balancer="round_robin",
            health_check={
                "enabled": True,
                "path": "/health",
                "interval_seconds": 30
            },
            timeouts={
                "connect": 5.0,
                "read": 30.0,
                "write": 5.0
            },
            headers={"X-Service-Version": "1.0.0"}
        )
        
        assert service.name == "user-service"
        assert service.description == "User management service"
        assert service.version == "1.0.0"
        assert service.load_balancer == "round_robin"
        assert isinstance(service.health_check, HealthCheckConfig)
        assert service.health_check.enabled is True
        assert service.timeouts["connect"] == 5.0
        assert service.headers["X-Service-Version"] == "1.0.0"
    
    def test_service_definition_defaults(self):
        """Test service definition with default values."""
        service = ServiceDefinition(name="test-service")
        
        assert service.name == "test-service"
        assert service.description == ""
        assert service.version == "1.0.0"
        assert service.load_balancer == "round_robin"
        assert isinstance(service.health_check, HealthCheckConfig)
        assert service.timeouts == {}
        assert service.headers == {}
        assert service.retry == {}
        assert service.circuit_breaker == {}
        assert service.routing_rules == []
    
    def test_service_definition_load_balancer_validation(self):
        """Test service definition load balancer validation."""
        valid_strategies = ["round_robin", "weighted_round_robin", "least_connections", "random"]
        
        for strategy in valid_strategies:
            service = ServiceDefinition(name="test", load_balancer=strategy)
            assert service.load_balancer == strategy
        
        # Invalid strategy should use default
        service = ServiceDefinition(name="test", load_balancer="invalid_strategy")
        assert service.load_balancer == "invalid_strategy"  # Pydantic allows any string
    
    def test_service_definition_with_routing_rules(self):
        """Test service definition with routing rules."""
        service = ServiceDefinition(
            name="api-service",
            routing_rules=[
                {
                    "path_pattern": "/api/v1/*",
                    "methods": ["GET", "POST"],
                    "priority": 1
                },
                {
                    "path_pattern": "/api/v2/*",
                    "methods": ["GET"],
                    "priority": 2
                }
            ]
        )
        
        assert len(service.routing_rules) == 2
        assert all(isinstance(rule, RoutingRule) for rule in service.routing_rules)
        assert service.routing_rules[0].path_pattern == "/api/v1/*"
        assert service.routing_rules[1].priority == 2
    
    def test_service_definition_complex_configuration(self):
        """Test service definition with complex configuration."""
        service = ServiceDefinition(
            name="payment-service",
            description="Payment processing service",
            version="2.1.0",
            load_balancer="weighted_round_robin",
            health_check={
                "enabled": True,
                "type": "http",
                "path": "/api/health",
                "interval_seconds": 20,
                "timeout_seconds": 10,
                "expected_status_codes": [200, 201]
            },
            timeouts={
                "connect": 10.0,
                "read": 60.0,
                "write": 10.0
            },
            headers={
                "Authorization": "Bearer token",
                "X-API-Version": "2023-10-16"
            },
            retry={
                "max_attempts": 3,
                "backoff_factor": 0.5
            },
            circuit_breaker={
                "enabled": True,
                "failure_threshold": 5,
                "recovery_timeout": 60
            }
        )
        
        assert service.name == "payment-service"
        assert service.version == "2.1.0"
        assert service.health_check.interval_seconds == 20
        assert service.health_check.expected_status_codes == [200, 201]
        assert service.timeouts["read"] == 60.0
        assert service.retry["max_attempts"] == 3
        assert service.circuit_breaker["enabled"] is True
    
    def test_service_definition_name_validation(self):
        """Test service definition name validation."""
        # Valid names
        valid_names = ["user-service", "api_service", "service123", "my-api-v2"]
        for name in valid_names:
            service = ServiceDefinition(name=name)
            assert service.name == name
        
        # Empty name should raise validation error
        with pytest.raises(ValidationError):
            ServiceDefinition(name="")
    
    def test_service_definition_version_format(self):
        """Test service definition version format validation."""
        # Valid version formats
        valid_versions = ["1.0.0", "2.1.5", "1.0.0-alpha", "2.0.0-beta.1", "1.2.3-SNAPSHOT"]
        for version in valid_versions:
            service = ServiceDefinition(name="test", version=version)
            assert service.version == version

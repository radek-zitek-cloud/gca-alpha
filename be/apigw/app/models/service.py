"""
Service models for the API Gateway.

This module defines data models for services, instances, and health checks.
"""

from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum

from pydantic import BaseModel, Field


class LoadBalancerType(str, Enum):
    """Load balancer types."""
    ROUND_ROBIN = "round_robin"
    LEAST_CONNECTIONS = "least_connections"
    WEIGHTED_ROUND_ROBIN = "weighted_round_robin"
    RANDOM = "random"


class HealthCheckType(str, Enum):
    """Health check types."""
    HTTP = "http"
    TCP = "tcp"
    GRPC = "grpc"


class ServiceInstanceStatus(str, Enum):
    """Service instance status."""
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class ServiceInstance(BaseModel):
    """Model for a service instance."""
    id: str = Field(..., description="Unique identifier for the instance")
    url: str = Field(..., description="Base URL of the service instance")
    weight: int = Field(default=1, description="Weight for load balancing")
    healthy: bool = Field(default=True, description="Current health status")
    last_health_check: Optional[datetime] = Field(default=None, description="Last health check timestamp")
    response_time_ms: Optional[float] = Field(default=None, description="Last response time in milliseconds")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional instance metadata")
    
    class Config:
        """Pydantic configuration."""
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class HealthCheckConfig(BaseModel):
    """Health check configuration."""
    enabled: bool = Field(default=True, description="Whether health checks are enabled")
    type: HealthCheckType = Field(default=HealthCheckType.HTTP, description="Type of health check")
    path: str = Field(default="/health", description="Health check endpoint path")
    interval_seconds: int = Field(default=30, description="Health check interval in seconds")
    timeout_seconds: int = Field(default=5, description="Health check timeout in seconds")
    healthy_threshold: int = Field(default=2, description="Consecutive successful checks to mark healthy")
    unhealthy_threshold: int = Field(default=3, description="Consecutive failed checks to mark unhealthy")
    expected_status_codes: List[int] = Field(default=[200], description="Expected HTTP status codes for healthy")


class ServiceDefinition(BaseModel):
    """Model for a service definition."""
    name: str = Field(..., description="Service name")
    description: str = Field(default="", description="Service description")
    version: str = Field(default="1.0.0", description="Service version")
    instances: List[ServiceInstance] = Field(default_factory=list, description="Service instances")
    load_balancer_type: LoadBalancerType = Field(default=LoadBalancerType.ROUND_ROBIN, description="Load balancing strategy")
    health_check: HealthCheckConfig = Field(default_factory=HealthCheckConfig, description="Health check configuration")
    timeout_config: Dict[str, float] = Field(
        default_factory=lambda: {
            "connect": 5.0,
            "read": 30.0,
            "write": 5.0,
            "pool": 5.0
        },
        description="Timeout configuration in seconds"
    )
    headers: Dict[str, str] = Field(default_factory=dict, description="Additional headers to add to requests")
    rate_limit: Optional[Dict[str, Any]] = Field(default=None, description="Rate limiting configuration")
    retry_config: Dict[str, Any] = Field(
        default_factory=lambda: {
            "max_retries": 3,
            "backoff_factor": 0.3,
            "status_codes": [502, 503, 504]
        },
        description="Retry configuration"
    )
    circuit_breaker: Dict[str, Any] = Field(
        default_factory=lambda: {
            "enabled": False,
            "failure_threshold": 5,
            "recovery_timeout": 60,
            "expected_exception": "httpx.RequestError"
        },
        description="Circuit breaker configuration"
    )
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Service creation timestamp")
    updated_at: datetime = Field(default_factory=datetime.utcnow, description="Service last update timestamp")
    
    class Config:
        """Pydantic configuration."""
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class ServiceHealth(BaseModel):
    """Model for service health status."""
    service_name: str = Field(..., description="Service name")
    overall_status: ServiceInstanceStatus = Field(..., description="Overall service health status")
    healthy_instances: int = Field(..., description="Number of healthy instances")
    total_instances: int = Field(..., description="Total number of instances")
    last_check: datetime = Field(..., description="Last health check timestamp")
    instance_health: List[Dict[str, Any]] = Field(default_factory=list, description="Individual instance health details")
    
    class Config:
        """Pydantic configuration."""
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class RoutingRule(BaseModel):
    """Model for routing rules."""
    id: str = Field(..., description="Unique rule identifier")
    path_pattern: str = Field(..., description="Path pattern to match (regex supported)")
    service_name: str = Field(..., description="Target service name")
    priority: int = Field(default=100, description="Rule priority (lower number = higher priority)")
    methods: List[str] = Field(default=["*"], description="HTTP methods to match")
    headers: Dict[str, str] = Field(default_factory=dict, description="Headers that must be present")
    query_params: Dict[str, str] = Field(default_factory=dict, description="Query parameters that must be present")
    path_rewrite: Optional[str] = Field(default=None, description="Path rewrite pattern")
    enabled: bool = Field(default=True, description="Whether the rule is active")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Rule creation timestamp")
    
    class Config:
        """Pydantic configuration."""
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class ServiceMetrics(BaseModel):
    """Model for service metrics."""
    service_name: str = Field(..., description="Service name")
    total_requests: int = Field(default=0, description="Total number of requests")
    successful_requests: int = Field(default=0, description="Number of successful requests")
    failed_requests: int = Field(default=0, description="Number of failed requests")
    average_response_time_ms: float = Field(default=0.0, description="Average response time in milliseconds")
    last_request_time: Optional[datetime] = Field(default=None, description="Last request timestamp")
    error_rate: float = Field(default=0.0, description="Error rate percentage")
    
    class Config:
        """Pydantic configuration."""
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

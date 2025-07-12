"""
Gateway proxy package.

This package contains HTTP client, load balancing, and service discovery
components for the API Gateway.
"""

from .http_client import UpstreamHTTPClient, http_client
from .load_balancer import load_balancer, LoadBalancer
from .service_discovery import ServiceDiscoveryManager, ServiceDiscoveryConfig

__all__ = [
    "UpstreamHTTPClient",
    "http_client",
    "load_balancer", 
    "LoadBalancer",
    "ServiceDiscoveryManager",
    "ServiceDiscoveryConfig"
]

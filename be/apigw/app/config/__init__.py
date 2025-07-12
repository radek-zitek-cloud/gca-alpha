"""
Configuration module for the API Gateway.

This module provides access to configuration settings and centralized
configuration management for the entire application.
"""

from typing import Dict, Any, Optional

from .settings import (
    GatewayConfig,
    ServerConfig,
    SecurityConfig,
    MonitoringConfig,
    ConfigLoader,
    get_services_config
)
from .logging import setup_logging, get_logger, StructuredLogger


# Global configuration instance
_config_loader = ConfigLoader()
_gateway_config: Optional[GatewayConfig] = None

def get_config() -> GatewayConfig:
    """Get the current gateway configuration."""
    global _gateway_config
    if _gateway_config is None:
        _gateway_config = _config_loader.load_config()
    return _gateway_config


def reload_config(environment: Optional[str] = None) -> GatewayConfig:
    """Reload the gateway configuration."""
    global _gateway_config
    _gateway_config = _config_loader.load_config(environment)
    return _gateway_config


# Export commonly used functions and classes
__all__ = [
    "GatewayConfig",
    "ServerConfig", 
    "SecurityConfig",
    "MonitoringConfig",
    "get_config",
    "reload_config",
    "get_services_config",
    "setup_logging",
    "get_logger",
    "StructuredLogger"
]
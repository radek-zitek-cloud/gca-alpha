import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field


class ServerConfig(BaseModel):
    """Server configuration settings."""
    host: str = "localhost"
    port: int = 8000
    workers: int = 1
    debug: bool = False
    reload: bool = False
    log_level: str = "info"
    access_log: bool = True


class SecurityConfig(BaseModel):
    """Security configuration settings."""
    cors_enabled: bool = True
    cors_allow_origins: list = ["*"]
    cors_allow_methods: list = ["*"]
    cors_allow_headers: list = ["*"]
    authentication_enabled: bool = False
    rate_limiting_enabled: bool = False
    api_keys_enabled: bool = False


class MonitoringConfig(BaseModel):
    """Monitoring and observability configuration."""
    metrics_enabled: bool = True
    metrics_endpoint: str = "/metrics"
    health_enabled: bool = True
    health_endpoint: str = "/health"
    tracing_enabled: bool = False
    request_logging_enabled: bool = True


class GatewayConfig(BaseModel):
    """Main gateway configuration."""
    server: ServerConfig = Field(default_factory=ServerConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    monitoring: MonitoringConfig = Field(default_factory=MonitoringConfig)
    
    # Raw configuration for complex nested structures
    raw_config: Dict[str, Any] = Field(default_factory=dict)


class ConfigLoader:
    """Configuration loader for YAML files with environment-specific overrides."""
    
    def __init__(self, config_dir: Optional[Path] = None):
        """Initialize the configuration loader.
        
        Args:
            config_dir: Directory containing configuration files.
                       Defaults to the config directory relative to this file.
        """
        if config_dir is None:
            # Default to the config directory in the project
            current_dir = Path(__file__).parent.parent.parent
            self.config_dir = current_dir / "config"
        else:
            self.config_dir = Path(config_dir)
    
    def load_config(self, environment: Optional[str] = None) -> GatewayConfig:
        """Load configuration for the specified environment.
        
        Args:
            environment: Environment name (development, production, etc.).
                        If None, will try to detect from ENVIRONMENT variable.
                        
        Returns:
            Loaded and validated configuration.
        """
        if environment is None:
            environment = os.getenv("ENVIRONMENT", "development")
        
        # Load base configuration
        config_data = self._load_base_config()
        
        # Load environment-specific configuration
        env_config = self._load_environment_config(environment)
        if env_config:
            config_data = self._merge_configs(config_data, env_config)
        
        # Substitute environment variables
        config_data = self._substitute_env_vars(config_data)
        
        # Create and validate configuration
        return self._create_gateway_config(config_data)
    
    def _load_base_config(self) -> Dict[str, Any]:
        """Load the base gateway configuration."""
        gateway_config_path = self.config_dir / "gateway.yaml"
        if gateway_config_path.exists():
            return self._load_yaml_file(gateway_config_path)
        return {}
    
    def _load_environment_config(self, environment: str) -> Optional[Dict[str, Any]]:
        """Load environment-specific configuration."""
        env_config_path = self.config_dir / f"{environment}.yaml"
        if env_config_path.exists():
            return self._load_yaml_file(env_config_path)
        return None
    
    def _load_yaml_file(self, file_path: Path) -> Dict[str, Any]:
        """Load and parse a YAML file."""
        try:
            with open(file_path, 'r') as file:
                return yaml.safe_load(file) or {}
        except Exception as e:
            print(f"Warning: Failed to load config file {file_path}: {e}")
            return {}
    
    def _merge_configs(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively merge configuration dictionaries."""
        result = base.copy()
        
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def _substitute_env_vars(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Substitute environment variables in configuration values."""
        if isinstance(config, dict):
            return {key: self._substitute_env_vars(value) for key, value in config.items()}
        elif isinstance(config, list):
            return [self._substitute_env_vars(item) for item in config]
        elif isinstance(config, str):
            return self._substitute_string_env_vars(config)
        else:
            return config
    
    def _substitute_string_env_vars(self, value: str) -> str:
        """Substitute environment variables in a string value."""
        # Handle ${VAR_NAME} format
        import re
        
        def replace_env_var(match):
            var_spec = match.group(1)
            if ':' in var_spec:
                var_name, default_value = var_spec.split(':', 1)
                return os.getenv(var_name, default_value)
            else:
                return os.getenv(var_spec, match.group(0))
        
        return re.sub(r'\$\{([^}]+)\}', replace_env_var, value)
    
    def _create_gateway_config(self, config_data: Dict[str, Any]) -> GatewayConfig:
        """Create a GatewayConfig object from configuration data."""
        # Extract known configuration sections
        server_config = ServerConfig(**config_data.get("server", {}))
        security_config = SecurityConfig(**self._flatten_security_config(config_data.get("security", {})))
        monitoring_config = MonitoringConfig(**self._flatten_monitoring_config(config_data.get("monitoring", {})))
        
        return GatewayConfig(
            server=server_config,
            security=security_config,
            monitoring=monitoring_config,
            raw_config=config_data
        )
    
    def _flatten_security_config(self, security_data: Dict[str, Any]) -> Dict[str, Any]:
        """Flatten nested security configuration for Pydantic model."""
        result = {}
        
        # Handle CORS configuration
        cors = security_data.get("cors", {})
        result["cors_enabled"] = cors.get("enabled", True)
        result["cors_allow_origins"] = cors.get("allow_origins", ["*"])
        result["cors_allow_methods"] = cors.get("allow_methods", ["*"])
        result["cors_allow_headers"] = cors.get("allow_headers", ["*"])
        
        # Handle other security settings
        result["authentication_enabled"] = security_data.get("authentication", {}).get("enabled", False)
        result["rate_limiting_enabled"] = security_data.get("rate_limiting", {}).get("enabled", False)
        result["api_keys_enabled"] = security_data.get("api_keys", {}).get("enabled", False)
        
        return result
    
    def _flatten_monitoring_config(self, monitoring_data: Dict[str, Any]) -> Dict[str, Any]:
        """Flatten nested monitoring configuration for Pydantic model."""
        result = {}
        
        # Handle metrics configuration
        metrics = monitoring_data.get("metrics", {})
        result["metrics_enabled"] = metrics.get("enabled", True)
        result["metrics_endpoint"] = metrics.get("endpoint", "/metrics")
        
        # Handle health check configuration
        health = monitoring_data.get("health_checks", {})
        result["health_enabled"] = health.get("enabled", True)
        result["health_endpoint"] = health.get("endpoint", "/health")
        
        # Handle other monitoring settings
        result["tracing_enabled"] = monitoring_data.get("tracing", {}).get("enabled", False)
        result["request_logging_enabled"] = monitoring_data.get("request_logging", {}).get("enabled", True)
        
        return result


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


def get_services_config() -> Dict[str, Any]:
    """Load services configuration from services.yaml."""
    services_path = _config_loader.config_dir / "services.yaml"
    if services_path.exists():
        return _config_loader._load_yaml_file(services_path)
    return {"services": {}}
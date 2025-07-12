"""Unit tests for configuration loading and management."""

import pytest
import yaml
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from app.config import (
    ConfigLoader,
    GatewayConfig,
    ServerConfig,
    SecurityConfig,
    MonitoringConfig,
    get_config,
    reload_config,
    get_services_config
)


class TestServerConfig:
    """Test cases for ServerConfig model."""
    
    def test_server_config_defaults(self):
        """Test server configuration with default values."""
        config = ServerConfig()
        
        assert config.host == "localhost"
        assert config.port == 8000
        assert config.workers == 1
        assert config.debug is False
        assert config.reload is False
        assert config.log_level == "info"
        assert config.access_log is True
    
    def test_server_config_custom_values(self):
        """Test server configuration with custom values."""
        config = ServerConfig(
            host="0.0.0.0",
            port=8080,
            workers=4,
            debug=True,
            reload=True,
            log_level="debug",
            access_log=False
        )
        
        assert config.host == "0.0.0.0"
        assert config.port == 8080
        assert config.workers == 4
        assert config.debug is True
        assert config.reload is True
        assert config.log_level == "debug"
        assert config.access_log is False
    
    def test_server_config_validation(self):
        """Test server configuration validation."""
        # Valid port range
        config = ServerConfig(port=8080)
        assert config.port == 8080
        
        # Valid worker count
        config = ServerConfig(workers=4)
        assert config.workers == 4


class TestSecurityConfig:
    """Test cases for SecurityConfig model."""
    
    def test_security_config_defaults(self):
        """Test security configuration with default values."""
        config = SecurityConfig()
        
        assert config.cors_enabled is True
        assert config.cors_allow_origins == ["*"]
        assert config.cors_allow_methods == ["*"]
        assert config.cors_allow_headers == ["*"]
        assert config.authentication_enabled is False
        assert config.rate_limiting_enabled is False
        assert config.api_keys_enabled is False
    
    def test_security_config_custom_values(self):
        """Test security configuration with custom values."""
        config = SecurityConfig(
            cors_enabled=False,
            cors_allow_origins=["https://example.com"],
            cors_allow_methods=["GET", "POST"],
            authentication_enabled=True,
            rate_limiting_enabled=True,
            api_keys_enabled=True
        )
        
        assert config.cors_enabled is False
        assert config.cors_allow_origins == ["https://example.com"]
        assert config.cors_allow_methods == ["GET", "POST"]
        assert config.authentication_enabled is True
        assert config.rate_limiting_enabled is True
        assert config.api_keys_enabled is True


class TestMonitoringConfig:
    """Test cases for MonitoringConfig model."""
    
    def test_monitoring_config_defaults(self):
        """Test monitoring configuration with default values."""
        config = MonitoringConfig()
        
        assert config.metrics_enabled is True
        assert config.metrics_endpoint == "/metrics"
        assert config.health_enabled is True
        assert config.health_endpoint == "/health"
        assert config.tracing_enabled is False
        assert config.request_logging_enabled is True
    
    def test_monitoring_config_custom_values(self):
        """Test monitoring configuration with custom values."""
        config = MonitoringConfig(
            metrics_enabled=False,
            metrics_endpoint="/prometheus",
            health_enabled=False,
            health_endpoint="/healthz",
            tracing_enabled=True,
            request_logging_enabled=False
        )
        
        assert config.metrics_enabled is False
        assert config.metrics_endpoint == "/prometheus"
        assert config.health_enabled is False
        assert config.health_endpoint == "/healthz"
        assert config.tracing_enabled is True
        assert config.request_logging_enabled is False


class TestGatewayConfig:
    """Test cases for GatewayConfig model."""
    
    def test_gateway_config_defaults(self):
        """Test gateway configuration with default values."""
        config = GatewayConfig()
        
        assert isinstance(config.server, ServerConfig)
        assert isinstance(config.security, SecurityConfig)
        assert isinstance(config.monitoring, MonitoringConfig)
        assert config.raw_config == {}
    
    def test_gateway_config_custom_values(self):
        """Test gateway configuration with custom values."""
        server_config = ServerConfig(port=8080, debug=True)
        security_config = SecurityConfig(authentication_enabled=True)
        monitoring_config = MonitoringConfig(tracing_enabled=True)
        raw_config = {"custom": {"setting": "value"}}
        
        config = GatewayConfig(
            server=server_config,
            security=security_config,
            monitoring=monitoring_config,
            raw_config=raw_config
        )
        
        assert config.server.port == 8080
        assert config.server.debug is True
        assert config.security.authentication_enabled is True
        assert config.monitoring.tracing_enabled is True
        assert config.raw_config == raw_config


class TestConfigLoader:
    """Test cases for ConfigLoader functionality."""
    
    def test_config_loader_initialization(self, temp_config_dir):
        """Test ConfigLoader initialization."""
        loader = ConfigLoader(temp_config_dir)
        assert loader.config_dir == temp_config_dir
    
    def test_config_loader_default_path(self):
        """Test ConfigLoader with default path."""
        loader = ConfigLoader()
        assert loader.config_dir.name == "config"
    
    def test_load_yaml_file(self, temp_config_dir):
        """Test loading YAML file."""
        loader = ConfigLoader(temp_config_dir)
        
        # Create test YAML file
        test_data = {"test": {"key": "value"}, "number": 42}
        yaml_file = temp_config_dir / "test.yaml"
        with open(yaml_file, 'w') as f:
            yaml.dump(test_data, f)
        
        # Load the file
        result = loader._load_yaml_file(yaml_file)
        assert result == test_data
    
    def test_load_yaml_file_not_exists(self, temp_config_dir):
        """Test loading non-existent YAML file."""
        loader = ConfigLoader(temp_config_dir)
        
        result = loader._load_yaml_file(temp_config_dir / "nonexistent.yaml")
        assert result == {}
    
    def test_load_yaml_file_invalid_yaml(self, temp_config_dir):
        """Test loading invalid YAML file."""
        loader = ConfigLoader(temp_config_dir)
        
        # Create invalid YAML file
        invalid_yaml = temp_config_dir / "invalid.yaml"
        invalid_yaml.write_text("invalid: yaml: content: [")
        
        result = loader._load_yaml_file(invalid_yaml)
        assert result == {}
    
    def test_merge_configs(self, temp_config_dir):
        """Test merging configuration dictionaries."""
        loader = ConfigLoader(temp_config_dir)
        
        base_config = {
            "server": {"host": "localhost", "port": 8000},
            "security": {"cors": {"enabled": True}},
            "shared": {"value": "base"}
        }
        
        override_config = {
            "server": {"port": 8080, "debug": True},
            "monitoring": {"metrics": {"enabled": True}},
            "shared": {"value": "override"}
        }
        
        result = loader._merge_configs(base_config, override_config)
        
        expected = {
            "server": {"host": "localhost", "port": 8080, "debug": True},
            "security": {"cors": {"enabled": True}},
            "monitoring": {"metrics": {"enabled": True}},
            "shared": {"value": "override"}
        }
        
        assert result == expected
    
    def test_substitute_env_vars(self, temp_config_dir):
        """Test environment variable substitution."""
        loader = ConfigLoader(temp_config_dir)
        
        # Set environment variables
        os.environ["TEST_HOST"] = "production.example.com"
        os.environ["TEST_PORT"] = "8080"
        
        config_with_env_vars = {
            "server": {
                "host": "${TEST_HOST}",
                "port": "${TEST_PORT}",
                "debug": "${DEBUG:false}",  # With default value
                "missing": "${MISSING_VAR}"  # No default
            },
            "nested": {
                "value": "${TEST_HOST}/api"
            }
        }
        
        result = loader._substitute_env_vars(config_with_env_vars)
        
        expected = {
            "server": {
                "host": "production.example.com",
                "port": "8080",
                "debug": "false",  # Default value used
                "missing": "${MISSING_VAR}"  # Unchanged when no default
            },
            "nested": {
                "value": "production.example.com/api"
            }
        }
        
        assert result == expected
        
        # Cleanup
        del os.environ["TEST_HOST"]
        del os.environ["TEST_PORT"]
    
    def test_substitute_env_vars_in_lists(self, temp_config_dir):
        """Test environment variable substitution in lists."""
        loader = ConfigLoader(temp_config_dir)
        
        os.environ["ALLOWED_ORIGIN"] = "https://example.com"
        
        config = {
            "cors": {
                "allow_origins": ["${ALLOWED_ORIGIN}", "https://localhost:3000"]
            }
        }
        
        result = loader._substitute_env_vars(config)
        
        expected = {
            "cors": {
                "allow_origins": ["https://example.com", "https://localhost:3000"]
            }
        }
        
        assert result == expected
        
        del os.environ["ALLOWED_ORIGIN"]
    
    def test_flatten_security_config(self, temp_config_dir):
        """Test flattening security configuration."""
        loader = ConfigLoader(temp_config_dir)
        
        security_data = {
            "cors": {
                "enabled": True,
                "allow_origins": ["https://example.com"],
                "allow_methods": ["GET", "POST"]
            },
            "authentication": {"enabled": True},
            "rate_limiting": {"enabled": False},
            "api_keys": {"enabled": True}
        }
        
        result = loader._flatten_security_config(security_data)
        
        expected = {
            "cors_enabled": True,
            "cors_allow_origins": ["https://example.com"],
            "cors_allow_methods": ["GET", "POST"],
            "cors_allow_headers": ["*"],  # Default value
            "authentication_enabled": True,
            "rate_limiting_enabled": False,
            "api_keys_enabled": True
        }
        
        assert result == expected
    
    def test_flatten_monitoring_config(self, temp_config_dir):
        """Test flattening monitoring configuration."""
        loader = ConfigLoader(temp_config_dir)
        
        monitoring_data = {
            "metrics": {
                "enabled": False,
                "endpoint": "/prometheus"
            },
            "health_checks": {
                "enabled": True,
                "endpoint": "/healthz"
            },
            "tracing": {"enabled": True},
            "request_logging": {"enabled": False}
        }
        
        result = loader._flatten_monitoring_config(monitoring_data)
        
        expected = {
            "metrics_enabled": False,
            "metrics_endpoint": "/prometheus",
            "health_enabled": True,
            "health_endpoint": "/healthz",
            "tracing_enabled": True,
            "request_logging_enabled": False
        }
        
        assert result == expected
    
    @patch.dict(os.environ, {"ENVIRONMENT": "development"})
    def test_load_config_development(self, temp_config_dir):
        """Test loading development configuration."""
        loader = ConfigLoader(temp_config_dir)
        
        # Create development.yaml
        dev_config = {
            "server": {"debug": True, "reload": True},
            "security": {"authentication": {"enabled": False}}
        }
        dev_file = temp_config_dir / "development.yaml"
        with open(dev_file, 'w') as f:
            yaml.dump(dev_config, f)
        
        config = loader.load_config()
        
        assert isinstance(config, GatewayConfig)
        assert config.server.debug is True
        assert config.server.reload is True
    
    @patch.dict(os.environ, {"ENVIRONMENT": "production"})
    def test_load_config_production(self, temp_config_dir):
        """Test loading production configuration."""
        loader = ConfigLoader(temp_config_dir)
        
        # Create production.yaml
        prod_config = {
            "server": {"debug": False, "workers": 4},
            "security": {"authentication": {"enabled": True}}
        }
        prod_file = temp_config_dir / "production.yaml"
        with open(prod_file, 'w') as f:
            yaml.dump(prod_config, f)
        
        config = loader.load_config()
        
        assert isinstance(config, GatewayConfig)
        assert config.server.debug is False
        assert config.server.workers == 4
    
    def test_load_config_explicit_environment(self, temp_config_dir):
        """Test loading configuration with explicit environment."""
        loader = ConfigLoader(temp_config_dir)
        
        # Create test.yaml
        test_config = {
            "server": {"port": 9999},
            "monitoring": {"tracing": {"enabled": True}}
        }
        test_file = temp_config_dir / "test.yaml"
        with open(test_file, 'w') as f:
            yaml.dump(test_config, f)
        
        config = loader.load_config("test")
        
        assert config.server.port == 9999
        assert config.monitoring.tracing_enabled is True
    
    def test_load_services_config(self, temp_config_dir):
        """Test loading services configuration."""
        loader = ConfigLoader(temp_config_dir)
        
        # Services config already exists from fixture
        services_config = loader._load_yaml_file(temp_config_dir / "services.yaml")
        
        assert "services" in services_config
        assert "test-service" in services_config["services"]


class TestConfigGlobalFunctions:
    """Test cases for global configuration functions."""
    
    @patch('app.config._config_loader')
    def test_get_config(self, mock_loader):
        """Test get_config function."""
        mock_config = MagicMock(spec=GatewayConfig)
        mock_loader.load_config.return_value = mock_config
        
        # First call should load config
        result1 = get_config()
        assert result1 == mock_config
        mock_loader.load_config.assert_called_once()
        
        # Second call should return cached config
        result2 = get_config()
        assert result2 == mock_config
        # Should not call load_config again
        assert mock_loader.load_config.call_count == 1
    
    @patch('app.config._config_loader')
    def test_reload_config(self, mock_loader):
        """Test reload_config function."""
        mock_config = MagicMock(spec=GatewayConfig)
        mock_loader.load_config.return_value = mock_config
        
        result = reload_config("production")
        
        assert result == mock_config
        mock_loader.load_config.assert_called_once_with("production")
    
    @patch('app.config._config_loader')
    def test_get_services_config(self, mock_loader):
        """Test get_services_config function."""
        mock_services = {"services": {"test": {"name": "test"}}}
        mock_loader._load_yaml_file.return_value = mock_services
        
        result = get_services_config()
        
        assert result == mock_services
        mock_loader._load_yaml_file.assert_called_once()
    
    @patch('app.config._config_loader')
    def test_get_services_config_file_not_exists(self, mock_loader):
        """Test get_services_config when file doesn't exist."""
        mock_loader.config_dir = Path("/nonexistent")
        mock_loader._load_yaml_file.return_value = {}
        
        result = get_services_config()
        
        assert result == {"services": {}}

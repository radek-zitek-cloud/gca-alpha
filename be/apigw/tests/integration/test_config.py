"""Integration tests for configuration loading and environment handling."""

import pytest
import os
import yaml
import tempfile
from pathlib import Path
from unittest.mock import patch

from app.config import ConfigLoader, get_config, reload_config, get_services_config


class TestConfigurationIntegration:
    """Integration tests for configuration system."""
    
    def test_config_loading_with_real_files(self, tmp_path):
        """Test configuration loading with real YAML files."""
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        
        # Create base gateway.yaml
        gateway_config = {
            "server": {
                "host": "0.0.0.0",
                "port": 8080,
                "debug": False
            },
            "security": {
                "cors": {
                    "enabled": True,
                    "allow_origins": ["https://example.com"]
                },
                "authentication": {
                    "enabled": True
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
        
        gateway_file = config_dir / "gateway.yaml"
        with open(gateway_file, 'w') as f:
            yaml.dump(gateway_config, f)
        
        # Create development.yaml override
        dev_config = {
            "server": {
                "debug": True,
                "reload": True,
                "log_level": "debug"
            },
            "security": {
                "cors": {
                    "allow_origins": ["*"]
                },
                "authentication": {
                    "enabled": False
                }
            },
            "development": {
                "mock_external_services": True
            }
        }
        
        dev_file = config_dir / "development.yaml"
        with open(dev_file, 'w') as f:
            yaml.dump(dev_config, f)
        
        # Load configuration
        loader = ConfigLoader(config_dir)
        config = loader.load_config("development")
        
        # Verify merged configuration
        assert config.server.host == "0.0.0.0"  # From base
        assert config.server.port == 8080  # From base
        assert config.server.debug is True  # Overridden by dev
        assert config.server.reload is True  # From dev
        
        assert config.security.cors_enabled is True  # From base
        assert config.security.cors_allow_origins == ["*"]  # Overridden by dev
        assert config.security.authentication_enabled is False  # Overridden by dev
        
        assert config.monitoring.metrics_enabled is True  # From base
        assert config.monitoring.health_enabled is True  # From base
        
        # Check raw config contains development-specific settings
        assert "development" in config.raw_config
        assert config.raw_config["development"]["mock_external_services"] is True
    
    def test_environment_variable_substitution_integration(self, tmp_path):
        """Test environment variable substitution in real configuration."""
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        
        # Set environment variables
        test_env = {
            "GATEWAY_HOST": "production.example.com",
            "GATEWAY_PORT": "443",
            "REDIS_HOST": "redis.cluster.internal",
            "JWT_SECRET": "super-secret-key",
            "ENVIRONMENT": "production"
        }
        
        with patch.dict(os.environ, test_env):
            # Create configuration with environment variables
            config_data = {
                "server": {
                    "host": "${GATEWAY_HOST}",
                    "port": "${GATEWAY_PORT}",
                    "workers": "${WORKERS:4}",  # With default
                    "debug": "${DEBUG:false}"
                },
                "cache": {
                    "redis": {
                        "host": "${REDIS_HOST}",
                        "port": "${REDIS_PORT:6379}",
                        "password": "${REDIS_PASSWORD:}"
                    }
                },
                "security": {
                    "jwt": {
                        "secret_key": "${JWT_SECRET}"
                    }
                },
                "environment": {
                    "name": "${ENVIRONMENT}",
                    "deployment_id": "${DEPLOYMENT_ID:local}"
                }
            }
            
            config_file = config_dir / "production.yaml"
            with open(config_file, 'w') as f:
                yaml.dump(config_data, f)
            
            # Load configuration
            loader = ConfigLoader(config_dir)
            config = loader.load_config("production")
            
            # Verify environment variable substitution
            assert config.server.host == "production.example.com"
            assert config.server.port == 443  # Should be converted to int
            
            raw_config = config.raw_config
            assert raw_config["server"]["workers"] == "4"  # Default value used
            assert raw_config["server"]["debug"] == "false"
            assert raw_config["cache"]["redis"]["host"] == "redis.cluster.internal"
            assert raw_config["cache"]["redis"]["port"] == "6379"  # Default
            assert raw_config["cache"]["redis"]["password"] == ""  # Empty default
            assert raw_config["security"]["jwt"]["secret_key"] == "super-secret-key"
            assert raw_config["environment"]["name"] == "production"
            assert raw_config["environment"]["deployment_id"] == "local"  # Default
    
    def test_services_configuration_loading(self, tmp_path):
        """Test loading services configuration with real YAML."""
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        
        # Create comprehensive services.yaml
        services_config = {
            "services": {
                "user-service": {
                    "name": "user-service",
                    "description": "User management and authentication",
                    "version": "2.1.0",
                    "instances": [
                        {
                            "id": "user-service-1",
                            "url": "http://user-service-1:8080",
                            "weight": 2,
                            "metadata": {
                                "region": "us-east-1",
                                "datacenter": "dc1",
                                "version": "2.1.0"
                            }
                        },
                        {
                            "id": "user-service-2",
                            "url": "http://user-service-2:8080",
                            "weight": 1,
                            "metadata": {
                                "region": "us-west-2",
                                "datacenter": "dc2",
                                "version": "2.0.5"
                            }
                        }
                    ],
                    "load_balancer": "weighted_round_robin",
                    "health_check": {
                        "enabled": True,
                        "type": "http",
                        "path": "/api/health",
                        "interval_seconds": 15,
                        "timeout_seconds": 5,
                        "healthy_threshold": 2,
                        "unhealthy_threshold": 3,
                        "expected_status_codes": [200, 204]
                    },
                    "timeouts": {
                        "connect": 3.0,
                        "read": 30.0,
                        "write": 5.0
                    },
                    "headers": {
                        "X-Service-Version": "2.1.0",
                        "X-API-Client": "gateway"
                    },
                    "retry": {
                        "max_attempts": 3,
                        "backoff_factor": 0.5,
                        "retry_on_status_codes": [502, 503, 504]
                    },
                    "circuit_breaker": {
                        "enabled": True,
                        "failure_threshold": 5,
                        "recovery_timeout": 60,
                        "half_open_max_calls": 3
                    }
                },
                "payment-service": {
                    "name": "payment-service",
                    "description": "Payment processing",
                    "version": "1.0.0",
                    "instances": [
                        {
                            "id": "payment-1",
                            "url": "https://api.payments.example.com",
                            "weight": 1,
                            "metadata": {
                                "provider": "stripe",
                                "environment": "production"
                            }
                        }
                    ],
                    "load_balancer": "round_robin",
                    "health_check": {
                        "enabled": True,
                        "path": "/v1/health",
                        "interval_seconds": 60,
                        "timeout_seconds": 10
                    },
                    "timeouts": {
                        "connect": 10.0,
                        "read": 60.0,
                        "write": 10.0
                    }
                }
            },
            "service_groups": {
                "core-services": {
                    "description": "Essential business services",
                    "services": ["user-service"],
                    "fallback_behavior": "fail_fast"
                },
                "external-services": {
                    "description": "Third-party integrations",
                    "services": ["payment-service"],
                    "fallback_behavior": "graceful_degradation"
                }
            }
        }
        
        services_file = config_dir / "services.yaml"
        with open(services_file, 'w') as f:
            yaml.dump(services_config, f)
        
        # Load services configuration
        loader = ConfigLoader(config_dir)
        loaded_services = loader._load_yaml_file(services_file)
        
        # Verify services configuration
        assert "services" in loaded_services
        assert "service_groups" in loaded_services
        
        # Check user-service details
        user_service = loaded_services["services"]["user-service"]
        assert user_service["name"] == "user-service"
        assert user_service["version"] == "2.1.0"
        assert len(user_service["instances"]) == 2
        
        # Check instance details
        instance1 = user_service["instances"][0]
        assert instance1["id"] == "user-service-1"
        assert instance1["weight"] == 2
        assert instance1["metadata"]["region"] == "us-east-1"
        
        # Check health check configuration
        health_check = user_service["health_check"]
        assert health_check["enabled"] is True
        assert health_check["path"] == "/api/health"
        assert health_check["expected_status_codes"] == [200, 204]
        
        # Check timeouts
        timeouts = user_service["timeouts"]
        assert timeouts["connect"] == 3.0
        assert timeouts["read"] == 30.0
        
        # Check service groups
        core_group = loaded_services["service_groups"]["core-services"]
        assert "user-service" in core_group["services"]
        assert core_group["fallback_behavior"] == "fail_fast"
    
    def test_configuration_hierarchy_integration(self, tmp_path):
        """Test configuration hierarchy with multiple environment files."""
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        
        # Base configuration
        base_config = {
            "server": {"host": "localhost", "port": 8000, "workers": 1},
            "security": {"cors": {"enabled": True}},
            "monitoring": {"metrics": {"enabled": True}},
            "features": {"feature_a": True, "feature_b": False}
        }
        
        # Development overrides
        dev_config = {
            "server": {"debug": True, "reload": True},
            "security": {"authentication": {"enabled": False}},
            "features": {"feature_b": True, "feature_dev": True}
        }
        
        # Production overrides
        prod_config = {
            "server": {"host": "0.0.0.0", "port": 8080, "workers": 4, "debug": False},
            "security": {
                "cors": {"allow_origins": ["https://app.example.com"]},
                "authentication": {"enabled": True}
            },
            "monitoring": {
                "tracing": {"enabled": True},
                "alerting": {"enabled": True}
            },
            "features": {"feature_a": True, "feature_b": True, "feature_prod": True}
        }
        
        # Docker overrides
        docker_config = {
            "server": {"host": "0.0.0.0"},
            "logging": {"format": "json", "output": "console"},
            "features": {"feature_docker": True}
        }
        
        # Write configuration files
        files = [
            ("gateway.yaml", base_config),
            ("development.yaml", dev_config),
            ("production.yaml", prod_config),
            ("docker.yaml", docker_config)
        ]
        
        for filename, config_data in files:
            config_file = config_dir / filename
            with open(config_file, 'w') as f:
                yaml.dump(config_data, f)
        
        loader = ConfigLoader(config_dir)
        
        # Test development configuration
        dev_loaded = loader.load_config("development")
        assert dev_loaded.server.host == "localhost"  # From base
        assert dev_loaded.server.debug is True  # From dev
        assert dev_loaded.security.authentication_enabled is False  # From dev
        assert dev_loaded.raw_config["features"]["feature_dev"] is True  # From dev
        
        # Test production configuration
        prod_loaded = loader.load_config("production")
        assert prod_loaded.server.host == "0.0.0.0"  # From prod
        assert prod_loaded.server.port == 8080  # From prod
        assert prod_loaded.server.workers == 4  # From prod
        assert prod_loaded.security.authentication_enabled is True  # From prod
        assert prod_loaded.raw_config["monitoring"]["alerting"]["enabled"] is True  # From prod
        assert prod_loaded.raw_config["features"]["feature_prod"] is True  # From prod
        
        # Test docker configuration
        docker_loaded = loader.load_config("docker")
        assert docker_loaded.server.host == "0.0.0.0"  # From docker
        assert docker_loaded.server.port == 8000  # From base (not overridden)
        assert docker_loaded.raw_config["logging"]["format"] == "json"  # From docker
        assert docker_loaded.raw_config["features"]["feature_docker"] is True  # From docker
    
    @patch.dict(os.environ, {"ENVIRONMENT": "integration_test"})
    def test_global_config_functions_integration(self, tmp_path):
        """Test global configuration functions with real files."""
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        
        # Create test configuration
        test_config = {
            "server": {"host": "test.example.com", "port": 9999},
            "monitoring": {"metrics": {"enabled": False}}
        }
        
        config_file = config_dir / "integration_test.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(test_config, f)
        
        # Create services configuration
        services_config = {
            "services": {
                "test-service": {
                    "name": "test-service",
                    "instances": [{"id": "test-1", "url": "http://test:8080"}]
                }
            }
        }
        
        services_file = config_dir / "services.yaml"
        with open(services_file, 'w') as f:
            yaml.dump(services_config, f)
        
        # Patch the config loader to use our test directory
        with patch('app.config._config_loader') as mock_loader:
            mock_loader.config_dir = config_dir
            mock_loader.load_config.return_value = ConfigLoader(config_dir).load_config("integration_test")
            mock_loader._load_yaml_file.return_value = services_config
            
            # Test get_config
            config = get_config()
            assert config.server.host == "test.example.com"
            assert config.server.port == 9999
            
            # Test reload_config
            reloaded_config = reload_config("integration_test")
            assert reloaded_config.server.host == "test.example.com"
            
            # Test get_services_config
            services = get_services_config()
            assert "services" in services
            assert "test-service" in services["services"]
    
    def test_configuration_validation_integration(self, tmp_path):
        """Test configuration validation with invalid and valid configs."""
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        
        # Test with missing required fields - should use defaults
        minimal_config = {
            "server": {"host": "minimal.example.com"}
        }
        
        config_file = config_dir / "minimal.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(minimal_config, f)
        
        loader = ConfigLoader(config_dir)
        config = loader.load_config("minimal")
        
        # Should fill in defaults
        assert config.server.host == "minimal.example.com"
        assert config.server.port == 8000  # Default
        assert config.security.cors_enabled is True  # Default
        assert config.monitoring.metrics_enabled is True  # Default
    
    def test_configuration_edge_cases_integration(self, tmp_path):
        """Test configuration loading edge cases."""
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        
        loader = ConfigLoader(config_dir)
        
        # Test with non-existent environment
        config = loader.load_config("nonexistent")
        
        # Should return defaults when no config files exist
        assert config.server.host == "localhost"
        assert config.server.port == 8000
        
        # Test with empty configuration file
        empty_file = config_dir / "empty.yaml"
        empty_file.write_text("")
        
        empty_config = loader.load_config("empty")
        assert empty_config.server.host == "localhost"
        
        # Test with invalid YAML (should be handled gracefully)
        invalid_file = config_dir / "invalid.yaml"
        invalid_file.write_text("invalid: yaml: content: [unclosed")
        
        invalid_config = loader.load_config("invalid")
        assert invalid_config.server.host == "localhost"  # Should use defaults

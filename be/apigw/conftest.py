"""
Pytest configuration and shared fixtures.

This file contains pytest configuration and fixtures that are available
to all test modules in the project.
"""

import pytest
import asyncio
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

# Import all fixtures from the fixtures module
from tests.fixtures import *


def pytest_configure(config):
    """Configure pytest settings."""
    # Register custom markers
    config.addinivalue_line(
        "markers", "unit: Unit tests that test individual components in isolation"
    )
    config.addinivalue_line(
        "markers", "integration: Integration tests that test component interactions"
    )
    config.addinivalue_line(
        "markers", "slow: Tests that take longer than 1 second to run"
    )
    config.addinivalue_line(
        "markers", "network: Tests that require network access"
    )
    config.addinivalue_line(
        "markers", "config: Configuration-related tests"
    )
    config.addinivalue_line(
        "markers", "gateway: Gateway routing and proxy tests"
    )
    config.addinivalue_line(
        "markers", "registry: Service registry tests"
    )
    config.addinivalue_line(
        "markers", "health: Health check tests"
    )
    config.addinivalue_line(
        "markers", "auth: Authentication and authorization tests"
    )
    config.addinivalue_line(
        "markers", "metrics: Metrics and monitoring tests"
    )


def pytest_collection_modifyitems(config, items):
    """Automatically mark tests based on their location and content."""
    for item in items:
        # Mark tests based on file location
        if "unit" in str(item.fspath):
            item.add_marker(pytest.mark.unit)
        elif "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
        
        # Mark tests based on function name patterns
        if "slow" in item.name or "timeout" in item.name:
            item.add_marker(pytest.mark.slow)
        
        if "network" in item.name or "http" in item.name:
            item.add_marker(pytest.mark.network)
        
        if "config" in item.name:
            item.add_marker(pytest.mark.config)
        
        if "gateway" in item.name or "proxy" in item.name or "routing" in item.name:
            item.add_marker(pytest.mark.gateway)
        
        if "registry" in item.name or "service" in item.name:
            item.add_marker(pytest.mark.registry)
        
        if "health" in item.name:
            item.add_marker(pytest.mark.health)
        
        if "auth" in item.name or "authentication" in item.name:
            item.add_marker(pytest.mark.auth)
        
        if "metric" in item.name or "monitoring" in item.name:
            item.add_marker(pytest.mark.metrics)


@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    """Set up the test environment before any tests run."""
    # Set test environment variables
    os.environ["ENVIRONMENT"] = "test"
    os.environ["TESTING"] = "true"
    
    # Create test logs directory
    logs_dir = Path("tests/logs")
    logs_dir.mkdir(parents=True, exist_ok=True)
    
    yield
    
    # Cleanup after all tests
    # Remove test environment variables
    os.environ.pop("ENVIRONMENT", None)
    os.environ.pop("TESTING", None)


@pytest.fixture(autouse=True)
def isolate_tests():
    """Isolate tests from each other by resetting global state."""
    # Clear any global caches or state before each test
    import importlib
    
    # Reload configuration module to reset any cached state
    if 'app.config' in sys.modules:
        importlib.reload(sys.modules['app.config'])
    
    yield
    
    # Clean up after each test
    pass


@pytest.fixture
def temp_directory():
    """Provide a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


@pytest.fixture
def mock_environment_variables():
    """Provide a context manager for mocking environment variables."""
    def _mock_env(**kwargs):
        return patch.dict(os.environ, kwargs)
    
    return _mock_env


@pytest.fixture
def capture_logs():
    """Capture log output during tests."""
    import logging
    import io
    
    # Create a string buffer to capture logs
    log_buffer = io.StringIO()
    
    # Create a handler that writes to our buffer
    handler = logging.StreamHandler(log_buffer)
    handler.setLevel(logging.DEBUG)
    
    # Add handler to root logger
    root_logger = logging.getLogger()
    root_logger.addHandler(handler)
    original_level = root_logger.level
    root_logger.setLevel(logging.DEBUG)
    
    yield log_buffer
    
    # Clean up
    root_logger.removeHandler(handler)
    root_logger.setLevel(original_level)


@pytest.fixture
def mock_time():
    """Mock time.time() for consistent testing."""
    with patch('time.time', return_value=1640995200.0):  # 2022-01-01 00:00:00 UTC
        yield


@pytest.fixture
def suppress_warnings():
    """Suppress specific warnings during tests."""
    import warnings
    
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        warnings.simplefilter("ignore", ResourceWarning)
        yield


# Performance testing fixtures
@pytest.fixture
def benchmark_timer():
    """Provide a simple benchmarking timer."""
    import time
    
    class Timer:
        def __init__(self):
            self.start_time = None
            self.end_time = None
        
        def start(self):
            self.start_time = time.time()
        
        def stop(self):
            self.end_time = time.time()
        
        @property
        def elapsed(self):
            if self.start_time and self.end_time:
                return self.end_time - self.start_time
            return None
    
    return Timer()


# Async testing utilities
@pytest.fixture
def event_loop():
    """Provide a fresh event loop for each test."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
async def async_context():
    """Provide an async context for tests that need async setup/teardown."""
    # Async setup
    context = {"initialized": True}
    
    yield context
    
    # Async cleanup
    context.clear()


# Import sys for module reloading
import sys

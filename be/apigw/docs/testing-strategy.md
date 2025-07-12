# Testing Strategy

## Overview

This document outlines a comprehensive testing strategy for the API Gateway codebase, addressing current testing gaps and establishing best practices for maintaining high code quality throughout the development lifecycle. The strategy encompasses unit testing, integration testing, performance testing, security testing, and quality assurance.

## Current Testing Assessment

### Existing Test Coverage
- **Total Test Code**: 3,057 lines
- **Application Code**: 4,766 lines  
- **Coverage Ratio**: ~64% (Good baseline)
- **Test Structure**: Well-organized with unit and integration directories
- **Framework**: pytest with async support

### Testing Gaps Identified
- ❌ **Security Testing**: No dedicated security test suite
- ❌ **Performance Testing**: No load testing or benchmarks
- ❌ **Chaos Testing**: No failure scenario testing
- ⚠️ **Integration Testing**: Limited real service integration
- ⚠️ **Edge Case Coverage**: Missing error path testing
- ⚠️ **End-to-End Testing**: Basic coverage only

## 🧪 Testing Framework Architecture

### Testing Pyramid Structure

```
                     E2E Tests (5%)
                 ┌─────────────────────┐
                 │   Production-like    │
                 │   Full system test   │
                 └─────────────────────┘
                
              Integration Tests (25%)
         ┌─────────────────────────────────┐
         │     Service interactions       │
         │     Database operations        │
         │     External API calls         │
         └─────────────────────────────────┘
         
          Unit Tests (70%)
    ┌─────────────────────────────────────────┐
    │        Individual functions             │
    │        Class methods                    │
    │        Business logic                   │
    └─────────────────────────────────────────┘
```

## 📝 Testing Categories

### 1. Unit Testing

#### **Coverage Target: 90%+**
**Current Status**: ~70% estimated  
**Priority**: HIGH

#### Enhanced Unit Testing Framework

```python
# tests/unit/conftest.py
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock
from fastapi.testclient import TestClient
from app.main import app

@pytest.fixture
def client():
    """Test client for API testing"""
    return TestClient(app)

@pytest.fixture
def mock_service_discovery():
    """Mock service discovery for testing"""
    mock = AsyncMock()
    mock.discover_services.return_value = [
        {"id": "test-service", "host": "localhost", "port": 8080}
    ]
    return mock

@pytest.fixture
def mock_load_balancer():
    """Mock load balancer for testing"""
    mock = AsyncMock()
    mock.select_server.return_value = "test-server"
    return mock

@pytest.fixture
async def async_session():
    """Async session for testing async code"""
    return await AsyncMock()

# Example enhanced unit test
# tests/unit/services/test_proxy_service.py
import pytest
from unittest.mock import AsyncMock, patch
from app.services.proxy import ProxyService
from app.models.requests import ProxyRequest

class TestProxyService:
    
    @pytest.fixture
    def proxy_service(self, mock_service_discovery, mock_load_balancer):
        return ProxyService(
            service_discovery=mock_service_discovery,
            load_balancer=mock_load_balancer
        )
    
    @pytest.mark.asyncio
    async def test_proxy_request_success(self, proxy_service):
        """Test successful proxy request"""
        # Arrange
        request = ProxyRequest(
            method="GET",
            path="/api/test",
            headers={"Content-Type": "application/json"}
        )
        
        with patch('httpx.AsyncClient.request') as mock_request:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.content = b'{"result": "success"}'
            mock_response.headers = {"Content-Type": "application/json"}
            mock_request.return_value = mock_response
            
            # Act
            result = await proxy_service.proxy_request(request)
            
            # Assert
            assert result.status_code == 200
            assert result.content == b'{"result": "success"}'
            mock_request.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_proxy_request_timeout(self, proxy_service):
        """Test proxy request timeout handling"""
        request = ProxyRequest(method="GET", path="/api/slow")
        
        with patch('httpx.AsyncClient.request') as mock_request:
            mock_request.side_effect = asyncio.TimeoutError()
            
            # Act & Assert
            with pytest.raises(Exception) as exc_info:
                await proxy_service.proxy_request(request)
            
            assert "timeout" in str(exc_info.value).lower()
    
    @pytest.mark.asyncio
    async def test_proxy_request_connection_error(self, proxy_service):
        """Test proxy request connection error handling"""
        request = ProxyRequest(method="GET", path="/api/unavailable")
        
        with patch('httpx.AsyncClient.request') as mock_request:
            mock_request.side_effect = ConnectionError("Connection failed")
            
            # Act & Assert
            with pytest.raises(Exception) as exc_info:
                await proxy_service.proxy_request(request)
            
            assert "connection" in str(exc_info.value).lower()

    @pytest.mark.parametrize("method,path,expected_cache", [
        ("GET", "/api/cacheable", True),
        ("POST", "/api/update", False),
        ("GET", "/api/nocache", False),
    ])
    async def test_cache_decision(self, proxy_service, method, path, expected_cache):
        """Test caching decision logic"""
        request = ProxyRequest(method=method, path=path)
        should_cache = proxy_service._should_cache_request(request)
        assert should_cache == expected_cache
```

#### Property-Based Testing

```python
# tests/unit/test_property_based.py
import pytest
from hypothesis import given, strategies as st
from app.services.routing import RoutePatternMatcher

class TestRoutePatternMatcher:
    
    @given(st.text(alphabet=st.characters(whitelist_categories=['L', 'N']), min_size=1))
    def test_valid_path_patterns(self, path):
        """Test that valid paths are handled correctly"""
        matcher = RoutePatternMatcher()
        # Should not raise exception for valid paths
        try:
            result = matcher.match_pattern(f"/{path}", "/api/*")
            assert isinstance(result, bool)
        except Exception as e:
            pytest.fail(f"Valid path caused exception: {e}")
    
    @given(st.integers(min_value=1, max_value=65535))
    def test_port_validation(self, port):
        """Test port validation with property-based testing"""
        from app.validators.network import validate_port
        assert validate_port(port) == True
        
    @given(st.floats(min_value=0.001, max_value=300.0))
    def test_timeout_values(self, timeout):
        """Test timeout handling with various values"""
        from app.config.timeouts import TimeoutConfig
        config = TimeoutConfig(request_timeout=timeout)
        assert config.request_timeout == timeout
```

### 2. Integration Testing

#### **Coverage Target: 80%+**
**Current Status**: ~40% estimated  
**Priority**: HIGH

#### Service Integration Tests

```python
# tests/integration/test_service_integration.py
import pytest
import httpx
from testcontainers import DockerCompose
from app.main import app
from fastapi.testclient import TestClient

@pytest.fixture(scope="session")
def docker_compose():
    """Start test services with Docker Compose"""
    with DockerCompose("tests/docker", compose_file_name="docker-compose.test.yml") as compose:
        # Wait for services to be ready
        httpx.get("http://localhost:8081/health", timeout=30)  # Test service 1
        httpx.get("http://localhost:8082/health", timeout=30)  # Test service 2
        yield compose

@pytest.fixture
def integration_client(docker_compose):
    """Test client with real backend services"""
    return TestClient(app)

class TestServiceIntegration:
    
    def test_proxy_to_real_service(self, integration_client):
        """Test proxying to real backend service"""
        response = integration_client.get("/api/v1/test-service/data")
        
        assert response.status_code == 200
        assert "test-data" in response.json()
    
    def test_load_balancing_across_services(self, integration_client):
        """Test load balancing across multiple service instances"""
        responses = []
        
        # Make multiple requests to trigger load balancing
        for _ in range(10):
            response = integration_client.get("/api/v1/balanced-service/info")
            responses.append(response.json()["server_id"])
        
        # Should have requests distributed across different servers
        unique_servers = set(responses)
        assert len(unique_servers) > 1, "Load balancing not working"
    
    def test_service_discovery_integration(self, integration_client):
        """Test service discovery with real services"""
        # Register new service
        response = integration_client.post("/admin/services", json={
            "name": "test-service-3",
            "host": "localhost",
            "port": 8083,
            "health_check": "/health"
        })
        assert response.status_code == 201
        
        # Verify service is discoverable
        response = integration_client.get("/admin/services")
        services = response.json()
        service_names = [s["name"] for s in services]
        assert "test-service-3" in service_names
    
    def test_circuit_breaker_integration(self, integration_client):
        """Test circuit breaker with failing service"""
        # Simulate service failure
        for _ in range(10):  # Trigger circuit breaker
            response = integration_client.get("/api/v1/failing-service/data")
            # Should get 503 or circuit breaker response
        
        # Circuit should be open now
        response = integration_client.get("/api/v1/failing-service/data")
        assert response.status_code == 503
        assert "circuit breaker" in response.json()["detail"].lower()
```

#### Database Integration Tests

```python
# tests/integration/test_database_integration.py
import pytest
import asyncio
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from app.database import Base, get_db_session
from app.models.cache import CacheEntry

@pytest.fixture
async def test_db():
    """Test database setup and teardown"""
    engine = create_async_engine("sqlite+aiosqlite:///test.db")
    
    # Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    yield engine
    
    # Cleanup
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

@pytest.fixture
async def db_session(test_db):
    """Database session for testing"""
    async with AsyncSession(test_db) as session:
        yield session

class TestDatabaseIntegration:
    
    @pytest.mark.asyncio
    async def test_cache_entry_crud(self, db_session):
        """Test cache entry CRUD operations"""
        # Create
        cache_entry = CacheEntry(
            key="test-key",
            value='{"data": "test"}',
            ttl=300
        )
        db_session.add(cache_entry)
        await db_session.commit()
        
        # Read
        result = await db_session.get(CacheEntry, cache_entry.id)
        assert result.key == "test-key"
        
        # Update
        result.value = '{"data": "updated"}'
        await db_session.commit()
        
        # Verify update
        updated = await db_session.get(CacheEntry, cache_entry.id)
        assert updated.value == '{"data": "updated"}'
        
        # Delete
        await db_session.delete(updated)
        await db_session.commit()
        
        # Verify deletion
        deleted = await db_session.get(CacheEntry, cache_entry.id)
        assert deleted is None
```

### 3. Performance Testing

#### **Coverage Target**: All critical paths  
**Priority**: HIGH

#### Load Testing Framework

```python
# tests/performance/test_load.py
import asyncio
import aiohttp
import time
import statistics
from typing import List, Dict
import pytest

class LoadTestRunner:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.results: List[Dict] = []
    
    async def run_load_test(
        self,
        endpoint: str,
        concurrent_users: int = 50,
        duration_seconds: int = 60,
        ramp_up_seconds: int = 10
    ) -> Dict:
        """Run comprehensive load test"""
        
        async def make_request(session: aiohttp.ClientSession, user_id: int):
            """Single request execution"""
            start_time = time.time()
            try:
                url = f"{self.base_url}{endpoint}"
                async with session.get(url) as response:
                    await response.read()
                    end_time = time.time()
                    
                    return {
                        "user_id": user_id,
                        "response_time": end_time - start_time,
                        "status_code": response.status,
                        "success": 200 <= response.status < 300,
                        "timestamp": start_time
                    }
            except Exception as e:
                end_time = time.time()
                return {
                    "user_id": user_id,
                    "response_time": end_time - start_time,
                    "status_code": 0,
                    "success": False,
                    "error": str(e),
                    "timestamp": start_time
                }
        
        # Configure HTTP client
        timeout = aiohttp.ClientTimeout(total=30)
        connector = aiohttp.TCPConnector(limit=concurrent_users * 2)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout
        ) as session:
            
            test_start = time.time()
            test_end = test_start + duration_seconds
            
            # Ramp up users gradually
            ramp_up_delay = ramp_up_seconds / concurrent_users if concurrent_users > 0 else 0
            
            tasks = []
            user_id = 0
            
            while time.time() < test_end:
                # Add new users during ramp-up period
                if len(tasks) < concurrent_users and time.time() - test_start < ramp_up_seconds:
                    for _ in range(min(5, concurrent_users - len(tasks))):  # Add 5 users at a time
                        task = asyncio.create_task(make_request(session, user_id))
                        tasks.append(task)
                        user_id += 1
                        if ramp_up_delay > 0:
                            await asyncio.sleep(ramp_up_delay)
                
                # Process completed tasks
                if tasks:
                    done, pending = await asyncio.wait(
                        tasks, 
                        timeout=0.1, 
                        return_when=asyncio.FIRST_COMPLETED
                    )
                    
                    for task in done:
                        result = await task
                        self.results.append(result)
                        tasks.remove(task)
                        
                        # Add new request to maintain concurrent users
                        if time.time() < test_end:
                            new_task = asyncio.create_task(make_request(session, user_id))
                            tasks.append(new_task)
                            user_id += 1
            
            # Wait for remaining tasks
            if tasks:
                remaining_results = await asyncio.gather(*tasks, return_exceptions=True)
                for result in remaining_results:
                    if isinstance(result, dict):
                        self.results.append(result)
        
        return self._analyze_results()
    
    def _analyze_results(self) -> Dict:
        """Analyze load test results"""
        if not self.results:
            return {}
        
        response_times = [r["response_time"] for r in self.results]
        successful_requests = [r for r in self.results if r["success"]]
        failed_requests = [r for r in self.results if not r["success"]]
        
        # Time-based analysis
        start_time = min(r["timestamp"] for r in self.results)
        end_time = max(r["timestamp"] for r in self.results)
        duration = end_time - start_time
        
        # Calculate percentiles
        sorted_times = sorted(response_times)
        percentiles = {}
        if sorted_times:
            percentiles = {
                "p50": self._percentile(sorted_times, 50),
                "p90": self._percentile(sorted_times, 90),
                "p95": self._percentile(sorted_times, 95),
                "p99": self._percentile(sorted_times, 99)
            }
        
        return {
            "summary": {
                "total_requests": len(self.results),
                "successful_requests": len(successful_requests),
                "failed_requests": len(failed_requests),
                "success_rate": len(successful_requests) / len(self.results) * 100,
                "duration_seconds": duration,
                "requests_per_second": len(self.results) / duration if duration > 0 else 0
            },
            "response_times": {
                "avg_ms": statistics.mean(response_times) * 1000,
                "min_ms": min(response_times) * 1000,
                "max_ms": max(response_times) * 1000,
                "median_ms": statistics.median(response_times) * 1000,
                "percentiles_ms": {k: v * 1000 for k, v in percentiles.items()}
            },
            "errors": self._analyze_errors(failed_requests)
        }
    
    def _percentile(self, data: List[float], percentile: float) -> float:
        """Calculate percentile"""
        index = int((percentile / 100) * len(data))
        return data[min(index, len(data) - 1)]
    
    def _analyze_errors(self, failed_requests: List[Dict]) -> Dict:
        """Analyze error patterns"""
        error_counts = {}
        for request in failed_requests:
            error_type = request.get("error", f"HTTP {request['status_code']}")
            error_counts[error_type] = error_counts.get(error_type, 0) + 1
        
        return error_counts

# Performance test cases
class TestPerformance:
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_health_endpoint_performance(self):
        """Test health endpoint under load"""
        runner = LoadTestRunner("http://localhost:8000")
        
        results = await runner.run_load_test(
            endpoint="/health",
            concurrent_users=100,
            duration_seconds=30
        )
        
        # Performance assertions
        assert results["summary"]["success_rate"] >= 99.0, "Health endpoint success rate too low"
        assert results["response_times"]["avg_ms"] <= 50, "Health endpoint too slow"
        assert results["summary"]["requests_per_second"] >= 1000, "Throughput too low"
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_proxy_endpoint_performance(self):
        """Test proxy endpoint under load"""
        runner = LoadTestRunner("http://localhost:8000")
        
        results = await runner.run_load_test(
            endpoint="/api/v1/test-service/data",
            concurrent_users=50,
            duration_seconds=60
        )
        
        # Performance assertions
        assert results["summary"]["success_rate"] >= 95.0, "Proxy success rate too low"
        assert results["response_times"]["percentiles_ms"]["p95"] <= 500, "P95 latency too high"
        assert results["summary"]["requests_per_second"] >= 500, "Proxy throughput too low"
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_concurrent_different_endpoints(self):
        """Test multiple endpoints concurrently"""
        endpoints = [
            "/health",
            "/api/v1/service1/data",
            "/api/v1/service2/info",
            "/api/v1/service3/status"
        ]
        
        runners = [LoadTestRunner("http://localhost:8000") for _ in endpoints]
        
        # Run tests concurrently
        tasks = [
            runner.run_load_test(
                endpoint=endpoint,
                concurrent_users=25,
                duration_seconds=30
            )
            for runner, endpoint in zip(runners, endpoints)
        ]
        
        results = await asyncio.gather(*tasks)
        
        # Aggregate analysis
        total_rps = sum(r["summary"]["requests_per_second"] for r in results)
        avg_success_rate = sum(r["summary"]["success_rate"] for r in results) / len(results)
        
        assert total_rps >= 1000, "Total system throughput too low"
        assert avg_success_rate >= 95.0, "Overall success rate too low"
```

#### Memory and Resource Testing

```python
# tests/performance/test_resource_usage.py
import psutil
import pytest
import asyncio
import time
from memory_profiler import profile
import gc

class TestResourceUsage:
    
    @pytest.mark.performance
    def test_memory_usage_under_load(self):
        """Test memory usage patterns under load"""
        import os
        process = psutil.Process(os.getpid())
        
        # Baseline memory
        baseline_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Simulate load
        self._simulate_memory_intensive_operations()
        
        # Force garbage collection
        gc.collect()
        
        # Check memory after load
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - baseline_memory
        
        # Memory should not increase more than 100MB
        assert memory_increase < 100, f"Memory leak detected: {memory_increase}MB increase"
    
    @pytest.mark.performance
    def test_cpu_usage_patterns(self):
        """Test CPU usage under different load patterns"""
        import os
        process = psutil.Process(os.getpid())
        
        # Monitor CPU usage
        cpu_percentages = []
        
        for _ in range(10):
            cpu_percent = process.cpu_percent(interval=1)
            cpu_percentages.append(cpu_percent)
        
        avg_cpu = sum(cpu_percentages) / len(cpu_percentages)
        max_cpu = max(cpu_percentages)
        
        # CPU usage should be reasonable
        assert avg_cpu < 50, f"Average CPU usage too high: {avg_cpu}%"
        assert max_cpu < 80, f"Peak CPU usage too high: {max_cpu}%"
    
    def _simulate_memory_intensive_operations(self):
        """Simulate memory-intensive operations"""
        # Create and process large data structures
        data = []
        for i in range(1000):
            data.append({"id": i, "data": "x" * 1000})
        
        # Process data
        processed = [item for item in data if item["id"] % 2 == 0]
        
        # Clean up
        del data
        del processed
```

### 4. Security Testing

#### **Coverage Target**: All security features  
**Priority**: CRITICAL

#### Security Test Suite

```python
# tests/security/test_security.py
import pytest
import jwt
import httpx
from fastapi.testclient import TestClient
from app.main import app

class TestSecurity:
    
    def setup_method(self):
        self.client = TestClient(app)
    
    def test_authentication_required(self):
        """Test that protected endpoints require authentication"""
        protected_endpoints = [
            "/api/v1/admin/users",
            "/api/v1/admin/services",
            "/api/v1/protected/data"
        ]
        
        for endpoint in protected_endpoints:
            response = self.client.get(endpoint)
            assert response.status_code == 401, f"Endpoint {endpoint} should require auth"
    
    def test_invalid_jwt_token(self):
        """Test handling of invalid JWT tokens"""
        invalid_tokens = [
            "invalid.token.here",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid",
            "",
            "Bearer invalid"
        ]
        
        for token in invalid_tokens:
            headers = {"Authorization": f"Bearer {token}"}
            response = self.client.get("/api/v1/protected/data", headers=headers)
            assert response.status_code == 401
    
    def test_sql_injection_protection(self):
        """Test SQL injection protection"""
        sql_injection_attempts = [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "admin'/*",
            "1; SELECT * FROM sensitive_data; --"
        ]
        
        for injection in sql_injection_attempts:
            response = self.client.get(f"/api/v1/search?q={injection}")
            # Should not return 500 error or expose database errors
            assert response.status_code != 500
            assert "sql" not in response.text.lower()
            assert "database" not in response.text.lower()
    
    def test_xss_protection(self):
        """Test XSS protection"""
        xss_attempts = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "';alert('XSS');//"
        ]
        
        for xss in xss_attempts:
            response = self.client.post("/api/v1/feedback", json={"message": xss})
            # Should sanitize or reject malicious input
            assert "<script>" not in response.text
            assert "javascript:" not in response.text
    
    def test_rate_limiting(self):
        """Test rate limiting protection"""
        # Make requests exceeding rate limit
        endpoint = "/api/v1/public/data"
        client_ip = "192.168.1.100"
        
        responses = []
        for i in range(20):  # Exceed typical rate limit
            headers = {"X-Forwarded-For": client_ip}
            response = self.client.get(endpoint, headers=headers)
            responses.append(response.status_code)
        
        # Should see 429 (Too Many Requests) responses
        assert 429 in responses, "Rate limiting not working"
    
    def test_cors_headers(self):
        """Test CORS security headers"""
        response = self.client.options("/api/v1/data")
        
        # Check security headers
        expected_headers = [
            "Access-Control-Allow-Origin",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "X-XSS-Protection"
        ]
        
        for header in expected_headers:
            assert header in response.headers, f"Missing security header: {header}"
        
        # Verify secure values
        assert response.headers.get("X-Frame-Options") == "DENY"
        assert response.headers.get("X-Content-Type-Options") == "nosniff"
    
    def test_sensitive_data_exposure(self):
        """Test that sensitive data is not exposed"""
        # Test error responses don't expose sensitive info
        response = self.client.get("/api/v1/nonexistent")
        error_text = response.text.lower()
        
        sensitive_patterns = [
            "password",
            "secret",
            "key",
            "token",
            "database",
            "internal",
            "stacktrace",
            "traceback"
        ]
        
        for pattern in sensitive_patterns:
            assert pattern not in error_text, f"Sensitive data exposed: {pattern}"
    
    def test_input_size_limits(self):
        """Test request size limiting"""
        # Test large payload rejection
        large_payload = {"data": "x" * (10 * 1024 * 1024)}  # 10MB
        
        response = self.client.post("/api/v1/upload", json=large_payload)
        assert response.status_code == 413, "Large payload should be rejected"
    
    def test_path_traversal_protection(self):
        """Test path traversal attack protection"""
        traversal_attempts = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f",
            "....//....//....//",
        ]
        
        for attempt in traversal_attempts:
            response = self.client.get(f"/api/v1/files/{attempt}")
            # Should not access files outside allowed directory
            assert response.status_code in [400, 403, 404]
            assert "passwd" not in response.text.lower()
```

#### Penetration Testing Framework

```python
# tests/security/test_penetration.py
import pytest
import asyncio
import aiohttp
from typing import List, Dict

class PenetrationTester:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.vulnerabilities: List[Dict] = []
    
    async def run_security_scan(self) -> Dict:
        """Run comprehensive security scan"""
        
        tests = [
            self._test_authentication_bypass,
            self._test_authorization_flaws,
            self._test_injection_attacks,
            self._test_broken_authentication,
            self._test_security_misconfigurations,
            self._test_sensitive_data_exposure,
            self._test_xxe_attacks,
            self._test_broken_access_control,
            self._test_security_logging_failures,
            self._test_server_side_request_forgery
        ]
        
        async with aiohttp.ClientSession() as session:
            for test in tests:
                try:
                    await test(session)
                except Exception as e:
                    self.vulnerabilities.append({
                        "test": test.__name__,
                        "severity": "ERROR",
                        "description": f"Test failed with error: {str(e)}"
                    })
        
        return self._generate_report()
    
    async def _test_authentication_bypass(self, session: aiohttp.ClientSession):
        """Test for authentication bypass vulnerabilities"""
        bypass_attempts = [
            {"headers": {"Authorization": "Bearer admin"}},
            {"headers": {"Authorization": "Basic YWRtaW46YWRtaW4="}},  # admin:admin
            {"headers": {"X-User-ID": "1", "X-Role": "admin"}},
            {"params": {"auth": "bypass"}},
        ]
        
        for attempt in bypass_attempts:
            async with session.get(
                f"{self.base_url}/api/v1/admin/users",
                **attempt
            ) as response:
                if response.status == 200:
                    self.vulnerabilities.append({
                        "test": "authentication_bypass",
                        "severity": "CRITICAL",
                        "description": f"Authentication bypass possible with: {attempt}",
                        "evidence": await response.text()
                    })
    
    async def _test_injection_attacks(self, session: aiohttp.ClientSession):
        """Test for various injection vulnerabilities"""
        payloads = {
            "sql": ["' OR '1'='1", "'; DROP TABLE users; --", "1' UNION SELECT * FROM sensitive_data --"],
            "nosql": ["'; return true; //", "{$gt: ''}", "'; return this.password.match(/.*/) //"],
            "ldap": ["*)(uid=*))(|(uid=*", "admin)(&(password=*)", "*)(|(password=*)"],
            "xpath": ["' or '1'='1", "'] | //user/*[contains(*,'admin')] | ['"],
            "command": ["; cat /etc/passwd", "| whoami", "&& dir", "; ls -la"],
        }
        
        endpoints = ["/api/v1/search", "/api/v1/filter", "/api/v1/query"]
        
        for endpoint in endpoints:
            for injection_type, injection_payloads in payloads.items():
                for payload in injection_payloads:
                    async with session.get(
                        f"{self.base_url}{endpoint}",
                        params={"q": payload}
                    ) as response:
                        response_text = await response.text()
                        
                        # Check for injection success indicators
                        if self._check_injection_success(injection_type, response_text, response.status):
                            self.vulnerabilities.append({
                                "test": f"{injection_type}_injection",
                                "severity": "HIGH",
                                "description": f"{injection_type.upper()} injection vulnerability in {endpoint}",
                                "payload": payload,
                                "evidence": response_text[:500]
                            })
    
    def _check_injection_success(self, injection_type: str, response_text: str, status_code: int) -> bool:
        """Check if injection attack was successful"""
        indicators = {
            "sql": ["mysql", "postgresql", "sqlite", "syntax error", "mysql_", "ORA-"],
            "nosql": ["MongoError", "CastError", "ValidationError"],
            "ldap": ["ldap", "distinguished name", "invalid dn"],
            "xpath": ["XPathException", "Invalid expression"],
            "command": ["root:", "etc/passwd", "Directory of", "total "],
        }
        
        if status_code == 500:  # Internal server error might indicate successful injection
            return True
        
        response_lower = response_text.lower()
        for indicator in indicators.get(injection_type, []):
            if indicator.lower() in response_lower:
                return True
        
        return False
    
    def _generate_report(self) -> Dict:
        """Generate security scan report"""
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "ERROR": 0}
        
        for vuln in self.vulnerabilities:
            severity = vuln.get("severity", "UNKNOWN")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            "total_vulnerabilities": len(self.vulnerabilities),
            "severity_breakdown": severity_counts,
            "vulnerabilities": self.vulnerabilities,
            "security_score": self._calculate_security_score(severity_counts),
            "recommendations": self._generate_recommendations()
        }
    
    def _calculate_security_score(self, severity_counts: Dict) -> float:
        """Calculate security score (0-100)"""
        weights = {"CRITICAL": -50, "HIGH": -20, "MEDIUM": -5, "LOW": -1, "INFO": 0, "ERROR": -2}
        
        score = 100
        for severity, count in severity_counts.items():
            score += weights.get(severity, 0) * count
        
        return max(0, min(100, score))
    
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if any(v["severity"] == "CRITICAL" for v in self.vulnerabilities):
            recommendations.append("URGENT: Critical vulnerabilities found. Fix immediately before production deployment.")
        
        if any("injection" in v["test"] for v in self.vulnerabilities):
            recommendations.append("Implement parameterized queries and input validation to prevent injection attacks.")
        
        if any("authentication" in v["test"] for v in self.vulnerabilities):
            recommendations.append("Review and strengthen authentication mechanisms.")
        
        return recommendations

# Penetration test cases
class TestPenetrationTesting:
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_comprehensive_security_scan(self):
        """Run comprehensive penetration testing"""
        tester = PenetrationTester("http://localhost:8000")
        report = await tester.run_security_scan()
        
        # Security assertions
        assert report["severity_breakdown"]["CRITICAL"] == 0, "Critical vulnerabilities found"
        assert report["severity_breakdown"]["HIGH"] <= 2, "Too many high-severity vulnerabilities"
        assert report["security_score"] >= 80, f"Security score too low: {report['security_score']}"
        
        # Log findings for review
        if report["total_vulnerabilities"] > 0:
            print("\nSecurity Scan Results:")
            print(f"Total vulnerabilities: {report['total_vulnerabilities']}")
            print(f"Security score: {report['security_score']}")
            
            for vuln in report["vulnerabilities"]:
                print(f"- {vuln['severity']}: {vuln['description']}")
```

### 5. Chaos Testing

#### **Coverage Target**: Critical failure scenarios  
**Priority**: MEDIUM

```python
# tests/chaos/test_chaos.py
import pytest
import asyncio
import random
import time
from contextlib import asynccontextmanager
from app.main import app
from fastapi.testclient import TestClient

class ChaosTestRunner:
    def __init__(self):
        self.failures: List[Dict] = []
        self.client = TestClient(app)
    
    @asynccontextmanager
    async def simulate_service_failure(self, service_name: str, failure_rate: float = 1.0):
        """Simulate service failure"""
        # Implementation would integrate with service discovery to mark service as failed
        try:
            yield
        finally:
            # Restore service
            pass
    
    @asynccontextmanager
    async def simulate_network_latency(self, delay_ms: int):
        """Simulate network latency"""
        # Implementation would add artificial delays to network calls
        try:
            yield
        finally:
            pass
    
    async def test_service_failure_resilience(self):
        """Test system resilience to service failures"""
        # Simulate random service failures
        services = ["service-1", "service-2", "service-3"]
        
        for service in services:
            async with self.simulate_service_failure(service):
                # System should continue operating
                response = self.client.get("/health")
                assert response.status_code == 200
                
                # Other services should still work
                response = self.client.get("/api/v1/available-services")
                assert response.status_code == 200
    
    async def test_high_latency_tolerance(self):
        """Test system behavior under high latency"""
        async with self.simulate_network_latency(5000):  # 5 second delay
            start_time = time.time()
            response = self.client.get("/api/v1/data", timeout=10)
            end_time = time.time()
            
            # Should handle latency gracefully
            assert response.status_code in [200, 504]  # Success or Gateway Timeout
            assert end_time - start_time < 10  # Should not hang indefinitely

class TestChaosEngineering:
    
    @pytest.mark.chaos
    @pytest.mark.asyncio
    async def test_random_service_failures(self):
        """Test random service failure scenarios"""
        runner = ChaosTestRunner()
        await runner.test_service_failure_resilience()
    
    @pytest.mark.chaos  
    @pytest.mark.asyncio
    async def test_network_partition_tolerance(self):
        """Test network partition tolerance"""
        runner = ChaosTestRunner()
        await runner.test_high_latency_tolerance()
```

## 📊 Testing Metrics & Coverage

### Coverage Targets by Category

| Test Category | Current | Target | Priority |
|---------------|---------|--------|----------|
| Unit Tests | ~70% | 90%+ | HIGH |
| Integration Tests | ~40% | 80%+ | HIGH |
| Security Tests | 0% | 100% | CRITICAL |
| Performance Tests | 0% | 80%+ | HIGH |
| Chaos Tests | 0% | 60%+ | MEDIUM |

### Quality Gates

#### Pre-commit Checks
- [ ] Unit test coverage ≥ 90%
- [ ] All tests passing
- [ ] Code linting passed
- [ ] Security scan passed

#### Pre-deployment Checks
- [ ] Integration tests passed
- [ ] Performance benchmarks met
- [ ] Security tests passed
- [ ] Load testing completed

#### Production Readiness
- [ ] Chaos testing passed
- [ ] End-to-end testing passed
- [ ] Security penetration testing passed
- [ ] Performance stress testing passed

## 🔧 Testing Infrastructure

### Test Environment Setup

```yaml
# docker-compose.test.yml
version: '3.8'
services:
  api-gateway:
    build: .
    ports:
      - "8000:8000"
    environment:
      - ENV=testing
      - DATABASE_URL=sqlite:///test.db
    depends_on:
      - redis
      - test-service-1
      - test-service-2

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

  test-service-1:
    image: httpbin/httpbin
    ports:
      - "8081:80"

  test-service-2:
    image: httpbin/httpbin
    ports:
      - "8082:80"

  prometheus:
    image: prom/prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./tests/config/prometheus.yml:/etc/prometheus/prometheus.yml

  jaeger:
    image: jaegertracing/all-in-one
    ports:
      - "16686:16686"
      - "14268:14268"
```

### CI/CD Integration

```yaml
# .github/workflows/test.yml
name: Testing Pipeline

on: [push, pull_request]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
        with:
          python-version: '3.13'
      - name: Install dependencies
        run: |
          pip install -r requirements/test.txt
      - name: Run unit tests
        run: |
          pytest tests/unit/ --cov=app --cov-report=xml
      - name: Upload coverage
        uses: codecov/codecov-action@v1

  integration-tests:
    runs-on: ubuntu-latest
    services:
      redis:
        image: redis
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    steps:
      - uses: actions/checkout@v2
      - name: Run integration tests
        run: |
          docker-compose -f docker-compose.test.yml up -d
          pytest tests/integration/
          docker-compose -f docker-compose.test.yml down

  security-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run security tests
        run: |
          pytest tests/security/
      - name: OWASP ZAP Scan
        uses: zaproxy/action-baseline@v0.4.0
        with:
          target: 'http://localhost:8000'

  performance-tests:
    runs-on: ubuntu-latest
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v2
      - name: Run performance tests
        run: |
          pytest tests/performance/ --benchmark-only
```

## 📋 Testing Schedule

### Daily Testing (Automated)
- Unit tests on every commit
- Integration tests on PR creation
- Security scans on code changes
- Smoke tests on deployments

### Weekly Testing (Automated)
- Full integration test suite
- Performance regression tests
- Security penetration testing
- Dependency vulnerability scans

### Monthly Testing (Manual + Automated)
- Comprehensive chaos testing
- End-to-end scenario testing
- Security audit and review
- Performance benchmarking

### Quarterly Testing (Manual)
- External security assessment
- Load testing with production data
- Disaster recovery testing
- Compliance testing

This comprehensive testing strategy ensures high code quality, security, and performance while enabling rapid development and deployment cycles.

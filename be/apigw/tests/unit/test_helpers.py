"""Unit tests for utility helper functions."""

import pytest
from urllib.parse import urljoin

from app.utils.helpers import (
    extract_service_from_path,
    build_upstream_url,
    normalize_path,
    match_path_pattern,
    sanitize_header_value,
    is_valid_url,
    extract_host_port,
    merge_query_params,
    calculate_weight_distribution,
    format_bytes,
    truncate_string
)


"""Unit tests for utility helper functions."""

import pytest
from urllib.parse import urljoin

from app.utils.helpers import (
    extract_service_from_path,
    build_upstream_url,
    normalize_path,
    match_path_pattern,
    sanitize_header_value,
    is_valid_url,
    extract_host_port,
    merge_query_params,
    calculate_weight_distribution,
    format_bytes,
    truncate_string
)


class TestPathHelpers:
    """Test cases for path manipulation helper functions."""
    
    def test_extract_service_from_path(self):
        """Test extracting service name from request path."""
        test_cases = [
            ("/user-service/api/users", ("user-service", "api/users")),
            ("/order-service/orders/123", ("order-service", "orders/123")),
            ("/payment-api/payments", ("payment-api", "payments")),
            ("/api/v2/health", ("api", "v2/health")),
            ("/service", ("service", "")),
            ("/", ("", "")),
            ("", ("", "")),
        ]
        
        for path, expected_result in test_cases:
            result = extract_service_from_path(path)
            assert result == expected_result, f"Failed for path: {path}"
    
    def test_build_upstream_url(self):
        """Test building upstream URL from components."""
        test_cases = [
            ("http://service:8080", "api/users", "", "http://service:8080/api/users"),
            ("https://api.example.com", "v1/charge", "", "https://api.example.com/v1/charge"),
            ("http://localhost:3000", "health", "", "http://localhost:3000/health"),
            ("http://service:8080/", "profile", "", "http://service:8080/profile"),
            ("http://api.test.com", "", "", "http://api.test.com"),
            ("http://service:8080", "users", "limit=10", "http://service:8080/users?limit=10"),
        ]
        
        for base_url, path, query, expected_url in test_cases:
            result = build_upstream_url(base_url, path, query)
            assert result == expected_url, f"Failed for {base_url} + {path} + {query}"
    
    def test_normalize_path(self):
        """Test path normalization functionality."""
        test_cases = [
            ("/api/users", "/api/users"),
            ("api/users", "/api/users"),
            ("/api//users", "/api/users"),
            ("/api/users/", "/api/users"),
            ("//api///users//", "/api/users"),
            ("/", "/"),
            ("", "/"),
        ]
        
        for input_path, expected_clean in test_cases:
            result = normalize_path(input_path)
            assert result == expected_clean, f"Failed for path: {input_path}"
    
    def test_match_path_pattern(self):
        """Test path pattern matching."""
        test_cases = [
            ("/api/*", "/api/users", True),
            ("/api/*", "/api/users/123", True),
            ("/api/v*/users", "/api/v1/users", True),
            ("/api/v*/users", "/api/v2/users", True),
            ("/api/users", "/api/users", True),
            ("/api/users", "/api/orders", False),
            ("*/health", "/service/health", True),
            ("*/health", "/health", True),
            ("/exact/path", "/exact/path", True),
            ("/exact/path", "/different/path", False),
        ]
        
        for pattern, path, expected_match in test_cases:
            result = match_path_pattern(pattern, path)
            assert result == expected_match, f"Pattern {pattern} with path {path}"


class TestHeaderHelpers:
    """Test cases for header manipulation helper functions."""
    
    def test_sanitize_header_value(self):
        """Test header value sanitization."""
        test_cases = [
            ("normal value", "normal value"),
            ("value\nwith\rcontrol\tchars", "value\nwith\rcontrol\tchars"),  # Allowed control chars
            ("value\x00with\x01bad\x1fchars", "valuewithbadchars"),  # Remove bad control chars
            ("  spaced value  ", "spaced value"),  # Trim spaces
            ("", ""),
            ("   ", ""),
        ]
        
        for input_value, expected_output in test_cases:
            result = sanitize_header_value(input_value)
            assert result == expected_output, f"Failed for: '{input_value}'"


class TestUrlHelpers:
    """Test cases for URL-related helper functions."""
    
    def test_is_valid_url(self):
        """Test URL validation."""
        valid_urls = [
            "http://example.com",
            "https://api.example.com",
            "http://localhost:8080",
            "https://service.internal.com:8443",
            "ftp://files.example.com"
        ]
        
        for url in valid_urls:
            assert is_valid_url(url), f"Should be valid: {url}"
        
        invalid_urls = [
            "not-a-url",
            "http://",
            "://example.com",
            "",
            "example.com",  # Missing scheme
        ]
        
        for url in invalid_urls:
            assert not is_valid_url(url), f"Should be invalid: {url}"
    
    def test_extract_host_port(self):
        """Test extracting host and port from URLs."""
        test_cases = [
            ("http://example.com", ("example.com", 80)),
            ("https://example.com", ("example.com", 443)),
            ("http://example.com:8080", ("example.com", 8080)),
            ("https://api.example.com:8443", ("api.example.com", 8443)),
            ("http://localhost:3000", ("localhost", 3000)),
        ]
        
        for url, expected_result in test_cases:
            result = extract_host_port(url)
            assert result == expected_result, f"Failed for URL: {url}"
    
    def test_merge_query_params(self):
        """Test merging query parameters."""
        # Test merging with existing params
        existing = "page=1&limit=10"
        additional = {"filter": "active", "sort": "name"}
        result = merge_query_params(existing, additional)
        
        # Should contain all parameters
        assert "page=1" in result
        assert "limit=10" in result
        assert "filter=active" in result
        assert "sort=name" in result
        
        # Test with empty existing
        result2 = merge_query_params("", {"test": "value"})
        assert "test=value" in result2
        
        # Test with no additional params
        result3 = merge_query_params("existing=value", {})
        assert result3 == "existing=value"


class TestUtilityHelpers:
    """Test cases for utility helper functions."""
    
    def test_calculate_weight_distribution(self):
        """Test weight distribution calculation."""
        class MockInstance:
            def __init__(self, id, weight):
                self.id = id
                self.weight = weight
        
        instances = [
            MockInstance("inst1", 1),
            MockInstance("inst2", 2),
            MockInstance("inst3", 1),
        ]
        
        result = calculate_weight_distribution(instances)
        
        assert result["inst1"] == 0.25  # 1/4
        assert result["inst2"] == 0.5   # 2/4
        assert result["inst3"] == 0.25  # 1/4
        
        # Test with empty list
        empty_result = calculate_weight_distribution([])
        assert empty_result == {}
    
    def test_format_bytes(self):
        """Test byte formatting."""
        test_cases = [
            (0, "0 B"),
            (1024, "1.0 KB"),
            (1048576, "1.0 MB"),
            (1073741824, "1.0 GB"),
            (1536, "1.5 KB"),  # 1.5 KB
            (500, "500.0 B"),
        ]
        
        for bytes_value, expected_format in test_cases:
            result = format_bytes(bytes_value)
            assert result == expected_format, f"Failed for bytes: {bytes_value}"
    
    def test_truncate_string(self):
        """Test string truncation."""
        # Test normal truncation
        long_text = "This is a very long string that should be truncated"
        result = truncate_string(long_text, 20)
        assert len(result) == 20
        assert result.endswith("...")
        
        # Test short string (no truncation)
        short_text = "Short"
        result = truncate_string(short_text, 20)
        assert result == short_text
        
        # Test with custom suffix
        result = truncate_string(long_text, 20, " [more]")
        assert len(result) == 20
        assert result.endswith(" [more]")
        
        # Test empty string
        result = truncate_string("", 10)
        assert result == ""

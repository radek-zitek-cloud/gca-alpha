"""
Utility helper functions for the API Gateway.

This module provides common utility functions used throughout the gateway.
"""

import re
from typing import Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode


def extract_service_from_path(path: str) -> Tuple[str, str]:
    """
    Extract service name and remaining path from a request path.
    
    Args:
        path: The request path (e.g., "/api/v1/users/123")
        
    Returns:
        Tuple of (service_name, remaining_path)
        
    Examples:
        "/api/v1/users/123" -> ("api", "v1/users/123")
        "/user-service/profile" -> ("user-service", "profile")
        "/health" -> ("health", "")
    """
    # Remove leading slash
    path = path.lstrip('/')
    
    if not path:
        return "", ""
    
    # Split on first slash
    parts = path.split('/', 1)
    service_name = parts[0]
    remaining_path = parts[1] if len(parts) > 1 else ""
    
    return service_name, remaining_path


def build_upstream_url(base_url: str, path: str, query_string: str = "") -> str:
    """
    Build the complete upstream URL from base URL, path, and query string.
    
    Args:
        base_url: Base URL of the upstream service
        path: Path to append to the base URL
        query_string: Query string to append
        
    Returns:
        Complete upstream URL
        
    Examples:
        ("http://api.example.com", "users/123", "limit=10") 
        -> "http://api.example.com/users/123?limit=10"
    """
    # Ensure base_url doesn't end with slash and path doesn't start with slash
    base_url = base_url.rstrip('/')
    path = path.lstrip('/') if path else ""
    
    # Build the URL
    if path:
        url = f"{base_url}/{path}"
    else:
        url = base_url
    
    # Add query string if present
    if query_string:
        separator = "&" if "?" in url else "?"
        url = f"{url}{separator}{query_string}"
    
    return url


def normalize_path(path: str) -> str:
    """
    Normalize a URL path by removing double slashes and trailing slashes.
    
    Args:
        path: Path to normalize
        
    Returns:
        Normalized path
    """
    if not path:
        return "/"
    
    # Remove double slashes
    path = re.sub(r'/+', '/', path)
    
    # Ensure starts with slash
    if not path.startswith('/'):
        path = '/' + path
    
    # Remove trailing slash unless it's just "/"
    if len(path) > 1 and path.endswith('/'):
        path = path.rstrip('/')
    
    return path


def match_path_pattern(pattern: str, path: str) -> bool:
    """
    Check if a path matches a pattern (supports wildcards and regex).
    
    Args:
        pattern: Pattern to match against (supports * wildcards)
        path: Path to check
        
    Returns:
        True if path matches pattern
        
    Examples:
        match_path_pattern("/api/*", "/api/users") -> True
        match_path_pattern("/api/v*/users", "/api/v1/users") -> True
    """
    # Convert wildcard pattern to regex
    regex_pattern = pattern.replace('*', '.*')
    
    # Escape special regex characters except * which we already handled
    special_chars = ['.', '^', '$', '+', '?', '{', '}', '[', ']', '|', '(', ')']
    for char in special_chars:
        if char != '.':  # We want to keep . for .* wildcard
            regex_pattern = regex_pattern.replace(char, '\\' + char)
    
    # Add anchors to match the entire string
    regex_pattern = f"^{regex_pattern}$"
    
    try:
        return bool(re.match(regex_pattern, path))
    except re.error:
        # If regex is invalid, fall back to exact match
        return pattern == path


def sanitize_header_value(value: str) -> str:
    """
    Sanitize header value by removing control characters.
    
    Args:
        value: Header value to sanitize
        
    Returns:
        Sanitized header value
    """
    if not value:
        return ""
    
    # Remove control characters but keep printable characters
    sanitized = ''.join(char for char in value if ord(char) >= 32 or char in '\t\n\r')
    
    return sanitized.strip()


def is_valid_url(url: str) -> bool:
    """
    Check if a URL is valid.
    
    Args:
        url: URL to validate
        
    Returns:
        True if URL is valid
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def extract_host_port(url: str) -> Tuple[str, Optional[int]]:
    """
    Extract host and port from a URL.
    
    Args:
        url: URL to parse
        
    Returns:
        Tuple of (host, port) where port may be None for default ports
    """
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port
        
        # Use default ports if not specified
        if port is None:
            if parsed.scheme == 'http':
                port = 80
            elif parsed.scheme == 'https':
                port = 443
        
        return host, port
    except Exception:
        return "", None


def merge_query_params(existing: str, additional: dict) -> str:
    """
    Merge additional query parameters with existing query string.
    
    Args:
        existing: Existing query string
        additional: Additional parameters to merge
        
    Returns:
        Merged query string
    """
    if not additional:
        return existing
    
    # Parse existing parameters
    params = parse_qs(existing, keep_blank_values=True)
    
    # Add additional parameters
    for key, value in additional.items():
        if isinstance(value, list):
            params[key] = value
        else:
            params[key] = [str(value)]
    
    # Rebuild query string
    return urlencode(params, doseq=True)


def calculate_weight_distribution(instances: list) -> dict:
    """
    Calculate weight distribution for weighted load balancing.
    
    Args:
        instances: List of instances with weight attribute
        
    Returns:
        Dictionary mapping instance ID to selection probability
    """
    total_weight = sum(getattr(instance, 'weight', 1) for instance in instances)
    
    if total_weight == 0:
        # Equal distribution if all weights are 0
        weight_per_instance = 1.0 / len(instances) if instances else 0
        return {getattr(instance, 'id', str(i)): weight_per_instance 
                for i, instance in enumerate(instances)}
    
    return {
        getattr(instance, 'id', str(i)): getattr(instance, 'weight', 1) / total_weight
        for i, instance in enumerate(instances)
    }


def format_bytes(bytes_value: int) -> str:
    """
    Format bytes value in human readable format.
    
    Args:
        bytes_value: Number of bytes
        
    Returns:
        Formatted string (e.g., "1.2 MB")
    """
    if bytes_value == 0:
        return "0 B"
    
    units = ["B", "KB", "MB", "GB", "TB"]
    unit_index = 0
    
    value = float(bytes_value)
    while value >= 1024 and unit_index < len(units) - 1:
        value /= 1024
        unit_index += 1
    
    return f"{value:.1f} {units[unit_index]}"


def truncate_string(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """
    Truncate a string to a maximum length.
    
    Args:
        text: Text to truncate
        max_length: Maximum length including suffix
        suffix: Suffix to add when truncating
        
    Returns:
        Truncated string
    """
    if not text or len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix

"""
Path matching utilities for the API Gateway.

This module provides advanced path matching capabilities including
wildcard patterns, regex matching, and parameter extraction.
"""

import re
from typing import Dict, List, Optional, Any, Pattern, Tuple
from dataclasses import dataclass

from app.config import get_logger

logger = get_logger(__name__)


@dataclass
class PathMatch:
    """Result of a path matching operation."""
    matched: bool
    service_name: Optional[str] = None
    remaining_path: Optional[str] = None
    parameters: Optional[Dict[str, str]] = None
    match_score: int = 0  # Higher score = more specific match
    
    def __post_init__(self):
        if self.parameters is None:
            self.parameters = {}


@dataclass
class PathPattern:
    """A path pattern for matching requests."""
    pattern: str
    service_name: str
    regex: Optional[Pattern] = None
    parameter_names: Optional[List[str]] = None
    priority: int = 100
    
    def __post_init__(self):
        """Compile the pattern and extract parameter names."""
        self.parameter_names = []
        self.regex = self._compile_pattern()
    
    def _compile_pattern(self) -> Pattern:
        """
        Compile a path pattern to a regex.
        
        Supports:
        - Wildcards: /api/* matches /api/anything
        - Parameters: /api/{user_id} captures user_id parameter
        - Multiple parameters: /api/{user_id}/posts/{post_id}
        - Exact matches: /api/health
        """
        # Escape regex special characters except our own
        escaped = re.escape(self.pattern)
        
        # Replace escaped wildcards with regex
        escaped = escaped.replace(r'\*', '([^/]*)')
        escaped = escaped.replace(r'\*\*', '(.*)')
        
        # Replace parameter placeholders with named groups
        param_pattern = r'\\{([^}]+)\\}'
        
        def replace_param(match):
            param_name = match.group(1)
            self.parameter_names.append(param_name)
            return f'(?P<{param_name}>[^/]+)'
        
        escaped = re.sub(param_pattern, replace_param, escaped)
        
        # Anchor the pattern
        pattern_str = f'^{escaped}(/.*)?$'
        
        return re.compile(pattern_str)


class PathMatcher:
    """
    Advanced path matcher that supports multiple pattern types.
    """
    
    def __init__(self):
        """Initialize the path matcher."""
        self._patterns: List[PathPattern] = []
        self._exact_matches: Dict[str, str] = {}  # path -> service_name
    
    def add_pattern(
        self,
        pattern: str,
        service_name: str,
        priority: int = 100
    ):
        """
        Add a path pattern for matching.
        
        Args:
            pattern: Path pattern (supports wildcards and parameters)
            service_name: Target service name
            priority: Pattern priority (lower = higher priority)
        """
        path_pattern = PathPattern(
            pattern=pattern,
            service_name=service_name,
            priority=priority
        )
        
        # Check if it's an exact match pattern
        if '*' not in pattern and '{' not in pattern:
            self._exact_matches[pattern] = service_name
        
        self._patterns.append(path_pattern)
        
        # Sort patterns by priority
        self._patterns.sort(key=lambda p: p.priority)
        
        logger.debug(
            f"Added path pattern",
            extra={
                "pattern": pattern,
                "service_name": service_name,
                "priority": priority,
                "has_parameters": bool(path_pattern.parameter_names)
            }
        )
    
    def remove_pattern(self, pattern: str) -> bool:
        """
        Remove a path pattern.
        
        Args:
            pattern: Pattern to remove
            
        Returns:
            True if pattern was removed, False if not found
        """
        for i, path_pattern in enumerate(self._patterns):
            if path_pattern.pattern == pattern:
                removed = self._patterns.pop(i)
                
                # Remove from exact matches if present
                if pattern in self._exact_matches:
                    del self._exact_matches[pattern]
                
                logger.debug(f"Removed path pattern {pattern}")
                return True
        
        return False
    
    def match(self, path: str) -> PathMatch:
        """
        Match a path against all patterns.
        
        Args:
            path: Request path to match
            
        Returns:
            PathMatch result with best match
        """
        # Quick exact match check first
        if path in self._exact_matches:
            return PathMatch(
                matched=True,
                service_name=self._exact_matches[path],
                remaining_path="",
                match_score=1000  # Exact matches get highest score
            )
        
        best_match = PathMatch(matched=False)
        
        for pattern in self._patterns:
            match = pattern.regex.match(path)
            if match:
                # Calculate match score (more specific = higher score)
                score = self._calculate_match_score(pattern, match)
                
                if score > best_match.match_score:
                    # Extract parameters
                    parameters = {}
                    for param_name in pattern.parameter_names:
                        if param_name in match.groupdict():
                            parameters[param_name] = match.group(param_name)
                    
                    # Calculate remaining path
                    remaining_path = ""
                    if match.lastindex and match.lastindex >= 1:
                        # Get the last captured group (remaining path)
                        last_group = match.group(match.lastindex)
                        if last_group and last_group.startswith('/'):
                            remaining_path = last_group[1:]  # Remove leading slash
                    
                    best_match = PathMatch(
                        matched=True,
                        service_name=pattern.service_name,
                        remaining_path=remaining_path,
                        parameters=parameters,
                        match_score=score
                    )
        
        if best_match.matched:
            logger.debug(
                f"Path matched",
                extra={
                    "path": path,
                    "service_name": best_match.service_name,
                    "remaining_path": best_match.remaining_path,
                    "parameters": best_match.parameters,
                    "match_score": best_match.match_score
                }
            )
        else:
            logger.debug(f"No pattern matched path: {path}")
        
        return best_match
    
    def _calculate_match_score(self, pattern: PathPattern, match: re.Match) -> int:
        """
        Calculate a score for how specific/good a match is.
        
        Higher scores indicate more specific matches.
        """
        score = 100  # Base score
        
        # Exact patterns get higher scores
        if '*' not in pattern.pattern and '{' not in pattern.pattern:
            score += 500
        
        # Fewer wildcards = higher score
        wildcard_count = pattern.pattern.count('*')
        score -= wildcard_count * 50
        
        # Fewer parameters = higher score (more specific)
        param_count = len(pattern.parameter_names)
        score -= param_count * 25
        
        # Longer patterns are generally more specific
        score += len(pattern.pattern)
        
        # Higher priority patterns get preference
        score += (1000 - pattern.priority)
        
        return score
    
    def list_patterns(self) -> List[Tuple[str, str, int]]:
        """
        List all registered patterns.
        
        Returns:
            List of tuples (pattern, service_name, priority)
        """
        return [
            (p.pattern, p.service_name, p.priority)
            for p in self._patterns
        ]
    
    def clear_patterns(self):
        """Clear all patterns."""
        self._patterns.clear()
        self._exact_matches.clear()
        logger.debug("Cleared all path patterns")


class ServicePathExtractor:
    """
    Utility class for extracting service names and paths from URLs.
    """
    
    @staticmethod
    def extract_from_path(path: str) -> Tuple[Optional[str], str]:
        """
        Extract service name from path using common conventions.
        
        Examples:
        - /api/user-service/users -> ("user-service", "users")
        - /user-service/profile -> ("user-service", "profile")
        - /v1/orders/123 -> ("orders", "123")
        
        Args:
            path: Request path
            
        Returns:
            Tuple of (service_name, remaining_path)
        """
        # Remove leading slash
        path = path.lstrip('/')
        
        if not path:
            return None, ""
        
        # Split into parts
        parts = path.split('/')
        
        # Strategy 1: Look for service-like names (containing hyphens)
        for i, part in enumerate(parts):
            if '-' in part and part.endswith('-service'):
                service_name = part
                remaining_path = '/'.join(parts[i+1:])
                return service_name, remaining_path
        
        # Strategy 2: Look for service names ending with 'service'
        for i, part in enumerate(parts):
            if part.endswith('service'):
                service_name = part
                remaining_path = '/'.join(parts[i+1:])
                return service_name, remaining_path
        
        # Strategy 3: Skip common prefixes and take first part
        skip_prefixes = {'api', 'v1', 'v2', 'v3'}
        for i, part in enumerate(parts):
            if part.lower() not in skip_prefixes:
                service_name = part
                remaining_path = '/'.join(parts[i+1:])
                return service_name, remaining_path
        
        # Strategy 4: Just take the first part
        if parts:
            return parts[0], '/'.join(parts[1:])
        
        return None, ""
    
    @staticmethod
    def build_upstream_path(
        base_path: str,
        remaining_path: str,
        remove_prefix: Optional[str] = None
    ) -> str:
        """
        Build the upstream service path.
        
        Args:
            base_path: Base path for the service
            remaining_path: Remaining path from routing
            remove_prefix: Optional prefix to remove from remaining path
            
        Returns:
            Complete upstream path
        """
        # Start with base path
        upstream_path = base_path.rstrip('/')
        
        # Process remaining path
        if remaining_path:
            # Remove prefix if specified
            if remove_prefix and remaining_path.startswith(remove_prefix):
                remaining_path = remaining_path[len(remove_prefix):]
            
            # Ensure remaining path starts with /
            if remaining_path and not remaining_path.startswith('/'):
                remaining_path = '/' + remaining_path
            
            upstream_path += remaining_path
        
        # Ensure path starts with /
        if not upstream_path.startswith('/'):
            upstream_path = '/' + upstream_path
        
        return upstream_path


# Global path matcher instance
path_matcher = PathMatcher()

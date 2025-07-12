"""
Routing rules engine for the API Gateway.

This module provides flexible routing rules that can be configured
to determine how requests are mapped to upstream services.
"""

import re
from typing import Dict, List, Optional, Any, Pattern
from dataclasses import dataclass
from enum import Enum

from app.config import get_logger

logger = get_logger(__name__)


class MatchType(Enum):
    """Types of routing rule matches."""
    EXACT = "exact"           # Exact path match
    PREFIX = "prefix"         # Path prefix match
    REGEX = "regex"           # Regular expression match
    HEADER = "header"         # Header-based match
    QUERY = "query"           # Query parameter match
    METHOD = "method"         # HTTP method match


@dataclass
class RoutingCondition:
    """A single routing condition."""
    type: MatchType
    field: str              # Path, header name, query param name, etc.
    value: str              # Value to match against
    case_sensitive: bool = True
    negate: bool = False    # Whether to negate the match
    
    def __post_init__(self):
        """Compile regex patterns if needed."""
        if self.type == MatchType.REGEX:
            flags = 0 if self.case_sensitive else re.IGNORECASE
            self._regex_pattern: Pattern = re.compile(self.value, flags)


@dataclass
class RoutingAction:
    """Action to take when routing conditions match."""
    service_name: str
    path_rewrite: Optional[str] = None     # Rewrite the path before forwarding
    add_headers: Optional[Dict[str, str]] = None    # Headers to add
    remove_headers: Optional[List[str]] = None      # Headers to remove
    timeout_override: Optional[float] = None        # Override service timeout
    priority: int = 100                   # Rule priority (lower = higher priority)
    
    def __post_init__(self):
        if self.add_headers is None:
            self.add_headers = {}
        if self.remove_headers is None:
            self.remove_headers = []


@dataclass
class RoutingRule:
    """Complete routing rule with conditions and actions."""
    id: str
    name: str
    description: str
    conditions: List[RoutingCondition]
    action: RoutingAction
    enabled: bool = True
    
    def matches(self, request_context: Dict[str, Any]) -> bool:
        """
        Check if this rule matches the given request context.
        
        Args:
            request_context: Dictionary containing request information
            
        Returns:
            True if all conditions match, False otherwise
        """
        if not self.enabled:
            return False
        
        for condition in self.conditions:
            if not self._evaluate_condition(condition, request_context):
                return False
        
        return True
    
    def _evaluate_condition(self, condition: RoutingCondition, context: Dict[str, Any]) -> bool:
        """Evaluate a single condition against the request context."""
        try:
            if condition.type == MatchType.EXACT:
                path = context.get("path", "")
                match = path == condition.value if condition.case_sensitive else path.lower() == condition.value.lower()
            
            elif condition.type == MatchType.PREFIX:
                path = context.get("path", "")
                if condition.case_sensitive:
                    match = path.startswith(condition.value)
                else:
                    match = path.lower().startswith(condition.value.lower())
            
            elif condition.type == MatchType.REGEX:
                path = context.get("path", "")
                match = bool(condition._regex_pattern.search(path))
            
            elif condition.type == MatchType.HEADER:
                headers = context.get("headers", {})
                header_value = headers.get(condition.field, "")
                if condition.case_sensitive:
                    match = header_value == condition.value
                else:
                    match = header_value.lower() == condition.value.lower()
            
            elif condition.type == MatchType.QUERY:
                query_params = context.get("query_params", {})
                param_value = query_params.get(condition.field, "")
                if condition.case_sensitive:
                    match = param_value == condition.value
                else:
                    match = param_value.lower() == condition.value.lower()
            
            elif condition.type == MatchType.METHOD:
                method = context.get("method", "")
                match = method.upper() == condition.value.upper()
            
            else:
                logger.warning(f"Unknown condition type: {condition.type}")
                match = False
            
            # Apply negation if specified
            if condition.negate:
                match = not match
            
            return match
            
        except Exception as e:
            logger.error(f"Error evaluating routing condition: {e}")
            return False


class RoutingRulesEngine:
    """
    Main routing rules engine that manages and evaluates routing rules.
    """
    
    def __init__(self):
        """Initialize the routing rules engine."""
        self._rules: List[RoutingRule] = []
        self._rules_by_service: Dict[str, List[RoutingRule]] = {}
    
    def add_rule(self, rule: RoutingRule):
        """
        Add a routing rule to the engine.
        
        Args:
            rule: Routing rule to add
        """
        # Remove existing rule with same ID if it exists
        self.remove_rule(rule.id)
        
        # Add the rule
        self._rules.append(rule)
        
        # Index by service name
        service_name = rule.action.service_name
        if service_name not in self._rules_by_service:
            self._rules_by_service[service_name] = []
        self._rules_by_service[service_name].append(rule)
        
        # Sort rules by priority (lower number = higher priority)
        self._rules.sort(key=lambda r: r.action.priority)
        self._rules_by_service[service_name].sort(key=lambda r: r.action.priority)
        
        logger.info(
            f"Added routing rule",
            extra={
                "rule_id": rule.id,
                "rule_name": rule.name,
                "service_name": service_name,
                "priority": rule.action.priority,
                "conditions_count": len(rule.conditions)
            }
        )
    
    def remove_rule(self, rule_id: str) -> bool:
        """
        Remove a routing rule by ID.
        
        Args:
            rule_id: ID of the rule to remove
            
        Returns:
            True if rule was removed, False if not found
        """
        for i, rule in enumerate(self._rules):
            if rule.id == rule_id:
                # Remove from main list
                removed_rule = self._rules.pop(i)
                
                # Remove from service index
                service_name = removed_rule.action.service_name
                if service_name in self._rules_by_service:
                    self._rules_by_service[service_name] = [
                        r for r in self._rules_by_service[service_name] 
                        if r.id != rule_id
                    ]
                    
                    # Clean up empty service entries
                    if not self._rules_by_service[service_name]:
                        del self._rules_by_service[service_name]
                
                logger.info(f"Removed routing rule {rule_id}")
                return True
        
        logger.warning(f"Routing rule {rule_id} not found for removal")
        return False
    
    def get_rule(self, rule_id: str) -> Optional[RoutingRule]:
        """
        Get a routing rule by ID.
        
        Args:
            rule_id: ID of the rule to get
            
        Returns:
            Routing rule if found, None otherwise
        """
        for rule in self._rules:
            if rule.id == rule_id:
                return rule
        return None
    
    def list_rules(self) -> List[RoutingRule]:
        """
        Get all routing rules.
        
        Returns:
            List of all routing rules sorted by priority
        """
        return self._rules.copy()
    
    def list_rules_for_service(self, service_name: str) -> List[RoutingRule]:
        """
        Get all routing rules for a specific service.
        
        Args:
            service_name: Name of the service
            
        Returns:
            List of routing rules for the service
        """
        return self._rules_by_service.get(service_name, []).copy()
    
    def find_matching_rule(self, request_context: Dict[str, Any]) -> Optional[RoutingRule]:
        """
        Find the first routing rule that matches the request context.
        
        Args:
            request_context: Dictionary containing request information
            
        Returns:
            First matching routing rule or None if no match found
        """
        for rule in self._rules:
            if rule.matches(request_context):
                logger.debug(
                    f"Routing rule matched",
                    extra={
                        "rule_id": rule.id,
                        "rule_name": rule.name,
                        "service_name": rule.action.service_name,
                        "path": request_context.get("path", ""),
                        "method": request_context.get("method", "")
                    }
                )
                return rule
        
        logger.debug(
            f"No routing rule matched",
            extra={
                "path": request_context.get("path", ""),
                "method": request_context.get("method", ""),
                "total_rules": len(self._rules)
            }
        )
        return None
    
    def apply_action(self, rule: RoutingRule, request_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply the routing action to modify the request context.
        
        Args:
            rule: Routing rule whose action to apply
            request_context: Original request context
            
        Returns:
            Modified request context
        """
        modified_context = request_context.copy()
        action = rule.action
        
        # Apply path rewrite
        if action.path_rewrite:
            original_path = modified_context.get("path", "")
            # Simple string replacement for now - could be enhanced with regex
            modified_context["path"] = action.path_rewrite
            modified_context["original_path"] = original_path
            
            logger.debug(
                f"Applied path rewrite",
                extra={
                    "rule_id": rule.id,
                    "original_path": original_path,
                    "rewritten_path": action.path_rewrite
                }
            )
        
        # Apply header modifications
        headers = modified_context.get("headers", {}).copy()
        
        # Add headers
        if action.add_headers:
            headers.update(action.add_headers)
            logger.debug(
                f"Added headers",
                extra={
                    "rule_id": rule.id,
                    "added_headers": list(action.add_headers.keys())
                }
            )
        
        # Remove headers
        if action.remove_headers:
            for header_name in action.remove_headers:
                headers.pop(header_name, None)
            logger.debug(
                f"Removed headers",
                extra={
                    "rule_id": rule.id,
                    "removed_headers": action.remove_headers
                }
            )
        
        modified_context["headers"] = headers
        
        # Apply timeout override
        if action.timeout_override:
            modified_context["timeout_override"] = action.timeout_override
        
        # Add routing metadata
        modified_context["routing_rule_id"] = rule.id
        modified_context["target_service"] = action.service_name
        
        return modified_context
    
    def clear_rules(self):
        """Clear all routing rules."""
        self._rules.clear()
        self._rules_by_service.clear()
        logger.info("Cleared all routing rules")
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get statistics about the routing rules.
        
        Returns:
            Dictionary containing rule statistics
        """
        enabled_rules = [r for r in self._rules if r.enabled]
        disabled_rules = [r for r in self._rules if not r.enabled]
        
        services_with_rules = set(rule.action.service_name for rule in self._rules)
        
        return {
            "total_rules": len(self._rules),
            "enabled_rules": len(enabled_rules),
            "disabled_rules": len(disabled_rules),
            "services_with_rules": len(services_with_rules),
            "services": list(services_with_rules)
        }


# Global routing rules engine instance
routing_engine = RoutingRulesEngine()

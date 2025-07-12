"""
Load balancer implementation for the API Gateway.

This module provides different load balancing strategies for distributing
requests across multiple service instances.
"""

import random
import time
from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from enum import Enum

from app.models.service import ServiceInstance, LoadBalancerType
from app.config import get_logger

logger = get_logger(__name__)


class LoadBalancingStrategy(ABC):
    """Abstract base class for load balancing strategies."""
    
    @abstractmethod
    async def select_instance(
        self,
        instances: List[ServiceInstance],
        request_context: Optional[Dict[str, Any]] = None
    ) -> Optional[ServiceInstance]:
        """
        Select an instance from the available instances.
        
        Args:
            instances: List of available service instances
            request_context: Optional request context for decision making
            
        Returns:
            Selected service instance or None if no instances available
        """
        pass


class RoundRobinStrategy(LoadBalancingStrategy):
    """Round-robin load balancing strategy."""
    
    def __init__(self):
        """Initialize round-robin strategy."""
        self._counters: Dict[str, int] = {}
    
    async def select_instance(
        self,
        instances: List[ServiceInstance],
        request_context: Optional[Dict[str, Any]] = None
    ) -> Optional[ServiceInstance]:
        """Select instance using round-robin algorithm."""
        if not instances:
            return None
        
        # Get service name from first instance for counter key
        service_key = f"rr_{instances[0].id.split('-')[0]}"
        
        # Get current counter value
        current = self._counters.get(service_key, 0)
        
        # Select instance and increment counter
        selected = instances[current % len(instances)]
        self._counters[service_key] = current + 1
        
        logger.debug(
            f"Round-robin selected instance",
            extra={
                "strategy": "round_robin",
                "selected_instance": selected.id,
                "total_instances": len(instances),
                "counter": current
            }
        )
        
        return selected


class WeightedRoundRobinStrategy(LoadBalancingStrategy):
    """Weighted round-robin load balancing strategy."""
    
    def __init__(self):
        """Initialize weighted round-robin strategy."""
        self._current_weights: Dict[str, Dict[str, int]] = {}
    
    async def select_instance(
        self,
        instances: List[ServiceInstance],
        request_context: Optional[Dict[str, Any]] = None
    ) -> Optional[ServiceInstance]:
        """Select instance using weighted round-robin algorithm."""
        if not instances:
            return None
        
        # Get service name from first instance for tracking
        service_key = f"wrr_{instances[0].id.split('-')[0]}"
        
        # Initialize current weights if not exists
        if service_key not in self._current_weights:
            self._current_weights[service_key] = {
                instance.id: 0 for instance in instances
            }
        
        current_weights = self._current_weights[service_key]
        
        # Add weights to current weights
        for instance in instances:
            if instance.id not in current_weights:
                current_weights[instance.id] = 0
            current_weights[instance.id] += instance.weight
        
        # Find instance with highest current weight
        selected_instance = None
        max_weight = -1
        
        for instance in instances:
            if current_weights[instance.id] > max_weight:
                max_weight = current_weights[instance.id]
                selected_instance = instance
        
        if selected_instance:
            # Calculate total weight
            total_weight = sum(instance.weight for instance in instances)
            
            # Reduce current weight by total weight
            current_weights[selected_instance.id] -= total_weight
            
            logger.debug(
                f"Weighted round-robin selected instance",
                extra={
                    "strategy": "weighted_round_robin",
                    "selected_instance": selected_instance.id,
                    "instance_weight": selected_instance.weight,
                    "current_weight": current_weights[selected_instance.id],
                    "total_weight": total_weight
                }
            )
        
        return selected_instance


class LeastConnectionsStrategy(LoadBalancingStrategy):
    """Least connections load balancing strategy."""
    
    def __init__(self):
        """Initialize least connections strategy."""
        self._connection_counts: Dict[str, int] = {}
    
    async def select_instance(
        self,
        instances: List[ServiceInstance],
        request_context: Optional[Dict[str, Any]] = None
    ) -> Optional[ServiceInstance]:
        """Select instance with least connections."""
        if not instances:
            return None
        
        # Find instance with minimum connections
        selected_instance = None
        min_connections = float('inf')
        
        for instance in instances:
            connections = self._connection_counts.get(instance.id, 0)
            if connections < min_connections:
                min_connections = connections
                selected_instance = instance
        
        if selected_instance:
            # Increment connection count for selected instance
            self._connection_counts[selected_instance.id] = \
                self._connection_counts.get(selected_instance.id, 0) + 1
            
            logger.debug(
                f"Least connections selected instance",
                extra={
                    "strategy": "least_connections",
                    "selected_instance": selected_instance.id,
                    "connections": self._connection_counts[selected_instance.id]
                }
            )
        
        return selected_instance
    
    def release_connection(self, instance_id: str):
        """Release a connection for an instance."""
        if instance_id in self._connection_counts:
            self._connection_counts[instance_id] = max(
                0, self._connection_counts[instance_id] - 1
            )


class RandomStrategy(LoadBalancingStrategy):
    """Random load balancing strategy."""
    
    async def select_instance(
        self,
        instances: List[ServiceInstance],
        request_context: Optional[Dict[str, Any]] = None
    ) -> Optional[ServiceInstance]:
        """Select random instance."""
        if not instances:
            return None
        
        selected = random.choice(instances)
        
        logger.debug(
            f"Random strategy selected instance",
            extra={
                "strategy": "random",
                "selected_instance": selected.id,
                "total_instances": len(instances)
            }
        )
        
        return selected


class LoadBalancer:
    """Main load balancer class that manages different strategies."""
    
    def __init__(self):
        """Initialize load balancer with available strategies."""
        self._strategies = {
            LoadBalancerType.ROUND_ROBIN: RoundRobinStrategy(),
            LoadBalancerType.WEIGHTED_ROUND_ROBIN: WeightedRoundRobinStrategy(),
            LoadBalancerType.LEAST_CONNECTIONS: LeastConnectionsStrategy(),
            LoadBalancerType.RANDOM: RandomStrategy(),
        }
    
    async def select_instance(
        self,
        instances: List[ServiceInstance],
        strategy: LoadBalancerType = LoadBalancerType.ROUND_ROBIN,
        request_context: Optional[Dict[str, Any]] = None
    ) -> Optional[ServiceInstance]:
        """
        Select an instance using the specified strategy.
        
        Args:
            instances: List of available service instances
            strategy: Load balancing strategy to use
            request_context: Optional request context
            
        Returns:
            Selected service instance or None if no instances available
        """
        # Filter to only healthy instances
        healthy_instances = [instance for instance in instances if instance.healthy]
        
        if not healthy_instances:
            logger.warning(
                f"No healthy instances available for load balancing",
                extra={
                    "total_instances": len(instances),
                    "healthy_instances": 0,
                    "strategy": strategy.value
                }
            )
            return None
        
        # Get the appropriate strategy
        load_balancing_strategy = self._strategies.get(strategy)
        if not load_balancing_strategy:
            logger.warning(
                f"Unknown load balancing strategy, falling back to round-robin",
                extra={"requested_strategy": strategy.value}
            )
            load_balancing_strategy = self._strategies[LoadBalancerType.ROUND_ROBIN]
        
        # Select instance using the strategy
        selected = await load_balancing_strategy.select_instance(
            healthy_instances, request_context
        )
        
        if selected:
            logger.info(
                f"Load balancer selected instance",
                extra={
                    "strategy": strategy.value,
                    "selected_instance": selected.id,
                    "instance_url": selected.url,
                    "instance_weight": selected.weight,
                    "healthy_instances": len(healthy_instances),
                    "total_instances": len(instances)
                }
            )
        
        return selected
    
    def release_connection(self, instance_id: str, strategy: LoadBalancerType):
        """
        Release a connection for strategies that track connections.
        
        Args:
            instance_id: ID of the instance to release connection for
            strategy: Load balancing strategy that was used
        """
        if strategy == LoadBalancerType.LEAST_CONNECTIONS:
            strategy_impl = self._strategies[strategy]
            if hasattr(strategy_impl, 'release_connection'):
                strategy_impl.release_connection(instance_id)


# Global load balancer instance
load_balancer = LoadBalancer()

"""
Service registry for managing upstream services.

This module provides service discovery, health checking, and load balancing
functionality for the API Gateway.
"""

import asyncio
import random
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from collections import defaultdict

import httpx

from app.models.service import (
    ServiceDefinition, ServiceInstance, ServiceHealth, 
    ServiceInstanceStatus, LoadBalancerType, RoutingRule
)


class ServiceRegistry:
    """Service registry for managing upstream services."""
    
    def __init__(self):
        self._services: Dict[str, ServiceDefinition] = {}
        self._routing_rules: List[RoutingRule] = []
        self._round_robin_counters: Dict[str, int] = defaultdict(int)
        self._connection_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._health_check_tasks: Dict[str, asyncio.Task] = {}
        
    async def register_service(self, service: ServiceDefinition) -> None:
        """
        Register a new service or update existing one.
        
        Args:
            service: Service definition to register
        """
        service.updated_at = datetime.utcnow()
        self._services[service.name] = service
        
        # Start health check task if not already running
        if service.health_check.enabled and service.name not in self._health_check_tasks:
            task = asyncio.create_task(self._health_check_loop(service.name))
            self._health_check_tasks[service.name] = task
    
    async def unregister_service(self, service_name: str) -> bool:
        """
        Unregister a service.
        
        Args:
            service_name: Name of the service to unregister
            
        Returns:
            bool: True if service was found and removed
        """
        if service_name in self._services:
            # Cancel health check task
            if service_name in self._health_check_tasks:
                self._health_check_tasks[service_name].cancel()
                del self._health_check_tasks[service_name]
            
            del self._services[service_name]
            return True
        return False
    
    async def get_service(self, service_name: str) -> Optional[ServiceDefinition]:
        """
        Get service definition by name.
        
        Args:
            service_name: Name of the service
            
        Returns:
            ServiceDefinition or None if not found
        """
        return self._services.get(service_name)
    
    async def list_services(self) -> Dict[str, ServiceDefinition]:
        """
        List all registered services.
        
        Returns:
            Dictionary of service name to service definition
        """
        return self._services.copy()
    
    async def add_service_instance(self, service_name: str, instance: ServiceInstance) -> bool:
        """
        Add an instance to a service.
        
        Args:
            service_name: Name of the service
            instance: Instance to add
            
        Returns:
            bool: True if instance was added successfully
        """
        service = self._services.get(service_name)
        if not service:
            return False
        
        # Check if instance already exists
        for existing_instance in service.instances:
            if existing_instance.id == instance.id:
                # Update existing instance
                existing_instance.url = instance.url
                existing_instance.weight = instance.weight
                existing_instance.metadata = instance.metadata
                return True
        
        # Add new instance
        service.instances.append(instance)
        service.updated_at = datetime.utcnow()
        return True
    
    async def remove_service_instance(self, service_name: str, instance_id: str) -> bool:
        """
        Remove an instance from a service.
        
        Args:
            service_name: Name of the service
            instance_id: ID of the instance to remove
            
        Returns:
            bool: True if instance was found and removed
        """
        service = self._services.get(service_name)
        if not service:
            return False
        
        for i, instance in enumerate(service.instances):
            if instance.id == instance_id:
                del service.instances[i]
                service.updated_at = datetime.utcnow()
                return True
        return False
    
    async def get_best_instance(self, service_name: str) -> Optional[Dict[str, Any]]:
        """
        Get the best available instance using load balancing strategy.
        
        Args:
            service_name: Name of the service
            
        Returns:
            Dictionary with instance info or None if no healthy instances
        """
        service = self._services.get(service_name)
        if not service:
            return None
        
        # Filter healthy instances
        healthy_instances = [inst for inst in service.instances if inst.healthy]
        if not healthy_instances:
            return None
        
        # Apply load balancing strategy
        if service.load_balancer_type == LoadBalancerType.ROUND_ROBIN:
            instance = self._round_robin_selection(service_name, healthy_instances)
        elif service.load_balancer_type == LoadBalancerType.LEAST_CONNECTIONS:
            instance = self._least_connections_selection(service_name, healthy_instances)
        elif service.load_balancer_type == LoadBalancerType.WEIGHTED_ROUND_ROBIN:
            instance = self._weighted_round_robin_selection(service_name, healthy_instances)
        elif service.load_balancer_type == LoadBalancerType.RANDOM:
            instance = random.choice(healthy_instances)
        else:
            instance = healthy_instances[0]  # Fallback
        
        return {
            "id": instance.id,
            "url": instance.url,
            "weight": instance.weight,
            "metadata": instance.metadata
        }
    
    def _round_robin_selection(self, service_name: str, instances: List[ServiceInstance]) -> ServiceInstance:
        """Round robin instance selection."""
        counter = self._round_robin_counters[service_name]
        instance = instances[counter % len(instances)]
        self._round_robin_counters[service_name] = (counter + 1) % len(instances)
        return instance
    
    def _least_connections_selection(self, service_name: str, instances: List[ServiceInstance]) -> ServiceInstance:
        """Least connections instance selection."""
        conn_counts = self._connection_counts[service_name]
        min_connections = min(conn_counts.get(inst.id, 0) for inst in instances)
        candidates = [inst for inst in instances if conn_counts.get(inst.id, 0) == min_connections]
        return random.choice(candidates)
    
    def _weighted_round_robin_selection(self, service_name: str, instances: List[ServiceInstance]) -> ServiceInstance:
        """Weighted round robin instance selection."""
        # Create weighted list
        weighted_instances = []
        for instance in instances:
            weighted_instances.extend([instance] * instance.weight)
        
        if not weighted_instances:
            return instances[0]
        
        counter = self._round_robin_counters[service_name]
        instance = weighted_instances[counter % len(weighted_instances)]
        self._round_robin_counters[service_name] = (counter + 1) % len(weighted_instances)
        return instance
    
    async def is_service_healthy(self, service_name: str) -> bool:
        """
        Check if a service has at least one healthy instance.
        
        Args:
            service_name: Name of the service
            
        Returns:
            bool: True if service has healthy instances
        """
        service = self._services.get(service_name)
        if not service:
            return False
        
        return any(instance.healthy for instance in service.instances)
    
    async def get_service_health(self, service_name: str) -> Optional[ServiceHealth]:
        """
        Get detailed health status for a service.
        
        Args:
            service_name: Name of the service
            
        Returns:
            ServiceHealth object or None if service not found
        """
        service = self._services.get(service_name)
        if not service:
            return None
        
        healthy_count = sum(1 for inst in service.instances if inst.healthy)
        total_count = len(service.instances)
        
        overall_status = ServiceInstanceStatus.HEALTHY if healthy_count > 0 else ServiceInstanceStatus.UNHEALTHY
        if total_count == 0:
            overall_status = ServiceInstanceStatus.UNKNOWN
        
        instance_health = [
            {
                "id": inst.id,
                "url": inst.url,
                "healthy": inst.healthy,
                "last_check": inst.last_health_check.isoformat() if inst.last_health_check else None,
                "response_time_ms": inst.response_time_ms
            }
            for inst in service.instances
        ]
        
        return ServiceHealth(
            service_name=service_name,
            overall_status=overall_status,
            healthy_instances=healthy_count,
            total_instances=total_count,
            last_check=datetime.utcnow(),
            instance_health=instance_health
        )
    
    async def check_service_health(self, service_name: str) -> Dict[str, Any]:
        """
        Manually trigger health check for all instances of a service.
        
        Args:
            service_name: Name of the service
            
        Returns:
            Dictionary with health check results
        """
        service = self._services.get(service_name)
        if not service:
            return {"error": "Service not found"}
        
        results = {}
        for instance in service.instances:
            result = await self._check_instance_health(service, instance)
            results[instance.id] = result
        
        return results
    
    async def _check_instance_health(self, service: ServiceDefinition, instance: ServiceInstance) -> Dict[str, Any]:
        """
        Check health of a single instance.
        
        Args:
            service: Service definition
            instance: Instance to check
            
        Returns:
            Dictionary with health check result
        """
        health_config = service.health_check
        
        if not health_config.enabled:
            return {"status": "disabled", "healthy": True}
        
        start_time = time.time()
        
        try:
            if health_config.type.value == "http":
                health_url = f"{instance.url.rstrip('/')}{health_config.path}"
                
                timeout = httpx.Timeout(health_config.timeout_seconds)
                async with httpx.AsyncClient(timeout=timeout) as client:
                    response = await client.get(health_url)
                    
                response_time_ms = (time.time() - start_time) * 1000
                
                is_healthy = response.status_code in health_config.expected_status_codes
                
                # Update instance health
                instance.last_health_check = datetime.utcnow()
                instance.response_time_ms = response_time_ms
                instance.healthy = is_healthy
                
                return {
                    "status": "healthy" if is_healthy else "unhealthy",
                    "healthy": is_healthy,
                    "status_code": response.status_code,
                    "response_time_ms": response_time_ms,
                    "url": health_url
                }
                
        except Exception as e:
            response_time_ms = (time.time() - start_time) * 1000
            
            # Update instance health
            instance.last_health_check = datetime.utcnow()
            instance.response_time_ms = response_time_ms
            instance.healthy = False
            
            return {
                "status": "unhealthy",
                "healthy": False,
                "error": str(e),
                "response_time_ms": response_time_ms
            }
    
    async def _health_check_loop(self, service_name: str):
        """
        Background health check loop for a service.
        
        Args:
            service_name: Name of the service to monitor
        """
        while True:
            try:
                service = self._services.get(service_name)
                if not service or not service.health_check.enabled:
                    break
                
                # Check all instances
                for instance in service.instances:
                    await self._check_instance_health(service, instance)
                
                # Wait for next check
                await asyncio.sleep(service.health_check.interval_seconds)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Error in health check loop for {service_name}: {e}")
                await asyncio.sleep(30)  # Wait before retrying
    
    async def mark_instance_unhealthy(self, service_name: str, instance_id: str):
        """
        Mark a specific instance as unhealthy.
        
        Args:
            service_name: Name of the service
            instance_id: ID of the instance to mark unhealthy
        """
        service = self._services.get(service_name)
        if not service:
            return
        
        for instance in service.instances:
            if instance.id == instance_id:
                instance.healthy = False
                instance.last_health_check = datetime.utcnow()
                break
    
    async def get_routing_rules(self) -> List[Dict[str, Any]]:
        """
        Get current routing rules.
        
        Returns:
            List of routing rules
        """
        return [rule.dict() for rule in self._routing_rules]
    
    async def add_routing_rule(self, rule: RoutingRule) -> None:
        """
        Add a routing rule.
        
        Args:
            rule: Routing rule to add
        """
        self._routing_rules.append(rule)
        # Sort by priority (lower number = higher priority)
        self._routing_rules.sort(key=lambda r: r.priority)
    
    async def load_initial_services(self):
        """
        Load initial service configuration.
        This would typically load from a configuration file or database.
        """
        # Example service for demonstration
        example_service = ServiceDefinition(
            name="example-service",
            description="Example upstream service",
            instances=[
                ServiceInstance(
                    id="example-1",
                    url="http://httpbin.org",
                    weight=1
                )
            ]
        )
        
        await self.register_service(example_service)
    
    async def cleanup(self):
        """Cleanup resources on shutdown."""
        # Cancel all health check tasks
        for task in self._health_check_tasks.values():
            task.cancel()
        
        # Wait for tasks to complete
        if self._health_check_tasks:
            await asyncio.gather(*self._health_check_tasks.values(), return_exceptions=True)

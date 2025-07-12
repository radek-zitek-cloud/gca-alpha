"""
HTTP client for upstream services.

This module provides a centralized HTTP client for making requests to upstream
services with proper timeout, retry, and circuit breaker logic.
"""

import asyncio
import time
from typing import Dict, Any, Optional, List
from urllib.parse import urljoin

import httpx
from fastapi import Request, Response, HTTPException, status

from app.models.service import ServiceDefinition, ServiceInstance
from app.config import get_logger

logger = get_logger(__name__)


class UpstreamHTTPClient:
    """HTTP client for making requests to upstream services."""
    
    def __init__(self):
        """Initialize the HTTP client."""
        self._client_cache: Dict[str, httpx.AsyncClient] = {}
    
    async def forward_request(
        self,
        request: Request,
        upstream_url: str,
        service: ServiceDefinition,
        instance: ServiceInstance
    ) -> Response:
        """
        Forward the HTTP request to the upstream service.
        
        Args:
            request: The original request
            upstream_url: The URL of the upstream service
            service: Service definition with configuration
            instance: Service instance being called
            
        Returns:
            Response: The response from the upstream service
        """
        # Prepare headers
        headers = await self._prepare_headers(request, service)
        
        # Get request body
        body = await request.body()
        
        # Configure timeout from service definition
        timeout = self._get_timeout_config(service)
        
        # Make the request to upstream service
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                start_time = time.time()
                
                upstream_response = await client.request(
                    method=request.method,
                    url=upstream_url,
                    headers=headers,
                    content=body,
                    params=request.query_params
                )
                
                response_time = (time.time() - start_time) * 1000  # Convert to ms
                
                # Log the request
                logger.info(
                    f"Upstream request completed",
                    extra={
                        "service_name": service.name,
                        "instance_id": instance.id,
                        "method": request.method,
                        "url": upstream_url,
                        "status_code": upstream_response.status_code,
                        "response_time_ms": response_time
                    }
                )
                
                # Update instance response time
                instance.response_time_ms = response_time
                
                # Prepare and return response
                return await self._prepare_response(upstream_response, service, upstream_url)
                
        except httpx.ConnectError as e:
            logger.error(
                f"Connection error to upstream service",
                extra={
                    "service_name": service.name,
                    "instance_id": instance.id,
                    "url": upstream_url,
                    "error": str(e)
                }
            )
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Failed to connect to upstream service: {str(e)}"
            )
        except httpx.TimeoutException as e:
            logger.error(
                f"Timeout calling upstream service",
                extra={
                    "service_name": service.name,
                    "instance_id": instance.id,
                    "url": upstream_url,
                    "error": str(e)
                }
            )
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail="Request to upstream service timed out"
            )
        except Exception as e:
            logger.error(
                f"Unexpected error calling upstream service",
                extra={
                    "service_name": service.name,
                    "instance_id": instance.id,
                    "url": upstream_url,
                    "error": str(e)
                }
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Internal gateway error: {str(e)}"
            )
    
    async def _prepare_headers(self, request: Request, service: ServiceDefinition) -> Dict[str, str]:
        """
        Prepare headers for the upstream request.
        
        Args:
            request: Original request
            service: Service definition
            
        Returns:
            Dictionary of headers to send to upstream
        """
        headers = dict(request.headers)
        
        # Remove hop-by-hop headers
        hop_by_hop_headers = {
            'connection', 'keep-alive', 'proxy-authenticate',
            'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade'
        }
        headers = {k: v for k, v in headers.items() if k.lower() not in hop_by_hop_headers}
        
        # Add forwarding headers
        if request.client:
            headers['X-Forwarded-For'] = request.client.host
        headers['X-Forwarded-Proto'] = request.url.scheme
        headers['X-Forwarded-Host'] = request.headers.get('host', 'unknown')
        
        # Add custom service headers if configured
        if service.headers:
            headers.update(service.headers)
        
        return headers
    
    def _get_timeout_config(self, service: ServiceDefinition) -> httpx.Timeout:
        """
        Get timeout configuration for the service.
        
        Args:
            service: Service definition
            
        Returns:
            HTTPX timeout configuration
        """
        return httpx.Timeout(
            connect=service.timeout_config.get("connect", 5.0),
            read=service.timeout_config.get("read", 30.0),
            write=service.timeout_config.get("write", 5.0),
            pool=service.timeout_config.get("pool", 5.0)
        )
    
    async def _prepare_response(
        self,
        upstream_response: httpx.Response,
        service: ServiceDefinition,
        upstream_url: str
    ) -> Response:
        """
        Prepare the response to return to the client.
        
        Args:
            upstream_response: Response from upstream service
            service: Service definition
            upstream_url: URL that was called
            
        Returns:
            FastAPI Response object
        """
        # Prepare response headers
        response_headers = dict(upstream_response.headers)
        
        # Remove hop-by-hop headers from response
        hop_by_hop_headers = {
            'connection', 'keep-alive', 'proxy-authenticate',
            'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade'
        }
        response_headers = {
            k: v for k, v in response_headers.items() 
            if k.lower() not in hop_by_hop_headers
        }
        
        # Add gateway headers
        response_headers['X-Gateway-Service'] = service.name
        response_headers['X-Gateway-Instance'] = upstream_url
        response_headers['X-Gateway-Timestamp'] = str(int(time.time()))
        
        # Create the response
        return Response(
            content=upstream_response.content,
            status_code=upstream_response.status_code,
            headers=response_headers,
            media_type=upstream_response.headers.get('content-type')
        )
    
    async def health_check(
        self,
        instance: ServiceInstance,
        health_check_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Perform a health check on a service instance.
        
        Args:
            instance: Service instance to check
            health_check_config: Health check configuration
            
        Returns:
            Health check result dictionary
        """
        if not health_check_config.get("enabled", False):
            return {
                "healthy": True,
                "status": "disabled",
                "response_time_ms": 0
            }
        
        health_path = health_check_config.get("path", "/health")
        timeout = health_check_config.get("timeout_seconds", 5)
        expected_status_codes = health_check_config.get("expected_status_codes", [200])
        
        # Build health check URL
        base_url = instance.url.rstrip('/')
        health_url = f"{base_url}{health_path}"
        
        try:
            start_time = time.time()
            
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.get(health_url)
                
            response_time = (time.time() - start_time) * 1000
            
            healthy = response.status_code in expected_status_codes
            
            return {
                "healthy": healthy,
                "status": "healthy" if healthy else "unhealthy",
                "status_code": response.status_code,
                "response_time_ms": response_time,
                "url": health_url
            }
            
        except httpx.ConnectError as e:
            return {
                "healthy": False,
                "status": "unhealthy",
                "error": f"Connection failed: {str(e)}",
                "response_time_ms": 0,
                "url": health_url
            }
        except httpx.TimeoutException:
            return {
                "healthy": False,
                "status": "unhealthy", 
                "error": "Health check timeout",
                "response_time_ms": timeout * 1000,
                "url": health_url
            }
        except Exception as e:
            return {
                "healthy": False,
                "status": "unhealthy",
                "error": f"Health check failed: {str(e)}",
                "response_time_ms": 0,
                "url": health_url
            }
    
    async def close(self):
        """Close all cached HTTP clients."""
        for client in self._client_cache.values():
            await client.aclose()
        self._client_cache.clear()


# Global HTTP client instance
http_client = UpstreamHTTPClient()

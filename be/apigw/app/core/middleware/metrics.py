"""
Metrics middleware for tracking HTTP requests.

This middleware automatically collects metrics for all HTTP requests
including response times, status codes, and request paths.
"""

import time
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app.api.v1.endpoints.metrics import track_request_metrics


class MetricsMiddleware(BaseHTTPMiddleware):
    """Middleware to track request metrics."""
    
    async def dispatch(self, request: Request, call_next):
        """
        Process HTTP request and track metrics.
        
        Args:
            request: The incoming HTTP request
            call_next: The next middleware/handler in the chain
            
        Returns:
            Response: The HTTP response with added metrics tracking
        """
        start_time = time.time()
        
        # Process the request
        response = await call_next(request)
        
        # Calculate processing time
        process_time = time.time() - start_time
        
        # Track the request metrics
        track_request_metrics(request, response, process_time)
        
        # Add response time header for debugging/monitoring
        response.headers["X-Process-Time"] = str(round(process_time, 6))
        
        return response

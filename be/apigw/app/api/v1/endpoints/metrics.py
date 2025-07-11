"""
Metrics endpoint for the API Gateway.

This module provides metrics collection and exposure functionality
for monitoring and observability of the API Gateway service.
"""

import time
import psutil
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from collections import defaultdict, deque

from fastapi import APIRouter, Response, HTTPException
from pydantic import BaseModel


class MetricPoint(BaseModel):
    """A single metric data point."""
    timestamp: datetime
    value: float
    labels: Dict[str, str] = {}


class Metric(BaseModel):
    """Metric definition with metadata."""
    name: str
    help: str
    type: str  # counter, gauge, histogram, summary
    points: List[MetricPoint] = []


class MetricsResponse(BaseModel):
    """Response model for JSON metrics."""
    timestamp: datetime
    metrics: List[Metric]


# In-memory metrics storage (in production, use proper metrics backend)
class MetricsCollector:
    """Simple in-memory metrics collector."""
    
    def __init__(self):
        self.counters = defaultdict(float)
        self.gauges = defaultdict(float)
        self.histograms = defaultdict(list)
        self.request_durations = deque(maxlen=1000)  # Keep last 1000 requests
        self.start_time = time.time()
        
    def increment_counter(self, name: str, value: float = 1.0, labels: Optional[Dict[str, str]] = None):
        """Increment a counter metric."""
        key = self._make_key(name, labels)
        self.counters[key] += value
        
    def set_gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        """Set a gauge metric value."""
        key = self._make_key(name, labels)
        self.gauges[key] = value
        
    def observe_histogram(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        """Observe a value for a histogram metric."""
        key = self._make_key(name, labels)
        self.histograms[key].append(value)
        
    def record_request_duration(self, duration: float, method: str, endpoint: str, status_code: int):
        """Record HTTP request duration."""
        self.request_durations.append({
            'duration': duration,
            'method': method,
            'endpoint': endpoint,
            'status_code': status_code,
            'timestamp': time.time()
        })
        
    def _make_key(self, name: str, labels: Optional[Dict[str, str]] = None) -> str:
        """Create a unique key for a metric with labels."""
        if not labels:
            return name
        label_str = ','.join(f'{k}={v}' for k, v in sorted(labels.items()))
        return f'{name}{{{label_str}}}'


# Global metrics collector instance
metrics_collector = MetricsCollector()

# Router for metrics endpoints
router = APIRouter(prefix="/metrics", tags=["metrics"])


@router.get(
    "/",
    summary="Prometheus metrics",
    description="Returns metrics in Prometheus format"
)
async def get_prometheus_metrics() -> Response:
    """
    Get metrics in Prometheus format.
    
    Returns:
        Response: Plain text response with Prometheus-formatted metrics.
    """
    prometheus_text = _generate_prometheus_metrics()
    return Response(content=prometheus_text, media_type="text/plain")


@router.get(
    "/json",
    response_model=MetricsResponse,
    summary="JSON metrics",
    description="Returns metrics in JSON format"
)
async def get_json_metrics() -> MetricsResponse:
    """
    Get metrics in JSON format.
    
    Returns:
        MetricsResponse: JSON-formatted metrics data.
    """
    metrics = _collect_all_metrics()
    return MetricsResponse(
        timestamp=datetime.now(timezone.utc),
        metrics=metrics
    )


@router.get(
    "/system",
    summary="System metrics",
    description="Returns current system resource metrics"
)
async def get_system_metrics() -> Dict[str, Any]:
    """
    Get current system metrics.
    
    Returns:
        Dict: Current system resource usage metrics.
    """
    try:
        # CPU metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_count = psutil.cpu_count()
        cpu_freq = psutil.cpu_freq()
        
        # Memory metrics
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        # Disk metrics
        disk = psutil.disk_usage('/')
        
        # Network metrics
        network = psutil.net_io_counters()
        
        # Process metrics
        process = psutil.Process()
        process_memory = process.memory_info()
        
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "cpu": {
                "usage_percent": cpu_percent,
                "count": cpu_count,
                "frequency_mhz": cpu_freq.current if cpu_freq else None
            },
            "memory": {
                "total_bytes": memory.total,
                "available_bytes": memory.available,
                "used_bytes": memory.used,
                "usage_percent": memory.percent,
                "swap_total_bytes": swap.total,
                "swap_used_bytes": swap.used,
                "swap_usage_percent": swap.percent
            },
            "disk": {
                "total_bytes": disk.total,
                "used_bytes": disk.used,
                "free_bytes": disk.free,
                "usage_percent": (disk.used / disk.total) * 100
            },
            "network": {
                "bytes_sent": network.bytes_sent,
                "bytes_received": network.bytes_recv,
                "packets_sent": network.packets_sent,
                "packets_received": network.packets_recv
            },
            "process": {
                "memory_rss_bytes": process_memory.rss,
                "memory_vms_bytes": process_memory.vms,
                "cpu_percent": process.cpu_percent(),
                "num_threads": process.num_threads(),
                "num_fds": process.num_fds() if hasattr(process, 'num_fds') else None
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to collect system metrics: {str(e)}")


@router.get(
    "/requests",
    summary="Request metrics", 
    description="Returns HTTP request metrics and statistics"
)
async def get_request_metrics() -> Dict[str, Any]:
    """
    Get HTTP request metrics and statistics.
    
    Returns:
        Dict: Request metrics including counts, durations, and status codes.
    """
    if not metrics_collector.request_durations:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_requests": 0,
            "average_duration_ms": 0,
            "status_codes": {},
            "methods": {},
            "endpoints": {}
        }
    
    # Analyze request data
    total_requests = len(metrics_collector.request_durations)
    durations = [req['duration'] for req in metrics_collector.request_durations]
    avg_duration = sum(durations) / len(durations) if durations else 0
    
    # Count by status code
    status_codes = defaultdict(int)
    methods = defaultdict(int)
    endpoints = defaultdict(int)
    
    for req in metrics_collector.request_durations:
        status_codes[str(req['status_code'])] += 1
        methods[req['method']] += 1
        endpoints[req['endpoint']] += 1
    
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_requests": total_requests,
        "average_duration_ms": round(avg_duration * 1000, 2),
        "min_duration_ms": round(min(durations) * 1000, 2) if durations else 0,
        "max_duration_ms": round(max(durations) * 1000, 2) if durations else 0,
        "status_codes": dict(status_codes),
        "methods": dict(methods),
        "endpoints": dict(endpoints)
    }


@router.post(
    "/increment/{metric_name}",
    summary="Increment counter",
    description="Manually increment a counter metric"
)
async def increment_metric(metric_name: str, value: float = 1.0) -> Dict[str, str]:
    """
    Manually increment a counter metric.
    
    Args:
        metric_name: Name of the counter to increment
        value: Value to increment by (default: 1.0)
        
    Returns:
        Dict: Success message
    """
    metrics_collector.increment_counter(metric_name, value)
    return {"message": f"Counter '{metric_name}' incremented by {value}"}


def _generate_prometheus_metrics() -> str:
    """Generate metrics in Prometheus format."""
    lines = []
    current_time = time.time()
    
    # Application uptime
    uptime_seconds = current_time - metrics_collector.start_time
    lines.append("# HELP app_uptime_seconds Application uptime in seconds")
    lines.append("# TYPE app_uptime_seconds gauge")
    lines.append(f"app_uptime_seconds {uptime_seconds}")
    
    # System metrics
    try:
        # CPU usage
        cpu_percent = psutil.cpu_percent()
        lines.append("# HELP system_cpu_usage_percent CPU usage percentage")
        lines.append("# TYPE system_cpu_usage_percent gauge")
        lines.append(f"system_cpu_usage_percent {cpu_percent}")
        
        # Memory usage
        memory = psutil.virtual_memory()
        lines.append("# HELP system_memory_usage_percent Memory usage percentage")
        lines.append("# TYPE system_memory_usage_percent gauge")
        lines.append(f"system_memory_usage_percent {memory.percent}")
        
        lines.append("# HELP system_memory_total_bytes Total system memory in bytes")
        lines.append("# TYPE system_memory_total_bytes gauge")
        lines.append(f"system_memory_total_bytes {memory.total}")
        
        # Request metrics
        if metrics_collector.request_durations:
            total_requests = len(metrics_collector.request_durations)
            lines.append("# HELP http_requests_total Total HTTP requests")
            lines.append("# TYPE http_requests_total counter")
            lines.append(f"http_requests_total {total_requests}")
            
            # Average response time
            durations = [req['duration'] for req in metrics_collector.request_durations]
            avg_duration = sum(durations) / len(durations)
            lines.append("# HELP http_request_duration_seconds_avg Average HTTP request duration")
            lines.append("# TYPE http_request_duration_seconds_avg gauge")
            lines.append(f"http_request_duration_seconds_avg {avg_duration}")
        
    except Exception:
        # If system metrics fail, continue with what we have
        pass
    
    # Custom counters
    for key, value in metrics_collector.counters.items():
        metric_name = key.split('{')[0]  # Remove labels for help text
        lines.append(f"# HELP {metric_name} Custom counter metric")
        lines.append(f"# TYPE {metric_name} counter")
        lines.append(f"{key} {value}")
    
    # Custom gauges
    for key, value in metrics_collector.gauges.items():
        metric_name = key.split('{')[0]  # Remove labels for help text
        lines.append(f"# HELP {metric_name} Custom gauge metric")
        lines.append(f"# TYPE {metric_name} gauge")
        lines.append(f"{key} {value}")
    
    return '\n'.join(lines) + '\n'


def _collect_all_metrics() -> List[Metric]:
    """Collect all metrics in a structured format."""
    metrics = []
    current_time = datetime.now(timezone.utc)
    
    # Application uptime
    uptime_seconds = time.time() - metrics_collector.start_time
    metrics.append(Metric(
        name="app_uptime_seconds",
        help="Application uptime in seconds",
        type="gauge",
        points=[MetricPoint(timestamp=current_time, value=uptime_seconds)]
    ))
    
    # System metrics
    try:
        cpu_percent = psutil.cpu_percent()
        memory = psutil.virtual_memory()
        
        metrics.extend([
            Metric(
                name="system_cpu_usage_percent",
                help="CPU usage percentage",
                type="gauge",
                points=[MetricPoint(timestamp=current_time, value=cpu_percent)]
            ),
            Metric(
                name="system_memory_usage_percent", 
                help="Memory usage percentage",
                type="gauge",
                points=[MetricPoint(timestamp=current_time, value=memory.percent)]
            ),
            Metric(
                name="system_memory_total_bytes",
                help="Total system memory in bytes",
                type="gauge",
                points=[MetricPoint(timestamp=current_time, value=float(memory.total))]
            )
        ])
    except Exception:
        pass
    
    # Request metrics
    if metrics_collector.request_durations:
        total_requests = len(metrics_collector.request_durations)
        durations = [req['duration'] for req in metrics_collector.request_durations]
        avg_duration = sum(durations) / len(durations)
        
        metrics.extend([
            Metric(
                name="http_requests_total",
                help="Total HTTP requests",
                type="counter",
                points=[MetricPoint(timestamp=current_time, value=float(total_requests))]
            ),
            Metric(
                name="http_request_duration_seconds_avg",
                help="Average HTTP request duration",
                type="gauge", 
                points=[MetricPoint(timestamp=current_time, value=avg_duration)]
            )
        ])
    
    return metrics


# Middleware function to track request metrics
def track_request_metrics(request, response, duration: float):
    """Track request metrics. Should be called from middleware."""
    metrics_collector.record_request_duration(
        duration=duration,
        method=request.method,
        endpoint=str(request.url.path),
        status_code=response.status_code
    )

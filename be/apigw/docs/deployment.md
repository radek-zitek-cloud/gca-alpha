# API Gateway Deployment Guide

## Overview

This guide covers deployment strategies, configuration, and operational considerations for the FastAPI-based API Gateway.

## Deployment Options

### 1. Local Development

#### Prerequisites
- Python 3.8+ (recommended: 3.13)
- Virtual environment tool (venv, conda, etc.)
- Git

#### Setup
```bash
# Clone repository
git clone https://github.com/radek-zitek-cloud/gca-alpha.git
cd gca-alpha/be/apigw

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
make install
# or manually: pip install -r requirements/base.txt

# Run development server
make run
# or manually: uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

#### Development Commands
```bash
# Install development dependencies
make dev

# Run tests
make test

# Code formatting
make format

# Linting
make lint

# Clean cache
make clean
```

### 2. Docker Deployment

#### Create Dockerfile
```dockerfile
FROM python:3.13-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements/base.txt requirements/production.txt ./requirements/

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements/production.txt

# Copy application code
COPY app/ ./app/
COPY scripts/ ./scripts/

# Create non-root user
RUN useradd --create-home --shell /bin/bash app
USER app

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health/live || exit 1

# Start application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

#### Docker Compose
```yaml
version: '3.8'

services:
  api-gateway:
    build: .
    ports:
      - "8000:8000"
    environment:
      - ENVIRONMENT=production
      - LOG_LEVEL=info
      - GATEWAY_NAME=api-gateway
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/api/v1/health/live"]
      interval: 30s
      timeout: 10s
      retries: 3
    restart: unless-stopped
    
  # Optional: Redis for future caching/rate limiting
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    restart: unless-stopped
    
  # Optional: Prometheus for monitoring
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./config/prometheus.yml:/etc/prometheus/prometheus.yml
    restart: unless-stopped
```

#### Build and Run
```bash
# Build image
docker build -t api-gateway:latest .

# Run with Docker Compose
docker-compose up -d

# Check logs
docker-compose logs -f api-gateway

# Scale instances
docker-compose up -d --scale api-gateway=3
```

### 3. Kubernetes Deployment

#### Namespace
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: api-gateway
```

#### Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-gateway
  namespace: api-gateway
  labels:
    app: api-gateway
spec:
  replicas: 3
  selector:
    matchLabels:
      app: api-gateway
  template:
    metadata:
      labels:
        app: api-gateway
    spec:
      containers:
      - name: api-gateway
        image: api-gateway:latest
        ports:
        - containerPort: 8000
        env:
        - name: ENVIRONMENT
          value: "production"
        - name: LOG_LEVEL
          value: "info"
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /api/v1/health/live
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /api/v1/health/ready
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 10
```

#### Service
```yaml
apiVersion: v1
kind: Service
metadata:
  name: api-gateway-service
  namespace: api-gateway
spec:
  selector:
    app: api-gateway
  ports:
  - port: 80
    targetPort: 8000
  type: ClusterIP
```

#### Ingress
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: api-gateway-ingress
  namespace: api-gateway
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  tls:
  - hosts:
    - api.yourdomain.com
    secretName: api-gateway-tls
  rules:
  - host: api.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: api-gateway-service
            port:
              number: 80
```

#### Deploy to Kubernetes
```bash
# Apply manifests
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/ingress.yaml

# Check status
kubectl get pods -n api-gateway
kubectl get svc -n api-gateway
kubectl get ingress -n api-gateway

# View logs
kubectl logs -f deployment/api-gateway -n api-gateway

# Scale deployment
kubectl scale deployment api-gateway --replicas=5 -n api-gateway
```

### 4. Cloud Platform Deployment

#### AWS ECS/Fargate
```json
{
  "family": "api-gateway",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "256",
  "memory": "512",
  "executionRoleArn": "arn:aws:iam::ACCOUNT:role/ecsTaskExecutionRole",
  "containerDefinitions": [
    {
      "name": "api-gateway",
      "image": "ACCOUNT.dkr.ecr.REGION.amazonaws.com/api-gateway:latest",
      "portMappings": [
        {
          "containerPort": 8000,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "ENVIRONMENT",
          "value": "production"
        }
      ],
      "healthCheck": {
        "command": [
          "CMD-SHELL",
          "curl -f http://localhost:8000/api/v1/health/live || exit 1"
        ],
        "interval": 30,
        "timeout": 5,
        "retries": 3
      }
    }
  ]
}
```

#### Google Cloud Run
```yaml
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: api-gateway
  annotations:
    run.googleapis.com/ingress: all
spec:
  template:
    metadata:
      annotations:
        autoscaling.knative.dev/maxScale: "10"
        run.googleapis.com/cpu-throttling: "false"
    spec:
      containerConcurrency: 100
      containers:
      - image: gcr.io/PROJECT_ID/api-gateway:latest
        ports:
        - containerPort: 8000
        env:
        - name: ENVIRONMENT
          value: production
        resources:
          limits:
            cpu: 1000m
            memory: 512Mi
```

## Configuration Management

### Environment Variables

#### Required Variables
```bash
# Gateway Configuration
GATEWAY_NAME=api-gateway
GATEWAY_VERSION=1.0.0
ENVIRONMENT=production

# Logging
LOG_LEVEL=info
LOG_FORMAT=json

# Performance
WORKERS=4
MAX_REQUESTS=1000
TIMEOUT=30
```

#### Optional Variables
```bash
# External Services
CONSUL_URL=http://consul:8500
REDIS_URL=redis://redis:6379
PROMETHEUS_URL=http://prometheus:9090

# Security
SECRET_KEY=your-secret-key
JWT_SECRET=your-jwt-secret

# Database (future use)
DATABASE_URL=postgresql://user:pass@db:5432/gateway
```

### Configuration Files

#### Production Settings (`config/production.yaml`)
```yaml
gateway:
  name: "api-gateway"
  version: "1.0.0"
  environment: "production"

services:
  default_health_check_interval: 30
  default_timeout: 30.0
  default_load_balancer: "round_robin"

logging:
  level: "info"
  format: "json"
  
monitoring:
  metrics_enabled: true
  health_check_enabled: true
  prometheus_endpoint: "/metrics"

security:
  cors_enabled: true
  rate_limiting_enabled: true
  auth_required: false
```

## Monitoring and Observability

### Health Check Endpoints

```bash
# Basic health check
curl http://api-gateway:8000/api/v1/health
# Response: {"status": "healthy", "timestamp": "...", "uptime_seconds": 123}

# Detailed health check
curl http://api-gateway:8000/api/v1/health/detailed
# Response: Full system and dependency health information

# Kubernetes liveness probe
curl http://api-gateway:8000/api/v1/health/live
# Response: {"status": "alive"}

# Kubernetes readiness probe  
curl http://api-gateway:8000/api/v1/health/ready
# Response: {"status": "ready"}
```

### Metrics Collection

#### Prometheus Metrics
```bash
# Prometheus format metrics
curl http://api-gateway:8000/api/v1/metrics

# JSON format metrics
curl http://api-gateway:8000/api/v1/metrics/json

# System resource metrics
curl http://api-gateway:8000/api/v1/metrics/system

# Request statistics
curl http://api-gateway:8000/api/v1/metrics/requests
```

#### Prometheus Configuration (`config/prometheus.yml`)
```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'api-gateway'
    static_configs:
      - targets: ['api-gateway:8000']
    metrics_path: '/api/v1/metrics'
    scrape_interval: 30s
```

### Logging Configuration

#### Structured Logging
```python
import structlog

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)
```

## Performance Tuning

### Uvicorn Configuration

#### Production Settings
```bash
# Basic production configuration
uvicorn app.main:app \
  --host 0.0.0.0 \
  --port 8000 \
  --workers 4 \
  --loop uvloop \
  --http httptools \
  --access-log \
  --log-level info

# High-performance configuration
uvicorn app.main:app \
  --host 0.0.0.0 \
  --port 8000 \
  --workers $(($(nproc) * 2)) \
  --loop uvloop \
  --http httptools \
  --no-access-log \
  --log-level warning \
  --backlog 2048 \
  --limit-max-requests 1000
```

#### Gunicorn Alternative
```bash
# Using Gunicorn with Uvicorn workers
gunicorn app.main:app \
  -w 4 \
  -k uvicorn.workers.UvicornWorker \
  -b 0.0.0.0:8000 \
  --max-requests 1000 \
  --max-requests-jitter 100 \
  --timeout 30 \
  --keep-alive 2
```

### Load Balancer Configuration

#### NGINX Configuration
```nginx
upstream api_gateway {
    least_conn;
    server api-gateway-1:8000 max_fails=3 fail_timeout=30s;
    server api-gateway-2:8000 max_fails=3 fail_timeout=30s;
    server api-gateway-3:8000 max_fails=3 fail_timeout=30s;
}

server {
    listen 80;
    server_name api.yourdomain.com;
    
    location / {
        proxy_pass http://api_gateway;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts
        proxy_connect_timeout 5s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
        
        # Health check
        proxy_next_upstream error timeout invalid_header http_500 http_502 http_503;
    }
    
    # Health check endpoint
    location /health {
        access_log off;
        proxy_pass http://api_gateway/api/v1/health/live;
    }
}
```

### Resource Requirements

#### Minimum Requirements
- **CPU**: 1 vCPU
- **Memory**: 512 MB RAM
- **Storage**: 1 GB (for logs and temporary files)
- **Network**: 100 Mbps

#### Recommended Production
- **CPU**: 2-4 vCPUs
- **Memory**: 2-4 GB RAM  
- **Storage**: 10 GB SSD
- **Network**: 1 Gbps

#### High-Traffic Production
- **CPU**: 4-8 vCPUs
- **Memory**: 8-16 GB RAM
- **Storage**: 50 GB SSD
- **Network**: 10 Gbps

## Security Hardening

### Container Security

#### Dockerfile Security Best Practices
```dockerfile
# Use specific version tags
FROM python:3.13.2-slim

# Create non-root user
RUN groupadd -r app && useradd -r -g app app

# Set security-focused environment
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random

# Install security updates
RUN apt-get update && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*

# Copy and install dependencies as root
COPY requirements/ ./requirements/
RUN pip install --no-cache-dir -r requirements/production.txt

# Copy application code
COPY --chown=app:app app/ ./app/

# Switch to non-root user
USER app

# Set read-only filesystem
COPY --chown=app:app . .
RUN chmod -R 555 app/
```

#### Kubernetes Security Context
```yaml
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
  containers:
  - name: api-gateway
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
        - ALL
    volumeMounts:
    - name: tmp
      mountPath: /tmp
    - name: var-log
      mountPath: /var/log
  volumes:
  - name: tmp
    emptyDir: {}
  - name: var-log
    emptyDir: {}
```

### Network Security

#### Network Policies
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-gateway-network-policy
  namespace: api-gateway
spec:
  podSelector:
    matchLabels:
      app: api-gateway
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8000
  egress:
  - to: []
    ports:
    - protocol: TCP
      port: 80
    - protocol: TCP
      port: 443
    - protocol: TCP
      port: 53
    - protocol: UDP
      port: 53
```

## Troubleshooting

### Common Issues

#### 1. Service Not Starting
```bash
# Check logs
docker logs api-gateway
kubectl logs deployment/api-gateway -n api-gateway

# Common causes:
# - Missing environment variables
# - Port already in use
# - Dependency conflicts
# - Insufficient permissions
```

#### 2. Health Check Failures
```bash
# Test health endpoints directly
curl -v http://localhost:8000/api/v1/health/live

# Check service registry
curl http://localhost:8000/gateway/services

# Common causes:
# - Service registration issues
# - Network connectivity problems
# - Health check timeout too low
```

#### 3. High Latency
```bash
# Check metrics
curl http://localhost:8000/api/v1/metrics/requests

# Profile bottlenecks:
# - Upstream service latency
# - Load balancer configuration
# - Resource constraints
# - Connection pooling issues
```

#### 4. Memory Leaks
```bash
# Monitor memory usage
curl http://localhost:8000/api/v1/metrics/system

# Common causes:
# - Unclosed HTTP connections
# - Large request/response caching
# - Memory-intensive operations
# - Circular references
```

### Debugging Tools

#### Development Debugging
```bash
# Enable debug logging
export LOG_LEVEL=debug

# Run with debugger
python -m debugpy --listen 5678 --wait-for-client -m uvicorn app.main:app

# Performance profiling
python -m cProfile -o profile.stats -m uvicorn app.main:app
```

#### Production Debugging
```bash
# Memory profiling
pip install memory-profiler
python -m memory_profiler app/main.py

# Request tracing
# Enable request correlation IDs in logs
# Use distributed tracing tools (Jaeger, Zipkin)
```

This deployment guide provides comprehensive instructions for deploying the API Gateway in various environments, from local development to production Kubernetes clusters, with proper monitoring, security, and troubleshooting guidance.

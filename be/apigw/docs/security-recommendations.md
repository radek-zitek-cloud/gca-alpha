# Security Recommendations

## Overview

This document outlines comprehensive security recommendations for the API Gateway codebase. The current implementation lacks essential security features required for production deployment. This document provides prioritized recommendations with implementation guidance.

## Current Security Posture: **❌ CRITICAL GAPS**

### Risk Assessment
- **Authentication**: ❌ None implemented (CRITICAL)
- **Authorization**: ❌ None implemented (CRITICAL)  
- **Input Validation**: ⚠️ Basic only (HIGH)
- **Security Headers**: ❌ Missing (HIGH)
- **Rate Limiting**: ❌ None implemented (HIGH)
- **Encryption**: ⚠️ HTTPS only (MEDIUM)
- **Audit Logging**: ⚠️ Partial (MEDIUM)

## 🚨 Critical Security Requirements

### 1. Authentication & Authorization

#### **Implementation Priority: CRITICAL (Week 1)**

#### JWT Token Authentication
```python
# Recommended implementation structure
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer
import jwt

class JWTAuthenticator:
    def __init__(self, secret_key: str, algorithm: str = "HS256"):
        self.secret_key = secret_key
        self.algorithm = algorithm
        
    async def authenticate(self, token: str) -> dict:
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except jwt.InvalidTokenError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token"
            )
```

#### API Key Management
```python
class APIKeyAuthenticator:
    def __init__(self, api_keys: dict):
        self.api_keys = api_keys  # key -> permissions mapping
        
    async def authenticate(self, api_key: str) -> dict:
        if api_key not in self.api_keys:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key"
            )
        return {"permissions": self.api_keys[api_key]}
```

#### OAuth2 Integration
```python
from authlib.integrations.fastapi_oauth2 import OAuth2

oauth2 = OAuth2()

# Support for major providers
OAUTH_PROVIDERS = {
    "google": {
        "client_id": "your-google-client-id",
        "client_secret": "your-google-client-secret",
        "scopes": ["openid", "email", "profile"]
    },
    "github": {
        "client_id": "your-github-client-id", 
        "client_secret": "your-github-client-secret",
        "scopes": ["user:email"]
    }
}
```

### 2. Role-Based Access Control (RBAC)

#### **Implementation Priority: CRITICAL (Week 1)**

```python
from enum import Enum
from typing import List, Dict

class Permission(Enum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMIN = "admin"

class Role(Enum):
    GUEST = "guest"
    USER = "user"
    MODERATOR = "moderator"
    ADMIN = "admin"

ROLE_PERMISSIONS = {
    Role.GUEST: [Permission.READ],
    Role.USER: [Permission.READ, Permission.WRITE],
    Role.MODERATOR: [Permission.READ, Permission.WRITE, Permission.DELETE],
    Role.ADMIN: [Permission.READ, Permission.WRITE, Permission.DELETE, Permission.ADMIN]
}

class RBACManager:
    def __init__(self):
        self.role_permissions = ROLE_PERMISSIONS
        
    def has_permission(self, user_role: Role, required_permission: Permission) -> bool:
        return required_permission in self.role_permissions.get(user_role, [])
        
    def check_permission(self, user_role: Role, required_permission: Permission):
        if not self.has_permission(user_role, required_permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required: {required_permission.value}"
            )
```

### 3. Security Headers & Middleware

#### **Implementation Priority: HIGH (Week 1)**

```python
from fastapi import Request, Response
from fastapi.middleware.base import BaseHTTPMiddleware

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        
        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        
        return response
```

#### CORS Configuration
```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://trusted-domain.com"],  # Never use "*" in production
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Correlation-ID"],
    expose_headers=["X-Correlation-ID"],
    max_age=3600,
)
```

### 4. Input Validation & Sanitization

#### **Implementation Priority: HIGH (Week 1)**

```python
from pydantic import BaseModel, validator, Field
import re
from typing import Optional

class SecureRequest(BaseModel):
    """Base model with security validations"""
    
    @validator('*', pre=True)
    def prevent_xss(cls, v):
        if isinstance(v, str):
            # Remove potentially dangerous characters
            dangerous_chars = ['<', '>', '"', "'", '&', 'javascript:', 'data:']
            for char in dangerous_chars:
                if char in v.lower():
                    raise ValueError(f"Invalid character detected: {char}")
        return v
    
    @validator('*', pre=True) 
    def prevent_sql_injection(cls, v):
        if isinstance(v, str):
            # Basic SQL injection patterns
            sql_patterns = [
                r"(\b(union|select|insert|update|delete|drop|create|alter)\b)",
                r"(-{2}|/\*|\*/)",
                r"(;|\||&)"
            ]
            for pattern in sql_patterns:
                if re.search(pattern, v.lower()):
                    raise ValueError("Potentially malicious input detected")
        return v

class PathParameters(SecureRequest):
    path: str = Field(..., regex=r"^[a-zA-Z0-9/_-]+$", max_length=500)
    
class QueryParameters(SecureRequest):
    query: Optional[str] = Field(None, max_length=1000)
```

### 5. Rate Limiting

#### **Implementation Priority: HIGH (Week 1)**

```python
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import redis

# Redis-based rate limiter for distributed deployments
redis_client = redis.Redis(host='localhost', port=6379, db=0)

limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="redis://localhost:6379",
    default_limits=["100/minute", "1000/hour"]
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Usage in routes
@app.get("/api/v1/data")
@limiter.limit("10/minute")
async def get_data(request: Request):
    return {"data": "sensitive information"}

# Different limits for authenticated users
@app.get("/api/v1/premium-data")
@limiter.limit("100/minute")  # Higher limit for authenticated users
async def get_premium_data(request: Request, user: dict = Depends(get_current_user)):
    return {"data": "premium information"}
```

### 6. Request Size Limits

#### **Implementation Priority: HIGH (Week 1)**

```python
from fastapi import HTTPException
from starlette.middleware.base import BaseHTTPMiddleware

class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_size: int = 10 * 1024 * 1024):  # 10MB default
        super().__init__(app)
        self.max_size = max_size
        
    async def dispatch(self, request: Request, call_next):
        if request.method in ["POST", "PUT", "PATCH"]:
            content_length = request.headers.get("content-length")
            if content_length and int(content_length) > self.max_size:
                raise HTTPException(
                    status_code=413,
                    detail=f"Request too large. Maximum size: {self.max_size} bytes"
                )
        return await call_next(request)
```

## 🔒 Advanced Security Features

### 1. Audit Logging

#### **Implementation Priority: MEDIUM (Week 2)**

```python
import json
from datetime import datetime
from typing import Optional

class SecurityAuditLogger:
    def __init__(self, logger):
        self.logger = logger
        
    async def log_authentication_event(
        self, 
        user_id: Optional[str], 
        event_type: str, 
        success: bool, 
        ip_address: str,
        user_agent: str
    ):
        audit_event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": f"auth.{event_type}",
            "user_id": user_id,
            "success": success,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "severity": "INFO" if success else "WARNING"
        }
        self.logger.info(f"SECURITY_AUDIT: {json.dumps(audit_event)}")
        
    async def log_authorization_event(
        self,
        user_id: str,
        resource: str,
        action: str,
        success: bool,
        ip_address: str
    ):
        audit_event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "authz.access_check",
            "user_id": user_id,
            "resource": resource,
            "action": action,
            "success": success,
            "ip_address": ip_address,
            "severity": "INFO" if success else "WARNING"
        }
        self.logger.info(f"SECURITY_AUDIT: {json.dumps(audit_event)}")
```

### 2. Security Monitoring

#### **Implementation Priority: MEDIUM (Week 2)**

```python
from collections import defaultdict
import asyncio
from datetime import datetime, timedelta

class SecurityMonitor:
    def __init__(self):
        self.failed_attempts = defaultdict(list)  # IP -> [timestamps]
        self.blocked_ips = set()
        self.max_attempts = 5
        self.block_duration = timedelta(minutes=15)
        
    async def record_failed_attempt(self, ip_address: str):
        now = datetime.utcnow()
        
        # Clean old attempts
        cutoff_time = now - timedelta(minutes=5)
        self.failed_attempts[ip_address] = [
            attempt for attempt in self.failed_attempts[ip_address]
            if attempt > cutoff_time
        ]
        
        # Record new attempt
        self.failed_attempts[ip_address].append(now)
        
        # Check if should block
        if len(self.failed_attempts[ip_address]) >= self.max_attempts:
            self.blocked_ips.add(ip_address)
            # Schedule unblock
            asyncio.create_task(self._unblock_ip_after_delay(ip_address))
            
    async def is_blocked(self, ip_address: str) -> bool:
        return ip_address in self.blocked_ips
        
    async def _unblock_ip_after_delay(self, ip_address: str):
        await asyncio.sleep(self.block_duration.total_seconds())
        self.blocked_ips.discard(ip_address)
```

### 3. Secrets Management

#### **Implementation Priority: MEDIUM (Week 3)**

```python
import os
from cryptography.fernet import Fernet
from typing import Dict, Optional

class SecretsManager:
    def __init__(self, encryption_key: Optional[bytes] = None):
        self.encryption_key = encryption_key or Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key)
        self.secrets: Dict[str, bytes] = {}
        
    def store_secret(self, key: str, value: str):
        """Store encrypted secret"""
        encrypted_value = self.cipher.encrypt(value.encode())
        self.secrets[key] = encrypted_value
        
    def get_secret(self, key: str) -> Optional[str]:
        """Retrieve and decrypt secret"""
        encrypted_value = self.secrets.get(key)
        if encrypted_value:
            return self.cipher.decrypt(encrypted_value).decode()
        return None
        
    @classmethod
    def from_environment(cls):
        """Load secrets from environment variables"""
        instance = cls()
        
        # Load common secrets
        secrets_mapping = {
            "jwt_secret": "JWT_SECRET_KEY",
            "database_url": "DATABASE_URL", 
            "redis_url": "REDIS_URL",
            "oauth_client_secret": "OAUTH_CLIENT_SECRET"
        }
        
        for secret_key, env_var in secrets_mapping.items():
            env_value = os.getenv(env_var)
            if env_value:
                instance.store_secret(secret_key, env_value)
                
        return instance
```

## 📋 Security Configuration

### Environment Variables
```bash
# Authentication
JWT_SECRET_KEY=your-super-secret-jwt-key-here
JWT_ALGORITHM=HS256
JWT_EXPIRATION_HOURS=24

# API Keys
API_KEYS_CONFIG_PATH=/etc/api-gateway/api-keys.json

# OAuth2
OAUTH_CLIENT_ID=your-oauth-client-id
OAUTH_CLIENT_SECRET=your-oauth-client-secret

# Rate Limiting
REDIS_URL=redis://localhost:6379/0
RATE_LIMIT_DEFAULT=100/minute,1000/hour

# Security
CORS_ALLOWED_ORIGINS=https://trusted-domain.com,https://another-trusted.com
SECURITY_HEADERS_ENABLED=true
REQUEST_SIZE_LIMIT=10485760  # 10MB in bytes

# Monitoring
SECURITY_MONITORING_ENABLED=true
AUDIT_LOG_LEVEL=INFO
FAILED_ATTEMPTS_THRESHOLD=5
BLOCK_DURATION_MINUTES=15
```

### Production Security Checklist

#### Pre-deployment Security Audit
- [ ] Authentication middleware implemented and tested
- [ ] Authorization/RBAC system configured  
- [ ] All security headers configured
- [ ] Rate limiting implemented with Redis backend
- [ ] Input validation covers all endpoints
- [ ] Request size limits configured
- [ ] CORS properly configured (no wildcards)
- [ ] Security audit logging enabled
- [ ] Failed attempt monitoring active
- [ ] Secrets properly encrypted and managed
- [ ] HTTPS enforced (no HTTP endpoints)
- [ ] Security headers tested with security scanners
- [ ] Penetration testing completed
- [ ] Dependency security scan passed
- [ ] Security documentation updated

#### Ongoing Security Maintenance
- [ ] Regular security dependency updates
- [ ] Monthly security audit log reviews
- [ ] Quarterly penetration testing
- [ ] Annual security architecture review
- [ ] Incident response plan tested
- [ ] Security training for development team

## 🔧 Implementation Timeline

### Week 1: Critical Security Foundation
- Day 1-2: JWT Authentication implementation
- Day 3-4: RBAC system and authorization middleware
- Day 5: Security headers and CORS configuration

### Week 2: Enhanced Security Features  
- Day 1-2: Rate limiting with Redis
- Day 3-4: Input validation and sanitization
- Day 5: Security audit logging

### Week 3: Advanced Security
- Day 1-2: Security monitoring and alerting
- Day 3-4: Secrets management system
- Day 5: Security testing and validation

### Week 4: Security Hardening
- Day 1-2: Penetration testing
- Day 3-4: Security documentation
- Day 5: Production security deployment

## 📚 Additional Resources

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [FastAPI Security Documentation](https://fastapi.tiangolo.com/tutorial/security/)
- [Python Security Best Practices](https://python-security.readthedocs.io/)
- [JWT Security Best Practices](https://tools.ietf.org/html/rfc8725)

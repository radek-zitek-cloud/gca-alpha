# API Key Management System

## Overview

The API Key Management system provides secure, scalable API key authentication for the Gateway. It includes comprehensive features for key generation, validation, rate limiting, scope-based access control, and analytics.

## Features

### Core Features
- **Secure API Key Generation**: Cryptographically secure key generation using Python's `secrets` module
- **Key Lifecycle Management**: Create, rotate, revoke, and expire API keys
- **Rate Limiting**: Per-key rate limiting with configurable limits (RPM, RPH, RPD)
- **Scope-based Access Control**: Fine-grained permissions with predefined scopes
- **Usage Analytics**: Comprehensive tracking of API key usage and performance
- **IP and Domain Restrictions**: Optional IP allowlisting for enhanced security
- **Integration**: Seamless integration with existing JWT authentication

### Security Features
- **Hashed Storage**: API keys are stored as SHA-256 hashes, never in plain text
- **Automatic Expiration**: Configurable key expiration with automatic status updates
- **Audit Logging**: Comprehensive logging of all API key operations
- **Rate Limit Protection**: Built-in rate limiting to prevent abuse
- **Security Headers**: Automatic injection of security headers in responses

## Architecture

### Components

1. **APIKeyManager** (`app/services/api_keys.py`)
   - Main service class for API key management
   - Handles key creation, validation, rotation, and revocation
   - Integrates with storage, rate limiting, and validation components

2. **APIKeyStore** (`app/services/api_keys.py`)
   - Storage layer for API key metadata
   - In-memory implementation (production should use Redis/Database)
   - Supports key lookup by hash and ID

3. **APIKeyValidator** (`app/services/api_keys.py`)
   - Validates API keys and enforces security policies
   - Checks expiration, IP restrictions, and scope permissions
   - Updates usage statistics

4. **RateLimiter** (`app/services/api_keys.py`)
   - Implements sliding window rate limiting
   - Per-key rate limit enforcement
   - In-memory implementation (production should use Redis)

5. **APIKeyAuthMiddleware** (`app/middleware/api_key_middleware.py`)
   - FastAPI middleware for automatic API key authentication
   - Route-based configuration for API key requirements
   - Integration with existing authentication system

6. **API Endpoints** (`app/api/v1/endpoints/api_keys.py`)
   - REST API for API key management
   - User endpoints for key lifecycle management
   - Admin endpoints for system-wide key management

## API Key Scopes

The system supports the following predefined scopes:

- **`read_only`**: Read-only access to all endpoints
- **`read_write`**: Read and write access to user-owned resources
- **`admin`**: Administrative access to all resources
- **`gateway_management`**: Access to gateway configuration and management
- **`metrics`**: Access to metrics and monitoring data
- **`weather`**: Access to weather service endpoints

## API Endpoints

### User Endpoints

#### Create API Key
```http
POST /api/v1/keys/
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "name": "My API Key",
  "description": "Key for accessing weather data",
  "scopes": ["weather", "read_only"],
  "expires_in_days": 365,
  "rate_limit_rpm": 100,
  "allowed_ips": ["192.168.1.100"]
}
```

#### List API Keys
```http
GET /api/v1/keys/
Authorization: Bearer <jwt_token>
```

#### Get API Key Details
```http
GET /api/v1/keys/{key_id}
Authorization: Bearer <jwt_token>
```

#### Rotate API Key
```http
POST /api/v1/keys/{key_id}/rotate
Authorization: Bearer <jwt_token>
```

#### Revoke API Key
```http
DELETE /api/v1/keys/{key_id}
Authorization: Bearer <jwt_token>
```

#### Get API Key Analytics
```http
GET /api/v1/keys/{key_id}/analytics
Authorization: Bearer <jwt_token>
```

#### Get Rate Limit Status
```http
GET /api/v1/keys/{key_id}/rate-limit
Authorization: Bearer <jwt_token>
```

### Admin Endpoints

#### List All API Keys (Admin)
```http
GET /api/v1/keys/admin/all
Authorization: Bearer <admin_jwt_token>
```

#### Revoke Any API Key (Admin)
```http
DELETE /api/v1/keys/admin/{key_id}
Authorization: Bearer <admin_jwt_token>
```

#### Get System Analytics (Admin)
```http
GET /api/v1/keys/admin/analytics/summary
Authorization: Bearer <admin_jwt_token>
```

### Utility Endpoints

#### System Health
```http
GET /api/v1/keys/health
```

#### Available Scopes
```http
GET /api/v1/keys/scopes
```

## Usage Examples

### Using API Keys for Authentication

There are three ways to provide API keys:

1. **X-API-Key Header** (Recommended):
```http
GET /api/v1/gateway/services
X-API-Key: gca_abc123def456...
```

2. **Authorization Header**:
```http
GET /api/v1/gateway/services
Authorization: ApiKey gca_abc123def456...
```

3. **Query Parameter** (Not recommended for production):
```http
GET /api/v1/gateway/services?api_key=gca_abc123def456...
```

### Rate Limiting

API keys are subject to rate limiting based on their configuration:

- **Rate Limit Headers**: Responses include rate limit information
- **429 Status Code**: Returned when rate limit is exceeded
- **Retry-After Header**: Indicates when to retry the request

Example response headers:
```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 3600
X-API-Key-ID: key_1234567890_abcdef12
X-API-Key-Scopes: weather,read_only
```

### Error Responses

#### Invalid API Key
```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: ApiKey
Content-Type: application/json

{
  "detail": "Invalid API key",
  "timestamp": "2025-07-12T10:30:00Z"
}
```

#### Insufficient Scope
```http
HTTP/1.1 403 Forbidden
Content-Type: application/json

{
  "detail": "Required scope 'admin' not granted",
  "timestamp": "2025-07-12T10:30:00Z"
}
```

#### Rate Limited
```http
HTTP/1.1 429 Too Many Requests
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 3600
Retry-After: 3600
Content-Type: application/json

{
  "detail": "Rate limit exceeded",
  "rate_limit": {
    "limit": 100,
    "reset_in_seconds": 3600
  }
}
```

## Configuration

### Environment Variables

API key system behavior can be configured through environment variables:

```bash
# JWT configuration (also used by API key system)
JWT_SECRET_KEY=your-secret-key
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30

# API key system configuration
API_KEY_PREFIX=gca_
API_KEY_LENGTH=32
API_KEY_DEFAULT_EXPIRY_DAYS=365
API_KEY_MAX_KEYS_PER_USER=10
API_KEY_ENABLE_IP_RESTRICTION=true
API_KEY_ENABLE_RATE_LIMITING=true
```

### Middleware Configuration

Configure API key middleware in your FastAPI app:

```python
from app.middleware.api_key_middleware import APIKeyAuthMiddleware, create_api_key_middleware_config

# Create configuration
api_key_config = create_api_key_middleware_config(
    enable_for_all_api_routes=True,
    require_for_gateway=True,
    require_for_weather=True,
    require_for_metrics=True,
    require_for_admin=True
)

# Add middleware
app.add_middleware(APIKeyAuthMiddleware, **api_key_config)
```

## Security Considerations

### Best Practices

1. **Secure Storage**: Store API keys securely on the client side
2. **HTTPS Only**: Always use HTTPS in production
3. **Scope Principle**: Grant minimal necessary scopes
4. **Regular Rotation**: Rotate keys regularly for enhanced security
5. **Monitor Usage**: Monitor API key usage for suspicious activity
6. **IP Restrictions**: Use IP allowlisting when possible
7. **Expiration**: Set appropriate expiration dates

### Security Features

- **Hash-based Storage**: Keys are never stored in plain text
- **Automatic Expiration**: Keys automatically expire based on configuration
- **Rate Limiting**: Built-in protection against abuse
- **Audit Logging**: Comprehensive logging for security monitoring
- **IP Restrictions**: Optional IP-based access control
- **Scope Enforcement**: Fine-grained permission control

## Testing

### Running Tests

Execute the comprehensive test suite:

```bash
# Make the test script executable
chmod +x scripts/test_api_keys.py

# Run the test suite
python scripts/test_api_keys.py
```

### Test Coverage

The test suite covers:

- API key creation and validation
- Rate limiting functionality
- Scope-based access control
- Key management operations (rotate, revoke, list)
- Admin functionality
- Security features
- Error handling scenarios
- Analytics and monitoring

### Manual Testing

#### 1. Create an API Key
```bash
# Login first to get JWT token
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test@example.com&password=testpassword123"

# Create API key
curl -X POST "http://localhost:8000/api/v1/keys/" \
  -H "Authorization: Bearer <jwt_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Key",
    "description": "Testing API key",
    "scopes": ["weather", "read_only"],
    "rate_limit_rpm": 60
  }'
```

#### 2. Use the API Key
```bash
# Use the API key to access protected endpoints
curl -X GET "http://localhost:8000/api/v1/gateway/services" \
  -H "X-API-Key: <api_key_from_creation_response>"
```

#### 3. Check Rate Limiting
```bash
# Make multiple rapid requests to test rate limiting
for i in {1..70}; do
  curl -X GET "http://localhost:8000/api/v1/gateway/health" \
    -H "X-API-Key: <api_key>" \
    -w "Request $i: %{http_code}\n" \
    -s -o /dev/null
done
```

## Production Deployment

### Redis Integration

For production deployment, replace in-memory storage with Redis:

```python
import redis
from app.services.api_keys import APIKeyStore

class RedisAPIKeyStore(APIKeyStore):
    def __init__(self, redis_url: str):
        self.redis = redis.from_url(redis_url)
    
    async def store_key(self, key_hash: str, metadata: APIKeyMetadata) -> bool:
        # Implement Redis storage
        pass
    
    # Implement other methods...
```

### Database Integration

For persistent storage, integrate with your database:

```python
from sqlalchemy import create_engine
from app.services.api_keys import APIKeyStore

class DatabaseAPIKeyStore(APIKeyStore):
    def __init__(self, database_url: str):
        self.engine = create_engine(database_url)
    
    # Implement database storage methods...
```

### Monitoring Integration

Integrate with your monitoring system:

```python
import prometheus_client
from app.middleware.api_key_middleware import APIKeyMetricsCollector

class PrometheusAPIKeyMetrics(APIKeyMetricsCollector):
    def __init__(self):
        self.request_counter = prometheus_client.Counter(
            'api_key_requests_total',
            'Total API key requests',
            ['key_id', 'method', 'path', 'status']
        )
    
    def record_request(self, key_id: str, method: str, path: str, status_code: int):
        self.request_counter.labels(
            key_id=key_id,
            method=method,
            path=path,
            status=str(status_code)
        ).inc()
```

## Troubleshooting

### Common Issues

#### 1. API Key Not Working
- Check if the key is properly formatted with the correct prefix
- Verify the key hasn't expired
- Ensure the required scope is granted
- Check if IP restrictions are blocking access

#### 2. Rate Limiting Issues
- Check current rate limit status via the API
- Verify rate limit configuration
- Consider increasing limits for legitimate use cases

#### 3. Integration Issues
- Ensure middleware is properly configured
- Check middleware order (API key should come after JWT)
- Verify route protection configuration

### Debug Mode

Enable debug logging for detailed information:

```python
import logging
logging.getLogger("app.services.api_keys").setLevel(logging.DEBUG)
logging.getLogger("app.middleware.api_key_middleware").setLevel(logging.DEBUG)
```

### Health Checks

Monitor system health:

```bash
# Check API key system health
curl http://localhost:8000/api/v1/keys/health

# Check overall system health
curl http://localhost:8000/api/v1/health
```

## Migration from JWT-only

To migrate from a JWT-only system:

1. **Dual Authentication**: The system supports both JWT and API key authentication
2. **Gradual Migration**: Existing JWT users continue to work
3. **Client Choice**: Clients can choose their preferred authentication method
4. **Unified Endpoints**: Same endpoints work with both authentication types

Example dependency for dual authentication:

```python
from app.middleware.api_key_middleware import get_current_user_or_api_key

@app.get("/protected-endpoint")
async def protected_endpoint(current_user=Depends(get_current_user_or_api_key)):
    # Works with both JWT and API key authentication
    return {"user": current_user}
```

## Roadmap

### Phase 1 (Current)
- ✅ Core API key management
- ✅ Rate limiting
- ✅ Scope-based access control
- ✅ Basic analytics

### Phase 2 (Future)
- [ ] Redis integration for production storage
- [ ] Database persistence
- [ ] Advanced analytics dashboard
- [ ] Prometheus metrics integration
- [ ] Webhook notifications for key events

### Phase 3 (Future)
- [ ] Machine learning for anomaly detection
- [ ] Advanced rate limiting algorithms
- [ ] Key sharing and delegation
- [ ] Multi-tenant key management

## Support

For issues, questions, or contributions:

1. Check the troubleshooting section
2. Review the test suite for examples
3. Check the logs for detailed error information
4. Refer to the API documentation

The API Key Management system is designed to be secure, scalable, and easy to use while providing comprehensive features for modern API authentication needs.

# Weather Service Integration

This document provides information about the OpenWeatherMap.org integration in the API Gateway.

## Overview

The API Gateway now includes a comprehensive weather service that integrates with OpenWeatherMap.org to provide:

- ✅ **Current Weather Data** - Real-time weather conditions for any location
- ✅ **Weather Forecasts** - Up to 5-day forecasts with 3-hour intervals  
- ✅ **Weather Alerts** - Severe weather warnings and advisories (paid plan required)
- ✅ **Multiple Location Formats** - Search by city name or coordinates
- ✅ **Multiple Units** - Metric, Imperial, or Standard units
- ✅ **Multiple Languages** - Support for 8+ languages
- ✅ **Intelligent Caching** - Configurable response caching (default: 10 minutes)
- ✅ **Error Handling** - Comprehensive error handling and validation

## Quick Start

### 1. Get OpenWeatherMap API Key

1. Visit [OpenWeatherMap API](https://openweathermap.org/api)
2. Sign up for a free account
3. Navigate to the "API keys" section
4. Copy your API key (it may take up to 2 hours to activate)

### 2. Configure Environment

```bash
export OPENWEATHER_API_KEY='your_api_key_here'
```

### 3. Start the API Gateway

```bash
cd /Users/radekzitek/Documents/GitHub/gca-alpha/be/apigw
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### 4. Test the Weather API

```bash
# Get current weather for London
curl "http://localhost:8000/api/v1/weather/current?city=London&country=GB"

# Get weather forecast for New York
curl "http://localhost:8000/api/v1/weather/forecast?city=New York&country=US&days=3"

# Get current weather by coordinates (Paris)
curl "http://localhost:8000/api/v1/weather/current?lat=48.8566&lon=2.3522&units=metric"
```

## API Endpoints

### Current Weather

**GET** `/api/v1/weather/current`

Get current weather conditions for a location.

**Parameters:**
- `city` (string, optional): City name
- `country` (string, optional): ISO 3166 country code (e.g., US, GB, DE)
- `lat` (float, optional): Latitude (-90 to 90)
- `lon` (float, optional): Longitude (-180 to 180)
- `units` (string, optional): `metric` (default), `imperial`, or `standard`
- `lang` (string, optional): Language code (default: `en`)

**Example Requests:**
```bash
# By city name
GET /api/v1/weather/current?city=London&country=GB

# By coordinates
GET /api/v1/weather/current?lat=51.5074&lon=-0.1278

# With units and language
GET /api/v1/weather/current?city=Tokyo&country=JP&units=metric&lang=en
```

**Example Response:**
```json
{
  "location": {
    "city": "London",
    "country": "GB",
    "latitude": 51.5074,
    "longitude": -0.1278,
    "timezone": null
  },
  "current": {
    "temperature": 15.2,
    "feels_like": 13.8,
    "humidity": 72,
    "pressure": 1013,
    "visibility": 10000,
    "weather": {
      "main": "Clouds",
      "description": "overcast clouds",
      "icon": "04d"
    },
    "wind": {
      "speed": 3.6,
      "direction": 230
    },
    "clouds": 90,
    "sunrise": "2025-07-12T05:05:00",
    "sunset": "2025-07-12T21:20:00"
  },
  "units": "metric",
  "timestamp": "2025-07-12T14:30:00"
}
```

### Weather Forecast

**GET** `/api/v1/weather/forecast`

Get weather forecast for up to 5 days with 3-hour intervals.

**Parameters:**
- `city` (string, optional): City name
- `country` (string, optional): ISO 3166 country code
- `lat` (float, optional): Latitude (-90 to 90)
- `lon` (float, optional): Longitude (-180 to 180)
- `days` (integer, optional): Number of forecast days (1-5, default: 5)
- `units` (string, optional): `metric` (default), `imperial`, or `standard`
- `lang` (string, optional): Language code (default: `en`)

**Example Request:**
```bash
GET /api/v1/weather/forecast?city=Paris&country=FR&days=3&units=metric
```

### Weather Alerts

**GET** `/api/v1/weather/alerts`

Get weather alerts for specific coordinates (requires paid OpenWeatherMap subscription).

**Parameters:**
- `lat` (float, required): Latitude (-90 to 90)
- `lon` (float, required): Longitude (-180 to 180)
- `lang` (string, optional): Language code (default: `en`)

**Example Request:**
```bash
GET /api/v1/weather/alerts?lat=40.7128&lon=-74.0060
```

### Service Information

**GET** `/api/v1/weather/info`

Get information about the weather service integration.

**GET** `/api/v1/weather/health`

Check weather service health status.

## Configuration

### Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `OPENWEATHER_API_KEY` | OpenWeatherMap API key | ✅ Yes | None |

### Configuration Files

The weather service can be configured in the gateway configuration files:

**`config/gateway.yaml`:**
```yaml
integrations:
  weather:
    enabled: true
    provider: "openweathermap"
    api_timeout: 30.0
    cache_ttl: 600  # 10 minutes
    default_units: "metric"
    default_language: "en"
    rate_limit:
      calls_per_minute: 60
      calls_per_day: 1000
```

**`config/development.yaml`:**
```yaml
integrations:
  weather:
    enabled: true
    api_timeout: 60.0      # Longer timeout for debugging
    cache_ttl: 300         # Shorter cache (5 minutes)
    debug_mode: true       # Enable debug logging
    mock_responses: false  # Set to true for testing
```

**`config/services.yaml`:**
```yaml
services:
  weather-service:
    name: "weather-service"
    description: "OpenWeatherMap API integration"
    instances:
      - id: "openweathermap-api"
        url: "https://api.openweathermap.org"
    health_check:
      enabled: true
      path: "/data/2.5/weather?q=London&appid=${OPENWEATHER_API_KEY}"
      interval_seconds: 300
    circuit_breaker:
      enabled: true
      failure_threshold: 5
```

## Features

### Intelligent Caching

- **L1 Cache**: In-memory cache for fastest access
- **L2 Cache**: Redis cache for shared storage (when configured)
- **TTL Configuration**: Configurable cache duration (default: 10 minutes)
- **Cache Keys**: Automatically generated based on request parameters

### Error Handling

- **API Key Validation**: Checks for valid API key
- **Location Validation**: Validates coordinates and city names
- **Rate Limit Handling**: Proper handling of API rate limits
- **Timeout Management**: Configurable timeouts with fallbacks
- **Service Unavailability**: Graceful handling when service is down

### Multi-Language Support

Supported languages:
- `en` - English (default)
- `es` - Spanish
- `fr` - French
- `de` - German
- `it` - Italian
- `ja` - Japanese
- `zh_cn` - Chinese Simplified
- `ru` - Russian

### Multiple Units

- **`metric`** (default): Celsius, meter/sec, hPa
- **`imperial`**: Fahrenheit, miles/hour, hPa  
- **`standard`**: Kelvin, meter/sec, hPa

## Testing

### Automated Testing

Run the weather service integration test:

```bash
cd /Users/radekzitek/Documents/GitHub/gca-alpha/be/apigw
python scripts/test_weather.py
```

### Manual Testing

1. **Health Check:**
```bash
curl http://localhost:8000/api/v1/weather/health
```

2. **Service Info:**
```bash
curl http://localhost:8000/api/v1/weather/info
```

3. **Current Weather:**
```bash
curl "http://localhost:8000/api/v1/weather/current?city=London&country=GB"
```

## Rate Limits & Pricing

### Free Tier (Default)
- **1,000 calls/day**
- **60 calls/minute**
- Current weather and 5-day forecast included
- Weather alerts **NOT** included

### Paid Plans
- Higher rate limits
- Weather alerts included
- Historical weather data
- Extended forecasts

Visit [OpenWeatherMap Pricing](https://openweathermap.org/price) for details.

## API Documentation

When the gateway is running, visit:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## Troubleshooting

### Common Issues

1. **"Invalid API key" Error**
   - Verify your API key is correct
   - Ensure API key is activated (can take up to 2 hours)
   - Check if you're using the correct environment variable name

2. **"Location not found" Error**
   - Check city name spelling
   - Try adding country code
   - Use coordinates instead of city name

3. **"Rate limit exceeded" Error**
   - You've exceeded the free tier limits
   - Wait for the limit to reset (daily/monthly)
   - Consider upgrading to a paid plan

4. **"Request timeout" Error**
   - Check your internet connection
   - OpenWeatherMap service may be temporarily down
   - Increase timeout in configuration

### Debug Mode

Enable debug mode in development configuration:

```yaml
integrations:
  weather:
    debug_mode: true
```

This will provide detailed logging of all weather service requests and responses.

### Mock Responses

For testing without API calls, enable mock responses:

```yaml
integrations:
  weather:
    mock_responses: true
```

## Integration Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   API Gateway   │    │ Weather Service │    │ OpenWeatherMap  │
│                 │    │                 │    │      API        │
│  ┌───────────┐  │    │  ┌───────────┐  │    │                 │
│  │ Weather   │  │───▶│  │ HTTP      │  │───▶│  Current        │
│  │ Endpoints │  │    │  │ Client    │  │    │  Weather        │
│  └───────────┘  │    │  └───────────┘  │    │                 │
│                 │    │  ┌───────────┐  │    │  Forecasts      │
│  ┌───────────┐  │    │  │ Cache     │  │    │                 │
│  │ Cache     │  │    │  │ Manager   │  │    │  Alerts         │
│  │ Layer     │  │    │  └───────────┘  │    │                 │
│  └───────────┘  │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Security Considerations

- **API Key Protection**: Never expose API keys in client-side code
- **Rate Limiting**: Implement application-level rate limiting
- **Input Validation**: All inputs are validated before API calls
- **Error Sanitization**: Sensitive error details are not exposed to clients
- **HTTPS Only**: All API calls use HTTPS encryption

## Performance Optimization

- **Connection Pooling**: HTTP connections are pooled for efficiency
- **Caching Strategy**: Intelligent caching reduces API calls
- **Async Operations**: All operations are fully asynchronous
- **Error Circuit Breaker**: Prevents cascading failures
- **Timeout Management**: Prevents hanging requests

## Monitoring

The weather service includes comprehensive monitoring:

- **Health Checks**: Regular service health verification
- **Metrics Collection**: Request/response metrics
- **Error Tracking**: Detailed error logging
- **Performance Monitoring**: Response time tracking
- **Cache Hit Rates**: Cache performance metrics

Access metrics at: http://localhost:8000/api/v1/metrics

---

For more information about the API Gateway architecture, see the main [README.md](../README.md) and [architecture documentation](docs/architecture.md).

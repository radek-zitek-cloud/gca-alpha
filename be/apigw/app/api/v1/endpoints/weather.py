"""
Weather API endpoints for the API Gateway.

This module provides RESTful endpoints for accessing weather data
through the OpenWeatherMap service integration.
"""

from typing import Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Query, Depends
from fastapi.responses import JSONResponse

from app.services.weather_service import WeatherService, WeatherServiceError


router = APIRouter(prefix="/weather", tags=["weather"])


def get_weather_service() -> WeatherService:
    """
    Dependency to get weather service instance.
    
    Returns:
        WeatherService instance
        
    Raises:
        HTTPException: If API key is not configured
    """
    import os
    
    api_key = os.getenv("OPENWEATHER_API_KEY")
    if not api_key:
        raise HTTPException(
            status_code=500,
            detail="OpenWeatherMap API key not configured. Please set OPENWEATHER_API_KEY environment variable."
        )
    
    return WeatherService(api_key=api_key)


@router.get("/current")
async def get_current_weather(
    city: Optional[str] = Query(None, description="City name"),
    country: Optional[str] = Query(None, description="ISO 3166 country code (e.g., US, GB, DE)"),
    lat: Optional[float] = Query(None, description="Latitude (-90 to 90)"),
    lon: Optional[float] = Query(None, description="Longitude (-180 to 180)"),
    units: str = Query("metric", description="Units: standard, metric, imperial"),
    lang: str = Query("en", description="Language code (e.g., en, es, fr, de)"),
    weather_service: WeatherService = Depends(get_weather_service)
) -> Dict[str, Any]:
    """
    Get current weather data.
    
    You can specify location either by:
    - City name (optionally with country code)
    - Latitude and longitude coordinates
    
    **Parameters:**
    - **city**: City name (required if lat/lon not provided)
    - **country**: ISO 3166 country code (optional, helps with city disambiguation)
    - **lat**: Latitude in decimal degrees (required if city not provided)
    - **lon**: Longitude in decimal degrees (required if city not provided)
    - **units**: Temperature units
        - `standard`: Kelvin, meter/sec, hPa
        - `metric`: Celsius, meter/sec, hPa (default)
        - `imperial`: Fahrenheit, miles/hour, hPa
    - **lang**: Language for weather descriptions (ISO 639-1 codes)
    
    **Example requests:**
    - `/weather/current?city=London&country=GB`
    - `/weather/current?lat=51.5074&lon=-0.1278`
    - `/weather/current?city=New York&units=imperial&lang=en`
    """
    try:
        # Validate input parameters
        if not city and (lat is None or lon is None):
            raise HTTPException(
                status_code=400,
                detail="Either 'city' or both 'lat' and 'lon' parameters must be provided"
            )
        
        if lat is not None and (lat < -90 or lat > 90):
            raise HTTPException(
                status_code=400,
                detail="Latitude must be between -90 and 90 degrees"
            )
        
        if lon is not None and (lon < -180 or lon > 180):
            raise HTTPException(
                status_code=400,
                detail="Longitude must be between -180 and 180 degrees"
            )
        
        if units not in ["standard", "metric", "imperial"]:
            raise HTTPException(
                status_code=400,
                detail="Units must be one of: standard, metric, imperial"
            )
        
        # Get weather data
        weather_data = await weather_service.get_current_weather(
            city=city,
            country_code=country,
            latitude=lat,
            longitude=lon,
            units=units,
            lang=lang
        )
        
        return weather_data
        
    except WeatherServiceError as e:
        if "Invalid API key" in str(e):
            raise HTTPException(status_code=401, detail="Invalid OpenWeatherMap API key")
        elif "Location not found" in str(e):
            raise HTTPException(status_code=404, detail="Location not found")
        elif "rate limit" in str(e).lower():
            raise HTTPException(status_code=429, detail="API rate limit exceeded")
        else:
            raise HTTPException(status_code=500, detail=f"Weather service error: {str(e)}")
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.get("/forecast")
async def get_weather_forecast(
    city: Optional[str] = Query(None, description="City name"),
    country: Optional[str] = Query(None, description="ISO 3166 country code (e.g., US, GB, DE)"),
    lat: Optional[float] = Query(None, description="Latitude (-90 to 90)"),
    lon: Optional[float] = Query(None, description="Longitude (-180 to 180)"),
    days: int = Query(5, description="Number of forecast days (1-5)", ge=1, le=5),
    units: str = Query("metric", description="Units: standard, metric, imperial"),
    lang: str = Query("en", description="Language code (e.g., en, es, fr, de)"),
    weather_service: WeatherService = Depends(get_weather_service)
) -> Dict[str, Any]:
    """
    Get weather forecast data.
    
    Returns weather forecast for up to 5 days with 3-hour intervals.
    
    **Parameters:**
    - **city**: City name (required if lat/lon not provided)
    - **country**: ISO 3166 country code (optional, helps with city disambiguation)
    - **lat**: Latitude in decimal degrees (required if city not provided)
    - **lon**: Longitude in decimal degrees (required if city not provided)
    - **days**: Number of forecast days (1-5, default: 5)
    - **units**: Temperature units
        - `standard`: Kelvin, meter/sec, hPa
        - `metric`: Celsius, meter/sec, hPa (default)
        - `imperial`: Fahrenheit, miles/hour, hPa
    - **lang**: Language for weather descriptions (ISO 639-1 codes)
    
    **Example requests:**
    - `/weather/forecast?city=Paris&country=FR&days=3`
    - `/weather/forecast?lat=48.8566&lon=2.3522&units=imperial`
    """
    try:
        # Validate input parameters
        if not city and (lat is None or lon is None):
            raise HTTPException(
                status_code=400,
                detail="Either 'city' or both 'lat' and 'lon' parameters must be provided"
            )
        
        if lat is not None and (lat < -90 or lat > 90):
            raise HTTPException(
                status_code=400,
                detail="Latitude must be between -90 and 90 degrees"
            )
        
        if lon is not None and (lon < -180 or lon > 180):
            raise HTTPException(
                status_code=400,
                detail="Longitude must be between -180 and 180 degrees"
            )
        
        if units not in ["standard", "metric", "imperial"]:
            raise HTTPException(
                status_code=400,
                detail="Units must be one of: standard, metric, imperial"
            )
        
        # Get forecast data
        forecast_data = await weather_service.get_forecast(
            city=city,
            country_code=country,
            latitude=lat,
            longitude=lon,
            days=days,
            units=units,
            lang=lang
        )
        
        return forecast_data
        
    except WeatherServiceError as e:
        if "Invalid API key" in str(e):
            raise HTTPException(status_code=401, detail="Invalid OpenWeatherMap API key")
        elif "Location not found" in str(e):
            raise HTTPException(status_code=404, detail="Location not found")
        elif "rate limit" in str(e).lower():
            raise HTTPException(status_code=429, detail="API rate limit exceeded")
        else:
            raise HTTPException(status_code=500, detail=f"Weather service error: {str(e)}")
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.get("/alerts")
async def get_weather_alerts(
    lat: float = Query(..., description="Latitude (-90 to 90)"),
    lon: float = Query(..., description="Longitude (-180 to 180)"),
    lang: str = Query("en", description="Language code (e.g., en, es, fr, de)"),
    weather_service: WeatherService = Depends(get_weather_service)
) -> Dict[str, Any]:
    """
    Get weather alerts for specific coordinates.
    
    Returns active weather alerts such as severe weather warnings,
    watches, and advisories for the specified location.
    
    **Parameters:**
    - **lat**: Latitude in decimal degrees (required)
    - **lon**: Longitude in decimal degrees (required)
    - **lang**: Language for alert descriptions (ISO 639-1 codes)
    
    **Example requests:**
    - `/weather/alerts?lat=40.7128&lon=-74.0060` (New York City)
    - `/weather/alerts?lat=51.5074&lon=-0.1278&lang=en` (London)
    
    **Note:** Weather alerts are only available for some regions and
    require OpenWeatherMap One Call API subscription.
    """
    try:
        # Validate coordinates
        if lat < -90 or lat > 90:
            raise HTTPException(
                status_code=400,
                detail="Latitude must be between -90 and 90 degrees"
            )
        
        if lon < -180 or lon > 180:
            raise HTTPException(
                status_code=400,
                detail="Longitude must be between -180 and 180 degrees"
            )
        
        # Get weather alerts
        alerts_data = await weather_service.get_alerts(
            latitude=lat,
            longitude=lon,
            lang=lang
        )
        
        return alerts_data
        
    except WeatherServiceError as e:
        if "Invalid API key" in str(e):
            raise HTTPException(status_code=401, detail="Invalid OpenWeatherMap API key")
        elif "rate limit" in str(e).lower():
            raise HTTPException(status_code=429, detail="API rate limit exceeded")
        else:
            raise HTTPException(status_code=500, detail=f"Weather service error: {str(e)}")
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.get("/info")
async def get_weather_service_info() -> Dict[str, Any]:
    """
    Get information about the weather service.
    
    Returns metadata about the weather service integration,
    including supported features, API limits, and configuration.
    """
    import os
    
    return {
        "service": "OpenWeatherMap",
        "version": "2.5 / 3.0",
        "endpoints": {
            "current_weather": "/weather/current",
            "forecast": "/weather/forecast",
            "alerts": "/weather/alerts"
        },
        "features": {
            "current_weather": True,
            "forecast": True,
            "alerts": True,
            "caching": True,
            "multiple_languages": True,
            "multiple_units": True
        },
        "supported_units": ["standard", "metric", "imperial"],
        "supported_languages": [
            "en", "es", "fr", "de", "it", "ja", "zh_cn", "ru"
        ],
        "limits": {
            "forecast_days": 5,
            "cache_ttl_seconds": 600,
            "rate_limit": "1000 calls/day (free tier)"
        },
        "configuration": {
            "api_key_configured": bool(os.getenv("OPENWEATHER_API_KEY")),
            "api_key_source": "Environment variable: OPENWEATHER_API_KEY"
        }
    }


@router.get("/health")
async def weather_service_health(
    weather_service: WeatherService = Depends(get_weather_service)
) -> Dict[str, Any]:
    """
    Check weather service health.
    
    Performs a lightweight health check by making a test API call
    to verify the service is accessible and the API key is valid.
    """
    try:
        # Make a lightweight test call (get weather for London)
        await weather_service.get_current_weather(
            city="London",
            country_code="GB",
            units="metric",
            lang="en"
        )
        
        return {
            "status": "healthy",
            "service": "OpenWeatherMap",
            "api_accessible": True,
            "api_key_valid": True,
            "timestamp": "2025-07-12T10:30:00Z"
        }
        
    except WeatherServiceError as e:
        status = "unhealthy"
        api_accessible = True
        api_key_valid = True
        
        if "Invalid API key" in str(e):
            api_key_valid = False
        elif "timeout" in str(e).lower() or "connection" in str(e).lower():
            api_accessible = False
        
        return JSONResponse(
            status_code=503,
            content={
                "status": status,
                "service": "OpenWeatherMap",
                "api_accessible": api_accessible,
                "api_key_valid": api_key_valid,
                "error": str(e),
                "timestamp": "2025-07-12T10:30:00Z"
            }
        )
    
    except Exception as e:
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy", 
                "service": "OpenWeatherMap",
                "api_accessible": False,
                "api_key_valid": False,
                "error": f"Health check failed: {str(e)}",
                "timestamp": "2025-07-12T10:30:00Z"
            }
        )

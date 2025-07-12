"""
Weather service integration for OpenWeatherMap.org

This module provides weather data retrieval functionality using the
OpenWeatherMap API, including current weather, forecasts, and weather alerts.
"""

import asyncio
import httpx
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from enum import Enum

from app.config.settings import ConfigLoader


class WeatherUnits(str, Enum):
    """Weather units for API requests."""
    STANDARD = "standard"  # Kelvin, meter/sec, hPa
    METRIC = "metric"      # Celsius, meter/sec, hPa
    IMPERIAL = "imperial"  # Fahrenheit, miles/hour, hPa


class WeatherLang(str, Enum):
    """Supported languages for weather descriptions."""
    EN = "en"  # English
    ES = "es"  # Spanish
    FR = "fr"  # French
    DE = "de"  # German
    IT = "it"  # Italian
    JA = "ja"  # Japanese
    ZH_CN = "zh_cn"  # Chinese Simplified
    RU = "ru"  # Russian


@dataclass
class WeatherLocation:
    """Weather location data."""
    city: str
    country: str
    latitude: float
    longitude: float
    timezone: Optional[str] = None


@dataclass
class CurrentWeather:
    """Current weather data."""
    location: WeatherLocation
    temperature: float
    feels_like: float
    humidity: int
    pressure: int
    visibility: Optional[int]
    uv_index: Optional[float]
    weather_main: str
    weather_description: str
    weather_icon: str
    wind_speed: float
    wind_direction: int
    cloudiness: int
    sunrise: datetime
    sunset: datetime
    timestamp: datetime
    units: WeatherUnits


@dataclass
class WeatherForecast:
    """Weather forecast data."""
    location: WeatherLocation
    forecasts: List[Dict[str, Any]]
    units: WeatherUnits
    timestamp: datetime


@dataclass
class WeatherAlert:
    """Weather alert data."""
    sender_name: str
    event: str
    start: datetime
    end: datetime
    description: str
    tags: List[str]


class WeatherServiceError(Exception):
    """Custom exception for weather service errors."""
    pass


class OpenWeatherMapClient:
    """
    OpenWeatherMap API client for fetching weather data.
    
    This client handles all interactions with the OpenWeatherMap API,
    including current weather, forecasts, and weather alerts.
    """
    
    BASE_URL = "https://api.openweathermap.org"
    
    def __init__(self, api_key: str, timeout: float = 30.0, cache_ttl: int = 600):
        """
        Initialize the OpenWeatherMap client.
        
        Args:
            api_key: OpenWeatherMap API key
            timeout: Request timeout in seconds
            cache_ttl: Cache TTL in seconds (default: 10 minutes)
        """
        self.api_key = api_key
        self.timeout = httpx.Timeout(timeout)
        self.cache_ttl = cache_ttl
        self._cache: Dict[str, Dict[str, Any]] = {}
        
        # HTTP client configuration
        self.client = httpx.AsyncClient(
            timeout=self.timeout,
            headers={
                "User-Agent": "API-Gateway-Weather-Service/1.0",
                "Accept": "application/json",
            }
        )
    
    async def __aenter__(self):
        """Async context manager entry."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
    
    async def close(self):
        """Close the HTTP client."""
        await self.client.aclose()
    
    def _get_cache_key(self, endpoint: str, params: Dict[str, Any]) -> str:
        """Generate cache key for request."""
        params_str = json.dumps(params, sort_keys=True)
        return f"{endpoint}:{hash(params_str)}"
    
    def _is_cache_valid(self, cache_entry: Dict[str, Any]) -> bool:
        """Check if cache entry is still valid."""
        if not cache_entry:
            return False
        
        cached_time = datetime.fromisoformat(cache_entry["timestamp"])
        return datetime.utcnow() - cached_time < timedelta(seconds=self.cache_ttl)
    
    def _get_from_cache(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get data from cache if valid."""
        cache_entry = self._cache.get(cache_key)
        if cache_entry and self._is_cache_valid(cache_entry):
            return cache_entry["data"]
        return None
    
    def _store_in_cache(self, cache_key: str, data: Dict[str, Any]):
        """Store data in cache."""
        self._cache[cache_key] = {
            "data": data,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    async def _make_request(self, endpoint: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Make HTTP request to OpenWeatherMap API.
        
        Args:
            endpoint: API endpoint
            params: Query parameters
            
        Returns:
            API response data
            
        Raises:
            WeatherServiceError: If request fails
        """
        # Add API key to parameters
        params["appid"] = self.api_key
        
        # Check cache first
        cache_key = self._get_cache_key(endpoint, params)
        cached_data = self._get_from_cache(cache_key)
        if cached_data:
            return cached_data
        
        url = f"{self.BASE_URL}{endpoint}"
        
        try:
            response = await self.client.get(url, params=params)
            response.raise_for_status()
            
            data = response.json()
            
            # Store in cache
            self._store_in_cache(cache_key, data)
            
            return data
            
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise WeatherServiceError("Invalid API key") from e
            elif e.response.status_code == 404:
                raise WeatherServiceError("Location not found") from e
            elif e.response.status_code == 429:
                raise WeatherServiceError("API rate limit exceeded") from e
            else:
                raise WeatherServiceError(f"API request failed: {e.response.status_code}") from e
                
        except httpx.TimeoutException as e:
            raise WeatherServiceError("Request timeout") from e
            
        except httpx.RequestError as e:
            raise WeatherServiceError(f"Request error: {str(e)}") from e
    
    async def get_current_weather_by_city(
        self,
        city: str,
        country_code: Optional[str] = None,
        units: WeatherUnits = WeatherUnits.METRIC,
        lang: WeatherLang = WeatherLang.EN
    ) -> CurrentWeather:
        """
        Get current weather by city name.
        
        Args:
            city: City name
            country_code: ISO 3166 country code (optional)
            units: Temperature units
            lang: Language for weather descriptions
            
        Returns:
            Current weather data
        """
        # Construct location query
        location_query = city
        if country_code:
            location_query = f"{city},{country_code}"
        
        params = {
            "q": location_query,
            "units": units.value,
            "lang": lang.value
        }
        
        data = await self._make_request("/data/2.5/weather", params)
        return self._parse_current_weather(data, units)
    
    async def get_current_weather_by_coordinates(
        self,
        latitude: float,
        longitude: float,
        units: WeatherUnits = WeatherUnits.METRIC,
        lang: WeatherLang = WeatherLang.EN
    ) -> CurrentWeather:
        """
        Get current weather by coordinates.
        
        Args:
            latitude: Latitude
            longitude: Longitude
            units: Temperature units
            lang: Language for weather descriptions
            
        Returns:
            Current weather data
        """
        params = {
            "lat": latitude,
            "lon": longitude,
            "units": units.value,
            "lang": lang.value
        }
        
        data = await self._make_request("/data/2.5/weather", params)
        return self._parse_current_weather(data, units)
    
    async def get_weather_forecast(
        self,
        city: str,
        country_code: Optional[str] = None,
        days: int = 5,
        units: WeatherUnits = WeatherUnits.METRIC,
        lang: WeatherLang = WeatherLang.EN
    ) -> WeatherForecast:
        """
        Get weather forecast by city name.
        
        Args:
            city: City name
            country_code: ISO 3166 country code (optional)
            days: Number of forecast days (1-5)
            units: Temperature units
            lang: Language for weather descriptions
            
        Returns:
            Weather forecast data
        """
        # Construct location query
        location_query = city
        if country_code:
            location_query = f"{city},{country_code}"
        
        params = {
            "q": location_query,
            "cnt": min(days * 8, 40),  # 8 forecasts per day, max 40
            "units": units.value,
            "lang": lang.value
        }
        
        data = await self._make_request("/data/2.5/forecast", params)
        return self._parse_weather_forecast(data, units)
    
    async def get_weather_forecast_by_coordinates(
        self,
        latitude: float,
        longitude: float,
        days: int = 5,
        units: WeatherUnits = WeatherUnits.METRIC,
        lang: WeatherLang = WeatherLang.EN
    ) -> WeatherForecast:
        """
        Get weather forecast by coordinates.
        
        Args:
            latitude: Latitude
            longitude: Longitude
            days: Number of forecast days (1-5)
            units: Temperature units
            lang: Language for weather descriptions
            
        Returns:
            Weather forecast data
        """
        params = {
            "lat": latitude,
            "lon": longitude,
            "cnt": min(days * 8, 40),  # 8 forecasts per day, max 40
            "units": units.value,
            "lang": lang.value
        }
        
        data = await self._make_request("/data/2.5/forecast", params)
        return self._parse_weather_forecast(data, units)
    
    async def get_weather_alerts(
        self,
        latitude: float,
        longitude: float,
        lang: WeatherLang = WeatherLang.EN
    ) -> List[WeatherAlert]:
        """
        Get weather alerts for coordinates.
        
        Args:
            latitude: Latitude
            longitude: Longitude
            lang: Language for alert descriptions
            
        Returns:
            List of weather alerts
        """
        params = {
            "lat": latitude,
            "lon": longitude,
            "exclude": "minutely,hourly,daily",
            "lang": lang.value
        }
        
        data = await self._make_request("/data/3.0/onecall", params)
        
        alerts_data = data.get("alerts", [])
        alerts = []
        
        for alert_data in alerts_data:
            alert = WeatherAlert(
                sender_name=alert_data.get("sender_name", ""),
                event=alert_data.get("event", ""),
                start=datetime.fromtimestamp(alert_data.get("start", 0)),
                end=datetime.fromtimestamp(alert_data.get("end", 0)),
                description=alert_data.get("description", ""),
                tags=alert_data.get("tags", [])
            )
            alerts.append(alert)
        
        return alerts
    
    def _parse_current_weather(self, data: Dict[str, Any], units: WeatherUnits) -> CurrentWeather:
        """Parse current weather API response."""
        location = WeatherLocation(
            city=data["name"],
            country=data["sys"]["country"],
            latitude=data["coord"]["lat"],
            longitude=data["coord"]["lon"]
        )
        
        main_data = data["main"]
        weather_data = data["weather"][0]
        wind_data = data.get("wind", {})
        sys_data = data["sys"]
        
        return CurrentWeather(
            location=location,
            temperature=main_data["temp"],
            feels_like=main_data["feels_like"],
            humidity=main_data["humidity"],
            pressure=main_data["pressure"],
            visibility=data.get("visibility"),
            uv_index=None,  # Not available in current weather endpoint
            weather_main=weather_data["main"],
            weather_description=weather_data["description"],
            weather_icon=weather_data["icon"],
            wind_speed=wind_data.get("speed", 0),
            wind_direction=wind_data.get("deg", 0),
            cloudiness=data["clouds"]["all"],
            sunrise=datetime.fromtimestamp(sys_data["sunrise"]),
            sunset=datetime.fromtimestamp(sys_data["sunset"]),
            timestamp=datetime.fromtimestamp(data["dt"]),
            units=units
        )
    
    def _parse_weather_forecast(self, data: Dict[str, Any], units: WeatherUnits) -> WeatherForecast:
        """Parse weather forecast API response."""
        city_data = data["city"]
        location = WeatherLocation(
            city=city_data["name"],
            country=city_data["country"],
            latitude=city_data["coord"]["lat"],
            longitude=city_data["coord"]["lon"],
            timezone=city_data.get("timezone")
        )
        
        forecasts = []
        for forecast_data in data["list"]:
            forecast = {
                "datetime": datetime.fromtimestamp(forecast_data["dt"]),
                "temperature": forecast_data["main"]["temp"],
                "feels_like": forecast_data["main"]["feels_like"],
                "temp_min": forecast_data["main"]["temp_min"],
                "temp_max": forecast_data["main"]["temp_max"],
                "pressure": forecast_data["main"]["pressure"],
                "humidity": forecast_data["main"]["humidity"],
                "weather_main": forecast_data["weather"][0]["main"],
                "weather_description": forecast_data["weather"][0]["description"],
                "weather_icon": forecast_data["weather"][0]["icon"],
                "clouds": forecast_data["clouds"]["all"],
                "wind_speed": forecast_data.get("wind", {}).get("speed", 0),
                "wind_direction": forecast_data.get("wind", {}).get("deg", 0),
                "visibility": forecast_data.get("visibility"),
                "pop": forecast_data.get("pop", 0),  # Probability of precipitation
            }
            forecasts.append(forecast)
        
        return WeatherForecast(
            location=location,
            forecasts=forecasts,
            units=units,
            timestamp=datetime.utcnow()
        )


class WeatherService:
    """
    High-level weather service for the API Gateway.
    
    This service provides a simplified interface for weather operations
    and integrates with the service registry.
    """
    
    def __init__(self, api_key: str):
        """
        Initialize weather service.
        
        Args:
            api_key: OpenWeatherMap API key
        """
        self.api_key = api_key
        self._client: Optional[OpenWeatherMapClient] = None
    
    async def get_client(self) -> OpenWeatherMapClient:
        """Get or create OpenWeatherMap client."""
        if not self._client:
            # Load configuration for weather service settings
            config_loader = ConfigLoader()
            config = config_loader.load_config()
            
            # Get weather-specific configuration from raw config
            weather_config = config.raw_config.get('weather', {})
            timeout = weather_config.get('api_timeout', 30.0)
            cache_ttl = weather_config.get('cache_ttl', 600)
            
            self._client = OpenWeatherMapClient(
                api_key=self.api_key,
                timeout=timeout,
                cache_ttl=cache_ttl
            )
        return self._client
    
    async def get_current_weather(
        self,
        city: Optional[str] = None,
        country_code: Optional[str] = None,
        latitude: Optional[float] = None,
        longitude: Optional[float] = None,
        units: str = "metric",
        lang: str = "en"
    ) -> Dict[str, Any]:
        """
        Get current weather data.
        
        Args:
            city: City name
            country_code: ISO 3166 country code
            latitude: Latitude (if not using city)
            longitude: Longitude (if not using city)
            units: Temperature units (standard, metric, imperial)
            lang: Language code
            
        Returns:
            Current weather data as dictionary
        """
        client = await self.get_client()
        
        try:
            weather_units = WeatherUnits(units)
            weather_lang = WeatherLang(lang)
            
            if city:
                weather = await client.get_current_weather_by_city(
                    city=city,
                    country_code=country_code,
                    units=weather_units,
                    lang=weather_lang
                )
            elif latitude is not None and longitude is not None:
                weather = await client.get_current_weather_by_coordinates(
                    latitude=latitude,
                    longitude=longitude,
                    units=weather_units,
                    lang=weather_lang
                )
            else:
                raise WeatherServiceError("Either city or coordinates must be provided")
            
            # Convert to dictionary for API response
            return {
                "location": {
                    "city": weather.location.city,
                    "country": weather.location.country,
                    "latitude": weather.location.latitude,
                    "longitude": weather.location.longitude,
                    "timezone": weather.location.timezone
                },
                "current": {
                    "temperature": weather.temperature,
                    "feels_like": weather.feels_like,
                    "humidity": weather.humidity,
                    "pressure": weather.pressure,
                    "visibility": weather.visibility,
                    "uv_index": weather.uv_index,
                    "weather": {
                        "main": weather.weather_main,
                        "description": weather.weather_description,
                        "icon": weather.weather_icon
                    },
                    "wind": {
                        "speed": weather.wind_speed,
                        "direction": weather.wind_direction
                    },
                    "clouds": weather.cloudiness,
                    "sunrise": weather.sunrise.isoformat(),
                    "sunset": weather.sunset.isoformat()
                },
                "units": weather.units.value,
                "timestamp": weather.timestamp.isoformat()
            }
            
        except ValueError as e:
            raise WeatherServiceError(f"Invalid parameter: {str(e)}") from e
    
    async def get_forecast(
        self,
        city: Optional[str] = None,
        country_code: Optional[str] = None,
        latitude: Optional[float] = None,
        longitude: Optional[float] = None,
        days: int = 5,
        units: str = "metric",
        lang: str = "en"
    ) -> Dict[str, Any]:
        """
        Get weather forecast data.
        
        Args:
            city: City name
            country_code: ISO 3166 country code
            latitude: Latitude (if not using city)
            longitude: Longitude (if not using city)
            days: Number of forecast days (1-5)
            units: Temperature units (standard, metric, imperial)
            lang: Language code
            
        Returns:
            Weather forecast data as dictionary
        """
        client = await self.get_client()
        
        try:
            weather_units = WeatherUnits(units)
            weather_lang = WeatherLang(lang)
            
            if city:
                forecast = await client.get_weather_forecast(
                    city=city,
                    country_code=country_code,
                    days=days,
                    units=weather_units,
                    lang=weather_lang
                )
            elif latitude is not None and longitude is not None:
                forecast = await client.get_weather_forecast_by_coordinates(
                    latitude=latitude,
                    longitude=longitude,
                    days=days,
                    units=weather_units,
                    lang=weather_lang
                )
            else:
                raise WeatherServiceError("Either city or coordinates must be provided")
            
            # Convert to dictionary for API response
            return {
                "location": {
                    "city": forecast.location.city,
                    "country": forecast.location.country,
                    "latitude": forecast.location.latitude,
                    "longitude": forecast.location.longitude,
                    "timezone": forecast.location.timezone
                },
                "forecast": [
                    {
                        "datetime": f["datetime"].isoformat(),
                        "temperature": f["temperature"],
                        "feels_like": f["feels_like"],
                        "temp_min": f["temp_min"],
                        "temp_max": f["temp_max"],
                        "pressure": f["pressure"],
                        "humidity": f["humidity"],
                        "weather": {
                            "main": f["weather_main"],
                            "description": f["weather_description"],
                            "icon": f["weather_icon"]
                        },
                        "clouds": f["clouds"],
                        "wind": {
                            "speed": f["wind_speed"],
                            "direction": f["wind_direction"]
                        },
                        "visibility": f["visibility"],
                        "precipitation_probability": f["pop"]
                    }
                    for f in forecast.forecasts
                ],
                "units": forecast.units.value,
                "timestamp": forecast.timestamp.isoformat()
            }
            
        except ValueError as e:
            raise WeatherServiceError(f"Invalid parameter: {str(e)}") from e
    
    async def get_alerts(
        self,
        latitude: float,
        longitude: float,
        lang: str = "en"
    ) -> Dict[str, Any]:
        """
        Get weather alerts for coordinates.
        
        Args:
            latitude: Latitude
            longitude: Longitude
            lang: Language code
            
        Returns:
            Weather alerts data as dictionary
        """
        client = await self.get_client()
        
        try:
            weather_lang = WeatherLang(lang)
            alerts = await client.get_weather_alerts(
                latitude=latitude,
                longitude=longitude,
                lang=weather_lang
            )
            
            return {
                "location": {
                    "latitude": latitude,
                    "longitude": longitude
                },
                "alerts": [
                    {
                        "sender": alert.sender_name,
                        "event": alert.event,
                        "start": alert.start.isoformat(),
                        "end": alert.end.isoformat(),
                        "description": alert.description,
                        "tags": alert.tags
                    }
                    for alert in alerts
                ],
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except ValueError as e:
            raise WeatherServiceError(f"Invalid parameter: {str(e)}") from e
    
    async def cleanup(self):
        """Cleanup resources."""
        if self._client:
            await self._client.close()

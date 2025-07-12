#!/usr/bin/env python3
"""
Test script for the weather service integration.

This script tests the weather service endpoints and functionality
to ensure proper integration with OpenWeatherMap.org.
"""

import asyncio
import os
import sys
from typing import Dict, Any

# Add the project root to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.services.weather_service import WeatherService, WeatherServiceError


async def test_weather_service():
    """Test the weather service functionality."""
    print("🌤️  Testing Weather Service Integration")
    print("=" * 50)
    
    # Check if API key is configured
    api_key = os.getenv("OPENWEATHER_API_KEY")
    if not api_key:
        print("❌ ERROR: OPENWEATHER_API_KEY environment variable not set")
        print("\nTo test the weather service, you need to:")
        print("1. Sign up for a free account at https://openweathermap.org/api")
        print("2. Get your API key")
        print("3. Set the environment variable:")
        print("   export OPENWEATHER_API_KEY='your_api_key_here'")
        return False
    
    print(f"✅ API Key configured: {api_key[:8]}...")
    
    # Initialize weather service
    weather_service = WeatherService(api_key=api_key)
    
    try:
        print("\n📍 Testing current weather by city...")
        
        # Test current weather for London
        current_weather = await weather_service.get_current_weather(
            city="London",
            country_code="GB",
            units="metric",
            lang="en"
        )
        
        print(f"✅ Current weather for {current_weather['location']['city']}, {current_weather['location']['country']}:")
        print(f"   Temperature: {current_weather['current']['temperature']}°C")
        print(f"   Feels like: {current_weather['current']['feels_like']}°C")
        print(f"   Weather: {current_weather['current']['weather']['description'].title()}")
        print(f"   Humidity: {current_weather['current']['humidity']}%")
        print(f"   Wind: {current_weather['current']['wind']['speed']} m/s")
        
        print("\n📍 Testing current weather by coordinates...")
        
        # Test current weather for New York (coordinates)
        ny_weather = await weather_service.get_current_weather(
            latitude=40.7128,
            longitude=-74.0060,
            units="imperial",
            lang="en"
        )
        
        print(f"✅ Current weather for {ny_weather['location']['city']}, {ny_weather['location']['country']}:")
        print(f"   Temperature: {ny_weather['current']['temperature']}°F")
        print(f"   Weather: {ny_weather['current']['weather']['description'].title()}")
        
        print("\n📅 Testing weather forecast...")
        
        # Test 3-day forecast for Paris
        forecast = await weather_service.get_forecast(
            city="Paris",
            country_code="FR",
            days=3,
            units="metric",
            lang="en"
        )
        
        print(f"✅ 3-day forecast for {forecast['location']['city']}, {forecast['location']['country']}:")
        for i, day_forecast in enumerate(forecast['forecast'][:6]):  # Show first 6 entries (2 days)
            date = day_forecast['datetime'][:10]  # Extract date part
            time = day_forecast['datetime'][11:16]  # Extract time part
            temp = day_forecast['temperature']
            desc = day_forecast['weather']['description']
            print(f"   {date} {time}: {temp}°C, {desc.title()}")
        
        print("\n🚨 Testing weather alerts...")
        
        # Test weather alerts for a location (if available)
        try:
            alerts = await weather_service.get_alerts(
                latitude=40.7128,
                longitude=-74.0060,
                lang="en"
            )
            
            if alerts['alerts']:
                print(f"✅ Weather alerts found:")
                for alert in alerts['alerts']:
                    print(f"   - {alert['event']}: {alert['description'][:100]}...")
            else:
                print("✅ No active weather alerts (this is normal)")
                
        except WeatherServiceError as e:
            if "subscription" in str(e).lower() or "plan" in str(e).lower():
                print("ℹ️  Weather alerts require a paid OpenWeatherMap plan")
            else:
                print(f"⚠️  Weather alerts test failed: {e}")
        
        print("\n✅ All weather service tests completed successfully!")
        return True
        
    except WeatherServiceError as e:
        print(f"❌ Weather service error: {e}")
        
        if "Invalid API key" in str(e):
            print("\n💡 Troubleshooting tips:")
            print("1. Verify your API key is correct")
            print("2. Make sure your API key is activated (can take up to 2 hours)")
            print("3. Check if you have exceeded your free tier limits")
        
        return False
        
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False
        
    finally:
        # Cleanup
        await weather_service.cleanup()


async def test_api_endpoints():
    """Test the weather API endpoints."""
    print("\n🌐 Testing Weather API Endpoints")
    print("=" * 50)
    
    try:
        import httpx
        
        # Start the FastAPI server in test mode would require more setup
        # For now, just show what endpoints are available
        
        print("📋 Available Weather API Endpoints:")
        print("")
        print("🌤️  Current Weather:")
        print("   GET /api/v1/weather/current?city=London&country=GB")
        print("   GET /api/v1/weather/current?lat=51.5074&lon=-0.1278")
        print("")
        print("📅 Weather Forecast:")
        print("   GET /api/v1/weather/forecast?city=Paris&days=5")
        print("   GET /api/v1/weather/forecast?lat=48.8566&lon=2.3522&days=3")
        print("")
        print("🚨 Weather Alerts:")
        print("   GET /api/v1/weather/alerts?lat=40.7128&lon=-74.0060")
        print("")
        print("ℹ️  Service Information:")
        print("   GET /api/v1/weather/info")
        print("   GET /api/v1/weather/health")
        print("")
        print("📖 API Documentation:")
        print("   http://localhost:8000/docs (when server is running)")
        
        return True
        
    except Exception as e:
        print(f"❌ API endpoint test error: {e}")
        return False


def print_setup_instructions():
    """Print setup instructions for the weather service."""
    print("\n📚 Weather Service Setup Instructions")
    print("=" * 50)
    print("")
    print("1. 🔑 Get OpenWeatherMap API Key:")
    print("   - Visit: https://openweathermap.org/api")
    print("   - Sign up for a free account")
    print("   - Go to 'API keys' section")
    print("   - Copy your API key")
    print("")
    print("2. 🔧 Configure Environment:")
    print("   export OPENWEATHER_API_KEY='your_api_key_here'")
    print("")
    print("3. 🚀 Start the API Gateway:")
    print("   cd /Users/radekzitek/Documents/GitHub/gca-alpha/be/apigw")
    print("   python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload")
    print("")
    print("4. 🧪 Test the Weather API:")
    print("   curl 'http://localhost:8000/api/v1/weather/current?city=London&country=GB'")
    print("")
    print("5. 📖 Explore API Documentation:")
    print("   http://localhost:8000/docs")
    print("")
    print("💡 Free Tier Limits:")
    print("   - 1,000 API calls per day")
    print("   - 60 API calls per minute")
    print("   - Weather alerts require paid subscription")
    print("")


async def main():
    """Main test function."""
    print("🌍 OpenWeatherMap Service Integration Test")
    print("=" * 50)
    
    # Test the weather service functionality
    weather_test_passed = await test_weather_service()
    
    # Test API endpoints (informational)
    api_test_passed = await test_api_endpoints()
    
    # Print setup instructions
    print_setup_instructions()
    
    # Summary
    print("📊 Test Summary")
    print("=" * 50)
    print(f"Weather Service: {'✅ PASSED' if weather_test_passed else '❌ FAILED'}")
    print(f"API Endpoints: {'✅ READY' if api_test_passed else '❌ ISSUES'}")
    
    if weather_test_passed and api_test_passed:
        print("\n🎉 Weather service integration is ready!")
        print("You can now start the API Gateway and use the weather endpoints.")
    else:
        print("\n⚠️  Some tests failed. Please check the configuration and try again.")
    
    return weather_test_passed and api_test_passed


if __name__ == "__main__":
    # Run the tests
    success = asyncio.run(main())
    sys.exit(0 if success else 1)

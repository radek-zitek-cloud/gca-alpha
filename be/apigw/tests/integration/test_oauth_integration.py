"""
Comprehensive OAuth2 Integration Tests.

Tests all aspects of the OAuth2 system:
- OAuth flow initiation
- Provider callback handling
- Token operations
- User information retrieval
- JWT integration
- Account linking/unlinking
- Error handling
- Security validation
"""

import pytest
import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, Mock, patch
from typing import Dict, Any

from fastapi.testclient import TestClient
from fastapi import status

from app.main import app
from app.services.oauth import (
    oauth_service,
    oauth_jwt_integration,
    OAuthProvider,
    OAuthService,
    OAuthUserInfo,
    OAuthTokenResponse,
    OAuthAuthorizationRequest,
    OAuthCallbackRequest
)
from app.middleware.auth import create_admin_token, create_test_user_token


@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app)


@pytest.fixture
async def admin_token():
    """Create admin token for testing."""
    token_data = await create_admin_token()
    return token_data["access_token"]


@pytest.fixture
async def user_token():
    """Create user token for testing."""
    token_data = await create_test_user_token()
    return token_data["access_token"]


@pytest.fixture
def mock_oauth_service():
    """Create mock OAuth service."""
    service = Mock(spec=OAuthService)
    service.state_storage = {}
    return service


@pytest.fixture
def sample_google_user_data():
    """Sample Google user data."""
    return {
        "id": "123456789",
        "email": "test@gmail.com",
        "verified_email": True,
        "name": "Test User",
        "picture": "https://example.com/avatar.jpg"
    }


@pytest.fixture
def sample_github_user_data():
    """Sample GitHub user data."""
    return {
        "id": 987654321,
        "login": "testuser",
        "name": "Test User",
        "email": "test@example.com",
        "avatar_url": "https://avatars.githubusercontent.com/u/987654321"
    }


class TestOAuthService:
    """Test OAuth service functionality."""
    
    def test_oauth_service_initialization(self):
        """Test OAuth service initializes correctly."""
        service = OAuthService()
        
        assert OAuthProvider.GOOGLE in service.providers
        assert OAuthProvider.GITHUB in service.providers
        assert service.http_client is not None
        assert isinstance(service.state_storage, dict)
    
    def test_provider_configuration(self):
        """Test OAuth provider configuration."""
        service = OAuthService()
        
        # Test Google configuration
        google_config = service.get_provider_config(OAuthProvider.GOOGLE)
        assert google_config.provider == OAuthProvider.GOOGLE
        assert "accounts.google.com" in google_config.authorization_url
        assert "oauth2.googleapis.com" in google_config.token_url
    
    def test_generate_authorization_url(self):
        """Test authorization URL generation."""
        service = OAuthService()
        
        request = OAuthAuthorizationRequest(
            provider=OAuthProvider.GOOGLE,
            scopes=["openid", "email", "profile"]
        )
        
        result = service.generate_authorization_url(request)
        
        assert "authorization_url" in result
        assert "state" in result
        assert "provider" in result
        assert "accounts.google.com" in result["authorization_url"]
        assert "client_id=" in result["authorization_url"]
        assert "scope=" in result["authorization_url"]
        assert "state=" in result["authorization_url"]
    
    def test_state_validation(self):
        """Test OAuth state validation."""
        service = OAuthService()
        
        # Generate state
        request = OAuthAuthorizationRequest(provider=OAuthProvider.GOOGLE)
        result = service.generate_authorization_url(request)
        state = result["state"]
        
        # Validate state
        state_data = service._validate_state(state)
        assert state_data.provider == "google"
        assert state_data.nonce is not None
    
    def test_expired_state_validation(self):
        """Test expired state handling."""
        service = OAuthService()
        
        # Create expired state
        from app.services.oauth import OAuthStateData
        expired_state = OAuthStateData(
            provider="google",
            redirect_uri="http://localhost:8000/callback",
            scopes=["email"],
            created_at=datetime.now(timezone.utc) - timedelta(minutes=20),
            nonce="test_nonce"
        )
        
        service.state_storage["expired_state"] = expired_state
        
        # Should raise exception for expired state
        with pytest.raises(Exception):
            service._validate_state("expired_state")
    
    def test_parse_google_user_info(self, sample_google_user_data):
        """Test parsing Google user information."""
        service = OAuthService()
        
        user_info = service._parse_google_user_info(sample_google_user_data)
        
        assert user_info.provider == "google"
        assert user_info.provider_id == "123456789"
        assert user_info.email == "test@gmail.com"
        assert user_info.name == "Test User"
        assert user_info.verified_email is True
        assert user_info.avatar_url == "https://example.com/avatar.jpg"
    
    @pytest.mark.asyncio
    async def test_parse_github_user_info(self, sample_github_user_data):
        """Test parsing GitHub user information."""
        service = OAuthService()
        
        # Mock the email API call
        with patch.object(service, '_get_github_primary_email', return_value="test@example.com"):
            user_info = await service._parse_github_user_info(sample_github_user_data, "mock_token")
        
        assert user_info.provider == "github"
        assert user_info.provider_id == "987654321"
        assert user_info.email == "test@example.com"
        assert user_info.name == "Test User"
        assert user_info.username == "testuser"
    
    def test_get_supported_providers(self):
        """Test getting supported providers."""
        service = OAuthService()
        
        providers = service.get_supported_providers()
        
        assert len(providers) >= 2
        provider_names = [p["provider"] for p in providers]
        assert "google" in provider_names
        assert "github" in provider_names
    
    @pytest.mark.asyncio
    async def test_cleanup_expired_states(self):
        """Test cleanup of expired OAuth states."""
        service = OAuthService()
        
        # Add some expired states
        from app.services.oauth import OAuthStateData
        expired_state = OAuthStateData(
            provider="google",
            redirect_uri="http://localhost:8000/callback",
            scopes=["email"],
            created_at=datetime.now(timezone.utc) - timedelta(minutes=20),
            nonce="test_nonce"
        )
        
        service.state_storage["expired1"] = expired_state
        service.state_storage["expired2"] = expired_state
        
        # Add valid state
        valid_state = OAuthStateData(
            provider="google",
            redirect_uri="http://localhost:8000/callback",
            scopes=["email"],
            created_at=datetime.now(timezone.utc),
            nonce="test_nonce"
        )
        service.state_storage["valid"] = valid_state
        
        await service.cleanup_expired_states()
        
        # Only valid state should remain
        assert len(service.state_storage) == 1
        assert "valid" in service.state_storage


class TestOAuthEndpoints:
    """Test OAuth API endpoints."""
    
    def test_get_oauth_providers(self, client: TestClient):
        """Test getting OAuth providers."""
        response = client.get("/api/v1/auth/oauth/providers")
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 2
        
        provider_names = [p["provider"] for p in data]
        assert "google" in provider_names
        assert "github" in provider_names
    
    def test_get_specific_oauth_provider(self, client: TestClient):
        """Test getting specific OAuth provider info."""
        response = client.get("/api/v1/auth/oauth/providers/google")
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["provider"] == "google"
        assert data["name"] == "Google"
        assert "scopes" in data
        assert "configured" in data
    
    def test_get_nonexistent_oauth_provider(self, client: TestClient):
        """Test getting non-existent OAuth provider."""
        response = client.get("/api/v1/auth/oauth/providers/nonexistent")
        
        assert response.status_code == status.HTTP_404_NOT_FOUND
    
    def test_initiate_oauth_login(self, client: TestClient):
        """Test initiating OAuth login."""
        login_data = {
            "provider": "google",
            "scopes": ["openid", "email", "profile"]
        }
        
        response = client.post("/api/v1/auth/oauth/login", json=login_data)
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "authorization_url" in data
        assert "state" in data
        assert data["provider"] == "google"
        assert "accounts.google.com" in data["authorization_url"]
    
    def test_initiate_oauth_login_direct_redirect(self, client: TestClient):
        """Test direct OAuth login with redirect."""
        response = client.get("/api/v1/auth/oauth/login/github", allow_redirects=False)
        
        assert response.status_code == status.HTTP_302_FOUND
        assert "github.com" in response.headers["location"]
    
    def test_oauth_callback_missing_params(self, client: TestClient):
        """Test OAuth callback with missing parameters."""
        response = client.get("/api/v1/auth/oauth/callback/google")
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Missing required OAuth callback parameters" in response.json()["detail"]
    
    def test_oauth_callback_with_error(self, client: TestClient):
        """Test OAuth callback with OAuth error."""
        response = client.get(
            "/api/v1/auth/oauth/callback/google",
            params={
                "error": "access_denied",
                "error_description": "User denied access"
            }
        )
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "OAuth error" in response.json()["detail"]
    
    @patch('app.services.oauth.oauth_service.handle_callback')
    @patch('app.services.oauth.oauth_jwt_integration.create_jwt_from_oauth')
    def test_successful_oauth_callback(self, mock_jwt_create, mock_handle_callback, client: TestClient):
        """Test successful OAuth callback."""
        # Mock OAuth service response
        mock_user_info = {
            "provider": "google",
            "provider_id": "123456789",
            "email": "test@gmail.com",
            "name": "Test User",
            "avatar_url": "https://example.com/avatar.jpg",
            "verified_email": True,
            "raw_data": {}
        }
        
        mock_handle_callback.return_value = {
            "user_info": mock_user_info,
            "tokens": {
                "access_token": "oauth_access_token",
                "token_type": "Bearer"
            },
            "provider": "google"
        }
        
        # Mock JWT creation
        mock_jwt_create.return_value = {
            "access_token": "jwt_access_token",
            "refresh_token": "jwt_refresh_token",
            "token_type": "bearer",
            "user_data": {
                "user_id": "google_123456789",
                "email": "test@gmail.com",
                "name": "Test User"
            }
        }
        
        # Generate a valid state first
        login_response = client.post("/api/v1/auth/oauth/login", json={"provider": "google"})
        state = login_response.json()["state"]
        
        # Test callback
        response = client.get(
            "/api/v1/auth/oauth/callback/google",
            params={
                "code": "test_auth_code",
                "state": state
            }
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["provider"] == "google"
        assert "user_info" in data
    
    def test_oauth_admin_cleanup(self, client: TestClient, admin_token: str):
        """Test OAuth admin cleanup endpoint."""
        response = client.post(
            "/api/v1/auth/oauth/admin/cleanup",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "message" in data
        assert "timestamp" in data
    
    def test_oauth_admin_cleanup_unauthorized(self, client: TestClient, user_token: str):
        """Test OAuth admin cleanup without admin privileges."""
        response = client.post(
            "/api/v1/auth/oauth/admin/cleanup",
            headers={"Authorization": f"Bearer {user_token}"}
        )
        
        assert response.status_code == status.HTTP_403_FORBIDDEN
    
    def test_oauth_admin_stats(self, client: TestClient, admin_token: str):
        """Test OAuth admin statistics endpoint."""
        response = client.get(
            "/api/v1/auth/oauth/admin/stats",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "total_providers" in data
        assert "configured_providers" in data
        assert "active_oauth_states" in data
        assert "providers" in data


class TestOAuthJWTIntegration:
    """Test OAuth-JWT integration."""
    
    @pytest.mark.asyncio
    async def test_create_jwt_from_oauth(self, sample_google_user_data):
        """Test creating JWT tokens from OAuth user info."""
        user_info = OAuthUserInfo(
            provider="google",
            provider_id="123456789",
            email="test@gmail.com",
            name="Test User",
            verified_email=True
        )
        
        with patch('app.services.oauth.authenticator') as mock_auth:
            mock_auth.create_access_token.return_value = "jwt_access_token"
            mock_auth.create_refresh_token.return_value = "jwt_refresh_token"
            
            result = await oauth_jwt_integration.create_jwt_from_oauth(user_info, "google")
        
        assert result["access_token"] == "jwt_access_token"
        assert result["refresh_token"] == "jwt_refresh_token"
        assert result["token_type"] == "bearer"
        assert "user_data" in result
        
        user_data = result["user_data"]
        assert user_data["user_id"] == "google_123456789"
        assert user_data["email"] == "test@gmail.com"
        assert user_data["provider"] == "google"
        assert user_data["oauth_authenticated"] is True
    
    @pytest.mark.asyncio
    async def test_link_oauth_account(self):
        """Test linking OAuth account to JWT user."""
        user_info = OAuthUserInfo(
            provider="github",
            provider_id="987654321",
            email="test@example.com",
            name="Test User"
        )
        
        result = await oauth_jwt_integration.link_oauth_account("jwt_user_123", user_info)
        assert result is True
    
    @pytest.mark.asyncio
    async def test_unlink_oauth_account(self):
        """Test unlinking OAuth account from JWT user."""
        result = await oauth_jwt_integration.unlink_oauth_account("jwt_user_123", "github")
        assert result is True


class TestOAuthSecurity:
    """Test OAuth security features."""
    
    def test_state_parameter_security(self):
        """Test OAuth state parameter security."""
        service = OAuthService()
        
        # Generate multiple states
        states = []
        for _ in range(10):
            request = OAuthAuthorizationRequest(provider=OAuthProvider.GOOGLE)
            result = service.generate_authorization_url(request)
            states.append(result["state"])
        
        # All states should be unique
        assert len(set(states)) == len(states)
        
        # States should be sufficiently long
        for state in states:
            assert len(state) >= 32
    
    def test_nonce_generation(self):
        """Test nonce generation for security."""
        service = OAuthService()
        
        nonces = [service._generate_nonce() for _ in range(10)]
        
        # All nonces should be unique
        assert len(set(nonces)) == len(nonces)
        
        # Nonces should be sufficiently long
        for nonce in nonces:
            assert len(nonce) >= 16
    
    def test_invalid_state_rejection(self):
        """Test rejection of invalid OAuth states."""
        service = OAuthService()
        
        # Test with invalid state
        with pytest.raises(Exception):
            service._validate_state("invalid_state_123")
        
        # Test with empty state
        with pytest.raises(Exception):
            service._validate_state("")
    
    @pytest.mark.asyncio
    async def test_token_validation(self):
        """Test OAuth token validation."""
        service = OAuthService()
        
        # Mock HTTP client for token validation
        with patch.object(service, '_get_user_info') as mock_get_user:
            mock_get_user.return_value = OAuthUserInfo(
                provider="google",
                provider_id="123",
                email="test@example.com",
                name="Test User"
            )
            
            result = await service.validate_token("valid_token", OAuthProvider.GOOGLE)
            assert result["valid"] is True
            assert "user_info" in result
        
        # Test with invalid token
        with patch.object(service, '_get_user_info', side_effect=Exception("Invalid token")):
            result = await service.validate_token("invalid_token", OAuthProvider.GOOGLE)
            assert result["valid"] is False


class TestOAuthErrorHandling:
    """Test OAuth error handling."""
    
    def test_unsupported_provider_error(self, client: TestClient):
        """Test error handling for unsupported providers."""
        response = client.get("/api/v1/auth/oauth/login/unsupported")
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Unsupported OAuth provider" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_token_exchange_error_handling(self):
        """Test error handling during token exchange."""
        service = OAuthService()
        
        # Mock HTTP client to return error
        with patch.object(service.http_client, 'post') as mock_post:
            mock_response = Mock()
            mock_response.raise_for_status.side_effect = Exception("HTTP Error")
            mock_post.return_value = mock_response
            
            with pytest.raises(Exception):
                await service._exchange_code_for_tokens("invalid_code", OAuthProvider.GOOGLE)
    
    @pytest.mark.asyncio
    async def test_user_info_error_handling(self):
        """Test error handling during user info retrieval."""
        service = OAuthService()
        
        # Mock HTTP client to return error
        with patch.object(service.http_client, 'get') as mock_get:
            mock_response = Mock()
            mock_response.raise_for_status.side_effect = Exception("HTTP Error")
            mock_get.return_value = mock_response
            
            with pytest.raises(Exception):
                await service._get_user_info("invalid_token", OAuthProvider.GOOGLE)
    
    def test_oauth_callback_invalid_provider(self, client: TestClient):
        """Test OAuth callback with invalid provider."""
        response = client.get(
            "/api/v1/auth/oauth/callback/invalid_provider",
            params={
                "code": "test_code",
                "state": "test_state"
            }
        )
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Unsupported OAuth provider" in response.json()["detail"]


# Performance tests
class TestOAuthPerformance:
    """Test OAuth system performance."""
    
    def test_authorization_url_generation_performance(self):
        """Test performance of authorization URL generation."""
        service = OAuthService()
        
        import time
        start_time = time.time()
        
        # Generate 100 authorization URLs
        for _ in range(100):
            request = OAuthAuthorizationRequest(provider=OAuthProvider.GOOGLE)
            service.generate_authorization_url(request)
        
        end_time = time.time()
        avg_time = (end_time - start_time) / 100
        
        # Should be fast (< 10ms per generation)
        assert avg_time < 0.01, f"Authorization URL generation too slow: {avg_time:.3f}s"
    
    @pytest.mark.asyncio
    async def test_state_cleanup_performance(self):
        """Test performance of state cleanup."""
        service = OAuthService()
        
        # Add 1000 expired states
        from app.services.oauth import OAuthStateData
        expired_state = OAuthStateData(
            provider="google",
            redirect_uri="http://localhost:8000/callback",
            scopes=["email"],
            created_at=datetime.now(timezone.utc) - timedelta(minutes=20),
            nonce="test_nonce"
        )
        
        for i in range(1000):
            service.state_storage[f"expired_{i}"] = expired_state
        
        import time
        start_time = time.time()
        
        await service.cleanup_expired_states()
        
        end_time = time.time()
        cleanup_time = end_time - start_time
        
        # Cleanup should be fast (< 100ms for 1000 states)
        assert cleanup_time < 0.1, f"State cleanup too slow: {cleanup_time:.3f}s"
        assert len(service.state_storage) == 0


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"])

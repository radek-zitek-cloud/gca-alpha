"""
Unit tests for OAuth2 service components.

Tests individual components in isolation:
- OAuth configuration
- Provider validation
- Token handling
- User info parsing
- Security utilities
"""

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch, AsyncMock
from typing import Dict, Any

from app.services.oauth import (
    OAuthService,
    OAuthProvider,
    OAuthUserInfo,
    OAuthTokenResponse,
    OAuthAuthorizationRequest,
    OAuthCallbackRequest,
    OAuthStateData,
    OAuthConfig
)


class TestOAuthProvider:
    """Test OAuth provider enum."""
    
    def test_oauth_provider_values(self):
        """Test OAuth provider enum values."""
        assert OAuthProvider.GOOGLE.value == "google"
        assert OAuthProvider.GITHUB.value == "github"
    
    def test_oauth_provider_string_conversion(self):
        """Test OAuth provider string conversion."""
        assert OAuthProvider.GOOGLE.value == "google"
        assert OAuthProvider.GITHUB.value == "github"


class TestOAuthUserInfo:
    """Test OAuth user info model."""
    
    def test_oauth_user_info_creation(self):
        """Test OAuth user info creation."""
        user_info = OAuthUserInfo(
            provider="google",
            provider_id="123456789",
            email="test@gmail.com",
            name="Test User",
            username="testuser",
            avatar_url="https://example.com/avatar.jpg",
            verified_email=True,
            raw_data={"extra": "data"}
        )
        
        assert user_info.provider == "google"
        assert user_info.provider_id == "123456789"
        assert user_info.email == "test@gmail.com"
        assert user_info.name == "Test User"
        assert user_info.username == "testuser"
        assert user_info.avatar_url == "https://example.com/avatar.jpg"
        assert user_info.verified_email is True
        assert user_info.raw_data == {"extra": "data"}
    
    def test_oauth_user_info_minimal(self):
        """Test OAuth user info with minimal data."""
        user_info = OAuthUserInfo(
            provider="github",
            provider_id="987654321",
            email="test@example.com"
        )
        
        assert user_info.provider == "github"
        assert user_info.provider_id == "987654321"
        assert user_info.email == "test@example.com"
        assert user_info.name is None
        assert user_info.username is None
        assert user_info.avatar_url is None
        assert user_info.verified_email is None
        assert user_info.raw_data is None


class TestOAuthTokenResponse:
    """Test OAuth token response model."""
    
    def test_oauth_token_response_creation(self):
        """Test OAuth token response creation."""
        token_response = OAuthTokenResponse(
            access_token="access_token_123",
            token_type="Bearer",
            expires_in=3600,
            refresh_token="refresh_token_123",
            scope="read write"
        )
        
        assert token_response.access_token == "access_token_123"
        assert token_response.token_type == "Bearer"
        assert token_response.expires_in == 3600
        assert token_response.refresh_token == "refresh_token_123"
        assert token_response.scope == "read write"
    
    def test_oauth_token_response_minimal(self):
        """Test OAuth token response with minimal data."""
        token_response = OAuthTokenResponse(
            access_token="access_token_123",
            token_type="Bearer"
        )
        
        assert token_response.access_token == "access_token_123"
        assert token_response.token_type == "Bearer"
        assert token_response.expires_in is None
        assert token_response.refresh_token is None
        assert token_response.scope is None


class TestOAuthStateData:
    """Test OAuth state data model."""
    
    def test_oauth_state_data_creation(self):
        """Test OAuth state data creation."""
        created_at = datetime.now(timezone.utc)
        state_data = OAuthStateData(
            provider="google",
            redirect_uri="http://localhost:8000/callback",
            scopes=["openid", "email", "profile"],
            created_at=created_at,
            nonce="test_nonce_123"
        )
        
        assert state_data.provider == "google"
        assert state_data.redirect_uri == "http://localhost:8000/callback"
        assert state_data.scopes == ["openid", "email", "profile"]
        assert state_data.created_at == created_at
        assert state_data.nonce == "test_nonce_123"
    
    def test_oauth_state_data_is_expired(self):
        """Test OAuth state expiration check."""
        # Recent state
        recent_state = OAuthStateData(
            provider="google",
            redirect_uri="http://localhost:8000/callback",
            scopes=["email"],
            created_at=datetime.now(timezone.utc),
            nonce="test_nonce"
        )
        assert not recent_state.is_expired()
        
        # Expired state
        expired_state = OAuthStateData(
            provider="google",
            redirect_uri="http://localhost:8000/callback",
            scopes=["email"],
            created_at=datetime.now(timezone.utc) - timedelta(minutes=20),
            nonce="test_nonce"
        )
        assert expired_state.is_expired()


class TestOAuthServiceMethods:
    """Test OAuth service individual methods."""
    
    def test_generate_nonce(self):
        """Test nonce generation."""
        service = OAuthService()
        
        nonce1 = service._generate_nonce()
        nonce2 = service._generate_nonce()
        
        # Nonces should be different
        assert nonce1 != nonce2
        
        # Nonces should be long enough
        assert len(nonce1) >= 16
        assert len(nonce2) >= 16
        
        # Nonces should be alphanumeric
        assert nonce1.isalnum()
        assert nonce2.isalnum()
    
    def test_generate_state_token(self):
        """Test state token generation."""
        service = OAuthService()
        
        state_data = OAuthStateData(
            provider="google",
            redirect_uri="http://localhost:8000/callback",
            scopes=["email"],
            created_at=datetime.now(timezone.utc),
            nonce="test_nonce"
        )
        
        state_token = service._generate_state_token(state_data)
        
        # State token should be non-empty
        assert len(state_token) > 0
        
        # Should be able to decode the state
        decoded_data = service._decode_state_token(state_token)
        assert decoded_data.provider == "google"
        assert decoded_data.nonce == "test_nonce"
    
    def test_validate_state_token(self):
        """Test state token validation."""
        service = OAuthService()
        
        # Create valid state
        state_data = OAuthStateData(
            provider="google",
            redirect_uri="http://localhost:8000/callback",
            scopes=["email"],
            created_at=datetime.now(timezone.utc),
            nonce="test_nonce"
        )
        
        state_token = service._generate_state_token(state_data)
        service.state_storage[state_token] = state_data
        
        # Valid state should pass
        validated_data = service._validate_state(state_token)
        assert validated_data.provider == "google"
        assert validated_data.nonce == "test_nonce"
        
        # Invalid state should fail
        with pytest.raises(Exception):
            service._validate_state("invalid_state_token")
    
    def test_build_authorization_url(self):
        """Test authorization URL building."""
        service = OAuthService()
        
        # Create a mock provider config-like object
        from types import SimpleNamespace
        provider_config = SimpleNamespace(
            provider=OAuthProvider.GOOGLE,
            name="Google",
            client_id="test_client_id",
            authorization_url="https://accounts.google.com/oauth/authorize",
            scopes=["email", "profile"]
        )
        
        url = service._build_authorization_url(
            provider_config,
            "test_state",
            "http://localhost:8000/callback",
            ["email", "profile"]
        )
        
        assert "accounts.google.com" in url
        assert "client_id=test_client_id" in url
        assert "state=test_state" in url
        assert "redirect_uri=" in url
        assert "scope=" in url
    
    def test_parse_google_user_info(self):
        """Test parsing Google user information."""
        service = OAuthService()
        
        google_data = {
            "id": "123456789",
            "email": "test@gmail.com",
            "verified_email": True,
            "name": "Test User",
            "given_name": "Test",
            "family_name": "User",
            "picture": "https://example.com/avatar.jpg",
            "locale": "en"
        }
        
        user_info = service._parse_google_user_info(google_data)
        
        assert user_info.provider == "google"
        assert user_info.provider_id == "123456789"
        assert user_info.email == "test@gmail.com"
        assert user_info.name == "Test User"
        assert user_info.verified_email is True
        assert user_info.avatar_url == "https://example.com/avatar.jpg"
        assert user_info.raw_data == google_data
    
    @pytest.mark.asyncio
    async def test_parse_github_user_info(self):
        """Test parsing GitHub user information."""
        service = OAuthService()
        
        github_data = {
            "id": 987654321,
            "login": "testuser",
            "name": "Test User",
            "email": None,
            "avatar_url": "https://avatars.githubusercontent.com/u/987654321",
            "bio": "Software Developer"
        }
        
        # Mock email API call
        with patch.object(service, '_get_github_primary_email', return_value="test@example.com"):
            user_info = await service._parse_github_user_info(github_data, "test_token")
        
        assert user_info.provider == "github"
        assert user_info.provider_id == "987654321"
        assert user_info.username == "testuser"
        assert user_info.name == "Test User"
        assert user_info.email == "test@example.com"
        assert user_info.avatar_url == "https://avatars.githubusercontent.com/u/987654321"
        assert user_info.raw_data == github_data
    
    @pytest.mark.asyncio
    async def test_github_email_retrieval(self):
        """Test GitHub email retrieval."""
        service = OAuthService()
        
        # Mock HTTP client
        mock_response = Mock()
        mock_response.json.return_value = [
            {"email": "secondary@example.com", "primary": False, "verified": True},
            {"email": "primary@example.com", "primary": True, "verified": True},
            {"email": "unverified@example.com", "primary": False, "verified": False}
        ]
        mock_response.raise_for_status.return_value = None
        
        with patch.object(service.http_client, 'get', return_value=mock_response):
            email = await service._get_github_primary_email("test_token")
        
        assert email == "primary@example.com"
    
    @pytest.mark.asyncio
    async def test_github_email_retrieval_fallback(self):
        """Test GitHub email retrieval with fallback."""
        service = OAuthService()
        
        # Mock HTTP client with no primary email
        mock_response = Mock()
        mock_response.json.return_value = [
            {"email": "only@example.com", "primary": False, "verified": True}
        ]
        mock_response.raise_for_status.return_value = None
        
        with patch.object(service.http_client, 'get', return_value=mock_response):
            email = await service._get_github_primary_email("test_token")
        
        assert email == "only@example.com"
    
    def test_cleanup_expired_states_sync(self):
        """Test synchronous cleanup of expired states."""
        service = OAuthService()
        
        # Add mixed states
        now = datetime.now(timezone.utc)
        
        valid_state = OAuthStateData(
            provider="google",
            redirect_uri="http://localhost:8000/callback",
            scopes=["email"],
            created_at=now,
            nonce="valid"
        )
        
        expired_state = OAuthStateData(
            provider="google",
            redirect_uri="http://localhost:8000/callback",
            scopes=["email"],
            created_at=now - timedelta(minutes=20),
            nonce="expired"
        )
        
        service.state_storage["valid"] = valid_state
        service.state_storage["expired"] = expired_state
        
        # Cleanup
        removed_count = service._cleanup_expired_states_sync()
        
        assert removed_count == 1
        assert "valid" in service.state_storage
        assert "expired" not in service.state_storage


class TestOAuthServiceConfiguration:
    """Test OAuth service configuration handling."""
    
    def test_get_provider_config(self):
        """Test getting provider configuration."""
        service = OAuthService()
        
        google_config = service.get_provider_config(OAuthProvider.GOOGLE)
        assert google_config.provider == OAuthProvider.GOOGLE
        assert google_config.name == "Google"
        assert "accounts.google.com" in google_config.authorization_url
        
        github_config = service.get_provider_config(OAuthProvider.GITHUB)
        assert github_config.provider == OAuthProvider.GITHUB
        assert github_config.name == "GitHub"
        assert "github.com" in github_config.authorization_url
    
    def test_is_provider_supported(self):
        """Test provider support checking."""
        service = OAuthService()
        
        assert service.is_provider_supported("google") is True
        assert service.is_provider_supported("github") is True
        assert service.is_provider_supported("unsupported") is False
    
    def test_get_supported_providers(self):
        """Test getting all supported providers."""
        service = OAuthService()
        
        providers = service.get_supported_providers()
        
        assert len(providers) >= 2
        provider_names = [p["provider"] for p in providers]
        assert "google" in provider_names
        assert "github" in provider_names
        
        # Check structure
        for provider in providers:
            assert "provider" in provider
            assert "name" in provider
            assert "scopes" in provider
            assert "configured" in provider


class TestOAuthSecurityUtilities:
    """Test OAuth security utilities."""
    
    def test_secure_random_generation(self):
        """Test secure random string generation."""
        service = OAuthService()
        
        # Test multiple generations
        randoms = [service._generate_nonce() for _ in range(100)]
        
        # All should be unique
        assert len(set(randoms)) == len(randoms)
        
        # All should be alphanumeric
        for r in randoms:
            assert r.isalnum()
            assert len(r) >= 16
    
    def test_state_encoding_decoding(self):
        """Test state encoding and decoding."""
        service = OAuthService()
        
        original_data = OAuthStateData(
            provider="google",
            redirect_uri="http://localhost:8000/callback",
            scopes=["email", "profile"],
            created_at=datetime.now(timezone.utc),
            nonce="test_nonce_123"
        )
        
        # Encode
        encoded = service._generate_state_token(original_data)
        assert isinstance(encoded, str)
        assert len(encoded) > 0
        
        # Decode
        decoded = service._decode_state_token(encoded)
        assert decoded.provider == original_data.provider
        assert decoded.redirect_uri == original_data.redirect_uri
        assert decoded.scopes == original_data.scopes
        assert decoded.nonce == original_data.nonce
        # Note: datetime comparison might need tolerance due to serialization
    
    def test_invalid_state_decoding(self):
        """Test handling of invalid state tokens."""
        service = OAuthService()
        
        with pytest.raises(Exception):
            service._decode_state_token("invalid.token.here")
        
        with pytest.raises(Exception):
            service._decode_state_token("")
        
        with pytest.raises(Exception):
            service._decode_state_token("not_a_jwt_token")


class TestOAuthServiceEdgeCases:
    """Test OAuth service edge cases."""
    
    def test_empty_scopes_handling(self):
        """Test handling of empty scopes."""
        service = OAuthService()
        
        request = OAuthAuthorizationRequest(
            provider=OAuthProvider.GOOGLE,
            scopes=[]
        )
        
        result = service.generate_authorization_url(request)
        
        # Should use default scopes when empty
        assert "authorization_url" in result
        assert "scope=" in result["authorization_url"]
    
    def test_none_scopes_handling(self):
        """Test handling of None scopes."""
        service = OAuthService()
        
        request = OAuthAuthorizationRequest(
            provider=OAuthProvider.GOOGLE,
            scopes=None
        )
        
        result = service.generate_authorization_url(request)
        
        # Should handle None scopes gracefully
        assert "authorization_url" in result
    
    def test_large_state_storage_cleanup(self):
        """Test cleanup with large state storage."""
        service = OAuthService()
        
        # Add many expired states
        expired_time = datetime.now(timezone.utc) - timedelta(minutes=20)
        
        for i in range(1000):
            state_data = OAuthStateData(
                provider="google",
                redirect_uri="http://localhost:8000/callback",
                scopes=["email"],
                created_at=expired_time,
                nonce=f"nonce_{i}"
            )
            service.state_storage[f"state_{i}"] = state_data
        
        # Add one valid state
        valid_state = OAuthStateData(
            provider="google",
            redirect_uri="http://localhost:8000/callback",
            scopes=["email"],
            created_at=datetime.now(timezone.utc),
            nonce="valid_nonce"
        )
        service.state_storage["valid"] = valid_state
        
        # Cleanup should handle large numbers efficiently
        removed_count = service._cleanup_expired_states_sync()
        
        assert removed_count == 1000
        assert len(service.state_storage) == 1
        assert "valid" in service.state_storage
    
    def test_special_characters_in_user_data(self):
        """Test handling of special characters in user data."""
        service = OAuthService()
        
        google_data = {
            "id": "123456789",
            "email": "test+tag@gmail.com",
            "name": "Test Üser with Spéciål Chars",
            "picture": "https://example.com/avatar.jpg?param=value&other=param"
        }
        
        user_info = service._parse_google_user_info(google_data)
        
        assert user_info.email == "test+tag@gmail.com"
        assert user_info.name == "Test Üser with Spéciål Chars"
        assert "param=value" in user_info.avatar_url


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"])

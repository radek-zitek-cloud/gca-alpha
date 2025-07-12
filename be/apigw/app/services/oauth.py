"""
OAuth2 Integration Service for API Gateway.

This module provides comprehensive OAuth2 authentication support with multiple providers:
- Google OAuth2
- GitHub OAuth2
- Extensible provider framework
- Token exchange and validation
- User profile integration
- Session management

Features:
- Multiple OAuth2 provider support
- Secure token handling
- User profile synchronization
- Custom scope management
- State validation for security
- Token refresh handling
- Integration with existing JWT system
"""

import json
import secrets
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, List, Union
from urllib.parse import urlencode, parse_qs, urlparse
from dataclasses import dataclass, asdict
from enum import Enum

import httpx
from fastapi import HTTPException, status
from pydantic import BaseModel, Field, validator

logger = logging.getLogger(__name__)


class OAuthProvider(Enum):
    """Supported OAuth2 providers."""
    GOOGLE = "google"
    GITHUB = "github"


class OAuthScope(Enum):
    """Common OAuth2 scopes."""
    EMAIL = "email"
    PROFILE = "profile"
    OPENID = "openid"
    # GitHub specific
    USER = "user"
    USER_EMAIL = "user:email"
    # Google specific
    USERINFO_EMAIL = "https://www.googleapis.com/auth/userinfo.email"
    USERINFO_PROFILE = "https://www.googleapis.com/auth/userinfo.profile"


@dataclass
class OAuthConfig:
    """OAuth provider configuration."""
    provider: OAuthProvider
    client_id: str
    client_secret: str
    redirect_uri: str
    scopes: List[str]
    authorization_url: str
    token_url: str
    userinfo_url: str
    extra_params: Optional[Dict[str, str]] = None


@dataclass
class OAuthUserInfo:
    """Standardized user information from OAuth providers."""
    provider: str
    provider_id: str
    email: str
    name: str
    avatar_url: Optional[str] = None
    username: Optional[str] = None
    verified_email: bool = False
    raw_data: Optional[Dict[str, Any]] = None


class OAuthStateData(BaseModel):
    """OAuth state data for security validation."""
    provider: str
    redirect_uri: str
    scopes: List[str]
    created_at: datetime
    nonce: str
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class OAuthTokenResponse(BaseModel):
    """OAuth token response model."""
    access_token: str
    token_type: str = "Bearer"
    expires_in: Optional[int] = None
    refresh_token: Optional[str] = None
    scope: Optional[str] = None
    id_token: Optional[str] = None


class OAuthAuthorizationRequest(BaseModel):
    """OAuth authorization request model."""
    provider: OAuthProvider
    scopes: List[str] = Field(default_factory=list)
    redirect_uri: Optional[str] = None
    state: Optional[str] = None


class OAuthCallbackRequest(BaseModel):
    """OAuth callback request model."""
    code: str
    state: str
    provider: OAuthProvider
    error: Optional[str] = None
    error_description: Optional[str] = None


class OAuthService:
    """OAuth2 service for handling multiple providers."""
    
    def __init__(self):
        """Initialize OAuth service with provider configurations."""
        self.providers: Dict[OAuthProvider, OAuthConfig] = {}
        self.state_storage: Dict[str, OAuthStateData] = {}  # In production, use Redis
        self.http_client = httpx.AsyncClient(timeout=30.0)
        
        # Initialize default provider configurations
        self._setup_default_providers()
    
    def _setup_default_providers(self):
        """Setup default OAuth provider configurations."""
        # Google OAuth2 configuration
        google_config = OAuthConfig(
            provider=OAuthProvider.GOOGLE,
            client_id="YOUR_GOOGLE_CLIENT_ID",  # Configure from environment
            client_secret="YOUR_GOOGLE_CLIENT_SECRET",
            redirect_uri="http://localhost:8000/api/v1/auth/oauth/callback/google",
            scopes=[
                OAuthScope.OPENID.value,
                OAuthScope.EMAIL.value,
                OAuthScope.PROFILE.value
            ],
            authorization_url="https://accounts.google.com/o/oauth2/v2/auth",
            token_url="https://oauth2.googleapis.com/token",
            userinfo_url="https://www.googleapis.com/oauth2/v2/userinfo"
        )
        
        # GitHub OAuth2 configuration
        github_config = OAuthConfig(
            provider=OAuthProvider.GITHUB,
            client_id="YOUR_GITHUB_CLIENT_ID",  # Configure from environment
            client_secret="YOUR_GITHUB_CLIENT_SECRET",
            redirect_uri="http://localhost:8000/api/v1/auth/oauth/callback/github",
            scopes=[
                OAuthScope.USER.value,
                OAuthScope.USER_EMAIL.value
            ],
            authorization_url="https://github.com/login/oauth/authorize",
            token_url="https://github.com/login/oauth/access_token",
            userinfo_url="https://api.github.com/user"
        )
        
        self.providers[OAuthProvider.GOOGLE] = google_config
        self.providers[OAuthProvider.GITHUB] = github_config
    
    def configure_provider(self, config: OAuthConfig):
        """Configure an OAuth provider."""
        self.providers[config.provider] = config
        logger.info(f"Configured OAuth provider: {config.provider.value}")
    
    def get_provider_config(self, provider: OAuthProvider) -> OAuthConfig:
        """Get provider configuration."""
        if provider not in self.providers:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"OAuth provider '{provider.value}' not configured"
            )
        return self.providers[provider]
    
    def generate_authorization_url(self, request: OAuthAuthorizationRequest) -> Dict[str, str]:
        """Generate OAuth authorization URL."""
        try:
            config = self.get_provider_config(request.provider)
            
            # Generate secure state parameter
            state = self._generate_state()
            nonce = self._generate_nonce()
            
            # Store state data for validation
            state_data = OAuthStateData(
                provider=request.provider.value,
                redirect_uri=request.redirect_uri or config.redirect_uri,
                scopes=request.scopes or config.scopes,
                created_at=datetime.now(timezone.utc),
                nonce=nonce
            )
            self.state_storage[state] = state_data
            
            # Build authorization parameters
            auth_params = {
                "client_id": config.client_id,
                "redirect_uri": config.redirect_uri,
                "scope": " ".join(request.scopes or config.scopes),
                "state": state,
                "response_type": "code"
            }
            
            # Add provider-specific parameters
            if request.provider == OAuthProvider.GOOGLE:
                auth_params.update({
                    "access_type": "offline",
                    "prompt": "consent",
                    "nonce": nonce
                })
            elif request.provider == OAuthProvider.GITHUB:
                auth_params["allow_signup"] = "true"
            
            # Add any extra parameters from config
            if config.extra_params:
                auth_params.update(config.extra_params)
            
            authorization_url = f"{config.authorization_url}?{urlencode(auth_params)}"
            
            logger.info(f"Generated authorization URL for {request.provider.value}")
            
            return {
                "authorization_url": authorization_url,
                "state": state,
                "provider": request.provider.value
            }
            
        except Exception as e:
            logger.error(f"Failed to generate authorization URL: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to generate authorization URL: {str(e)}"
            )
    
    async def handle_callback(self, callback: OAuthCallbackRequest) -> Dict[str, Any]:
        """Handle OAuth callback and exchange code for tokens."""
        try:
            # Check for OAuth errors
            if callback.error:
                error_msg = callback.error_description or callback.error
                logger.error(f"OAuth error: {error_msg}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"OAuth error: {error_msg}"
                )
            
            # Validate state parameter
            state_data = self._validate_state(callback.state)
            if state_data.provider != callback.provider.value:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid provider in callback"
                )
            
            # Exchange authorization code for tokens
            tokens = await self._exchange_code_for_tokens(callback.code, callback.provider)
            
            # Get user information
            user_info = await self._get_user_info(tokens.access_token, callback.provider)
            
            # Clean up state
            self.state_storage.pop(callback.state, None)
            
            logger.info(f"Successfully authenticated user via {callback.provider.value}: {user_info.email}")
            
            return {
                "user_info": asdict(user_info),
                "tokens": tokens.dict(),
                "provider": callback.provider.value,
                "authenticated_at": datetime.now(timezone.utc).isoformat()
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"OAuth callback handling failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"OAuth callback handling failed: {str(e)}"
            )
    
    async def _exchange_code_for_tokens(self, code: str, provider: OAuthProvider) -> OAuthTokenResponse:
        """Exchange authorization code for access tokens."""
        config = self.get_provider_config(provider)
        
        token_data = {
            "client_id": config.client_id,
            "client_secret": config.client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": config.redirect_uri
        }
        
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        # GitHub requires specific Accept header
        if provider == OAuthProvider.GITHUB:
            headers["Accept"] = "application/json"
        
        try:
            response = await self.http_client.post(
                config.token_url,
                data=token_data,
                headers=headers
            )
            response.raise_for_status()
            
            token_response = response.json()
            
            # Validate required fields
            if "access_token" not in token_response:
                raise ValueError("No access token in response")
            
            return OAuthTokenResponse(**token_response)
            
        except httpx.HTTPStatusError as e:
            logger.error(f"Token exchange failed: {e.response.status_code} - {e.response.text}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to exchange authorization code for tokens"
            )
        except Exception as e:
            logger.error(f"Token exchange error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Token exchange failed"
            )
    
    async def _get_user_info(self, access_token: str, provider: OAuthProvider) -> OAuthUserInfo:
        """Get user information from OAuth provider."""
        config = self.get_provider_config(provider)
        
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json"
        }
        
        try:
            response = await self.http_client.get(
                config.userinfo_url,
                headers=headers
            )
            response.raise_for_status()
            
            user_data = response.json()
            
            # Parse user info based on provider
            if provider == OAuthProvider.GOOGLE:
                return self._parse_google_user_info(user_data)
            elif provider == OAuthProvider.GITHUB:
                return await self._parse_github_user_info(user_data, access_token)
            else:
                raise ValueError(f"Unsupported provider: {provider}")
                
        except httpx.HTTPStatusError as e:
            logger.error(f"User info request failed: {e.response.status_code} - {e.response.text}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to get user information"
            )
        except Exception as e:
            logger.error(f"User info error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to get user information"
            )
    
    def _parse_google_user_info(self, user_data: Dict[str, Any]) -> OAuthUserInfo:
        """Parse Google user information."""
        return OAuthUserInfo(
            provider="google",
            provider_id=user_data.get("id", ""),
            email=user_data.get("email", ""),
            name=user_data.get("name", ""),
            avatar_url=user_data.get("picture"),
            username=user_data.get("email", "").split("@")[0],
            verified_email=user_data.get("verified_email", False),
            raw_data=user_data
        )
    
    async def _parse_github_user_info(self, user_data: Dict[str, Any], access_token: str) -> OAuthUserInfo:
        """Parse GitHub user information."""
        # GitHub requires separate API call for email if not public
        email = user_data.get("email")
        if not email:
            email = await self._get_github_primary_email(access_token)
        
        return OAuthUserInfo(
            provider="github",
            provider_id=str(user_data.get("id", "")),
            email=email or "",
            name=user_data.get("name") or user_data.get("login", ""),
            avatar_url=user_data.get("avatar_url"),
            username=user_data.get("login"),
            verified_email=True,  # GitHub emails are generally verified
            raw_data=user_data
        )
    
    async def _get_github_primary_email(self, access_token: str) -> Optional[str]:
        """Get primary email from GitHub API."""
        try:
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json"
            }
            
            response = await self.http_client.get(
                "https://api.github.com/user/emails",
                headers=headers
            )
            response.raise_for_status()
            
            emails = response.json()
            
            # Find primary email
            for email_data in emails:
                if email_data.get("primary", False):
                    return email_data.get("email")
            
            # Fallback to first email
            if emails:
                return emails[0].get("email")
                
        except Exception as e:
            logger.error(f"Failed to get GitHub email: {e}")
        
        return None
    
    def _validate_state(self, state: str) -> OAuthStateData:
        """Validate OAuth state parameter."""
        if not state or state not in self.state_storage:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired OAuth state"
            )
        
        state_data = self.state_storage[state]
        
        # Check if state is expired (15 minutes)
        if datetime.now(timezone.utc) - state_data.created_at > timedelta(minutes=15):
            self.state_storage.pop(state, None)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="OAuth state expired"
            )
        
        return state_data
    
    def _generate_state(self) -> str:
        """Generate secure state parameter."""
        return secrets.token_urlsafe(32)
    
    def _generate_nonce(self) -> str:
        """Generate secure nonce for OpenID Connect."""
        return secrets.token_urlsafe(16)
    
    async def refresh_token(self, refresh_token: str, provider: OAuthProvider) -> OAuthTokenResponse:
        """Refresh OAuth access token."""
        config = self.get_provider_config(provider)
        
        # Not all providers support refresh tokens
        if provider == OAuthProvider.GITHUB:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="GitHub does not support token refresh"
            )
        
        token_data = {
            "client_id": config.client_id,
            "client_secret": config.client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token"
        }
        
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        try:
            response = await self.http_client.post(
                config.token_url,
                data=token_data,
                headers=headers
            )
            response.raise_for_status()
            
            token_response = response.json()
            return OAuthTokenResponse(**token_response)
            
        except httpx.HTTPStatusError as e:
            logger.error(f"Token refresh failed: {e.response.status_code} - {e.response.text}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to refresh token"
            )
        except Exception as e:
            logger.error(f"Token refresh error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Token refresh failed"
            )
    
    async def revoke_token(self, token: str, provider: OAuthProvider) -> bool:
        """Revoke OAuth access token."""
        config = self.get_provider_config(provider)
        
        # Provider-specific revocation endpoints
        revoke_urls = {
            OAuthProvider.GOOGLE: "https://oauth2.googleapis.com/revoke",
            OAuthProvider.GITHUB: None  # GitHub doesn't have a revocation endpoint
        }
        
        revoke_url = revoke_urls.get(provider)
        if not revoke_url:
            logger.warning(f"Token revocation not supported for {provider.value}")
            return False
        
        try:
            response = await self.http_client.post(
                revoke_url,
                data={"token": token},
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            return response.status_code == 200
            
        except Exception as e:
            logger.error(f"Token revocation failed: {e}")
            return False
    
    async def validate_token(self, token: str, provider: OAuthProvider) -> Dict[str, Any]:
        """Validate OAuth access token."""
        config = self.get_provider_config(provider)
        
        # Try to get user info with the token
        try:
            user_info = await self._get_user_info(token, provider)
            return {
                "valid": True,
                "user_info": asdict(user_info),
                "provider": provider.value
            }
        except HTTPException:
            return {
                "valid": False,
                "provider": provider.value
            }
    
    def get_supported_providers(self) -> List[Dict[str, Any]]:
        """Get list of supported OAuth providers."""
        return [
            {
                "provider": provider.value,
                "name": provider.value.title(),
                "scopes": config.scopes,
                "configured": bool(config.client_id and config.client_secret)
            }
            for provider, config in self.providers.items()
        ]
    
    async def cleanup_expired_states(self):
        """Clean up expired OAuth states."""
        now = datetime.now(timezone.utc)
        expired_states = [
            state for state, data in self.state_storage.items()
            if now - data.created_at > timedelta(minutes=15)
        ]
        
        for state in expired_states:
            self.state_storage.pop(state, None)
        
        if expired_states:
            logger.info(f"Cleaned up {len(expired_states)} expired OAuth states")
    
    async def close(self):
        """Close HTTP client and clean up resources."""
        await self.http_client.aclose()


# Global OAuth service instance
oauth_service = OAuthService()


# OAuth integration with existing JWT system
class OAuthJWTIntegration:
    """Integration between OAuth and JWT authentication systems."""
    
    def __init__(self, oauth_service: OAuthService):
        self.oauth_service = oauth_service
    
    async def create_jwt_from_oauth(self, user_info: OAuthUserInfo, provider: str) -> Dict[str, str]:
        """Create JWT tokens from OAuth user information."""
        # Import JWT authenticator (avoiding circular imports)
        from app.middleware.auth import authenticator
        
        # Create user data for JWT
        user_data = {
            "user_id": f"{provider}_{user_info.provider_id}",
            "username": user_info.username or user_info.email.split("@")[0],
            "email": user_info.email,
            "name": user_info.name,
            "avatar_url": user_info.avatar_url,
            "provider": provider,
            "verified_email": user_info.verified_email,
            "roles": ["user"],  # Default role, can be customized
            "oauth_authenticated": True
        }
        
        # Generate JWT tokens
        access_token = authenticator.create_access_token(user_data)
        refresh_token = authenticator.create_refresh_token(user_data)
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "user_data": user_data
        }
    
    async def link_oauth_account(self, jwt_user_id: str, oauth_user_info: OAuthUserInfo) -> bool:
        """Link OAuth account to existing JWT user."""
        # This would integrate with your user database
        # For now, just log the operation
        logger.info(f"Linking OAuth account {oauth_user_info.provider}:{oauth_user_info.provider_id} to user {jwt_user_id}")
        return True
    
    async def unlink_oauth_account(self, jwt_user_id: str, provider: str) -> bool:
        """Unlink OAuth account from JWT user."""
        logger.info(f"Unlinking OAuth account {provider} from user {jwt_user_id}")
        return True


# Global OAuth-JWT integration
oauth_jwt_integration = OAuthJWTIntegration(oauth_service)

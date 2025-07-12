"""
OAuth2 Authentication API Endpoints.

This module provides REST API endpoints for OAuth2 social login:
- OAuth authorization URL generation
- OAuth callback handling
- Provider management
- Token operations
- Account linking/unlinking

Endpoints support Google and GitHub OAuth2 providers with extensible
framework for additional providers.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

from app.services.oauth import (
    oauth_service,
    oauth_jwt_integration,
    OAuthProvider,
    OAuthAuthorizationRequest,
    OAuthCallbackRequest,
    OAuthUserInfo
)
from app.middleware.auth import get_current_user

router = APIRouter(prefix="/api/v1/auth/oauth", tags=["OAuth Authentication"])


# Request/Response Models

class OAuthLoginRequest(BaseModel):
    """Request model for initiating OAuth login."""
    provider: OAuthProvider = Field(..., description="OAuth provider")
    scopes: Optional[List[str]] = Field(None, description="Requested OAuth scopes")
    redirect_uri: Optional[str] = Field(None, description="Custom redirect URI")


class OAuthLoginResponse(BaseModel):
    """Response model for OAuth login initiation."""
    authorization_url: str = Field(..., description="OAuth authorization URL")
    state: str = Field(..., description="OAuth state parameter")
    provider: str = Field(..., description="OAuth provider name")


class OAuthCallbackResponse(BaseModel):
    """Response model for OAuth callback."""
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field(default="bearer", description="Token type")
    user_info: Dict[str, Any] = Field(..., description="User information")
    provider: str = Field(..., description="OAuth provider")
    expires_in: int = Field(default=3600, description="Token expiration in seconds")


class OAuthProviderInfo(BaseModel):
    """OAuth provider information."""
    provider: str = Field(..., description="Provider identifier")
    name: str = Field(..., description="Provider display name")
    scopes: List[str] = Field(..., description="Available scopes")
    configured: bool = Field(..., description="Whether provider is configured")


class OAuthTokenRefreshRequest(BaseModel):
    """Request model for OAuth token refresh."""
    refresh_token: str = Field(..., description="OAuth refresh token")
    provider: OAuthProvider = Field(..., description="OAuth provider")


class OAuthTokenValidationRequest(BaseModel):
    """Request model for OAuth token validation."""
    access_token: str = Field(..., description="OAuth access token")
    provider: OAuthProvider = Field(..., description="OAuth provider")


class OAuthAccountLinkRequest(BaseModel):
    """Request model for linking OAuth account."""
    provider: OAuthProvider = Field(..., description="OAuth provider")
    oauth_access_token: str = Field(..., description="OAuth access token")


# OAuth Login Endpoints

@router.post("/login", response_model=OAuthLoginResponse)
async def initiate_oauth_login(request: OAuthLoginRequest):
    """
    Initiate OAuth2 login flow.
    
    Generates authorization URL for the specified OAuth provider.
    Client should redirect user to this URL to begin OAuth flow.
    """
    try:
        auth_request = OAuthAuthorizationRequest(
            provider=request.provider,
            scopes=request.scopes or [],
            redirect_uri=request.redirect_uri
        )
        
        result = oauth_service.generate_authorization_url(auth_request)
        
        return OAuthLoginResponse(
            authorization_url=result["authorization_url"],
            state=result["state"],
            provider=result["provider"]
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to initiate OAuth login: {str(e)}"
        )


@router.get("/login/{provider}")
async def initiate_oauth_login_direct(provider: str, scopes: Optional[str] = None):
    """
    Direct OAuth login initiation (GET endpoint for easy browser access).
    
    Alternative endpoint that directly redirects to OAuth provider.
    Useful for simple integrations and testing.
    """
    try:
        # Parse provider
        try:
            oauth_provider = OAuthProvider(provider.lower())
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported OAuth provider: {provider}"
            )
        
        # Parse scopes
        scope_list = scopes.split(",") if scopes else []
        
        auth_request = OAuthAuthorizationRequest(
            provider=oauth_provider,
            scopes=scope_list
        )
        
        result = oauth_service.generate_authorization_url(auth_request)
        
        # Redirect directly to OAuth provider
        return RedirectResponse(
            url=result["authorization_url"],
            status_code=status.HTTP_302_FOUND
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to initiate OAuth login: {str(e)}"
        )


# OAuth Callback Endpoints

@router.get("/callback/{provider}")
async def oauth_callback(
    provider: str,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
    error_description: Optional[str] = None
):
    """
    Handle OAuth2 callback from provider.
    
    Processes the authorization code from OAuth provider,
    exchanges it for tokens, and creates JWT session.
    """
    try:
        # Parse provider
        try:
            oauth_provider = OAuthProvider(provider.lower())
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported OAuth provider: {provider}"
            )
        
        # Check for OAuth errors
        if error:
            error_msg = error_description or error
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"OAuth error: {error_msg}"
            )
        
        # Validate required parameters
        if not code or not state:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing required OAuth callback parameters"
            )
        
        # Process callback
        callback_request = OAuthCallbackRequest(
            code=code,
            state=state,
            provider=oauth_provider,
            error=error,
            error_description=error_description
        )
        
        # Handle OAuth callback
        oauth_result = await oauth_service.handle_callback(callback_request)
        
        # Create JWT tokens from OAuth user info
        user_info = OAuthUserInfo(**oauth_result["user_info"])
        jwt_tokens = await oauth_jwt_integration.create_jwt_from_oauth(
            user_info, provider
        )
        
        return OAuthCallbackResponse(
            access_token=jwt_tokens["access_token"],
            refresh_token=jwt_tokens["refresh_token"],
            token_type=jwt_tokens["token_type"],
            user_info=jwt_tokens["user_data"],
            provider=provider,
            expires_in=3600  # 1 hour
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"OAuth callback failed: {str(e)}"
        )


@router.post("/callback/{provider}", response_model=OAuthCallbackResponse)
async def oauth_callback_post(provider: str, callback_data: Dict[str, Any]):
    """
    Handle OAuth2 callback via POST (alternative for some integrations).
    
    Some OAuth flows may use POST for callback data.
    This endpoint handles the same logic as the GET version.
    """
    try:
        oauth_provider = OAuthProvider(provider.lower())
        
        callback_request = OAuthCallbackRequest(
            code=callback_data.get("code", ""),
            state=callback_data.get("state", ""),
            provider=oauth_provider,
            error=callback_data.get("error"),
            error_description=callback_data.get("error_description")
        )
        
        oauth_result = await oauth_service.handle_callback(callback_request)
        user_info = OAuthUserInfo(**oauth_result["user_info"])
        jwt_tokens = await oauth_jwt_integration.create_jwt_from_oauth(
            user_info, provider
        )
        
        return OAuthCallbackResponse(
            access_token=jwt_tokens["access_token"],
            refresh_token=jwt_tokens["refresh_token"],
            token_type=jwt_tokens["token_type"],
            user_info=jwt_tokens["user_data"],
            provider=provider,
            expires_in=3600
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"OAuth callback failed: {str(e)}"
        )


# Provider Information

@router.get("/providers", response_model=List[OAuthProviderInfo])
async def get_oauth_providers():
    """
    Get list of supported OAuth providers.
    
    Returns information about all configured OAuth providers
    including their capabilities and configuration status.
    """
    try:
        providers = oauth_service.get_supported_providers()
        
        return [
            OAuthProviderInfo(**provider)
            for provider in providers
        ]
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get OAuth providers: {str(e)}"
        )


@router.get("/providers/{provider}")
async def get_oauth_provider_info(provider: str):
    """Get information about a specific OAuth provider."""
    try:
        oauth_provider = OAuthProvider(provider.lower())
        config = oauth_service.get_provider_config(oauth_provider)
        
        return {
            "provider": provider,
            "name": provider.title(),
            "scopes": config.scopes,
            "authorization_url": config.authorization_url,
            "configured": bool(config.client_id and config.client_secret)
        }
        
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"OAuth provider '{provider}' not found"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get provider info: {str(e)}"
        )


# Token Operations

@router.post("/token/refresh")
async def refresh_oauth_token(request: OAuthTokenRefreshRequest):
    """
    Refresh OAuth access token.
    
    Note: Not all providers support token refresh (e.g., GitHub doesn't).
    """
    try:
        tokens = await oauth_service.refresh_token(
            request.refresh_token,
            request.provider
        )
        
        return {
            "access_token": tokens.access_token,
            "token_type": tokens.token_type,
            "expires_in": tokens.expires_in,
            "refresh_token": tokens.refresh_token,
            "scope": tokens.scope
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Token refresh failed: {str(e)}"
        )


@router.post("/token/validate")
async def validate_oauth_token(request: OAuthTokenValidationRequest):
    """Validate OAuth access token."""
    try:
        result = await oauth_service.validate_token(
            request.access_token,
            request.provider
        )
        
        return result
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Token validation failed: {str(e)}"
        )


@router.post("/token/revoke")
async def revoke_oauth_token(
    provider: str,
    access_token: str,
    current_user = Depends(get_current_user)
):
    """
    Revoke OAuth access token.
    
    Requires authentication. Only works for providers that support revocation.
    """
    try:
        oauth_provider = OAuthProvider(provider.lower())
        success = await oauth_service.revoke_token(access_token, oauth_provider)
        
        return {
            "revoked": success,
            "provider": provider,
            "message": "Token revoked successfully" if success else "Token revocation not supported"
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Token revocation failed: {str(e)}"
        )


# Account Management

@router.post("/account/link")
async def link_oauth_account(
    request: OAuthAccountLinkRequest,
    current_user = Depends(get_current_user)
):
    """
    Link OAuth account to current JWT user.
    
    Allows users to connect their social accounts to their existing account.
    """
    try:
        # Validate OAuth token and get user info
        validation_result = await oauth_service.validate_token(
            request.oauth_access_token,
            request.provider
        )
        
        if not validation_result["valid"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid OAuth token"
            )
        
        # Link account
        oauth_user_info = OAuthUserInfo(**validation_result["user_info"])
        success = await oauth_jwt_integration.link_oauth_account(
            current_user["user_id"],
            oauth_user_info
        )
        
        return {
            "linked": success,
            "provider": request.provider.value,
            "oauth_user_id": oauth_user_info.provider_id,
            "oauth_email": oauth_user_info.email
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Account linking failed: {str(e)}"
        )


@router.delete("/account/unlink/{provider}")
async def unlink_oauth_account(
    provider: str,
    current_user = Depends(get_current_user)
):
    """
    Unlink OAuth account from current JWT user.
    
    Removes the connection between the user's account and their social account.
    """
    try:
        oauth_provider = OAuthProvider(provider.lower())
        success = await oauth_jwt_integration.unlink_oauth_account(
            current_user["user_id"],
            provider
        )
        
        return {
            "unlinked": success,
            "provider": provider,
            "user_id": current_user["user_id"]
        }
        
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported provider: {provider}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Account unlinking failed: {str(e)}"
        )


@router.get("/account/linked")
async def get_linked_oauth_accounts(current_user = Depends(get_current_user)):
    """
    Get list of OAuth accounts linked to current user.
    
    Returns information about all social accounts connected to the user.
    """
    try:
        # In a real implementation, this would query the database
        # For now, return mock data based on current user info
        linked_accounts = []
        
        if current_user.get("provider"):
            linked_accounts.append({
                "provider": current_user["provider"],
                "provider_id": current_user.get("user_id", "").split("_", 1)[-1],
                "email": current_user.get("email"),
                "username": current_user.get("username"),
                "linked_at": datetime.utcnow().isoformat()
            })
        
        return {
            "user_id": current_user["user_id"],
            "linked_accounts": linked_accounts,
            "total_linked": len(linked_accounts)
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get linked accounts: {str(e)}"
        )


# System Administration

@router.post("/admin/cleanup")
async def cleanup_expired_oauth_states(current_user = Depends(get_current_user)):
    """
    Clean up expired OAuth states (Admin only).
    
    Removes expired OAuth state data to prevent memory leaks.
    """
    # Check admin permissions
    user_roles = current_user.get("roles", [])
    if not any(role in ["admin", "super_admin"] for role in user_roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative privileges required"
        )
    
    try:
        await oauth_service.cleanup_expired_states()
        
        return {
            "message": "OAuth state cleanup completed",
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Cleanup failed: {str(e)}"
        )


@router.get("/admin/stats")
async def get_oauth_stats(current_user = Depends(get_current_user)):
    """
    Get OAuth system statistics (Admin only).
    
    Returns usage and health statistics for the OAuth system.
    """
    # Check admin permissions
    user_roles = current_user.get("roles", [])
    if not any(role in ["admin", "super_admin"] for role in user_roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative privileges required"
        )
    
    try:
        providers = oauth_service.get_supported_providers()
        active_states = len(oauth_service.state_storage)
        
        return {
            "total_providers": len(providers),
            "configured_providers": sum(1 for p in providers if p["configured"]),
            "active_oauth_states": active_states,
            "providers": providers,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get OAuth stats: {str(e)}"
        )

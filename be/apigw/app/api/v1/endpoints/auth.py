"""
Authentication endpoints for JWT token management.

This module provides REST API endpoints for authentication including:
- User login with JWT token generation
- Token refresh
- Token revocation
- User registration (for testing)
- Authentication status
"""

from datetime import timedelta
from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, EmailStr, Field

from app.middleware.auth import (
    authenticator, 
    audit_logger, 
    get_current_user, 
    get_current_user_optional,
    UserContext,
    get_client_ip,
    get_user_agent
)

router = APIRouter(prefix="/auth", tags=["authentication"])


class LoginRequest(BaseModel):
    """Login request model."""
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6, max_length=100)


class TokenResponse(BaseModel):
    """Token response model."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 900  # 15 minutes in seconds


class RefreshRequest(BaseModel):
    """Token refresh request model."""
    refresh_token: str


class UserRegistration(BaseModel):
    """User registration model (for testing)."""
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=6, max_length=100)
    roles: list[str] = Field(default=["user"])


class AuthStatusResponse(BaseModel):
    """Authentication status response."""
    authenticated: bool
    user: UserContext | None = None
    message: str


# Mock user database (in production, use proper database)
MOCK_USERS = {
    "admin": {
        "user_id": "admin-123",
        "username": "admin",
        "email": "admin@example.com",
        "password_hash": authenticator.get_password_hash("admin123"),
        "roles": ["admin"],
        "active": True
    },
    "testuser": {
        "user_id": "user-456",
        "username": "testuser",
        "email": "test@example.com",
        "password_hash": authenticator.get_password_hash("test123"),
        "roles": ["user"],
        "active": True
    }
}


def authenticate_user(username: str, password: str) -> Dict[str, Any] | None:
    """Authenticate user with username and password."""
    user = MOCK_USERS.get(username)
    if not user or not user["active"]:
        return None
    
    if not authenticator.verify_password(password, user["password_hash"]):
        return None
    
    return user


@router.post("/login", response_model=TokenResponse)
async def login(request: Request, login_data: LoginRequest) -> TokenResponse:
    """
    Authenticate user and return JWT tokens.
    
    Returns access token (15 min) and refresh token (30 days).
    """
    client_ip = get_client_ip(request)
    user_agent = get_user_agent(request)
    
    # Authenticate user
    user = authenticate_user(login_data.username, login_data.password)
    if not user:
        # Log failed authentication
        await audit_logger.log_authentication_failure(
            username=login_data.username,
            ip_address=client_ip,
            user_agent=user_agent,
            reason="Invalid credentials"
        )
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    # Create tokens
    user_data = {
        "user_id": user["user_id"],
        "username": user["username"],
        "email": user["email"],
        "roles": user["roles"]
    }
    
    access_token = authenticator.create_access_token(user_data)
    refresh_token = authenticator.create_refresh_token(user_data)
    
    # Log successful authentication
    await audit_logger.log_authentication_success(
        user_id=user["user_id"],
        ip_address=client_ip,
        user_agent=user_agent
    )
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=authenticator.config.access_token_expire_minutes * 60
    )


@router.post("/refresh", response_model=Dict[str, str])
async def refresh_token(request: Request, refresh_data: RefreshRequest) -> Dict[str, str]:
    """
    Refresh access token using refresh token.
    
    Returns new access token.
    """
    client_ip = get_client_ip(request)
    
    try:
        # Generate new access token
        tokens = authenticator.refresh_access_token(refresh_data.refresh_token)
        
        # Extract user ID from refresh token for logging
        token_data = authenticator.verify_token(refresh_data.refresh_token)
        
        # Log token refresh
        await audit_logger.log_token_refresh(
            user_id=token_data.user_id,
            ip_address=client_ip
        )
        
        return tokens
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not refresh token"
        )


@router.post("/revoke")
async def revoke_token(request: Request, current_user: UserContext = Depends(get_current_user)) -> Dict[str, str]:
    """
    Revoke current access token.
    
    Adds token to revocation list.
    """
    client_ip = get_client_ip(request)
    
    if current_user.token_jti:
        authenticator.revoke_token(current_user.token_jti)
        
        # Log token revocation
        await audit_logger.log_token_revocation(
            user_id=current_user.user_id,
            jti=current_user.token_jti,
            ip_address=client_ip
        )
    
    return {"message": "Token revoked successfully"}


@router.get("/me", response_model=UserContext)
async def get_current_user_info(current_user: UserContext = Depends(get_current_user)) -> UserContext:
    """
    Get current authenticated user information.
    """
    return current_user


@router.get("/status", response_model=AuthStatusResponse)
async def auth_status(current_user: UserContext | None = Depends(get_current_user_optional)) -> AuthStatusResponse:
    """
    Check authentication status.
    
    Returns whether user is authenticated and user info if available.
    """
    if current_user:
        return AuthStatusResponse(
            authenticated=True,
            user=current_user,
            message="User is authenticated"
        )
    else:
        return AuthStatusResponse(
            authenticated=False,
            message="User is not authenticated"
        )


@router.post("/register", response_model=Dict[str, str])
async def register_user(user_data: UserRegistration) -> Dict[str, str]:
    """
    Register new user (for testing/development).
    
    In production, this would be a separate service with proper validation.
    """
    # Check if user already exists
    if user_data.username in MOCK_USERS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists"
        )
    
    # Hash password and store user
    password_hash = authenticator.get_password_hash(user_data.password)
    user_id = f"user-{len(MOCK_USERS) + 1}"
    
    MOCK_USERS[user_data.username] = {
        "user_id": user_id,
        "username": user_data.username,
        "email": str(user_data.email),
        "password_hash": password_hash,
        "roles": user_data.roles,
        "active": True
    }
    
    return {
        "message": "User registered successfully",
        "user_id": user_id
    }


@router.get("/test-tokens")
async def get_test_tokens() -> Dict[str, Any]:
    """
    Generate test tokens for development.
    
    This endpoint should be removed in production.
    """
    # Create test user token
    test_user_token = {
        "user_id": "test-user-123",
        "username": "testuser",
        "email": "test@example.com",
        "roles": ["user"]
    }
    
    # Create admin token
    admin_token = {
        "user_id": "admin-123", 
        "username": "admin",
        "email": "admin@example.com",
        "roles": ["admin"]
    }
    
    return {
        "test_user": {
            "access_token": authenticator.create_access_token(test_user_token),
            "refresh_token": authenticator.create_refresh_token(test_user_token),
            "token_type": "bearer"
        },
        "admin": {
            "access_token": authenticator.create_access_token(admin_token),
            "refresh_token": authenticator.create_refresh_token(admin_token),
            "token_type": "bearer"
        }
    }

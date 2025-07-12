"""
JWT Authentication configuration settings.

This module provides configuration management for JWT authentication
with environment variable support and secure defaults.
"""

import os
from typing import List, Optional
from pydantic_settings import BaseSettings
from pydantic import Field


class JWTSettings(BaseSettings):
    """JWT Authentication settings."""
    
    # Core JWT settings
    jwt_secret_key: str = Field(
        default="your-super-secret-jwt-key-change-in-production",
        env="JWT_SECRET_KEY",
        description="Secret key for JWT token signing"
    )
    
    jwt_algorithm: str = Field(
        default="HS256",
        env="JWT_ALGORITHM",
        description="JWT signing algorithm"
    )
    
    # Token expiration settings
    access_token_expire_minutes: int = Field(
        default=15,
        env="JWT_ACCESS_TOKEN_EXPIRE_MINUTES",
        description="Access token expiration in minutes"
    )
    
    refresh_token_expire_days: int = Field(
        default=30,
        env="JWT_REFRESH_TOKEN_EXPIRE_DAYS",
        description="Refresh token expiration in days"
    )
    
    # Token issuer and audience
    token_issuer: str = Field(
        default="gca-api-gateway",
        env="JWT_ISSUER",
        description="JWT token issuer"
    )
    
    token_audience: str = Field(
        default="gca-services",
        env="JWT_AUDIENCE",
        description="JWT token audience"
    )
    
    # Authentication behavior
    require_auth_by_default: bool = Field(
        default=False,
        env="JWT_REQUIRE_AUTH_BY_DEFAULT",
        description="Require authentication for all endpoints by default"
    )
    
    # Protected paths (require authentication)
    protected_paths: List[str] = Field(
        default=["/gateway", "/api/v1/admin", "/api/v1/metrics"],
        env="JWT_PROTECTED_PATHS",
        description="List of path prefixes that require authentication"
    )
    
    # Public paths (no authentication required)
    public_paths: List[str] = Field(
        default=["/docs", "/redoc", "/", "/api/v1/health", "/api/v1/auth", "/openapi.json"],
        env="JWT_PUBLIC_PATHS",
        description="List of path prefixes that don't require authentication"
    )
    
    # Security settings
    enable_audit_logging: bool = Field(
        default=True,
        env="JWT_ENABLE_AUDIT_LOGGING",
        description="Enable security audit logging"
    )
    
    audit_log_level: str = Field(
        default="INFO",
        env="JWT_AUDIT_LOG_LEVEL",
        description="Log level for audit events"
    )
    
    # Rate limiting for auth endpoints
    auth_rate_limit_enabled: bool = Field(
        default=True,
        env="JWT_AUTH_RATE_LIMIT_ENABLED",
        description="Enable rate limiting for auth endpoints"
    )
    
    auth_rate_limit_attempts: int = Field(
        default=5,
        env="JWT_AUTH_RATE_LIMIT_ATTEMPTS",
        description="Max auth attempts per time window"
    )
    
    auth_rate_limit_window_minutes: int = Field(
        default=15,
        env="JWT_AUTH_RATE_LIMIT_WINDOW_MINUTES",
        description="Rate limit time window in minutes"
    )
    
    # Token storage (for production use Redis)
    token_storage_backend: str = Field(
        default="memory",
        env="JWT_TOKEN_STORAGE_BACKEND",
        description="Token storage backend (memory, redis)"
    )
    
    redis_url: Optional[str] = Field(
        default=None,
        env="REDIS_URL",
        description="Redis URL for token storage"
    )
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


# Global settings instance
jwt_settings = JWTSettings()


def get_jwt_settings() -> JWTSettings:
    """Get JWT settings instance."""
    return jwt_settings


def validate_jwt_config() -> bool:
    """
    Validate JWT configuration.
    
    Returns:
        True if configuration is valid for production
    """
    settings = get_jwt_settings()
    
    issues = []
    
    # Check for default secret key
    if settings.jwt_secret_key == "your-super-secret-jwt-key-change-in-production":
        issues.append("❌ Using default JWT secret key - CHANGE FOR PRODUCTION!")
    
    # Check secret key strength
    if len(settings.jwt_secret_key) < 32:
        issues.append("⚠️  JWT secret key should be at least 32 characters long")
    
    # Check token expiration times
    if settings.access_token_expire_minutes > 60:
        issues.append("⚠️  Access token expiration is longer than 1 hour (security risk)")
    
    if settings.refresh_token_expire_days > 90:
        issues.append("⚠️  Refresh token expiration is longer than 90 days (security risk)")
    
    # Check Redis configuration if using Redis backend
    if settings.token_storage_backend == "redis" and not settings.redis_url:
        issues.append("❌ Redis backend selected but no Redis URL provided")
    
    if issues:
        print("JWT Configuration Issues:")
        for issue in issues:
            print(f"  {issue}")
        return False
    
    print("✅ JWT configuration is valid")
    return True


def print_jwt_config():
    """Print current JWT configuration (excluding sensitive data)."""
    settings = get_jwt_settings()
    
    print("Current JWT Configuration:")
    print("=" * 40)
    print(f"Algorithm: {settings.jwt_algorithm}")
    print(f"Access Token Expiry: {settings.access_token_expire_minutes} minutes")
    print(f"Refresh Token Expiry: {settings.refresh_token_expire_days} days")
    print(f"Issuer: {settings.token_issuer}")
    print(f"Audience: {settings.token_audience}")
    print(f"Require Auth by Default: {settings.require_auth_by_default}")
    print(f"Protected Paths: {settings.protected_paths}")
    print(f"Public Paths: {settings.public_paths}")
    print(f"Audit Logging: {settings.enable_audit_logging}")
    print(f"Rate Limiting: {settings.auth_rate_limit_enabled}")
    print(f"Token Storage: {settings.token_storage_backend}")
    print(f"Secret Key: {'*' * min(len(settings.jwt_secret_key), 20)}...")


if __name__ == "__main__":
    print_jwt_config()
    validate_jwt_config()

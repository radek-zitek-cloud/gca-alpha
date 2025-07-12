"""
OAuth2 Configuration Management.

This module provides configuration management for OAuth2 providers:
- Environment variable loading
- Provider configuration validation
- Dynamic configuration updates
- Security best practices
"""

import os
import logging
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict

from app.services.oauth import OAuthConfig, OAuthProvider, oauth_service

logger = logging.getLogger(__name__)


@dataclass
class OAuthProviderConfig:
    """OAuth provider configuration from environment."""
    provider: str
    client_id: str
    client_secret: str
    redirect_uri: str
    scopes: list
    enabled: bool = True


class OAuthConfigManager:
    """Manages OAuth provider configurations."""
    
    def __init__(self):
        """Initialize OAuth configuration manager."""
        self.configs: Dict[str, OAuthProviderConfig] = {}
        self.load_from_environment()
    
    def load_from_environment(self):
        """Load OAuth configurations from environment variables."""
        try:
            # Google OAuth Configuration
            self._load_google_config()
            
            # GitHub OAuth Configuration
            self._load_github_config()
            
            # Apply configurations to OAuth service
            self._apply_configurations()
            
            logger.info("OAuth configurations loaded successfully")
            
        except Exception as e:
            logger.error(f"Failed to load OAuth configurations: {e}")
    
    def _load_google_config(self):
        """Load Google OAuth configuration."""
        google_config = OAuthProviderConfig(
            provider="google",
            client_id=os.getenv("GOOGLE_OAUTH_CLIENT_ID", ""),
            client_secret=os.getenv("GOOGLE_OAUTH_CLIENT_SECRET", ""),
            redirect_uri=os.getenv(
                "GOOGLE_OAUTH_REDIRECT_URI", 
                "http://localhost:8000/api/v1/auth/oauth/callback/google"
            ),
            scopes=self._parse_scopes(os.getenv(
                "GOOGLE_OAUTH_SCOPES", 
                "openid,email,profile"
            )),
            enabled=os.getenv("GOOGLE_OAUTH_ENABLED", "false").lower() == "true"
        )
        
        if google_config.enabled and self._validate_config(google_config):
            self.configs["google"] = google_config
            logger.info("Google OAuth configuration loaded")
        elif google_config.enabled:
            logger.warning("Google OAuth enabled but configuration incomplete")
    
    def _load_github_config(self):
        """Load GitHub OAuth configuration."""
        github_config = OAuthProviderConfig(
            provider="github",
            client_id=os.getenv("GITHUB_OAUTH_CLIENT_ID", ""),
            client_secret=os.getenv("GITHUB_OAUTH_CLIENT_SECRET", ""),
            redirect_uri=os.getenv(
                "GITHUB_OAUTH_REDIRECT_URI",
                "http://localhost:8000/api/v1/auth/oauth/callback/github"
            ),
            scopes=self._parse_scopes(os.getenv(
                "GITHUB_OAUTH_SCOPES",
                "user,user:email"
            )),
            enabled=os.getenv("GITHUB_OAUTH_ENABLED", "false").lower() == "true"
        )
        
        if github_config.enabled and self._validate_config(github_config):
            self.configs["github"] = github_config
            logger.info("GitHub OAuth configuration loaded")
        elif github_config.enabled:
            logger.warning("GitHub OAuth enabled but configuration incomplete")
    
    def _parse_scopes(self, scopes_str: str) -> list:
        """Parse comma-separated scopes string."""
        if not scopes_str:
            return []
        return [scope.strip() for scope in scopes_str.split(",")]
    
    def _validate_config(self, config: OAuthProviderConfig) -> bool:
        """Validate OAuth provider configuration."""
        if not config.client_id:
            logger.error(f"{config.provider} OAuth: Missing client_id")
            return False
        
        if not config.client_secret:
            logger.error(f"{config.provider} OAuth: Missing client_secret")
            return False
        
        if not config.redirect_uri:
            logger.error(f"{config.provider} OAuth: Missing redirect_uri")
            return False
        
        return True
    
    def _apply_configurations(self):
        """Apply configurations to OAuth service."""
        for provider_name, config in self.configs.items():
            try:
                provider = OAuthProvider(provider_name.lower())
                
                # Map provider-specific URLs
                if provider == OAuthProvider.GOOGLE:
                    oauth_config = OAuthConfig(
                        provider=provider,
                        client_id=config.client_id,
                        client_secret=config.client_secret,
                        redirect_uri=config.redirect_uri,
                        scopes=config.scopes,
                        authorization_url="https://accounts.google.com/o/oauth2/v2/auth",
                        token_url="https://oauth2.googleapis.com/token",
                        userinfo_url="https://www.googleapis.com/oauth2/v2/userinfo"
                    )
                elif provider == OAuthProvider.GITHUB:
                    oauth_config = OAuthConfig(
                        provider=provider,
                        client_id=config.client_id,
                        client_secret=config.client_secret,
                        redirect_uri=config.redirect_uri,
                        scopes=config.scopes,
                        authorization_url="https://github.com/login/oauth/authorize",
                        token_url="https://github.com/login/oauth/access_token",
                        userinfo_url="https://api.github.com/user"
                    )
                else:
                    logger.warning(f"Unknown OAuth provider: {provider_name}")
                    continue
                
                oauth_service.configure_provider(oauth_config)
                logger.info(f"Configured OAuth provider: {provider_name}")
                
            except Exception as e:
                logger.error(f"Failed to configure OAuth provider {provider_name}: {e}")
    
    def get_config(self, provider: str) -> Optional[OAuthProviderConfig]:
        """Get configuration for a specific provider."""
        return self.configs.get(provider.lower())
    
    def get_all_configs(self) -> Dict[str, OAuthProviderConfig]:
        """Get all OAuth configurations."""
        return self.configs.copy()
    
    def is_provider_enabled(self, provider: str) -> bool:
        """Check if OAuth provider is enabled."""
        config = self.get_config(provider)
        return config is not None and config.enabled
    
    def get_enabled_providers(self) -> list:
        """Get list of enabled OAuth providers."""
        return [
            provider for provider, config in self.configs.items()
            if config.enabled
        ]
    
    def reload_configuration(self):
        """Reload OAuth configuration from environment."""
        self.configs.clear()
        self.load_from_environment()
    
    def get_configuration_status(self) -> Dict[str, Any]:
        """Get OAuth configuration status."""
        return {
            "total_providers": len(self.configs),
            "enabled_providers": len(self.get_enabled_providers()),
            "providers": {
                provider: {
                    "enabled": config.enabled,
                    "configured": bool(config.client_id and config.client_secret),
                    "scopes": config.scopes
                }
                for provider, config in self.configs.items()
            }
        }


# Example environment configuration template
OAUTH_ENV_TEMPLATE = """
# OAuth2 Configuration Template
# Copy this to your .env file and fill in your OAuth application credentials

# Google OAuth2 Configuration
GOOGLE_OAUTH_ENABLED=true
GOOGLE_OAUTH_CLIENT_ID=your_google_client_id.googleusercontent.com
GOOGLE_OAUTH_CLIENT_SECRET=your_google_client_secret
GOOGLE_OAUTH_REDIRECT_URI=http://localhost:8000/api/v1/auth/oauth/callback/google
GOOGLE_OAUTH_SCOPES=openid,email,profile

# GitHub OAuth2 Configuration  
GITHUB_OAUTH_ENABLED=true
GITHUB_OAUTH_CLIENT_ID=your_github_client_id
GITHUB_OAUTH_CLIENT_SECRET=your_github_client_secret
GITHUB_OAUTH_REDIRECT_URI=http://localhost:8000/api/v1/auth/oauth/callback/github
GITHUB_OAUTH_SCOPES=user,user:email

# OAuth Security Settings
OAUTH_STATE_TIMEOUT_MINUTES=15
OAUTH_NONCE_LENGTH=16
OAUTH_ENFORCE_HTTPS=false  # Set to true in production
"""


def create_env_template():
    """Create environment configuration template file."""
    template_path = ".env.oauth.template"
    
    try:
        with open(template_path, "w") as f:
            f.write(OAUTH_ENV_TEMPLATE)
        
        logger.info(f"Created OAuth environment template: {template_path}")
        return template_path
        
    except Exception as e:
        logger.error(f"Failed to create environment template: {e}")
        return None


def validate_oauth_setup() -> Dict[str, Any]:
    """Validate OAuth setup and return status."""
    config_manager = OAuthConfigManager()
    status = config_manager.get_configuration_status()
    
    issues = []
    recommendations = []
    
    # Check if any providers are configured
    if status["enabled_providers"] == 0:
        issues.append("No OAuth providers are enabled")
        recommendations.append("Enable at least one OAuth provider in environment variables")
    
    # Check provider configurations
    for provider, config in status["providers"].items():
        if config["enabled"] and not config["configured"]:
            issues.append(f"{provider} OAuth is enabled but not properly configured")
            recommendations.append(f"Set {provider.upper()}_OAUTH_CLIENT_ID and CLIENT_SECRET")
    
    # Security recommendations
    if os.getenv("OAUTH_ENFORCE_HTTPS", "false").lower() != "true":
        recommendations.append("Enable HTTPS enforcement for production (OAUTH_ENFORCE_HTTPS=true)")
    
    return {
        "status": "healthy" if not issues else "warning",
        "providers": status,
        "issues": issues,
        "recommendations": recommendations,
        "template_available": True
    }


# Global configuration manager
oauth_config_manager = OAuthConfigManager()


# Configuration validation on module import
if __name__ == "__main__":
    # Command-line configuration validation
    result = validate_oauth_setup()
    print("OAuth Configuration Status:")
    print(f"Status: {result['status']}")
    print(f"Enabled providers: {result['providers']['enabled_providers']}")
    
    if result['issues']:
        print("\nIssues:")
        for issue in result['issues']:
            print(f"  - {issue}")
    
    if result['recommendations']:
        print("\nRecommendations:")
        for rec in result['recommendations']:
            print(f"  - {rec}")
    
    if result['status'] != "healthy":
        print(f"\nTo fix configuration issues, create environment template:")
        print(f"python -c 'from app.config.oauth_config import create_env_template; create_env_template()'")

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    fusionauth_base_url: str = Field(
        default="http://fusionauth:9011",
        description="FusionAuth base URL"
    )

    fusionauth_api_key: str = Field(
        default="changeme-api-key",
        description="FusionAuth API key for service communication"
    )

    fusionauth_tenant_id: str = Field(
        default="",
        description="FusionAuth tenant ID (empty for default tenant)"
    )

    fusionauth_application_id: str = Field(
        default="10000000-0000-0002-0000-000000000001",
        description="FusionAuth application ID"
    )

    fusionauth_client_secret: str = Field(
        default="changeme-client-secret",
        description="FusionAuth application client secret"
    )

    jwt_expected_iss: str = Field(
        default="http://fusionauth:9011",
        description="Expected JWT issuer for token verification (FusionAuth internal issuer)"
    )

    jwt_expected_aud: str = Field(
        default="6bd5d02c-99b4-4338-9336-3f7572fd3c40",
        description="Expected JWT audience for token verification"
    )

    jwks_cache_ttl_seconds: int = Field(
        default=300,
        description="JWKS cache TTL in seconds"
    )

    # CORS Configuration
    cors_allow_origins: str = Field(
        default="http://localhost:3000,http://localhost:8081",
        description="Comma-separated list of allowed origins for CORS"
    )

    cors_allow_credentials: bool = Field(
        default=True,
        description="Allow credentials (cookies, authorization headers) in CORS requests"
    )

    cors_allow_methods: str = Field(
        default="GET,POST,PUT,DELETE,OPTIONS,PATCH",
        description="Comma-separated list of allowed HTTP methods"
    )

    cors_allow_headers: str = Field(
        default="Content-Type,Authorization",
        description="Comma-separated list of allowed headers"
    )

    @property
    def cors_origins_list(self) -> list[str]:
        """Parse comma-separated origins into a list"""
        return [origin.strip() for origin in self.cors_allow_origins.split(",") if origin.strip()]

    @property
    def cors_methods_list(self) -> list[str]:
        """Parse comma-separated methods into a list"""
        return [method.strip() for method in self.cors_allow_methods.split(",") if method.strip()]

    @property
    def cors_headers_list(self) -> list[str]:
        """Parse comma-separated headers into a list"""
        return [header.strip() for header in self.cors_allow_headers.split(",") if header.strip()]

    # Security Configuration
    snapauth_admin_api_key: str = Field(
        default="",
        description="Primary admin API key for administrative endpoints (legacy, use snapauth_admin_api_keys for multiple keys)"
    )

    snapauth_admin_api_keys: str = Field(
        default="",
        description="Comma-separated list of admin API keys for zero-downtime rotation"
    )

    admin_allowed_ips: str = Field(
        default="",
        description="Comma-separated list of allowed IP addresses or CIDR ranges (e.g., 192.168.1.0/24,10.0.0.1)"
    )

    trust_proxy: bool = Field(
        default=False,
        description="Trust X-Forwarded-For header for client IP detection (enable when behind reverse proxy)"
    )

    rate_limit_enabled: bool = Field(
        default=True,
        description="Enable rate limiting globally"
    )

    rate_limit_per_minute: int = Field(
        default=60,
        description="Default rate limit for authenticated endpoints (requests per minute)"
    )

    rate_limit_per_minute_auth: int = Field(
        default=10,
        description="Rate limit for authentication endpoints (requests per minute)"
    )

    rate_limit_per_minute_admin: int = Field(
        default=30,
        description="Rate limit for admin endpoints (requests per minute)"
    )

    @property
    def admin_api_keys_list(self) -> list[str]:
        """Get list of valid admin API keys (supports both single and multiple keys)"""
        keys = []
        # Add legacy single key if set
        if self.snapauth_admin_api_key:
            keys.append(self.snapauth_admin_api_key)
        # Add multiple keys if set
        if self.snapauth_admin_api_keys:
            keys.extend([key.strip() for key in self.snapauth_admin_api_keys.split(",") if key.strip()])
        return keys

    @property
    def admin_allowed_ips_list(self) -> list[str]:
        """Parse comma-separated IP addresses/CIDR ranges into a list"""
        if not self.admin_allowed_ips:
            return []
        return [ip.strip() for ip in self.admin_allowed_ips.split(",") if ip.strip()]


settings = Settings()

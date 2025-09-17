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

    jwt_expected_iss: str = Field(
        default="localhost:9011",
        description="Expected JWT issuer for token verification"
    )

    jwt_expected_aud: str = Field(
        default="6bd5d02c-99b4-4338-9336-3f7572fd3c40",
        description="Expected JWT audience for token verification"
    )

    jwks_cache_ttl_seconds: int = Field(
        default=300,
        description="JWKS cache TTL in seconds"
    )


settings = Settings()
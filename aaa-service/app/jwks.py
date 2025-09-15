import httpx
import json
import logging
from typing import Dict, Any, Optional
from cachetools import TTLCache
from jose import jwt, JWTError
from jose.exceptions import JWKError

from .settings import settings

logger = logging.getLogger(__name__)


class JWKSError(Exception):
    """Custom exception for JWKS-related errors"""
    pass


class JWTVerificationError(Exception):
    """Custom exception for JWT verification errors"""
    pass


class JWKSManager:
    def __init__(self):
        self.cache = TTLCache(maxsize=10, ttl=settings.jwks_cache_ttl_seconds)
        self.oidc_config_cache = TTLCache(maxsize=1, ttl=settings.jwks_cache_ttl_seconds)

    async def _fetch_oidc_configuration(self) -> Dict[str, Any]:
        """Fetch OIDC discovery configuration from FusionAuth"""
        cache_key = "oidc_config"

        if cache_key in self.oidc_config_cache:
            return self.oidc_config_cache[cache_key]

        try:
            oidc_url = f"{settings.fusionauth_base_url}/.well-known/openid-configuration"
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(oidc_url)
                response.raise_for_status()

                config = response.json()
                self.oidc_config_cache[cache_key] = config
                logger.info("OIDC configuration fetched and cached")
                return config

        except httpx.HTTPError as e:
            logger.error(f"Failed to fetch OIDC configuration: {e}")
            raise JWKSError(f"Failed to fetch OIDC configuration: {str(e)}")
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in OIDC configuration: {e}")
            raise JWKSError(f"Invalid OIDC configuration format: {str(e)}")

    async def _fetch_jwks(self, jwks_uri: str) -> Dict[str, Any]:
        """Fetch JWKS from the specified URI"""
        cache_key = "jwks"

        if cache_key in self.cache:
            return self.cache[cache_key]

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(jwks_uri)
                response.raise_for_status()

                jwks = response.json()
                self.cache[cache_key] = jwks
                logger.info("JWKS fetched and cached")
                return jwks

        except httpx.HTTPError as e:
            logger.error(f"Failed to fetch JWKS: {e}")
            raise JWKSError(f"Failed to fetch JWKS: {str(e)}")
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in JWKS: {e}")
            raise JWKSError(f"Invalid JWKS format: {str(e)}")

    async def get_jwks(self) -> Dict[str, Any]:
        """Get JWKS, fetching from cache or FusionAuth if needed"""
        try:
            oidc_config = await self._fetch_oidc_configuration()
            jwks_uri = oidc_config.get("jwks_uri")

            if not jwks_uri:
                raise JWKSError("No jwks_uri found in OIDC configuration")

            return await self._fetch_jwks(jwks_uri)

        except Exception as e:
            logger.error(f"Error getting JWKS: {e}")
            raise

    def _find_key_by_kid(self, jwks: Dict[str, Any], kid: str) -> Optional[Dict[str, Any]]:
        """Find the key with the specified kid in JWKS"""
        keys = jwks.get("keys", [])
        for key in keys:
            if key.get("kid") == kid:
                return key
        return None

    async def verify_jwt(self, token: str) -> Dict[str, Any]:
        """Verify JWT token and return payload"""
        logger.info(f"Starting JWT verification with issuer: {settings.jwt_expected_iss}, audience: {settings.jwt_expected_aud}")
        try:
            # Decode header to get kid
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get("kid")

            if not kid:
                raise JWTVerificationError("No 'kid' found in JWT header")

            # Get JWKS
            jwks = await self.get_jwks()

            # Find the key
            key = self._find_key_by_kid(jwks, kid)
            if not key:
                raise JWTVerificationError(f"No key found for kid: {kid}")

            # Verify the token
            payload = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                issuer=settings.jwt_expected_iss,
                audience=settings.jwt_expected_aud if settings.jwt_expected_aud else None,
                options={
                    "verify_signature": True,
                    "verify_iss": True,
                    "verify_aud": bool(settings.jwt_expected_aud),
                    "verify_exp": True
                }
            )

            logger.info(f"JWT verification successful for user: {payload.get('sub')}")
            logger.info(f"Expected issuer: {settings.jwt_expected_iss}, Token issuer: {payload.get('iss')}")

            return payload

        except JWTError as e:
            logger.error(f"JWT verification failed: {e}")
            raise JWTVerificationError(f"JWT verification failed: {str(e)}")
        except JWKError as e:
            logger.error(f"JWK error: {e}")
            raise JWTVerificationError(f"Key error: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error during JWT verification: {e}")
            raise JWTVerificationError(f"Unexpected verification error: {str(e)}")


# Global JWKS manager instance
jwks_manager = JWKSManager()
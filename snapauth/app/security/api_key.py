"""API key authentication for administrative endpoints.

Provides constant-time API key verification to prevent timing attacks
and supports multiple keys for zero-downtime rotation.
"""

import secrets
from typing import Optional

from fastapi import Header, HTTPException, Request, status
from fastapi.security import APIKeyHeader

from snapauth.app.settings import settings

# Define API key header scheme
api_key_header_scheme = APIKeyHeader(name="X-SnapAuth-API-Key", auto_error=False)


def verify_api_key(api_key: str) -> bool:
    """Verify API key using constant-time comparison.

    Uses secrets.compare_digest() to prevent timing attacks that could
    leak information about valid keys through response time analysis.

    Supports multiple valid keys (comma-separated in SNAPAUTH_ADMIN_API_KEYS)
    to enable zero-downtime key rotation.

    Args:
        api_key: The API key to verify

    Returns:
        True if the key is valid, False otherwise
    """
    valid_keys = settings.admin_api_keys_list

    if not valid_keys:
        # No keys configured - reject all requests
        return False

    # Use constant-time comparison for each valid key
    for valid_key in valid_keys:
        if secrets.compare_digest(api_key, valid_key):
            return True

    return False


def redact_api_key(api_key: str) -> str:
    """Redact API key for logging (show first 8 chars + "...").

    Args:
        api_key: The API key to redact

    Returns:
        Redacted API key string safe for logging
    """
    if len(api_key) <= 8:
        return "..."
    return api_key[:8] + "..."


async def require_admin_api_key(
    request: Request,
    x_snapauth_api_key: Optional[str] = Header(None, alias="X-SnapAuth-API-Key")
) -> str:
    """FastAPI dependency that requires valid admin API key.

    Validates the X-SnapAuth-API-Key header using constant-time comparison.
    Returns the validated (redacted) key for logging purposes.

    Args:
        request: FastAPI request object
        x_snapauth_api_key: API key from X-SnapAuth-API-Key header

    Returns:
        Redacted API key string

    Raises:
        HTTPException: 401 if API key is missing or invalid
    """
    if not x_snapauth_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key. Provide X-SnapAuth-API-Key header.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    if not verify_api_key(x_snapauth_api_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # Return redacted key for logging
    return redact_api_key(x_snapauth_api_key)

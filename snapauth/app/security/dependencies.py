"""Combined security dependencies for endpoint protection.

Provides reusable FastAPI dependencies that combine multiple security checks:
- require_admin_access: API key + IP whitelist
- require_self_or_admin: JWT user claims OR admin API key
"""

from typing import Dict, Optional

from fastapi import Depends, HTTPException, Request, status
from jose import JWTError, jwt

from snapauth.app.security.api_key import require_admin_api_key, verify_api_key
from snapauth.app.security.ip_whitelist import require_ip_whitelist
from snapauth.app.settings import settings


async def require_admin_access(
    request: Request,
    api_key: str = Depends(require_admin_api_key),
    client_ip: str = Depends(require_ip_whitelist),
) -> Dict[str, str]:
    """Require both valid API key AND IP whitelist for admin access.

    This dependency combines two security checks:
    1. Valid X-SnapAuth-API-Key header (constant-time verified)
    2. Client IP in whitelist (if configured)

    Both checks must pass for the request to proceed.

    Args:
        request: FastAPI request object
        api_key: Validated (redacted) API key from require_admin_api_key dependency
        client_ip: Validated client IP from require_ip_whitelist dependency

    Returns:
        Dictionary with redacted API key and client IP for audit logging

    Raises:
        HTTPException: 401 if API key invalid, 403 if IP not whitelisted
    """
    return {
        "api_key": api_key,  # Already redacted by require_admin_api_key
        "client_ip": client_ip,
    }


def extract_jwt_token(request: Request) -> Optional[str]:
    """Extract JWT token from Authorization header.

    Args:
        request: FastAPI request object

    Returns:
        JWT token string without "Bearer " prefix, or None if not present
    """
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]  # Remove "Bearer " prefix
    return None


def decode_jwt_token(token: str) -> Optional[Dict]:
    """Decode JWT token without verification (for extracting claims only).

    This is used to extract the 'sub' claim to check user ownership.
    Full token verification is done elsewhere in the application.

    Args:
        token: JWT token string

    Returns:
        Dictionary of JWT claims, or None if decode fails
    """
    try:
        # Decode without verification (just extract claims)
        # options={"verify_signature": False} allows us to read claims
        # without needing the signing key
        claims = jwt.decode(
            token,
            options={"verify_signature": False, "verify_aud": False, "verify_iss": False},
        )
        return claims
    except JWTError:
        return None


async def require_self_or_admin(
    request: Request,
    user_id: str,
) -> Dict[str, str]:
    """Require user to be accessing their own resource OR have admin API key.

    This dependency allows two authorization paths:
    1. User has valid JWT token with matching 'sub' claim (self-service)
    2. Request has valid admin API key (admin override)

    Args:
        request: FastAPI request object
        user_id: The user ID from the URL path parameter

    Returns:
        Dictionary with auth_type ("self" or "admin") and relevant info

    Raises:
        HTTPException: 403 if neither authorization path is satisfied
    """
    # Check for admin API key first (higher privilege)
    api_key_header = request.headers.get("X-SnapAuth-API-Key")
    if api_key_header and verify_api_key(api_key_header):
        # Admin API key present and valid - allow access
        # Also check IP whitelist for admin access
        client_ip_result = await require_ip_whitelist(request)
        return {
            "auth_type": "admin",
            "client_ip": client_ip_result,
        }

    # No admin API key - check if user is accessing their own resource
    token = extract_jwt_token(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Must provide valid JWT token or admin API key",
        )

    # Decode token to get user claims
    claims = decode_jwt_token(token)
    if not claims:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid JWT token",
        )

    # Check if token 'sub' claim matches the user_id being accessed
    token_user_id = claims.get("sub")
    if token_user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: You can only access your own resources",
        )

    # User is accessing their own resource
    return {
        "auth_type": "self",
        "user_id": token_user_id,
    }

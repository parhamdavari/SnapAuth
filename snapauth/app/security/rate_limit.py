"""Rate limiting for abuse prevention.

Uses slowapi library with Redis backend for distributed rate limiting.
Provides tiered limits based on endpoint type:
- Public auth endpoints: 10/minute (strict to prevent brute force)
- Admin endpoints: 30/minute
- Authenticated endpoints: 60/minute
"""

from slowapi import Limiter
from slowapi.util import get_remote_address
from fastapi import Request

from ..settings import settings
from .ip_whitelist import get_client_ip
from .api_key import redact_api_key


def get_client_identifier(request: Request) -> str:
    """Generate unique identifier for rate limiting.

    Combines client IP + API key (if present) to track rate limits.
    This allows different API keys from the same IP to have separate limits.

    Args:
        request: FastAPI request object

    Returns:
        Unique identifier string for this client
    """
    # Get client IP (respects X-Forwarded-For if TRUST_PROXY enabled)
    client_ip = get_client_ip(request)

    # Check for API key
    api_key = request.headers.get("X-SnapAuth-API-Key", "")

    if api_key:
        # Use redacted API key in identifier (first 8 chars)
        # This groups requests by the same API key together
        api_key_prefix = redact_api_key(api_key)
        return f"{client_ip}:{api_key_prefix}"

    # No API key - use IP only
    return client_ip


# Create limiter instance
# enabled=settings.rate_limit_enabled allows toggling rate limits in dev vs prod
limiter = Limiter(
    key_func=get_client_identifier,
    enabled=settings.rate_limit_enabled,
    # Storage backend will use in-memory by default
    # For production with multiple instances, configure Redis backend:
    # storage_uri="redis://localhost:6379"
)


# Rate limit decorator helpers for common patterns
def rate_limit_auth():
    """Rate limit decorator for authentication endpoints.

    Strict limit to prevent brute force password attacks.
    Default: 10 requests/minute (configurable via RATE_LIMIT_PER_MINUTE_AUTH)
    """
    limit = f"{settings.rate_limit_per_minute_auth}/minute"
    return limiter.limit(limit)


def rate_limit_admin():
    """Rate limit decorator for admin endpoints.

    Moderate limit for administrative operations.
    Default: 30 requests/minute (configurable via RATE_LIMIT_PER_MINUTE_ADMIN)
    """
    limit = f"{settings.rate_limit_per_minute_admin}/minute"
    return limiter.limit(limit)


def rate_limit_authenticated():
    """Rate limit decorator for authenticated user endpoints.

    Higher limit for normal authenticated operations.
    Default: 60 requests/minute (configurable via RATE_LIMIT_PER_MINUTE)
    """
    limit = f"{settings.rate_limit_per_minute}/minute"
    return limiter.limit(limit)

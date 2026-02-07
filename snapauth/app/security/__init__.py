"""Security module for SnapAuth.

This module provides authentication, authorization, and security features:
- API key authentication with constant-time comparison
- IP whitelisting with CIDR support
- Rate limiting for abuse prevention
- Security headers middleware
- Audit logging for compliance
"""

from snapauth.app.security.dependencies import (
    require_admin_access,
    require_self_or_admin,
)

__all__ = [
    "require_admin_access",
    "require_self_or_admin",
]

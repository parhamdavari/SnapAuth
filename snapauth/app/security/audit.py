"""Audit logging for security and compliance.

Provides structured JSON logging for security events like user creation,
deletion, login attempts, and administrative actions.

Logs are output to stdout in JSON format for collection by Docker/K8s logging.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Dict, Optional

from fastapi import Request

from .ip_whitelist import get_client_ip

# Configure logger for audit events
audit_logger = logging.getLogger("snapauth.audit")
audit_logger.setLevel(logging.INFO)


def log_audit_event(
    event_type: str,
    request: Request,
    user_id: Optional[str] = None,
    success: bool = True,
    details: Optional[Dict] = None,
) -> None:
    """Log structured audit event in JSON format.

    All audit events are logged with consistent structure for compliance
    queries and security analysis.

    Args:
        event_type: Event type identifier (e.g., "user.created", "auth.failed")
        request: FastAPI request object for extracting client IP
        user_id: User ID associated with event (optional)
        success: Whether the operation succeeded
        details: Additional event-specific details (optional)

    Event types:
        - user.created: New user account created
        - user.deleted: User account deleted
        - user.updated: User profile updated
        - user.login: Successful login
        - auth.failed: Failed login attempt
        - admin.action: Administrative action performed
    """
    # Get client IP (respects X-Forwarded-For if behind proxy)
    client_ip = get_client_ip(request)

    # Build audit log entry
    audit_entry = {
        # ISO 8601 timestamp with UTC timezone
        "timestamp": datetime.now(timezone.utc).isoformat(),

        # Event classification
        "event_type": event_type,

        # Client information
        "client_ip": client_ip,
        "user_agent": request.headers.get("User-Agent", "unknown"),

        # User context (if available)
        "user_id": user_id,

        # Operation result
        "success": success,

        # Additional context
        "details": redact_sensitive_data(details) if details else {},

        # Request metadata
        "method": request.method,
        "path": request.url.path,
    }

    # Log as JSON to stdout (collected by Docker/K8s)
    audit_logger.info(json.dumps(audit_entry))


def redact_sensitive_data(details: Dict) -> Dict:
    """Redact sensitive information from audit log details.

    Removes or masks:
    - Passwords (any field with "password" in name)
    - Full API keys (only log redacted versions)
    - JWT tokens (never log token content)

    Args:
        details: Dictionary potentially containing sensitive data

    Returns:
        New dictionary with sensitive data redacted
    """
    if not details:
        return {}

    redacted = {}

    for key, value in details.items():
        key_lower = key.lower()

        # Never log passwords
        if "password" in key_lower:
            redacted[key] = "[REDACTED]"

        # Never log full tokens
        elif "token" in key_lower or "jwt" in key_lower:
            redacted[key] = "[REDACTED]"

        # API keys should already be redacted, but double-check
        elif "api_key" in key_lower or "apikey" in key_lower:
            if isinstance(value, str) and len(value) > 8:
                redacted[key] = value[:8] + "..."
            else:
                redacted[key] = "[REDACTED]"

        # Keep other fields as-is
        else:
            redacted[key] = value

    return redacted

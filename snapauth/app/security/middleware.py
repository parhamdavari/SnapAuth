"""Security headers middleware for HTTP response hardening.

Adds security-related HTTP headers to all responses to protect against
common web vulnerabilities like clickjacking, XSS, and content sniffing.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware to add security headers to all HTTP responses.

    Headers added:
    - X-Frame-Options: Prevent clickjacking attacks
    - X-Content-Type-Options: Prevent MIME-sniffing
    - X-XSS-Protection: Enable browser XSS filter
    - Content-Security-Policy: Restrict resource loading
    - Strict-Transport-Security (HSTS): Force HTTPS (only when HTTPS detected)
    """

    async def dispatch(self, request: Request, call_next):
        """Process request and add security headers to response.

        Args:
            request: Incoming HTTP request
            call_next: Next middleware/endpoint in chain

        Returns:
            Response with added security headers
        """
        # Process request through the rest of the app
        response: Response = await call_next(request)

        # Add security headers to response
        response.headers.update({
            # Prevent page from being framed (clickjacking protection)
            "X-Frame-Options": "DENY",

            # Prevent MIME-sniffing (force browser to respect Content-Type)
            "X-Content-Type-Options": "nosniff",

            # Enable browser XSS protection
            "X-XSS-Protection": "1; mode=block",

            # Content Security Policy - restrict resource loading
            # default-src 'none' denies all sources by default
            # API endpoints don't load external resources, so this is safe
            "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
        })

        # Add HSTS header only when HTTPS is detected
        # This forces browser to always use HTTPS for future requests
        if request.url.scheme == "https":
            # max-age=31536000 = 1 year
            # includeSubDomains applies to all subdomains
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )

        return response

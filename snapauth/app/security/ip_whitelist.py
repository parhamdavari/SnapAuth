"""IP whitelisting for access control.

Supports CIDR notation for both IPv4 and IPv6 addresses.
Respects X-Forwarded-For header when behind reverse proxy.
"""

import ipaddress
from typing import Set, Union

from fastapi import HTTPException, Request, status

from snapauth.app.settings import settings


def parse_ip_whitelist() -> Set[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
    """Parse IP whitelist from settings into network objects.

    Supports both individual IP addresses (e.g., "192.168.1.100")
    and CIDR ranges (e.g., "10.0.0.0/8", "2001:db8::/32").

    Returns:
        Set of IPv4Network and IPv6Network objects
    """
    networks = set()
    allowed_ips = settings.admin_allowed_ips_list

    if not allowed_ips:
        return networks

    for ip_str in allowed_ips:
        try:
            # ipaddress.ip_network() handles both single IPs and CIDR notation
            # strict=False allows host bits to be set (e.g., 192.168.1.1/24 is valid)
            network = ipaddress.ip_network(ip_str, strict=False)
            networks.add(network)
        except ValueError:
            # Invalid IP/CIDR notation - skip and continue
            # In production, this should be logged as a configuration error
            pass

    return networks


def get_client_ip(request: Request) -> str:
    """Extract client IP address from request.

    When TRUST_PROXY is enabled, uses X-Forwarded-For header (leftmost IP).
    Otherwise, uses direct client connection IP.

    Args:
        request: FastAPI request object

    Returns:
        Client IP address as string
    """
    if settings.trust_proxy:
        # When behind reverse proxy, use X-Forwarded-For
        # Format: "client, proxy1, proxy2"
        # Take the leftmost (original client) IP
        forwarded_for = request.headers.get("X-Forwarded-For", "")
        if forwarded_for:
            # Split and take first IP, strip whitespace
            client_ip = forwarded_for.split(",")[0].strip()
            if client_ip:
                return client_ip

    # Fallback to direct connection IP
    if request.client and request.client.host:
        return request.client.host

    # Should never happen, but handle gracefully
    return "unknown"


def is_ip_allowed(client_ip: str) -> bool:
    """Check if client IP is in the whitelist.

    Supports CIDR matching for both IPv4 and IPv6.

    Args:
        client_ip: Client IP address as string

    Returns:
        True if IP is allowed (or whitelist is empty), False otherwise
    """
    networks = parse_ip_whitelist()

    # If no whitelist configured, allow all
    if not networks:
        return True

    try:
        # Parse client IP address
        client_addr = ipaddress.ip_address(client_ip)

        # Check if client IP is in any whitelisted network
        for network in networks:
            if client_addr in network:
                return True

        return False

    except ValueError:
        # Invalid IP address - reject
        return False


async def require_ip_whitelist(request: Request) -> str:
    """FastAPI dependency that requires client IP to be whitelisted.

    Args:
        request: FastAPI request object

    Returns:
        Client IP address

    Raises:
        HTTPException: 403 if IP is not whitelisted
    """
    client_ip = get_client_ip(request)

    if not is_ip_allowed(client_ip):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied: IP address {client_ip} is not authorized",
        )

    return client_ip

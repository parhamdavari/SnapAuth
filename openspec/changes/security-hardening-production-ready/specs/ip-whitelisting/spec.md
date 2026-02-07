## ADDED Requirements

### Requirement: IP whitelist enforcement for admin endpoints
Administrative endpoints SHALL enforce IP address whitelisting when `ADMIN_ALLOWED_IPS` environment variable is configured. Requests from non-whitelisted IP addresses MUST be rejected with HTTP 403 Forbidden.

#### Scenario: Request from whitelisted IP address
- **WHEN** a request is made to `POST /v1/users` from an IP address in the whitelist with a valid API key
- **THEN** the system processes the request normally

#### Scenario: Request from non-whitelisted IP address
- **WHEN** a request is made to `POST /v1/users` from an IP address NOT in the whitelist
- **THEN** the system returns HTTP 403 Forbidden with error message "IP not authorized"

#### Scenario: IP whitelist not configured
- **WHEN** the `ADMIN_ALLOWED_IPS` environment variable is empty or not set
- **THEN** the system SHALL NOT enforce IP whitelisting and SHALL allow requests from any IP (with valid API key)

### Requirement: CIDR notation support for IPv4 and IPv6
The system SHALL support CIDR notation for IP address ranges in the `ADMIN_ALLOWED_IPS` configuration, including both IPv4 (e.g., `192.168.1.0/24`) and IPv6 (e.g., `2001:db8::/32`) formats.

#### Scenario: IPv4 CIDR range match
- **WHEN** `ADMIN_ALLOWED_IPS=192.168.1.0/24` and a request is made from `192.168.1.100`
- **THEN** the system allows the request (IP is within the CIDR range)

#### Scenario: IPv4 CIDR range mismatch
- **WHEN** `ADMIN_ALLOWED_IPS=192.168.1.0/24` and a request is made from `192.168.2.100`
- **THEN** the system returns HTTP 403 Forbidden (IP is outside the CIDR range)

#### Scenario: IPv6 CIDR range match
- **WHEN** `ADMIN_ALLOWED_IPS=2001:db8::/32` and a request is made from `2001:db8::1`
- **THEN** the system allows the request (IP is within the IPv6 CIDR range)

#### Scenario: Single IP address specification
- **WHEN** `ADMIN_ALLOWED_IPS=10.0.0.1` and a request is made from `10.0.0.1`
- **THEN** the system allows the request (exact IP match)

### Requirement: Multiple IP ranges supported
The system SHALL support multiple IP addresses or CIDR ranges in the `ADMIN_ALLOWED_IPS` configuration, separated by commas. A request is allowed if its IP matches ANY entry in the list.

#### Scenario: Multiple CIDR ranges configured
- **WHEN** `ADMIN_ALLOWED_IPS=192.168.1.0/24,10.0.0.0/8` and a request is made from `10.5.3.100`
- **THEN** the system allows the request (matches the second range)

#### Scenario: Mixed single IPs and CIDR ranges
- **WHEN** `ADMIN_ALLOWED_IPS=192.168.1.50,10.0.0.0/16` and a request is made from `192.168.1.50`
- **THEN** the system allows the request (exact match on first entry)

### Requirement: X-Forwarded-For header support for proxied requests
When `TRUST_PROXY=true` environment variable is set, the system SHALL extract the client IP from the `X-Forwarded-For` header instead of the direct connection IP. This enables IP whitelisting when SnapAuth runs behind a reverse proxy or load balancer.

#### Scenario: Proxied request with X-Forwarded-For header
- **WHEN** `TRUST_PROXY=true` and a request includes header `X-Forwarded-For: 192.168.1.100, 10.0.0.1`
- **THEN** the system uses `192.168.1.100` (first IP in the list) for whitelist validation

#### Scenario: Direct request when proxy trust disabled
- **WHEN** `TRUST_PROXY=false` and a request includes header `X-Forwarded-For: 192.168.1.100`
- **THEN** the system ignores the header and uses the direct connection IP for validation

#### Scenario: Proxied request without X-Forwarded-For header
- **WHEN** `TRUST_PROXY=true` and a request does NOT include an `X-Forwarded-For` header
- **THEN** the system falls back to using the direct connection IP

### Requirement: IP validation occurs before API key validation
The system SHALL validate the client IP address before validating the API key to minimize information leakage. IP whitelist failures SHALL NOT reveal whether a valid API key was provided.

#### Scenario: Validation order enforcement
- **WHEN** a request is made from a non-whitelisted IP with a valid API key
- **THEN** the system returns HTTP 403 Forbidden without validating the API key

#### Scenario: IP whitelist pass proceeds to API key validation
- **WHEN** a request is made from a whitelisted IP with an invalid API key
- **THEN** the system passes IP validation and returns HTTP 401 Unauthorized (API key validation failure)

### Requirement: IP whitelist applies only to admin endpoints
The IP whitelist SHALL only be enforced on administrative endpoints. Public endpoints (`GET /health`, `POST /v1/auth/login`, etc.) SHALL remain accessible from any IP address regardless of the `ADMIN_ALLOWED_IPS` configuration.

#### Scenario: Public endpoint from non-whitelisted IP
- **WHEN** `ADMIN_ALLOWED_IPS=192.168.1.0/24` and a request is made to `GET /health` from `203.0.113.50`
- **THEN** the system returns HTTP 200 with health status (whitelist not enforced)

#### Scenario: Login endpoint from non-whitelisted IP
- **WHEN** `ADMIN_ALLOWED_IPS=192.168.1.0/24` and a request is made to `POST /v1/auth/login` from `203.0.113.50`
- **THEN** the system processes the login normally (whitelist not enforced)

### Requirement: Default private network ranges for safety
When no `ADMIN_ALLOWED_IPS` is configured, the bootstrap process SHALL generate a default whitelist including common private network ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) to prevent accidental public internet exposure.

#### Scenario: Fresh installation default whitelist
- **WHEN** `scripts/bootstrap.py` is executed for a fresh installation
- **THEN** the generated `.env` file includes `ADMIN_ALLOWED_IPS=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16`

#### Scenario: Operator overrides default whitelist
- **WHEN** an operator manually sets `ADMIN_ALLOWED_IPS=203.0.113.50` in the `.env` file
- **THEN** the system uses only the specified IP address and ignores the default private ranges

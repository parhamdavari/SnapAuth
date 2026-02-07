## MODIFIED Requirements

### Requirement: Login endpoint enforces rate limiting
The `POST /v1/auth/login` endpoint SHALL enforce rate limiting of 10 requests per minute per client to prevent brute force password attacks.

**Previous behavior**: No rate limiting was enforced, allowing unlimited login attempts.

**Breaking change**: Clients exceeding 10 login attempts per minute will receive HTTP 429 Too Many Requests.

#### Scenario: Login requests under rate limit
- **WHEN** a client makes 9 login requests within 1 minute
- **THEN** all requests are processed normally

#### Scenario: Login requests exceed rate limit
- **WHEN** a client makes 11 login requests within 1 minute
- **THEN** the 11th request returns HTTP 429 Too Many Requests with `Retry-After` header

#### Scenario: Rate limit tracked by client IP
- **WHEN** Client A (IP: 192.168.1.100) makes 10 login requests and Client B (IP: 192.168.1.101) makes 10 login requests
- **THEN** both clients' requests are processed (tracked separately by IP)

### Requirement: Failed login attempts logged in audit trail
Failed login attempts SHALL be logged with structured JSON including timestamp, client IP, attempted username, and `success: false` flag.

**Previous behavior**: Basic logging existed but not structured for compliance queries.

**Enhancement**: Audit logs now enable compliance queries like "all failed login attempts from IP X" or "failed attempts for username Y".

#### Scenario: Failed login creates audit log
- **WHEN** a login attempt fails with username "user@example.com" from IP 203.0.113.50
- **THEN** an audit log entry is created with `event_type: "auth.failed"`, `client_ip: "203.0.113.50"`, `success: false`, and `details: {"username": "user@example.com"}`

#### Scenario: Successful login creates audit log
- **WHEN** a user successfully logs in
- **THEN** an audit log entry is created with `event_type: "user.login"`, `user_id`, `client_ip`, and `success: true`

### Requirement: Token refresh endpoint remains unauthenticated
The `POST /v1/auth/refresh` endpoint behavior SHALL remain unchanged: it accepts refresh tokens without additional authentication.

**No breaking change**: This endpoint is not modified by this change.

#### Scenario: Token refresh with valid refresh token
- **WHEN** a client sends a valid refresh token to `POST /v1/auth/refresh`
- **THEN** the system returns a new access token

#### Scenario: Token refresh with invalid refresh token
- **WHEN** a client sends an invalid or expired refresh token
- **THEN** the system returns HTTP 401 Unauthorized

### Requirement: Token verification endpoint remains public
The `POST /v1/auth/verify-token` endpoint behavior SHALL remain unchanged: it accepts and validates JWT tokens without additional authentication.

**No breaking change**: This endpoint is not modified by this change and remains publicly accessible for client-side token verification.

#### Scenario: Valid token verification
- **WHEN** a client sends a valid JWT token to `POST /v1/auth/verify-token`
- **THEN** the system returns HTTP 200 OK with token claims

#### Scenario: Invalid token verification
- **WHEN** a client sends an invalid or expired JWT token
- **THEN** the system returns HTTP 401 Unauthorized

### Requirement: JWT token content not logged
JWT token values SHALL NOT be logged in any audit or application logs to prevent token leakage.

**Previous behavior**: First 20 characters of tokens were logged for debugging.

**Breaking change** (security improvement): Token logging removed entirely. Operators needing to debug token issues must use other methods.

#### Scenario: Token verification does not log token value
- **WHEN** a JWT token is verified
- **THEN** logs include the verification result but NOT the token value

#### Scenario: Failed auth logs username only
- **WHEN** a login attempt fails
- **THEN** logs include the attempted username but NOT the password or any tokens

### Requirement: Rate limiting configurable for authentication endpoints
The authentication endpoint rate limits SHALL be configurable via `RATE_LIMIT_PER_MINUTE_AUTH` environment variable (default: 10).

**Enhancement**: Allows operators to tune rate limits based on their deployment size and threat model.

#### Scenario: Custom auth rate limit
- **WHEN** `RATE_LIMIT_PER_MINUTE_AUTH=5` is set and a client makes 6 login requests within 1 minute
- **THEN** the 6th request returns HTTP 429 Too Many Requests

#### Scenario: Default auth rate limit
- **WHEN** `RATE_LIMIT_PER_MINUTE_AUTH` is not set and a client makes 11 login requests within 1 minute
- **THEN** the 11th request returns HTTP 429 (default 10/min limit)

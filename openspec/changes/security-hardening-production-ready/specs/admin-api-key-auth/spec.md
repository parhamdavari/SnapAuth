## ADDED Requirements

### Requirement: Admin endpoints require API key authentication
All administrative endpoints (`POST /v1/users`, `DELETE /v1/admin/users/{id}`, `PUT /v1/users/{id}/reset-password`) SHALL require a valid API key provided via the `X-SnapAuth-API-Key` HTTP header.

#### Scenario: Admin endpoint with valid API key
- **WHEN** a request is made to `POST /v1/users` with a valid `X-SnapAuth-API-Key` header
- **THEN** the system processes the request normally and returns the appropriate response

#### Scenario: Admin endpoint without API key header
- **WHEN** a request is made to `POST /v1/users` without an `X-SnapAuth-API-Key` header
- **THEN** the system returns HTTP 401 Unauthorized with error message "Invalid API key"

#### Scenario: Admin endpoint with invalid API key
- **WHEN** a request is made to `POST /v1/users` with an `X-SnapAuth-API-Key` header containing an invalid key
- **THEN** the system returns HTTP 401 Unauthorized with error message "Invalid API key"

### Requirement: API key comparison uses constant-time algorithm
The system SHALL use constant-time comparison (`secrets.compare_digest()`) when verifying API keys to prevent timing attacks.

#### Scenario: Timing attack prevention
- **WHEN** an attacker submits multiple invalid API keys with varying lengths
- **THEN** the comparison time SHALL be constant regardless of how many prefix characters match the valid key

### Requirement: Multiple active API keys supported
The system SHALL support multiple valid API keys simultaneously to enable zero-downtime key rotation. Valid keys are read from the `SNAPAUTH_ADMIN_API_KEYS` environment variable as a comma-separated list.

#### Scenario: Request with primary API key
- **WHEN** a request is made with the primary API key (first in the list)
- **THEN** the system authenticates successfully

#### Scenario: Request with secondary API key during rotation
- **WHEN** a request is made with a secondary API key (later in the list) during a rotation period
- **THEN** the system authenticates successfully

#### Scenario: Request with removed API key
- **WHEN** a request is made with an API key that has been removed from the environment variable
- **THEN** the system returns HTTP 401 Unauthorized

### Requirement: API key auto-generation during bootstrap
The bootstrap process (`scripts/bootstrap.py`) SHALL automatically generate a secure admin API key with 256-bit entropy using `secrets.token_urlsafe(32)` and write it to the `.env` file as `SNAPAUTH_ADMIN_API_KEY`.

#### Scenario: Fresh installation bootstrap
- **WHEN** `scripts/bootstrap.py` is executed for a fresh installation (no existing `.env` file)
- **THEN** a new admin API key is generated and written to `.env` with 256-bit entropy

#### Scenario: Re-running bootstrap with existing key
- **WHEN** `scripts/bootstrap.py` is executed with an existing `.env` file containing `SNAPAUTH_ADMIN_API_KEY`
- **THEN** the existing key is preserved and not overwritten

### Requirement: API key validation before request processing
The system SHALL validate the API key before processing any administrative operation and SHALL NOT leak sensitive information in error responses.

#### Scenario: Validation occurs before business logic
- **WHEN** a request is made to `POST /v1/users` with an invalid API key
- **THEN** the system returns 401 before attempting user creation or database queries

#### Scenario: Error response does not leak key details
- **WHEN** a request is made with an invalid API key
- **THEN** the error response SHALL NOT include the submitted key value or hints about valid key format

### Requirement: API key logging restrictions
The system SHALL NOT log API key values in plaintext. If logging is required for debugging, only the first 8 characters followed by "..." SHALL be logged.

#### Scenario: Audit log redacts API key
- **WHEN** an admin operation is logged for audit purposes
- **THEN** the audit log entry includes only the first 8 characters of the API key (e.g., "api_key": "abc12345...")

#### Scenario: Error logs do not expose keys
- **WHEN** an authentication failure is logged
- **THEN** the log entry SHALL NOT include the full API key value

### Requirement: Public endpoints remain unauthenticated
Public endpoints (`GET /health`, `GET /.well-known/jwks.json`, `POST /v1/auth/login`, `POST /v1/auth/refresh`, `POST /v1/auth/verify-token`) SHALL NOT require API key authentication and SHALL remain accessible without the `X-SnapAuth-API-Key` header.

#### Scenario: Health check without API key
- **WHEN** a request is made to `GET /health` without an `X-SnapAuth-API-Key` header
- **THEN** the system returns HTTP 200 with health status

#### Scenario: Login endpoint without API key
- **WHEN** a request is made to `POST /v1/auth/login` without an `X-SnapAuth-API-Key` header
- **THEN** the system processes the login attempt normally

#### Scenario: JWKS endpoint without API key
- **WHEN** a request is made to `GET /.well-known/jwks.json` without an `X-SnapAuth-API-Key` header
- **THEN** the system returns HTTP 200 with the JWKS configuration

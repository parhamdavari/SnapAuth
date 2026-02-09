## ADDED Requirements

### Requirement: JWT-authenticated self-deletion via JWKS verification
The system SHALL verify JWT tokens cryptographically against the JWKS endpoint when a user attempts to delete their own account via `DELETE /v1/users/{userId}`. The token MUST be validated for signature, expiration, and issuer before granting access.

#### Scenario: Valid self-delete with cryptographically verified JWT
- **WHEN** a user sends `DELETE /v1/users/{userId}` with a valid, signed JWT where the `sub` claim matches `{userId}`
- **THEN** the system SHALL verify the JWT signature against JWKS public keys
- **THEN** the system SHALL verify token expiration and issuer claims
- **THEN** the user record SHALL be deleted
- **THEN** the response status SHALL be HTTP 204 No Content

#### Scenario: Self-delete rejected due to expired JWT
- **WHEN** a user sends `DELETE /v1/users/{userId}` with an expired JWT
- **THEN** the system SHALL reject the request
- **THEN** the response status SHALL be HTTP 401 Unauthorized

#### Scenario: Self-delete rejected due to forged or invalid signature
- **WHEN** a user sends `DELETE /v1/users/{userId}` with a JWT signed by an unknown key
- **THEN** the system SHALL reject the request
- **THEN** the response status SHALL be HTTP 401 Unauthorized

#### Scenario: Self-delete rejected due to mismatched user ID
- **WHEN** a user sends `DELETE /v1/users/{userIdB}` with a valid JWT where `sub` equals `userIdA` (different user)
- **THEN** the system SHALL reject the request
- **THEN** the response status SHALL be HTTP 403 Forbidden

#### Scenario: Delete request without any credentials
- **WHEN** a client sends `DELETE /v1/users/{userId}` without an Authorization header or API key
- **THEN** the response status SHALL be HTTP 403 Forbidden

### Requirement: Admin API key bypass for user deletion
The system SHALL continue to accept valid admin API keys (`X-SnapAuth-API-Key`) for deleting any user, independent of JWT authentication.

#### Scenario: Admin deletes any user via API key
- **WHEN** a request sends `DELETE /v1/users/{userId}` with a valid admin API key and no JWT
- **THEN** the user record SHALL be deleted regardless of the `{userId}` value
- **THEN** the response status SHALL be HTTP 204 No Content

### Requirement: Async JWT token decoding
The `decode_jwt_token` function SHALL be asynchronous to support non-blocking JWKS key fetching during token verification.

#### Scenario: Token decoding does not block the event loop
- **WHEN** `decode_jwt_token` is called with a JWT token
- **THEN** it SHALL execute as an async coroutine
- **THEN** it SHALL delegate verification to `jwks_manager.verify_jwt()`
- **THEN** it SHALL return the verified claims dictionary on success, or `None` on any verification failure

## ADDED Requirements

### Requirement: User creation with validated username
The system SHALL validate username format when creating users via the user creation endpoint.

#### Scenario: Create user with valid Iran phone number
- **WHEN** admin creates user with username "09123456789" and valid password
- **THEN** user is created successfully
- **THEN** response includes userId

#### Scenario: Create user with invalid username format
- **WHEN** admin attempts to create user with username "invalid123" (not Iran phone format)
- **THEN** user creation fails with 422 status code
- **THEN** response includes validation error for username field

#### Scenario: Create user with valid username but missing required fields
- **WHEN** admin attempts to create user with valid username "09123456789" but missing password
- **THEN** user creation fails with 422 status code
- **THEN** response includes validation error for missing password field

### Requirement: User update with validated username
The system SHALL validate username format when updating usernames via the user update endpoint.

#### Scenario: Update username to valid Iran phone number
- **WHEN** user updates their username to "09987654321" (valid Iran phone)
- **THEN** username is updated successfully
- **THEN** response includes updated username

#### Scenario: Update username to invalid format
- **WHEN** user attempts to update username to "newusername" (not Iran phone format)
- **THEN** update fails with 422 status code
- **THEN** response includes validation error for username field

#### Scenario: Update other fields without changing username
- **WHEN** user updates password or metadata without providing username field
- **THEN** update succeeds
- **THEN** username validation is not triggered

### Requirement: Consistent validation across operations
The system SHALL apply the same Iran phone number validation rules to username field in both create and update operations.

#### Scenario: Same validation logic for create and update
- **WHEN** username "abc123" is provided in user creation request
- **THEN** validation fails with same error message as update operation
- **WHEN** username "abc123" is provided in user update request
- **THEN** validation fails with identical error message

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

### Requirement: Structured error responses for user creation
The `POST /v1/users` endpoint SHALL return structured error responses using the `fusionauth-error-mapping` schema when FusionAuth rejects the user creation request.

#### Scenario: Duplicate phone number on user creation
- **WHEN** a user creation request is sent with a phone number that already exists in FusionAuth
- **THEN** the response status SHALL be HTTP 400
- **THEN** the response body SHALL match `{"errors": [{"detail": "User with this phone number already exists", "error_code": "DUPLICATE_USER", "field": "username", "original_value": "<the phone number>"}]}`

#### Scenario: User creation with unmapped FusionAuth error
- **WHEN** a user creation request triggers an unmapped FusionAuth error code
- **THEN** the `errors` array SHALL contain an entry with `error_code: "AUTH_PROVIDER_ERROR"` and the original FusionAuth message as `detail`
- **THEN** the system SHALL NOT return HTTP 500

### Requirement: Structured error responses for user update
The `PATCH /v1/users/{userId}` endpoint SHALL return structured error responses using the `fusionauth-error-mapping` schema when FusionAuth rejects the user update request.

#### Scenario: Duplicate username on user update
- **WHEN** a user update request changes the username to a phone number that already exists
- **THEN** the response status SHALL be HTTP 400
- **THEN** the `errors` array SHALL contain an entry with `"error_code": "DUPLICATE_USER"` and `"field": "username"`

### Requirement: Structured error responses for user registration
The `POST /v1/users/{userId}/register` endpoint SHALL return structured error responses using the `fusionauth-error-mapping` schema when FusionAuth rejects the registration request.

#### Scenario: Invalid role on registration
- **WHEN** a registration request includes a role that does not exist in FusionAuth
- **THEN** the `errors` array SHALL contain an entry with `"error_code": "INVALID_ROLE"` and `"field": "roles"`

### Requirement: Structured error responses for user deletion
The `DELETE /v1/users/{userId}` and `DELETE /v1/admin/users/{userId}` endpoints SHALL return structured error responses using the `fusionauth-error-mapping` schema when FusionAuth rejects the deletion request.

#### Scenario: Delete non-existent user
- **WHEN** a deletion request targets a user ID that does not exist in FusionAuth
- **THEN** the response status SHALL match the status code returned by FusionAuth
- **THEN** the `errors` array SHALL contain an entry with `error_code: "AUTH_PROVIDER_ERROR"`

### Requirement: Structured error responses for login
The `POST /v1/auth/login` endpoint SHALL return structured error responses using the `fusionauth-error-mapping` schema when FusionAuth rejects the login request.

#### Scenario: Login with invalid credentials
- **WHEN** a login request is sent with incorrect username or password
- **THEN** the response status SHALL match the status code returned by FusionAuth
- **THEN** the response body SHALL use the structured error schema

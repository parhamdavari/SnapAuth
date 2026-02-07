## MODIFIED Requirements

### Requirement: User creation requires admin API key
The `POST /v1/users` endpoint SHALL require a valid `X-SnapAuth-API-Key` header. Requests without a valid API key SHALL be rejected with HTTP 401 Unauthorized.

**Previous behavior**: The endpoint was unauthenticated and allowed anyone with network access to create users.

**Breaking change**: Existing clients calling `POST /v1/users` without an API key header will receive HTTP 401.

#### Scenario: User creation with valid API key
- **WHEN** a request is made to `POST /v1/users` with a valid `X-SnapAuth-API-Key` header and user details
- **THEN** the system creates the user and returns HTTP 201 Created with the user ID

#### Scenario: User creation without API key
- **WHEN** a request is made to `POST /v1/users` without an `X-SnapAuth-API-Key` header
- **THEN** the system returns HTTP 401 Unauthorized without creating any user

#### Scenario: User creation with invalid API key
- **WHEN** a request is made to `POST /v1/users` with an invalid `X-SnapAuth-API-Key` header
- **THEN** the system returns HTTP 401 Unauthorized without creating any user

### Requirement: User deletion enforces self-only or admin access
The `DELETE /v1/users/{id}` endpoint SHALL enforce authorization: users can only delete their own account (verified via JWT token), OR an admin with a valid API key can delete any user.

**Previous behavior**: Any authenticated user could delete any other user by providing a valid JWT token.

**Breaking change**: Users attempting to delete other users' accounts will receive HTTP 403 Forbidden.

#### Scenario: User deletes own account
- **WHEN** user with ID "abc123" sends `DELETE /v1/users/abc123` with their JWT token
- **THEN** the system deletes the user and returns HTTP 200 OK

#### Scenario: User attempts to delete another user's account
- **WHEN** user with ID "abc123" sends `DELETE /v1/users/xyz789` with their JWT token (no API key)
- **THEN** the system returns HTTP 403 Forbidden without deleting the user

#### Scenario: Admin deletes any user via API key
- **WHEN** a request is made to `DELETE /v1/users/xyz789` with a valid `X-SnapAuth-API-Key` header
- **THEN** the system deletes user xyz789 and returns HTTP 200 OK

### Requirement: Admin force delete endpoint for administrative operations
A new endpoint `DELETE /v1/admin/users/{id}` SHALL be added for administrative deletions, requiring an API key and providing clearer intent for audit logs.

**New capability**: Separates self-service deletion from administrative deletion for better auditability.

#### Scenario: Admin force delete via dedicated endpoint
- **WHEN** a request is made to `DELETE /v1/admin/users/{id}` with a valid API key
- **THEN** the system deletes the user and logs event with `details: {"type": "admin_force"}`

#### Scenario: Admin force delete requires API key
- **WHEN** a request is made to `DELETE /v1/admin/users/{id}` with a JWT token but no API key
- **THEN** the system returns HTTP 401 Unauthorized

### Requirement: User creation with roles requires admin API key
When creating users with the `roles` field (e.g., assigning admin roles), the request SHALL require a valid admin API key. This prevents privilege escalation attacks.

**Previous behavior**: Any request could create users with arbitrary roles including "admin".

**Breaking change**: Creating users with roles now requires admin API key authentication.

#### Scenario: User creation with admin role requires API key
- **WHEN** a request is made to `POST /v1/users` with `roles: ["admin"]` but no API key
- **THEN** the system returns HTTP 401 Unauthorized

#### Scenario: Admin creates user with roles
- **WHEN** a request is made to `POST /v1/users` with `roles: ["admin"]` and a valid API key
- **THEN** the system creates the user with admin role and logs the event

### Requirement: User update endpoint remains self-only
The `PATCH /v1/users/{id}` endpoint behavior SHALL remain unchanged: users can only update their own profile using their JWT token.

**No breaking change**: This endpoint's behavior is not modified by this change.

#### Scenario: User updates own profile
- **WHEN** user with ID "abc123" sends `PATCH /v1/users/abc123` with their JWT token
- **THEN** the system updates the user profile and returns HTTP 200 OK

#### Scenario: User attempts to update another user's profile
- **WHEN** user with ID "abc123" sends `PATCH /v1/users/xyz789` with their JWT token
- **THEN** the system returns HTTP 403 Forbidden

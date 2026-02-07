## ADDED Requirements

### Requirement: Structured JSON audit logs for security events
The system SHALL emit structured JSON audit logs for all security-relevant events including user creation, user deletion, user updates, login success, login failure, and password reset operations.

#### Scenario: User creation audit log
- **WHEN** an admin creates a user via `POST /v1/users`
- **THEN** the system emits a JSON log entry with `event_type: "user.created"`, timestamp, client IP, and user ID

#### Scenario: User deletion audit log
- **WHEN** a user is deleted via `DELETE /v1/users/{id}`
- **THEN** the system emits a JSON log entry with `event_type: "user.deleted"`, timestamp, client IP, and deleted user ID

#### Scenario: Login success audit log
- **WHEN** a user successfully authenticates via `POST /v1/auth/login`
- **THEN** the system emits a JSON log entry with `event_type: "user.login"`, timestamp, client IP, and user ID

#### Scenario: Login failure audit log
- **WHEN** a login attempt fails due to invalid credentials
- **THEN** the system emits a JSON log entry with `event_type: "auth.failed"`, `success: false`, timestamp, client IP, and attempted username (NOT password)

### Requirement: Audit log fields include ISO 8601 timestamp
All audit log entries SHALL include a `timestamp` field in ISO 8601 format with UTC timezone (e.g., `"2025-02-07T14:30:00.123Z"`).

#### Scenario: Audit log timestamp format
- **WHEN** any security event is logged
- **THEN** the log entry includes `"timestamp": "2025-02-07T14:30:00.123Z"` (ISO 8601 with milliseconds and Z suffix)

#### Scenario: Timestamps use UTC timezone
- **WHEN** an event occurs at 10:00 AM Pacific Time (UTC-8)
- **THEN** the audit log records the timestamp as 6:00 PM UTC

### Requirement: Client IP address captured in audit logs
All audit log entries SHALL include the originating client IP address in the `client_ip` field, respecting the `TRUST_PROXY` configuration for X-Forwarded-For header handling.

#### Scenario: Direct connection IP captured
- **WHEN** `TRUST_PROXY=false` and a request comes from IP 192.168.1.100
- **THEN** the audit log includes `"client_ip": "192.168.1.100"`

#### Scenario: Proxied connection IP from X-Forwarded-For
- **WHEN** `TRUST_PROXY=true` and a request includes header `X-Forwarded-For: 203.0.113.50, 10.0.0.1`
- **THEN** the audit log includes `"client_ip": "203.0.113.50"` (first IP in the list)

### Requirement: Audit logs include success/failure status
All audit log entries SHALL include a `success` boolean field indicating whether the operation completed successfully.

#### Scenario: Successful operation audit log
- **WHEN** a user is created successfully
- **THEN** the audit log includes `"success": true`

#### Scenario: Failed operation audit log
- **WHEN** a login attempt fails due to invalid credentials
- **THEN** the audit log includes `"success": false`

### Requirement: Audit logs include user identifier
Audit log entries SHALL include the `user_id` field when the event involves a specific user (user creation, deletion, login, etc.). For events without a specific user (e.g., failed login before user lookup), this field MAY be null.

#### Scenario: User-specific event includes user ID
- **WHEN** user with ID "71fa1ed1-ad8f-4a51-a5a0-88d88020d573" successfully logs in
- **THEN** the audit log includes `"user_id": "71fa1ed1-ad8f-4a51-a5a0-88d88020d573"`

#### Scenario: Failed login without user ID
- **WHEN** a login attempt fails with a non-existent username
- **THEN** the audit log includes `"user_id": null` and `"details": {"username": "nonexistent@example.com"}`

### Requirement: Audit logs include optional details object
Audit log entries SHALL support an optional `details` object for additional context specific to the event type (e.g., operation type, failure reason, affected resources).

#### Scenario: Admin force delete includes operation type
- **WHEN** an admin force-deletes a user via `DELETE /v1/admin/users/{id}`
- **THEN** the audit log includes `"details": {"type": "admin_force"}`

#### Scenario: Failed login includes username
- **WHEN** a login attempt fails
- **THEN** the audit log includes `"details": {"username": "user@example.com"}` but NOT the password

#### Scenario: API key rotation event includes key ID
- **WHEN** an API key is rotated
- **THEN** the audit log includes `"details": {"old_key_prefix": "abc12345...", "new_key_prefix": "xyz67890..."}`

### Requirement: Audit logs written to stdout for Docker collection
Audit logs SHALL be written to stdout (standard output) using the application logger to enable Docker log drivers and centralized log aggregation systems to collect them.

#### Scenario: Audit log captured by Docker logs
- **WHEN** a security event occurs and is logged
- **THEN** running `docker logs <container-id>` shows the JSON audit log entry

#### Scenario: Audit log compatible with JSON log driver
- **WHEN** Docker is configured with the `json-file` log driver
- **THEN** audit logs are properly captured and parseable as JSON

### Requirement: Sensitive data excluded from audit logs
Audit logs SHALL NOT include sensitive data such as passwords, full API keys, or JWT tokens. For fields that must be logged for debugging, only redacted versions SHALL be included (e.g., first 8 characters of API key followed by "...").

#### Scenario: Password not logged in failed auth
- **WHEN** a login attempt fails with incorrect password
- **THEN** the audit log includes the username in details but NOT the submitted password

#### Scenario: API key redacted in audit log
- **WHEN** an admin operation is logged
- **THEN** the audit log includes `"api_key": "abc12345..."` (first 8 chars only)

#### Scenario: JWT token not logged
- **WHEN** a token verification event is logged
- **THEN** the audit log SHALL NOT include the full JWT token value

### Requirement: Audit log event types use consistent naming
Event types SHALL follow the naming convention `<resource>.<action>` (e.g., `user.created`, `user.deleted`, `auth.failed`) to enable consistent filtering and analysis.

#### Scenario: User lifecycle events
- **WHEN** user operations occur
- **THEN** event types include `user.created`, `user.updated`, `user.deleted`, `user.login`

#### Scenario: Authentication events
- **WHEN** authentication operations occur
- **THEN** event types include `auth.login`, `auth.failed`, `auth.token_refresh`, `auth.token_verify`

### Requirement: Audit logs queryable for compliance
Audit logs SHALL be structured to support compliance queries such as "all operations by user X", "all failed login attempts from IP Y", "all user deletions in time range Z".

#### Scenario: Query operations by user ID
- **WHEN** a compliance officer filters logs for `user_id: "abc123"`
- **THEN** all audit logs for operations involving that user are returned

#### Scenario: Query failed authentication attempts
- **WHEN** a security analyst filters logs for `event_type: "auth.failed"` and `success: false`
- **THEN** all failed login attempts are returned with timestamps and client IPs

#### Scenario: Query by time range
- **WHEN** an auditor filters logs for events between `2025-02-01T00:00:00Z` and `2025-02-07T23:59:59Z`
- **THEN** all events within that ISO 8601 timestamp range are returned

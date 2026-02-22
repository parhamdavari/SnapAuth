## ADDED Requirements

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

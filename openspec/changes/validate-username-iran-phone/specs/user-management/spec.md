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

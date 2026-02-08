## ADDED Requirements

### Requirement: Validate Iran mobile phone format
The system SHALL validate that username fields conform to Iran's mobile phone number format: exactly 11 digits starting with "09".

#### Scenario: Valid Iran phone number
- **WHEN** username is "09123456789" (11 digits, starts with 09)
- **THEN** validation passes

#### Scenario: Valid Iran phone number with different operator
- **WHEN** username is "09901234567" (11 digits, starts with 09, different operator prefix)
- **THEN** validation passes

#### Scenario: Invalid - does not start with 09
- **WHEN** username is "19123456789" (11 digits but starts with 19)
- **THEN** validation fails with error message "Username must be an Iran mobile number (09XXXXXXXXX)"

#### Scenario: Invalid - starts with 09 but wrong length (too short)
- **WHEN** username is "091234567" (only 9 digits)
- **THEN** validation fails with error message "Username must be an Iran mobile number (09XXXXXXXXX)"

#### Scenario: Invalid - starts with 09 but wrong length (too long)
- **WHEN** username is "091234567890" (12 digits)
- **THEN** validation fails with error message "Username must be an Iran mobile number (09XXXXXXXXX)"

#### Scenario: Invalid - contains non-numeric characters
- **WHEN** username is "0912345678a" (contains letter 'a')
- **THEN** validation fails with error message "Username must be an Iran mobile number (09XXXXXXXXX)"

#### Scenario: Invalid - contains spaces
- **WHEN** username is "0912 345 6789" (contains spaces)
- **THEN** validation fails with error message "Username must be an Iran mobile number (09XXXXXXXXX)"

#### Scenario: Invalid - contains special characters
- **WHEN** username is "0912-345-6789" (contains dashes)
- **THEN** validation fails with error message "Username must be an Iran mobile number (09XXXXXXXXX)"

### Requirement: Validation error messaging
The system SHALL return a clear, consistent error message when Iran phone validation fails.

#### Scenario: Error message format
- **WHEN** username validation fails
- **THEN** error message SHALL be "Username must be an Iran mobile number (09XXXXXXXXX)"

#### Scenario: Validation error response structure
- **WHEN** API request contains invalid username
- **THEN** response SHALL have status code 422 (Unprocessable Entity)
- **THEN** response body SHALL include validation error details with field name and error message

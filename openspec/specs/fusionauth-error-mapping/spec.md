## ADDED Requirements

### Requirement: Structured error response schema
The system SHALL return FusionAuth-originated errors using a consistent JSON schema: `{"errors": [...]}` where each entry contains `detail` (string, human-readable message), `error_code` (string, screaming snake case domain code), `field` (string or null, domain field name), and `original_value` (string or null, the rejected value). The `errors` array SHALL always be present, even for single errors.

#### Scenario: Single error returns array with one entry
- **WHEN** a request causes FusionAuth to return a single `[duplicate]user.username` error for value "+989356490485"
- **THEN** the response body SHALL be `{"errors": [{"detail": "User with this phone number already exists", "error_code": "DUPLICATE_USER", "field": "username", "original_value": "+989356490485"}]}`
- **THEN** the HTTP status code SHALL be the same status code returned by FusionAuth

#### Scenario: Error entry with null optional fields
- **WHEN** a FusionAuth error has no identifiable field or original value
- **THEN** the error entry SHALL include `"field": null` and `"original_value": null`
- **THEN** the `detail` and `error_code` fields SHALL still be present

### Requirement: Known FusionAuth field error code mapping
The system SHALL map the following FusionAuth field error codes to domain codes:

**Username errors:**
- `[duplicate]user.username` → `DUPLICATE_USER` ("User with this phone number already exists")
- `[blank]user.username` → `MISSING_FIELD` ("Username is required")

**Email errors:**
- `[duplicate]user.email` → `DUPLICATE_EMAIL` ("User with this email already exists")
- `[blank]user.email` → `MISSING_FIELD` ("Email is required")
- `[notEmail]user.email` → `INVALID_EMAIL_FORMAT` ("Invalid email address format")
- `[blocked]user.email` → `EMAIL_BLOCKED` ("This email domain is not allowed")

**Password errors:**
- `[blank]user.password` → `MISSING_FIELD` ("Password is required")
- `[tooShort]user.password` → `PASSWORD_TOO_SHORT` ("Password does not meet the minimum length requirement")
- `[tooLong]user.password` → `PASSWORD_TOO_LONG` ("Password exceeds the maximum length requirement")
- `[singleCase]user.password` → `PASSWORD_REQUIRES_MIXED_CASE` ("Password must contain both upper and lowercase characters")
- `[onlyAlpha]user.password` → `PASSWORD_REQUIRES_NON_ALPHA` ("Password must contain a non-alphabetic character")
- `[requireNumber]user.password` → `PASSWORD_REQUIRES_NUMBER` ("Password must contain a number")
- `[previouslyUsed]user.password` → `PASSWORD_PREVIOUSLY_USED` ("This password has been used recently")
- `[tooYoung]user.password` → `PASSWORD_CHANGE_TOO_RECENT` ("Password was changed too recently")
- `[breachedCommonPassword]user.password` → `PASSWORD_BREACHED` ("This password is not secure enough")
- `[breachedExactMatch]user.password` → `PASSWORD_BREACHED` ("This password is not secure enough")
- `[breachedSubAddressMatch]user.password` → `PASSWORD_BREACHED` ("This password is not secure enough")
- `[breachedPasswordOnly]user.password` → `PASSWORD_BREACHED` ("This password is not secure enough")

**Registration errors:**
- `[invalid]registration.roles` → `INVALID_ROLE` ("The specified role does not exist")
- `[duplicate]registration` → `DUPLICATE_REGISTRATION` ("User is already registered for this application")

**Login field errors:**
- `[blank]loginId` → `MISSING_FIELD` ("Login ID is required")
- `[blank]password` → `MISSING_FIELD` ("Password is required")

**User ID errors:**
- `[couldNotConvert]userId` → `INVALID_USER_ID` ("Invalid user ID format")

**Refresh token errors:**
- `[invalid]refreshToken` → `INVALID_REFRESH_TOKEN` ("Refresh token is invalid or expired")

#### Scenario: Duplicate email mapped correctly
- **WHEN** FusionAuth returns field error code `[duplicate]user.email`
- **THEN** the error entry SHALL contain `"error_code": "DUPLICATE_EMAIL"` and `"detail": "User with this email already exists"`
- **THEN** the `field` SHALL be `"email"`

#### Scenario: Password too short mapped correctly
- **WHEN** FusionAuth returns field error code `[tooShort]user.password`
- **THEN** the error entry SHALL contain `"error_code": "PASSWORD_TOO_SHORT"` and `"detail": "Password does not meet the minimum length requirement"`
- **THEN** the `field` SHALL be `"password"`

#### Scenario: Breached password mapped correctly
- **WHEN** FusionAuth returns field error code `[breachedExactMatch]user.password`
- **THEN** the error entry SHALL contain `"error_code": "PASSWORD_BREACHED"` and `"detail": "This password is not secure enough"`
- **THEN** the `field` SHALL be `"password"`

#### Scenario: Invalid user ID mapped correctly
- **WHEN** FusionAuth returns field error code `[couldNotConvert]userId`
- **THEN** the error entry SHALL contain `"error_code": "INVALID_USER_ID"` and `"detail": "Invalid user ID format"`

#### Scenario: Missing login field mapped correctly
- **WHEN** FusionAuth returns field error code `[blank]loginId`
- **THEN** the error entry SHALL contain `"error_code": "MISSING_FIELD"` and `"detail": "Login ID is required"`
- **THEN** the `field` SHALL be `"loginId"`

### Requirement: Known FusionAuth general error code mapping
The system SHALL map the following FusionAuth general error codes (from `generalErrors`) to domain codes:
- `[LoginPreventedException]` → `ACCOUNT_LOCKED` ("Your account has been locked")
- `[UserLockedException]` → `ACCOUNT_LOCKED` ("Your account has been locked")
- `[UserExpiredException]` → `ACCOUNT_EXPIRED` ("Your account has expired")
- `[UserAuthorizedNotRegisteredException]` → `NOT_REGISTERED` ("Your account is not registered for this application")

#### Scenario: Locked account returns ACCOUNT_LOCKED
- **WHEN** FusionAuth returns general error `[LoginPreventedException]`
- **THEN** the error entry SHALL contain `"error_code": "ACCOUNT_LOCKED"` and `"detail": "Your account has been locked"`
- **THEN** the `field` SHALL be `null`

#### Scenario: Expired account returns ACCOUNT_EXPIRED
- **WHEN** FusionAuth returns general error `[UserExpiredException]`
- **THEN** the error entry SHALL contain `"error_code": "ACCOUNT_EXPIRED"` and `"detail": "Your account has expired"`

### Requirement: Fallback for unmapped FusionAuth error codes
The system SHALL use error code `AUTH_PROVIDER_ERROR` for any FusionAuth error code not present in the mapping dictionary and SHALL preserve the original FusionAuth message in the `detail` field.

#### Scenario: Unmapped error code uses fallback
- **WHEN** FusionAuth returns an error with code `[invalid]password.strength` and message "Password does not meet strength requirements"
- **THEN** the response SHALL contain `"error_code": "AUTH_PROVIDER_ERROR"`
- **THEN** the `detail` field SHALL contain the original FusionAuth message "Password does not meet strength requirements"

#### Scenario: Completely unknown error structure uses fallback
- **WHEN** FusionAuth returns an error response with no recognizable `fieldErrors` or `generalErrors`
- **THEN** the response SHALL contain `"error_code": "AUTH_PROVIDER_ERROR"`
- **THEN** the system SHALL NOT return HTTP 500

### Requirement: HTTP status code propagation
The system SHALL return the identical HTTP status code received from FusionAuth in the error response.

#### Scenario: FusionAuth 400 propagated as 400
- **WHEN** FusionAuth returns HTTP 400 with a field error
- **THEN** the system SHALL return HTTP 400 to the client

#### Scenario: FusionAuth 404 propagated as 404
- **WHEN** FusionAuth returns HTTP 404 (user not found)
- **THEN** the system SHALL return HTTP 404 to the client

### Requirement: Raw error logging before mapping
The system SHALL log the complete, unmodified FusionAuth error response payload at ERROR severity level before performing any error code mapping or transformation.

#### Scenario: Full error payload logged
- **WHEN** FusionAuth returns any error response
- **THEN** the system SHALL log the raw error payload at ERROR level
- **THEN** the log entry SHALL be written before the mapped response is returned

#### Scenario: Multi-error payload fully logged
- **WHEN** FusionAuth returns `fieldErrors` with errors on both `user.username` and `user.email`
- **THEN** the system SHALL log the complete payload containing both field errors at ERROR level

### Requirement: All errors returned for multi-error responses
The system SHALL map and return all field errors when FusionAuth returns multiple field errors in a single response.

#### Scenario: Two field errors returns both in array
- **WHEN** FusionAuth returns `fieldErrors` with `[duplicate]user.username` and `[blank]user.email`
- **THEN** the `errors` array SHALL contain two entries: one mapped to `DUPLICATE_USER` and one mapped to `MISSING_FIELD`

#### Scenario: Multiple errors on same field returns all
- **WHEN** FusionAuth returns `fieldErrors` with two errors on `user.email`
- **THEN** the `errors` array SHALL contain two entries, both with `"field": "email"`

### Requirement: Domain field name extraction
The system SHALL extract the last segment of FusionAuth's dotted field path as the domain `field` value in the error response.

#### Scenario: Dotted path user.username becomes username
- **WHEN** the FusionAuth field path is `user.username`
- **THEN** the `field` value in the response SHALL be `"username"`

#### Scenario: Dotted path registration.roles becomes roles
- **WHEN** the FusionAuth field path is `registration.roles`
- **THEN** the `field` value in the response SHALL be `"roles"`

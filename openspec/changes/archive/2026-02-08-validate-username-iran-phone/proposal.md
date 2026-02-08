## Why

The username field in the user creation endpoint currently accepts any string with a minimum length of 3 characters. For this application's use case, usernames must follow Iran's mobile phone number format (starting with "09" and totaling 11 digits) to ensure consistency, prevent invalid data, and align with the business requirement of using phone numbers as user identifiers.

## What Changes

- Add validation to `UserCreateRequest.username` field to enforce Iran phone number format
- Enforce exact pattern: `09XXXXXXXXX` (starts with "09", total length 11 digits)
- Return descriptive validation error when username doesn't match the required format
- Apply same validation to `UserUpdateRequest.username` for consistency
- Update API documentation to reflect the username format requirement

## Capabilities

### New Capabilities
- `iran-phone-validation`: Validation logic for Iran mobile phone number format (09XXXXXXXXX pattern)

### Modified Capabilities
- `user-management`: Add phone number format constraint to username field in user creation and update operations

## Impact

**Affected Components:**
- `snapauth/app/schemas.py`: Add Pydantic field validator to `UserCreateRequest` and `UserUpdateRequest`
- `POST /v1/users`: User creation endpoint will enforce new validation
- `PATCH /v1/users/{user_id}`: User update endpoint will enforce validation on username changes
- API error responses: Will return validation errors with clear messaging about required format

**Breaking Change:** **BREAKING** - Existing clients attempting to create users with non-phone-number usernames will receive validation errors

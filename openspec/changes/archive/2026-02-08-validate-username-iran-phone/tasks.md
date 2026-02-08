## 1. Implementation

- [x] 1.1 Add Iran phone number regex pattern constant to `snapauth/app/schemas.py`
- [x] 1.2 Import `field_validator` from pydantic in `snapauth/app/schemas.py`
- [x] 1.3 Add `validate_username_iran_phone` field validator to `UserCreateRequest` class
- [x] 1.4 Add `validate_username_iran_phone` field validator to `UserUpdateRequest` class
- [x] 1.5 Update `UserCreateRequest.username` field description to reflect Iran phone format requirement
- [x] 1.6 Update `UserUpdateRequest.username` field description to reflect Iran phone format requirement

## 2. Testing

- [x] 2.1 Create test file `snapauth/tests/test_username_validation.py` for username validation tests
- [x] 2.2 Write test for valid Iran phone number (09123456789)
- [x] 2.3 Write test for valid Iran phone number with different operator (09901234567)
- [x] 2.4 Write test for invalid username - does not start with 09
- [x] 2.5 Write test for invalid username - too short (9 digits)
- [x] 2.6 Write test for invalid username - too long (12 digits)
- [x] 2.7 Write test for invalid username - contains non-numeric characters
- [x] 2.8 Write test for invalid username - contains spaces
- [x] 2.9 Write test for invalid username - contains special characters (dashes)
- [x] 2.10 Write integration test for POST /v1/users with valid Iran phone username
- [x] 2.11 Write integration test for POST /v1/users with invalid username (verify 422 response)
- [x] 2.12 Write integration test for PATCH /v1/users/{user_id} with valid username update
- [x] 2.13 Write integration test for PATCH /v1/users/{user_id} with invalid username update
- [x] 2.14 Verify validation error message format matches spec ("Username must be an Iran mobile number (09XXXXXXXXX)")

## 3. Verification

- [x] 3.1 Run all existing tests to ensure no regression
- [x] 3.2 Manually test user creation endpoint with valid Iran phone number
- [x] 3.3 Manually test user creation endpoint with invalid username to verify error response
- [x] 3.4 Verify error response returns 422 status code with proper validation details

## 1. Extend FusionAuthError and add mapping dictionaries

- [x] 1.1 Update `FusionAuthError.__init__` in `fusionauth_adapter.py` to replace `details: str` with `errors: list[dict] | None = None` where each dict has keys: `detail`, `error_code`, `field`, `original_value`
- [x] 1.2 Add `FUSIONAUTH_FIELD_ERROR_MAP` constant at module level in `fusionauth_adapter.py` with 27 entries mapping composite keys (`[code]field_path`) to `(domain_code, message)` tuples — covering username (2), email (4), password (12), registration (2), login fields (2), userId (1), refreshToken (1), and fallback codes
- [x] 1.3 Add `FUSIONAUTH_GENERAL_ERROR_MAP` constant at module level in `fusionauth_adapter.py` with 4 entries mapping standalone general error codes to `(domain_code, message)` tuples — covering `LoginPreventedException`, `UserLockedException`, `UserExpiredException`, `UserAuthorizedNotRegisteredException`
- [x] 1.4 Update all manual `FusionAuthError(...)` raise sites in adapter methods (create_user, register_user, login, get_user, delete_user, update_user) to use the new constructor signature — these fallback raises in `except Exception` blocks should use a single-entry errors list with `error_code="AUTH_PROVIDER_ERROR"`

## 2. Rewrite _handle_response with structured error parsing

- [x] 2.1 Log the complete raw `error_data` dict at ERROR level before any parsing
- [x] 2.2 Parse `fieldErrors` dict: iterate all fields and all errors per field, build the composite key (`[code]field_path`) for each, look up in `FUSIONAUTH_FIELD_ERROR_MAP`, extract domain field name from dotted path (last segment), extract `original_value`, and collect all mapped errors into the `errors` list
- [x] 2.3 Parse `generalErrors` list when present: iterate all general errors, look up each error's `code` in `FUSIONAUTH_GENERAL_ERROR_MAP`, fall back to `AUTH_PROVIDER_ERROR` for unmapped general codes
- [x] 2.4 Handle edge cases safely with `.get()` and defaults: missing keys, empty error lists, malformed payloads — all must fall back to a single `AUTH_PROVIDER_ERROR` entry without raising 500

## 3. Update exception handler and Pydantic schema

- [x] 3.1 Update `fusionauth_exception_handler` in `main.py` to return `{"errors": exc.errors}` instead of `{"error": ..., "details": ...}`
- [x] 3.2 Replace `ErrorResponse` in `schemas.py` with `FusionAuthFieldError` model (detail, error_code, field, original_value) and `FusionAuthErrorResponse` model (errors: list[FusionAuthFieldError])
- [x] 3.3 Remove any imports or references to the old `ErrorResponse` class across the codebase

## 4. Tests

- [x] 4.1 Unit test `_handle_response` with mock `fieldErrors` for representative mapped codes from each category (username, email, password, registration, login, userId, refreshToken) — verify correct `error_code`, `field`, `original_value` in each `errors` list entry
- [x] 4.2 Unit test `_handle_response` with mock `generalErrors` for each mapped general code — verify `ACCOUNT_LOCKED`, `ACCOUNT_EXPIRED`, `NOT_REGISTERED` domain codes with `field: null`
- [x] 4.3 Unit test `_handle_response` with an unmapped field error code and an unmapped general error code — verify fallback to `AUTH_PROVIDER_ERROR` with original message preserved
- [x] 4.4 Unit test `_handle_response` with multi-field `fieldErrors` (e.g., duplicate username + missing password) — verify all errors appear in the `errors` list
- [x] 4.5 Unit test `_handle_response` with malformed/empty error payloads — verify no 500 and graceful fallback to single `AUTH_PROVIDER_ERROR` entry
- [x] 4.6 Integration test: `POST /v1/users` with a duplicate username returns HTTP 400 with `{"errors": [{"detail": "...", "error_code": "DUPLICATE_USER", "field": "username", "original_value": "..."}]}`
- [x] 4.7 Integration test: verify the raw FusionAuth error payload appears in ERROR-level logs

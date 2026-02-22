## Why

When FusionAuth rejects a request (e.g., duplicate phone number, missing email), SnapAuth logs the detailed error internally but returns an opaque generic message to upstream callers (`{"error": "FusionAuth API error (status: 400)", "details": "<stringified dict>"}`). This prevents the frontend from displaying actionable feedback to end users — they see a generic "something went wrong" instead of "Phone number already exists."

This change replaces opaque error responses with structured, machine-readable JSON payloads that map FusionAuth-specific error codes to domain-friendly codes and human-readable messages.

## What Changes

- **BREAKING**: Error response schema changes from `{"error": str, "details": str}` to `{"errors": [{"detail": str, "error_code": str, "field": str|null, "original_value": str|null}, ...]}` for all FusionAuth-originated errors.
- Parse FusionAuth `fieldErrors` and `generalErrors` structures instead of stringifying them.
- Map known FusionAuth error codes to domain codes (`[duplicate]user.username` → `DUPLICATE_USER`, etc.).
- Unmapped errors fall back to `AUTH_PROVIDER_ERROR` with the original FusionAuth message preserved.
- Propagate FusionAuth's original HTTP status code (no more silent 500s from parse failures).
- Log the complete, unmodified FusionAuth error payload at ERROR level before mapping.
- For multi-error responses, return all mapped errors as an `errors` array. Single errors also use the array wrapper for a consistent client contract.

## Capabilities

### New Capabilities
- `fusionauth-error-mapping`: Structured parsing and domain mapping of FusionAuth error responses across all endpoints. Covers the error code mapping dictionary, the standardized error response schema, fallback behavior for unmapped codes, and raw error logging.

### Modified Capabilities
- `user-management`: Error responses from user creation, update, deletion, and registration endpoints change from opaque strings to the structured error schema.

## Impact

- **Code**: `fusionauth_adapter.py` (`_handle_response`, `FusionAuthError` class), `main.py` (global `fusionauth_exception_handler`)
- **API contract**: All endpoints returning FusionAuth errors will use the new schema — **breaking change** for upstream consumers (`rasa-main`)
- **Upstream coordination**: `rasa-main` must be updated to parse the new error shape before this deploys
- **No new dependencies**: Uses only stdlib and existing FastAPI/Pydantic

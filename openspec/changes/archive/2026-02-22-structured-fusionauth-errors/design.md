## Context

SnapAuth wraps FusionAuth as a facade. All FusionAuth calls flow through `FusionAuthAdapter._handle_response()`, which raises `FusionAuthError` on failure. A global FastAPI exception handler catches this and returns `{"error": str, "details": str}` — an opaque format that discards FusionAuth's structured error codes.

FusionAuth returns errors in two shapes:
- `fieldErrors`: `Dict[field_path, List[{code, message}]]` — validation failures tied to specific fields
- `generalErrors`: `List[{code, message}]` — non-field-specific errors (auth failures, server errors)

The current code stringifies both with `str()`, losing all granularity.

### Stakeholders
- **rasa-main** (upstream caller): Must be updated to parse the new error schema before deployment.
- **Frontend**: Indirect beneficiary — gets actionable error messages via rasa-main.

## Goals / Non-Goals

**Goals:**
- Replace opaque FusionAuth error responses with structured, machine-readable JSON across all endpoints.
- Map known FusionAuth error codes to domain-specific codes with human-readable messages.
- Gracefully handle unmapped/unknown errors with a fallback code.
- Log the complete raw FusionAuth error payload before mapping.

**Non-Goals:**
- Changing the error format for non-FusionAuth errors (JWT, JWKS, rate-limit errors keep their current shape).
- Updating rasa-main to consume the new schema (out of scope per PRD).
## Decisions

### D1: Error parsing lives in `_handle_response`, not in the exception handler

**Choice**: Parse `fieldErrors`/`generalErrors` in `FusionAuthAdapter._handle_response()` and attach structured data to `FusionAuthError`. The global exception handler simply serializes what the exception carries.

**Why over alternative** (parsing in the exception handler): The adapter is the single point where raw FusionAuth responses are available. Parsing there keeps the exception handler thin and ensures the raw payload is logged at the source, before any transformation.

### D2: Extend `FusionAuthError` to carry a list of structured errors

**Choice**: Replace the `details: str` field on `FusionAuthError` with an `errors` list:
```python
class FusionAuthError(Exception):
    def __init__(self, message: str, status_code: int | None = None,
                 errors: list[dict] | None = None):
```
Each dict in `errors` has keys: `detail` (str), `error_code` (str), `field` (str | None), `original_value` (str | None). When no structured errors are available, a single fallback entry with `error_code="AUTH_PROVIDER_ERROR"` is used.

**Why over alternative** (creating a separate exception class): The existing `FusionAuthError` is already the single exception type for all adapter failures, caught by exactly one handler. Extending it avoids a second exception class and a second handler.

### D3: Comprehensive mapping dictionaries as module-level constants

**Choice**: Define two mapping dicts at the top of `fusionauth_adapter.py`:
- `FUSIONAUTH_FIELD_ERROR_MAP`: maps composite keys (`[code]field_path`) from `fieldErrors` to `(domain_code, default_message)`.
- `FUSIONAUTH_GENERAL_ERROR_MAP`: maps standalone codes from `generalErrors` to `(domain_code, default_message)`.

```python
FUSIONAUTH_FIELD_ERROR_MAP: dict[str, tuple[str, str]] = {
    # Username
    "[duplicate]user.username":  ("DUPLICATE_USER", "User with this phone number already exists"),
    "[blank]user.username":      ("MISSING_FIELD", "Username is required"),

    # Email
    "[duplicate]user.email":     ("DUPLICATE_EMAIL", "User with this email already exists"),
    "[blank]user.email":         ("MISSING_FIELD", "Email is required"),
    "[notEmail]user.email":      ("INVALID_EMAIL_FORMAT", "Invalid email address format"),
    "[blocked]user.email":       ("EMAIL_BLOCKED", "This email domain is not allowed"),

    # Password
    "[blank]user.password":      ("MISSING_FIELD", "Password is required"),
    "[tooShort]user.password":   ("PASSWORD_TOO_SHORT", "Password does not meet the minimum length requirement"),
    "[tooLong]user.password":    ("PASSWORD_TOO_LONG", "Password exceeds the maximum length requirement"),
    "[singleCase]user.password": ("PASSWORD_REQUIRES_MIXED_CASE", "Password must contain both upper and lowercase characters"),
    "[onlyAlpha]user.password":  ("PASSWORD_REQUIRES_NON_ALPHA", "Password must contain a non-alphabetic character"),
    "[requireNumber]user.password":  ("PASSWORD_REQUIRES_NUMBER", "Password must contain a number"),
    "[previouslyUsed]user.password": ("PASSWORD_PREVIOUSLY_USED", "This password has been used recently"),
    "[tooYoung]user.password":       ("PASSWORD_CHANGE_TOO_RECENT", "Password was changed too recently"),
    "[breachedCommonPassword]user.password":   ("PASSWORD_BREACHED", "This password is not secure enough"),
    "[breachedExactMatch]user.password":       ("PASSWORD_BREACHED", "This password is not secure enough"),
    "[breachedSubAddressMatch]user.password":  ("PASSWORD_BREACHED", "This password is not secure enough"),
    "[breachedPasswordOnly]user.password":     ("PASSWORD_BREACHED", "This password is not secure enough"),

    # Registration
    "[invalid]registration.roles": ("INVALID_ROLE", "The specified role does not exist"),
    "[duplicate]registration":     ("DUPLICATE_REGISTRATION", "User is already registered for this application"),

    # Login fields
    "[blank]loginId":  ("MISSING_FIELD", "Login ID is required"),
    "[blank]password":  ("MISSING_FIELD", "Password is required"),

    # User ID
    "[couldNotConvert]userId": ("INVALID_USER_ID", "Invalid user ID format"),

    # Refresh token
    "[invalid]refreshToken": ("INVALID_REFRESH_TOKEN", "Refresh token is invalid or expired"),
}

FUSIONAUTH_GENERAL_ERROR_MAP: dict[str, tuple[str, str]] = {
    "[LoginPreventedException]":  ("ACCOUNT_LOCKED", "Your account has been locked"),
    "[UserLockedException]":      ("ACCOUNT_LOCKED", "Your account has been locked"),
    "[UserExpiredException]":     ("ACCOUNT_EXPIRED", "Your account has expired"),
    "[UserAuthorizedNotRegisteredException]": ("NOT_REGISTERED", "Your account is not registered for this application"),
}
```

**Why two maps instead of one**: `fieldErrors` and `generalErrors` have different key formats (composite `[code]field_path` vs standalone `[code]`). Separate maps avoid ambiguity and make lookup logic explicit.

**Why over alternatives** (config file, database, enum): O(1) lookup, zero I/O, trivially extensible by adding a line.

### D4: All errors returned as an array

**Choice**: When `fieldErrors` contains multiple fields or multiple errors per field, map and return all of them in the `errors` array. Single errors also use the array wrapper for a consistent client contract.

**Why**: Since the API contract is already breaking, there's no incremental cost. Returning all errors avoids unnecessary round-trips and gives the frontend everything it needs to display all validation failures at once.

### D5: Replace `ErrorResponse` Pydantic model with array schema

**Choice**: Replace the existing `ErrorResponse(error, details)` in `schemas.py` with two models: `FusionAuthFieldError(detail, error_code, field, original_value)` for individual error entries and `FusionAuthErrorResponse(errors: list[FusionAuthFieldError])` as the top-level envelope.

**Why over alternative** (keeping both): The old `ErrorResponse` is only used for OpenAPI documentation of FusionAuth errors. No other error types reference it. Replacing avoids dead code.

### D6: Extract field name from FusionAuth's dotted path

**Choice**: FusionAuth uses dotted paths like `user.username`, `user.email`, `registration.roles`. Extract the last segment as the `field` value (e.g., `user.username` → `username`).

**Why**: The upstream caller doesn't know FusionAuth's internal object hierarchy. Domain field names (`username`, `email`, `roles`) are what the frontend can act on.

## Risks / Trade-offs

**[Breaking API contract]** → Coordinate deployment with rasa-main team. The old `{"error", "details"}` shape is replaced entirely. Mitigation: deploy rasa-main update first (it should handle both shapes), then deploy SnapAuth.

**[Mapping maintenance]** → 27 field error codes and 4 general error codes are mapped, covering all critical and frequent codes for SnapAuth's actual API usage. Unmapped codes still fall back to `AUTH_PROVIDER_ERROR`. Mitigation: monitor `AUTH_PROVIDER_ERROR` frequency in logs and add mappings for any new FusionAuth codes.

**[FusionAuth error format changes]** → If FusionAuth changes its error response structure, parsing could fail. Mitigation: use `.get()` with defaults throughout; if parsing fails completely, fall back to `AUTH_PROVIDER_ERROR` with the raw stringified payload.

**[Array-always schema]** → Even single errors are wrapped in an array, which adds a layer of indirection for simple cases. Trade-off accepted for consistency — clients always parse the same shape.

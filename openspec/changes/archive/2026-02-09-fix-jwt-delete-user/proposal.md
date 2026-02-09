## Why

The `DELETE /v1/users/{userId}` endpoint crashes with an HTTP 500 (`TypeError: decode() missing 1 required positional argument: 'key'`) when a user attempts self-deletion with a valid JWT. The root cause is `decode_jwt_token()` in `dependencies.py` calling `jwt.decode()` without the mandatory `key` parameter. Beyond the crash, this function also skips signature verification entirely, meaning forged or expired tokens could theoretically be accepted. A proven, secure `JWKSManager.verify_jwt()` already exists but is not being used here — violating the Single Source of Truth principle.

## What Changes

- **Replace** `decode_jwt_token()` in `snapauth/app/security/dependencies.py` with a call to `jwks_manager.verify_jwt()`, which performs full cryptographic signature verification against the JWKS endpoint.
- **Convert** `decode_jwt_token()` from synchronous to asynchronous (since `verify_jwt` is async).
- **Update** the call site in `require_self_or_admin()` to `await` the now-async `decode_jwt_token()`.
- **Remove** the direct `jose.jwt` import from `dependencies.py` (replaced by the JWKS manager).
- **Add** proper error handling for `JWTVerificationError` in the decode path.

## Capabilities

### New Capabilities

_(none — this is a fix to existing behavior, not a new feature)_

### Modified Capabilities

- `user-management`: The self-delete authorization path (`require_self_or_admin`) changes from unverified JWT decoding to full JWKS-based signature verification. This changes the security contract: tokens must now be cryptographically valid (correct signature, not expired, correct issuer) rather than merely parseable.

## Impact

- **Code**: `snapauth/app/security/dependencies.py` — primary change target (imports, `decode_jwt_token`, `require_self_or_admin`)
- **API**: `DELETE /v1/users/{userId}` — previously returned 500 for valid JWTs, will now return 204 (valid) or 401 (invalid)
- **Dependencies**: Introduces runtime dependency on `snapauth.app.jwks.jwks_manager` from the dependencies module (already exists in the project)
- **Tests**: `snapauth/tests/test_security.py` must pass; existing tests may need updates to account for async changes

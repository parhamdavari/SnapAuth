## Context

The `DELETE /v1/users/{user_id}` endpoint in `main.py:243` calls `require_self_or_admin()` to authorize requests. This dependency function supports two authorization paths:

1. **Admin API key** — checked via `X-SnapAuth-API-Key` header (working correctly)
2. **JWT self-service** — checked via `Authorization: Bearer <token>` header (broken)

The JWT path calls `decode_jwt_token()` in `dependencies.py:63`, which invokes `jwt.decode()` without the mandatory `key` positional argument. This causes a `TypeError` crash (HTTP 500) on every JWT-authenticated delete request. Additionally, even if the `key` issue were fixed, the current implementation explicitly disables signature verification (`verify_signature: False`), meaning forged tokens would be accepted.

The project already has a production-ready `JWKSManager.verify_jwt()` method in `jwks.py:101` that performs full cryptographic verification (signature, expiration, issuer) against JWKS public keys. This method is the Single Source of Truth for JWT verification.

## Goals / Non-Goals

**Goals:**
- Eliminate the `TypeError` crash on JWT-authenticated delete requests
- Verify JWT signatures cryptographically via the existing `JWKSManager`
- Make `decode_jwt_token` async to support the async `verify_jwt` call
- Maintain the existing admin API key authorization path unchanged
- Ensure existing tests pass with the corrected code path

**Non-Goals:**
- Modifying the `JWKSManager` or `verify_jwt` implementation
- Changing the admin delete endpoint (`DELETE /v1/admin/users/{user_id}`)
- Adding new endpoints or changing response schemas
- Modifying FusionAuth configuration or JWKS provider setup

## Decisions

### Decision 1: Reuse `jwks_manager.verify_jwt()` instead of fixing `jwt.decode()` inline

**Chosen:** Replace the body of `decode_jwt_token()` with a call to `jwks_manager.verify_jwt(token)`.

**Alternatives considered:**
- *Fix `jwt.decode()` by adding a `key` parameter:* This would fix the crash but still require duplicating JWKS key fetching logic that already exists in `JWKSManager`. Violates Single Source of Truth.
- *Bypass `decode_jwt_token()` entirely and call `jwks_manager.verify_jwt()` directly in `require_self_or_admin`:* This would work but removes the abstraction layer. Keeping `decode_jwt_token` as a wrapper maintains the existing function contract and keeps the dependency module self-contained.

**Rationale:** Reusing `verify_jwt()` eliminates the crash, adds security (signature + expiration + issuer verification), and follows Single Source of Truth — all with minimal code change.

### Decision 2: Make `decode_jwt_token` async

**Chosen:** Change `def decode_jwt_token(token)` → `async def decode_jwt_token(token)`.

**Rationale:** `jwks_manager.verify_jwt()` is async (it may need to fetch JWKS keys over HTTP). The caller `require_self_or_admin()` is already async, so adding `await` at the call site is trivial.

### Decision 3: Catch `JWTVerificationError` instead of `JWTError`

**Chosen:** Import `JWTVerificationError` from `snapauth.app.jwks` and catch it in `decode_jwt_token`. Return `None` on failure (same contract as before).

**Rationale:** `verify_jwt()` raises `JWTVerificationError` (which wraps underlying `JWTError` and `JWKError`). Catching this single exception maintains the existing error-handling contract where `decode_jwt_token` returns `None` on any failure, and the caller raises HTTP 401.

### Decision 4: Remove direct `jose` imports from dependencies.py

**Chosen:** Remove `from jose import JWTError, jwt` since `dependencies.py` will no longer call `jwt.decode()` directly.

**Rationale:** Dead imports should be removed. The `jose` library interaction is now fully encapsulated in `jwks.py`.

## Risks / Trade-offs

**[JWKS availability]** → The new path depends on JWKS key availability. If FusionAuth is unreachable and keys aren't cached, self-delete requests will fail with 401 instead of the previous 500. **Mitigation:** `JWKSManager` already implements TTL-based caching via `cachetools.TTLCache`. This is an improvement over the status quo (crash).

**[Test mock path change]** → Tests currently mock `snapauth.app.main.jwks_manager.verify_jwt` (line 107 of `test_security.py`). After this change, `decode_jwt_token` will call `jwks_manager.verify_jwt` via the import in `dependencies.py`, so the mock path may need to be `snapauth.app.security.dependencies.jwks_manager.verify_jwt`. **Mitigation:** Verify mock paths during implementation and update if needed.

**[Async signature change]** → `decode_jwt_token` becomes async. Any other callers (if they exist) would need to be updated. **Mitigation:** Grep confirms `decode_jwt_token` is only called from `require_self_or_admin`, which is already async. No other callers exist.

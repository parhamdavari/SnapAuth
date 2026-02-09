## 1. Update imports in dependencies.py

- [x] 1.1 Add import for `jwks_manager` and `JWTVerificationError` from `snapauth.app.jwks` in `snapauth/app/security/dependencies.py`
- [x] 1.2 Remove the unused `from jose import JWTError, jwt` import

## 2. Refactor decode_jwt_token

- [x] 2.1 Change `decode_jwt_token` from `def` to `async def` in `snapauth/app/security/dependencies.py`
- [x] 2.2 Replace the function body: remove `jwt.decode()` call and replace with `await jwks_manager.verify_jwt(token)`
- [x] 2.3 Change the exception handler from `except JWTError` to `except JWTVerificationError`, keeping the `return None` contract
- [x] 2.4 Update the docstring from "Decode JWT token without verification (for extracting claims only)" to reflect that the function now performs full cryptographic verification via JWKS

## 3. Update call site in require_self_or_admin

- [x] 3.1 Change `claims = decode_jwt_token(token)` to `claims = await decode_jwt_token(token)` in `require_self_or_admin()`

## 4. Fix existing tests

- [x] 4.1 Update mock path in `test_user_cannot_delete_others` from `snapauth.app.main.jwks_manager.verify_jwt` to `snapauth.app.security.dependencies.jwks_manager.verify_jwt` — the current path patches the wrong namespace and the mock is never invoked
- [x] 4.2 Switch from `MagicMock` to `AsyncMock` (from `unittest.mock`) — awaiting a regular `MagicMock` with a dict `return_value` raises `TypeError`
- [x] 4.3 Add `mock_verify.assert_called_once()` assertion to confirm the mock is actually invoked (prevents false-positive passes)

## 5. Add missing test scenarios

- [x] 5.1 Add test: valid self-delete happy path — mock `verify_jwt` to return `{"sub": "user-123"}`, DELETE `/v1/users/user-123`, assert HTTP 204 and `fusionauth_adapter.delete_user` called
- [x] 5.2 Add test: expired JWT rejection — mock `verify_jwt` to raise `JWTVerificationError`, assert HTTP 401
- [x] 5.3 Add test: forged/invalid signature rejection — mock `verify_jwt` to raise `JWTVerificationError`, assert HTTP 401
- [x] 5.4 Add test: no credentials — DELETE `/v1/users/{userId}` without Authorization header or API key, assert HTTP 403
- [x] 5.5 Add test: admin API key bypass on `/v1/users/{userId}` endpoint (not `/v1/admin/users/`) — verify admin can delete any user via `require_self_or_admin` path, assert HTTP 204

## 6. Run test suite

- [x] 6.1 Run `pytest snapauth/snapauth/tests/test_security.py` and confirm all tests pass

## 7. Manual verification

- [x] 7.1 Confirm no `TypeError: decode() missing 1 required positional argument` errors appear when processing JWTs
- [x] 7.2 Confirm `DELETE /v1/users/{userId}` returns 204 with a valid JWT where `sub` matches `userId`
- [x] 7.3 Confirm `DELETE /v1/users/{userId}` returns 401 with an expired or forged JWT
- [x] 7.4 Confirm admin API key path still returns 204 (regression check)

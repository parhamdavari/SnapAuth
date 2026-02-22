"""Tests for structured FusionAuth error mapping.

Tests cover:
- Field error code mapping (username, email, password, registration, login, userId, refreshToken)
- General error code mapping (account locked, expired, not registered)
- Fallback behavior for unmapped codes
- Multi-error responses
- Malformed/empty error payloads
- Integration: structured error responses from API endpoints
- Raw error logging
"""

import logging
import pytest
from unittest.mock import MagicMock, patch, PropertyMock

from fastapi.testclient import TestClient

from snapauth.app.fusionauth_adapter import (
    FusionAuthAdapter,
    FusionAuthError,
    FUSIONAUTH_FIELD_ERROR_MAP,
    FUSIONAUTH_GENERAL_ERROR_MAP,
)
from snapauth.app.main import app
from snapauth.app.settings import Settings


@pytest.fixture
def adapter():
    """FusionAuthAdapter instance with mocked client"""
    with patch('snapauth.app.fusionauth_adapter.FusionAuthClient'):
        a = FusionAuthAdapter()
        return a


def _make_response(status, error_response=None, success_response=None):
    """Build a mock FusionAuth response object"""
    resp = MagicMock()
    resp.status = status
    resp.was_successful.return_value = success_response is not None
    resp.success_response = success_response
    resp.error_response = error_response
    return resp


# ---------------------------------------------------------------------------
# 4.1 Field error mapping — representative codes from each category
# ---------------------------------------------------------------------------

class TestFieldErrorMapping:

    def test_duplicate_username(self, adapter):
        response = _make_response(400, error_response={
            "fieldErrors": {
                "user.username": [{"code": "[duplicate]user.username",
                                   "message": "A user already exists", "value": "+989356490485"}]
            }
        })
        with pytest.raises(FusionAuthError) as exc_info:
            adapter._handle_response(response)
        err = exc_info.value.errors[0]
        assert err["error_code"] == "DUPLICATE_USER"
        assert err["field"] == "username"
        assert err["original_value"] == "+989356490485"
        assert err["detail"] == "User with this phone number already exists"

    def test_blank_email(self, adapter):
        response = _make_response(400, error_response={
            "fieldErrors": {
                "user.email": [{"code": "[blank]user.email", "message": "Required"}]
            }
        })
        with pytest.raises(FusionAuthError) as exc_info:
            adapter._handle_response(response)
        err = exc_info.value.errors[0]
        assert err["error_code"] == "MISSING_FIELD"
        assert err["field"] == "email"

    def test_not_email_format(self, adapter):
        response = _make_response(400, error_response={
            "fieldErrors": {
                "user.email": [{"code": "[notEmail]user.email", "message": "Invalid email",
                                "value": "not-an-email"}]
            }
        })
        with pytest.raises(FusionAuthError) as exc_info:
            adapter._handle_response(response)
        err = exc_info.value.errors[0]
        assert err["error_code"] == "INVALID_EMAIL_FORMAT"
        assert err["original_value"] == "not-an-email"

    def test_password_too_short(self, adapter):
        response = _make_response(400, error_response={
            "fieldErrors": {
                "user.password": [{"code": "[tooShort]user.password", "message": "Too short"}]
            }
        })
        with pytest.raises(FusionAuthError) as exc_info:
            adapter._handle_response(response)
        err = exc_info.value.errors[0]
        assert err["error_code"] == "PASSWORD_TOO_SHORT"
        assert err["field"] == "password"

    def test_password_breached(self, adapter):
        response = _make_response(400, error_response={
            "fieldErrors": {
                "user.password": [{"code": "[breachedExactMatch]user.password",
                                   "message": "Breached"}]
            }
        })
        with pytest.raises(FusionAuthError) as exc_info:
            adapter._handle_response(response)
        assert exc_info.value.errors[0]["error_code"] == "PASSWORD_BREACHED"

    def test_invalid_role(self, adapter):
        response = _make_response(400, error_response={
            "fieldErrors": {
                "registration.roles": [{"code": "[invalid]registration.roles",
                                        "message": "Invalid role"}]
            }
        })
        with pytest.raises(FusionAuthError) as exc_info:
            adapter._handle_response(response)
        err = exc_info.value.errors[0]
        assert err["error_code"] == "INVALID_ROLE"
        assert err["field"] == "roles"

    def test_blank_login_id(self, adapter):
        response = _make_response(400, error_response={
            "fieldErrors": {
                "loginId": [{"code": "[blank]loginId", "message": "Required"}]
            }
        })
        with pytest.raises(FusionAuthError) as exc_info:
            adapter._handle_response(response)
        err = exc_info.value.errors[0]
        assert err["error_code"] == "MISSING_FIELD"
        assert err["field"] == "loginId"

    def test_invalid_user_id(self, adapter):
        response = _make_response(400, error_response={
            "fieldErrors": {
                "userId": [{"code": "[couldNotConvert]userId", "message": "Invalid UUID"}]
            }
        })
        with pytest.raises(FusionAuthError) as exc_info:
            adapter._handle_response(response)
        assert exc_info.value.errors[0]["error_code"] == "INVALID_USER_ID"

    def test_invalid_refresh_token(self, adapter):
        response = _make_response(400, error_response={
            "fieldErrors": {
                "refreshToken": [{"code": "[invalid]refreshToken",
                                  "message": "Token expired"}]
            }
        })
        with pytest.raises(FusionAuthError) as exc_info:
            adapter._handle_response(response)
        assert exc_info.value.errors[0]["error_code"] == "INVALID_REFRESH_TOKEN"


# ---------------------------------------------------------------------------
# 4.2 General error mapping
# ---------------------------------------------------------------------------

class TestGeneralErrorMapping:

    def test_login_prevented(self, adapter):
        response = _make_response(423, error_response={
            "generalErrors": [{"code": "[LoginPreventedException]",
                               "message": "Your account has been locked."}]
        })
        with pytest.raises(FusionAuthError) as exc_info:
            adapter._handle_response(response)
        err = exc_info.value.errors[0]
        assert err["error_code"] == "ACCOUNT_LOCKED"
        assert err["field"] is None
        assert err["original_value"] is None

    def test_user_locked(self, adapter):
        response = _make_response(423, error_response={
            "generalErrors": [{"code": "[UserLockedException]",
                               "message": "Locked."}]
        })
        with pytest.raises(FusionAuthError) as exc_info:
            adapter._handle_response(response)
        assert exc_info.value.errors[0]["error_code"] == "ACCOUNT_LOCKED"

    def test_user_expired(self, adapter):
        response = _make_response(410, error_response={
            "generalErrors": [{"code": "[UserExpiredException]",
                               "message": "Expired."}]
        })
        with pytest.raises(FusionAuthError) as exc_info:
            adapter._handle_response(response)
        assert exc_info.value.errors[0]["error_code"] == "ACCOUNT_EXPIRED"

    def test_not_registered(self, adapter):
        response = _make_response(400, error_response={
            "generalErrors": [{"code": "[UserAuthorizedNotRegisteredException]",
                               "message": "Not registered."}]
        })
        with pytest.raises(FusionAuthError) as exc_info:
            adapter._handle_response(response)
        assert exc_info.value.errors[0]["error_code"] == "NOT_REGISTERED"


# ---------------------------------------------------------------------------
# 4.3 Unmapped error codes → AUTH_PROVIDER_ERROR fallback
# ---------------------------------------------------------------------------

class TestUnmappedErrors:

    def test_unmapped_field_error(self, adapter):
        response = _make_response(400, error_response={
            "fieldErrors": {
                "user.someField": [{"code": "[unknownCode]user.someField",
                                    "message": "Something unexpected happened"}]
            }
        })
        with pytest.raises(FusionAuthError) as exc_info:
            adapter._handle_response(response)
        err = exc_info.value.errors[0]
        assert err["error_code"] == "AUTH_PROVIDER_ERROR"
        assert err["detail"] == "Something unexpected happened"
        assert err["field"] == "someField"

    def test_unmapped_general_error(self, adapter):
        response = _make_response(500, error_response={
            "generalErrors": [{"code": "[SomeNewException]",
                               "message": "Unexpected server error"}]
        })
        with pytest.raises(FusionAuthError) as exc_info:
            adapter._handle_response(response)
        err = exc_info.value.errors[0]
        assert err["error_code"] == "AUTH_PROVIDER_ERROR"
        assert err["detail"] == "Unexpected server error"


# ---------------------------------------------------------------------------
# 4.4 Multi-field errors — all returned in array
# ---------------------------------------------------------------------------

class TestMultiErrors:

    def test_two_field_errors_both_returned(self, adapter):
        response = _make_response(400, error_response={
            "fieldErrors": {
                "user.username": [{"code": "[duplicate]user.username",
                                   "message": "Duplicate", "value": "09123456789"}],
                "user.password": [{"code": "[tooShort]user.password",
                                   "message": "Too short"}],
            }
        })
        with pytest.raises(FusionAuthError) as exc_info:
            adapter._handle_response(response)

        errors = exc_info.value.errors
        assert len(errors) == 2
        codes = {e["error_code"] for e in errors}
        assert "DUPLICATE_USER" in codes
        assert "PASSWORD_TOO_SHORT" in codes

    def test_multiple_errors_same_field(self, adapter):
        response = _make_response(400, error_response={
            "fieldErrors": {
                "user.password": [
                    {"code": "[tooShort]user.password", "message": "Too short"},
                    {"code": "[requireNumber]user.password", "message": "Needs number"},
                ]
            }
        })
        with pytest.raises(FusionAuthError) as exc_info:
            adapter._handle_response(response)

        errors = exc_info.value.errors
        assert len(errors) == 2
        assert all(e["field"] == "password" for e in errors)
        codes = {e["error_code"] for e in errors}
        assert "PASSWORD_TOO_SHORT" in codes
        assert "PASSWORD_REQUIRES_NUMBER" in codes


# ---------------------------------------------------------------------------
# 4.5 Malformed / empty payloads — graceful fallback
# ---------------------------------------------------------------------------

class TestMalformedPayloads:

    def test_none_error_response(self, adapter):
        response = _make_response(500, error_response=None)
        with pytest.raises(FusionAuthError) as exc_info:
            adapter._handle_response(response)
        errors = exc_info.value.errors
        assert len(errors) == 1
        assert errors[0]["error_code"] == "AUTH_PROVIDER_ERROR"

    def test_empty_dict_error_response(self, adapter):
        response = _make_response(400, error_response={})
        with pytest.raises(FusionAuthError) as exc_info:
            adapter._handle_response(response)
        errors = exc_info.value.errors
        assert len(errors) == 1
        assert errors[0]["error_code"] == "AUTH_PROVIDER_ERROR"

    def test_empty_field_errors(self, adapter):
        response = _make_response(400, error_response={"fieldErrors": {}})
        with pytest.raises(FusionAuthError) as exc_info:
            adapter._handle_response(response)
        errors = exc_info.value.errors
        assert len(errors) == 1
        assert errors[0]["error_code"] == "AUTH_PROVIDER_ERROR"

    def test_field_error_missing_code_key(self, adapter):
        response = _make_response(400, error_response={
            "fieldErrors": {
                "user.email": [{"message": "Something went wrong"}]
            }
        })
        with pytest.raises(FusionAuthError) as exc_info:
            adapter._handle_response(response)
        err = exc_info.value.errors[0]
        assert err["error_code"] == "AUTH_PROVIDER_ERROR"
        assert err["detail"] == "Something went wrong"

    def test_status_code_propagated(self, adapter):
        response = _make_response(404, error_response=None)
        with pytest.raises(FusionAuthError) as exc_info:
            adapter._handle_response(response)
        assert exc_info.value.status_code == 404


# ---------------------------------------------------------------------------
# 4.6 Integration: POST /v1/users with duplicate username
# ---------------------------------------------------------------------------

@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def valid_api_key():
    return "test-admin-api-key-12345678"


@pytest.fixture
def mock_settings_with_api_key(valid_api_key):
    with patch.object(Settings, 'admin_api_keys_list', new_callable=PropertyMock,
                      return_value=[valid_api_key]):
        yield


class TestIntegrationStructuredErrors:

    def test_duplicate_username_returns_structured_error(
        self, client, mock_settings_with_api_key, valid_api_key
    ):
        fa_error = FusionAuthError(
            message="FusionAuth API error (status: 400)",
            status_code=400,
            errors=[{
                "detail": "User with this phone number already exists",
                "error_code": "DUPLICATE_USER",
                "field": "username",
                "original_value": "09123456789",
            }],
        )
        with patch('snapauth.app.main.fusionauth_adapter') as mock_adapter:
            mock_adapter.create_user.side_effect = fa_error
            response = client.post(
                "/v1/users",
                json={"username": "09123456789", "password": "TestPassword123!"},
                headers={"X-SnapAuth-API-Key": valid_api_key},
            )

        assert response.status_code == 400
        body = response.json()
        assert "errors" in body
        assert len(body["errors"]) == 1
        err = body["errors"][0]
        assert err["error_code"] == "DUPLICATE_USER"
        assert err["field"] == "username"
        assert err["original_value"] == "09123456789"


# ---------------------------------------------------------------------------
# 4.7 Integration: raw error payload logged at ERROR level
# ---------------------------------------------------------------------------

class TestRawErrorLogging:

    def test_raw_payload_logged_before_mapping(self, adapter, caplog):
        raw_payload = {
            "fieldErrors": {
                "user.username": [{"code": "[duplicate]user.username",
                                   "message": "Duplicate", "value": "09123456789"}],
                "user.email": [{"code": "[blank]user.email", "message": "Required"}],
            }
        }
        response = _make_response(400, error_response=raw_payload)

        with caplog.at_level(logging.ERROR):
            with pytest.raises(FusionAuthError):
                adapter._handle_response(response)

        log_messages = [r.message for r in caplog.records if r.levelno >= logging.ERROR]
        assert any("fieldErrors" in msg for msg in log_messages)
        assert any("user.username" in msg for msg in log_messages)
        assert any("user.email" in msg for msg in log_messages)

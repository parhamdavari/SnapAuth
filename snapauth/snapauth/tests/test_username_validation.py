"""Username validation tests for Iran phone number format.

Tests cover:
- Valid Iran phone numbers (different operators)
- Invalid formats (wrong prefix, length, special characters)
- Integration with user creation and update endpoints
"""

import pytest
from pydantic import ValidationError
from fastapi.testclient import TestClient
from unittest.mock import patch

from snapauth.app.schemas import UserCreateRequest, UserUpdateRequest
from snapauth.app.main import app


class TestUsernameValidation:
    """Test username validation for Iran phone number format"""

    def test_valid_iran_phone_number(self):
        """Test that valid Iran phone number passes validation"""
        user_request = UserCreateRequest(
            username="09123456789",
            password="securePassword123"
        )
        assert user_request.username == "09123456789"

    def test_valid_iran_phone_number_different_operator(self):
        """Test valid Iran phone number with different operator prefix"""
        user_request = UserCreateRequest(
            username="09901234567",
            password="securePassword123"
        )
        assert user_request.username == "09901234567"

    def test_invalid_username_wrong_prefix(self):
        """Test that username not starting with 09 fails validation"""
        with pytest.raises(ValidationError) as exc_info:
            UserCreateRequest(
                username="19123456789",
                password="securePassword123"
            )
        assert "Username must be an Iran mobile number (09XXXXXXXXX)" in str(exc_info.value)

    def test_invalid_username_too_short(self):
        """Test that username shorter than 11 digits fails validation"""
        with pytest.raises(ValidationError) as exc_info:
            UserCreateRequest(
                username="091234567",
                password="securePassword123"
            )
        assert "Username must be an Iran mobile number (09XXXXXXXXX)" in str(exc_info.value)

    def test_invalid_username_too_long(self):
        """Test that username longer than 11 digits fails validation"""
        with pytest.raises(ValidationError) as exc_info:
            UserCreateRequest(
                username="091234567890",
                password="securePassword123"
            )
        assert "Username must be an Iran mobile number (09XXXXXXXXX)" in str(exc_info.value)

    def test_invalid_username_non_numeric(self):
        """Test that username with letters fails validation"""
        with pytest.raises(ValidationError) as exc_info:
            UserCreateRequest(
                username="0912345678a",
                password="securePassword123"
            )
        assert "Username must be an Iran mobile number (09XXXXXXXXX)" in str(exc_info.value)

    def test_invalid_username_with_spaces(self):
        """Test that username with spaces fails validation"""
        with pytest.raises(ValidationError) as exc_info:
            UserCreateRequest(
                username="0912 345 6789",
                password="securePassword123"
            )
        assert "Username must be an Iran mobile number (09XXXXXXXXX)" in str(exc_info.value)

    def test_invalid_username_with_dashes(self):
        """Test that username with dashes fails validation"""
        with pytest.raises(ValidationError) as exc_info:
            UserCreateRequest(
                username="0912-345-6789",
                password="securePassword123"
            )
        assert "Username must be an Iran mobile number (09XXXXXXXXX)" in str(exc_info.value)


class TestUserCreateIntegration:
    """Integration tests for user creation with username validation"""

    @pytest.fixture
    def client(self):
        """Test client"""
        return TestClient(app)

    @pytest.fixture
    def mock_fusionauth_and_settings(self):
        """Mock FusionAuth adapter and settings"""
        with patch('snapauth.app.main.fusionauth_adapter') as mock_fa, \
             patch('snapauth.app.security.dependencies.settings') as mock_settings:
            mock_fa.create_user.return_value = "test-user-id-123"
            mock_settings.admin_api_keys_list = ["test-api-key"]
            mock_settings.whitelisted_ips_list = []
            yield mock_fa, mock_settings

    def test_create_user_valid_phone(self, client, mock_fusionauth_and_settings):
        """Test creating user with valid Iran phone number"""
        response = client.post(
            "/v1/users",
            json={
                "username": "09123456789",
                "password": "securePassword123"
            },
            headers={"X-SnapAuth-API-Key": "test-api-key"}
        )
        assert response.status_code == 201
        assert "userId" in response.json()

    def test_create_user_invalid_username(self, client, mock_fusionauth_and_settings):
        """Test creating user with invalid username returns 422"""
        response = client.post(
            "/v1/users",
            json={
                "username": "invalid123",
                "password": "securePassword123"
            },
            headers={"X-SnapAuth-API-Key": "test-api-key"}
        )
        assert response.status_code == 422
        error_detail = response.json()["detail"]
        assert any("Username must be an Iran mobile number" in str(err) for err in error_detail)


class TestUserUpdateIntegration:
    """Integration tests for user update with username validation"""

    @pytest.fixture
    def client(self):
        """Test client"""
        return TestClient(app)

    @pytest.fixture
    def mock_fusionauth_and_jwt(self):
        """Mock FusionAuth adapter and JWT verification"""
        async def mock_verify_jwt(token):
            return {"sub": "test-user-id"}

        with patch('snapauth.app.main.fusionauth_adapter') as mock_fa, \
             patch('snapauth.app.main.jwks_manager') as mock_jwks:
            mock_fa.update_user.return_value = {
                "id": "test-user-id",
                "username": "09987654321",
                "data": {}
            }
            mock_jwks.verify_jwt = mock_verify_jwt
            yield mock_fa, mock_jwks

    def test_update_user_valid_phone(self, client, mock_fusionauth_and_jwt):
        """Test updating username to valid Iran phone number"""
        response = client.patch(
            "/v1/users/test-user-id",
            json={"username": "09987654321"},
            headers={"Authorization": "Bearer fake-jwt-token"}
        )
        assert response.status_code == 200
        assert response.json()["username"] == "09987654321"

    def test_update_user_invalid_username(self, client, mock_fusionauth_and_jwt):
        """Test updating username to invalid format returns 422"""
        response = client.patch(
            "/v1/users/test-user-id",
            json={"username": "newusername"},
            headers={"Authorization": "Bearer fake-jwt-token"}
        )
        assert response.status_code == 422
        error_detail = response.json()["detail"]
        assert any("Username must be an Iran mobile number" in str(err) for err in error_detail)


class TestValidationErrorMessage:
    """Test validation error message format"""

    def test_error_message_format(self):
        """Test that validation error message matches spec"""
        with pytest.raises(ValidationError) as exc_info:
            UserCreateRequest(
                username="invalid",
                password="securePassword123"
            )
        error_message = str(exc_info.value)
        assert "Username must be an Iran mobile number (09XXXXXXXXX)" in error_message

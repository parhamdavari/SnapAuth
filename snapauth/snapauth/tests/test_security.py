"""Security tests for SnapAuth authentication and authorization.

Tests cover:
- API key authentication
- IP whitelisting
- Rate limiting
- Authorization (self-only vs admin)
- Audit logging
- Security headers
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
import json

from snapauth.app.main import app
from snapauth.app.settings import settings


@pytest.fixture
def client():
    """Test client with default settings"""
    return TestClient(app)


@pytest.fixture
def valid_api_key():
    """Valid admin API key for testing"""
    return "test-admin-api-key-12345678"


@pytest.fixture
def mock_settings_with_api_key(valid_api_key):
    """Mock settings with admin API key configured"""
    with patch.object(settings, 'admin_api_keys_list', return_value=[valid_api_key]):
        yield


@pytest.fixture
def mock_fusionauth_adapter():
    """Mock FusionAuth adapter to avoid external dependencies"""
    with patch('snapauth.app.main.fusionauth_adapter') as mock:
        mock.create_user.return_value = "test-user-id-123"
        mock.delete_user.return_value = None
        mock.login.return_value = {
            "token": "test-jwt-token",
            "refreshToken": "test-refresh-token",
            "userId": "test-user-id"
        }
        yield mock


class TestAPIKeyAuthentication:
    """Test API key authentication for admin endpoints"""

    def test_create_user_without_api_key(self, client, mock_fusionauth_adapter):
        """Test that user creation without API key returns 401"""
        response = client.post(
            "/v1/users",
            json={
                "username": "testuser",
                "password": "TestPassword123!",
            }
        )
        assert response.status_code == 401
        assert "API key" in response.json()["detail"]

    def test_create_user_with_invalid_api_key(self, client, mock_settings_with_api_key, mock_fusionauth_adapter):
        """Test that user creation with invalid API key returns 401"""
        response = client.post(
            "/v1/users",
            json={
                "username": "testuser",
                "password": "TestPassword123!",
            },
            headers={"X-SnapAuth-API-Key": "invalid-key"}
        )
        assert response.status_code == 401
        assert "Invalid API key" in response.json()["detail"]

    def test_create_user_with_valid_api_key(self, client, mock_settings_with_api_key, valid_api_key, mock_fusionauth_adapter):
        """Test that user creation with valid API key returns 201"""
        response = client.post(
            "/v1/users",
            json={
                "username": "testuser",
                "password": "TestPassword123!",
            },
            headers={"X-SnapAuth-API-Key": valid_api_key}
        )
        assert response.status_code == 201
        assert "userId" in response.json()


class TestAuthorization:
    """Test authorization rules for user-specific endpoints"""

    @pytest.fixture
    def mock_jwt_token(self):
        """Mock JWT token for user authentication"""
        return "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTEyMyJ9.test"

    def test_user_cannot_delete_others(self, client, mock_jwt_token, mock_fusionauth_adapter):
        """Test that users cannot delete other users' accounts"""
        # Mock JWT verification to return different user ID
        with patch('snapauth.app.main.jwks_manager.verify_jwt') as mock_verify:
            mock_verify.return_value = {"sub": "user-123"}  # Different from URL

            response = client.delete(
                "/v1/users/other-user-456",
                headers={"Authorization": mock_jwt_token}
            )
            assert response.status_code == 403
            assert "only access your own" in response.json()["detail"]

    def test_admin_can_delete_any_user(self, client, mock_settings_with_api_key, valid_api_key, mock_fusionauth_adapter):
        """Test that admin API key allows deleting any user"""
        response = client.delete(
            "/v1/admin/users/any-user-id",
            headers={"X-SnapAuth-API-Key": valid_api_key}
        )
        assert response.status_code == 204


class TestRateLimiting:
    """Test rate limiting on authentication endpoints"""

    @pytest.fixture(autouse=True)
    def enable_rate_limiting(self):
        """Ensure rate limiting is enabled for tests"""
        with patch.object(settings, 'rate_limit_enabled', True):
            with patch.object(settings, 'rate_limit_per_minute_auth', 10):
                yield

    def test_rate_limit_login(self, client, mock_fusionauth_adapter):
        """Test that login endpoint enforces rate limit (10/min)"""
        # Mock login to fail (faster than success)
        mock_fusionauth_adapter.login.side_effect = Exception("Invalid credentials")

        # Make 11 requests - 11th should be rate limited
        for i in range(11):
            response = client.post(
                "/v1/auth/login",
                json={"username": "test", "password": "test"}
            )

        # Last request should be rate limited
        assert response.status_code == 429
        assert "Rate limit exceeded" in response.json()["error"]


class TestIPWhitelisting:
    """Test IP whitelisting for admin endpoints"""

    @pytest.fixture
    def mock_ip_whitelist(self):
        """Mock IP whitelist settings"""
        with patch.object(settings, 'admin_allowed_ips_list', return_value=["192.168.1.0/24"]):
            yield

    def test_ip_whitelist_blocks_unauthorized_ip(self, client, mock_settings_with_api_key, mock_ip_whitelist, valid_api_key, mock_fusionauth_adapter):
        """Test that non-whitelisted IPs are blocked"""
        # Override get_client_ip to return non-whitelisted IP
        with patch('snapauth.app.security.ip_whitelist.get_client_ip', return_value="10.0.0.1"):
            response = client.post(
                "/v1/users",
                json={"username": "test", "password": "test123"},
                headers={"X-SnapAuth-API-Key": valid_api_key}
            )
            assert response.status_code == 403
            assert "not authorized" in response.json()["detail"]

    def test_ip_whitelist_allows_whitelisted_ip(self, client, mock_settings_with_api_key, mock_ip_whitelist, valid_api_key, mock_fusionauth_adapter):
        """Test that whitelisted IPs are allowed"""
        # Override get_client_ip to return whitelisted IP (in range 192.168.1.0/24)
        with patch('snapauth.app.security.ip_whitelist.get_client_ip', return_value="192.168.1.100"):
            response = client.post(
                "/v1/users",
                json={"username": "test", "password": "test123"},
                headers={"X-SnapAuth-API-Key": valid_api_key}
            )
            assert response.status_code == 201


class TestSecurityHeaders:
    """Test security headers are present in responses"""

    def test_security_headers_present(self, client):
        """Test that all required security headers are present"""
        response = client.get("/health")

        assert response.status_code == 200

        # Check all required security headers
        headers = response.headers
        assert headers.get("X-Frame-Options") == "DENY"
        assert headers.get("X-Content-Type-Options") == "nosniff"
        assert headers.get("X-XSS-Protection") == "1; mode=block"
        assert "Content-Security-Policy" in headers

        # HSTS should only be present on HTTPS
        # In test client (HTTP), HSTS should not be present
        assert "Strict-Transport-Security" not in headers


class TestAuditLogging:
    """Test audit logging for security events"""

    def test_audit_log_created(self, client, mock_settings_with_api_key, valid_api_key, mock_fusionauth_adapter, caplog):
        """Test that audit log is created for user creation"""
        import logging
        caplog.set_level(logging.INFO, logger="snapauth.audit")

        response = client.post(
            "/v1/users",
            json={"username": "testuser", "password": "test123"},
            headers={"X-SnapAuth-API-Key": valid_api_key}
        )

        assert response.status_code == 201

        # Check audit log was written
        audit_logs = [record for record in caplog.records if record.name == "snapauth.audit"]
        assert len(audit_logs) > 0

        # Parse JSON audit log
        audit_entry = json.loads(audit_logs[0].message)

        # Validate audit log structure
        assert "timestamp" in audit_entry
        assert audit_entry["event_type"] == "user.created"
        assert "client_ip" in audit_entry
        assert audit_entry["success"] is True
        assert "details" in audit_entry
        assert audit_entry["details"]["username"] == "testuser"

        # Ensure password is not in audit log
        assert "password" not in json.dumps(audit_entry)

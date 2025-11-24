from typing import Optional, List, Dict, Any
from fusionauth.fusionauth_client import FusionAuthClient
from tenacity import retry, stop_after_attempt, wait_exponential
import logging

from .settings import settings

logger = logging.getLogger(__name__)


class FusionAuthError(Exception):
    """Custom exception for FusionAuth errors"""
    def __init__(self, message: str, status_code: Optional[int] = None, details: Optional[str] = None):
        self.message = message
        self.status_code = status_code
        self.details = details
        super().__init__(self.message)


class FusionAuthAdapter:
    def __init__(self):
        self.client = FusionAuthClient(
            api_key=settings.fusionauth_api_key,
            base_url=settings.fusionauth_base_url
        )
        self.application_id = settings.fusionauth_application_id
        self.tenant_id = settings.fusionauth_tenant_id or None

    def _handle_response(self, response) -> Dict[str, Any]:
        """Handle FusionAuth API response and extract data or raise error"""
        if response.was_successful():
            return response.success_response
        else:
            error_data = response.error_response
            error_msg = f"FusionAuth API error (status: {response.status})"
            details = None

            if error_data:
                if 'fieldErrors' in error_data:
                    details = str(error_data['fieldErrors'])
                elif 'generalErrors' in error_data:
                    details = str(error_data['generalErrors'])
                else:
                    details = str(error_data)

            logger.error(f"FusionAuth error: {error_msg}, details: {details}")

            raise FusionAuthError(
                message=error_msg,
                status_code=response.status,
                details=details
            )

    @retry(
        reraise=True,
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
    )
    def create_user(self, username: str, password: str, metadata: Dict[str, str]) -> str:
        """Create a new user in FusionAuth"""
        try:
            user_request = {
                "user": {
                    "username": username,
                    "password": password,
                    "active": True,
                    "data": metadata
                }
            }

            if self.tenant_id:
                user_request["user"]["tenantId"] = self.tenant_id

            response = self.client.create_user(user_request)
            result = self._handle_response(response)

            return result["user"]["id"]

        except FusionAuthError:
            raise
        except Exception as e:
            logger.error(f"Error creating user: {e}")
            raise FusionAuthError(f"Failed to create user: {str(e)}")

    @retry(
        reraise=True,
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
    )
    def register_user(self, user_id: str, roles: List[str]) -> None:
        """Register user to application with specified roles"""
        try:
            registration_request = {
                "registration": {
                    "applicationId": self.application_id,
                    "roles": roles
                }
            }

            response = self.client.register(registration_request, user_id)
            self._handle_response(response)

        except FusionAuthError:
            raise
        except Exception as e:
            logger.error(f"Error registering user: {e}")
            raise FusionAuthError(f"Failed to register user: {str(e)}")

    @retry(
        reraise=True,
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
    )
    def login(self, username: str, password: str) -> Dict[str, Optional[str]]:
        """Authenticate user and return tokens"""
        try:
            login_request = {
                "loginId": username,
                "password": password,
                "applicationId": self.application_id,
                "generateRefreshTokens": True,
                "noJWT": False,
            }

            response = self.client.login(login_request)
            result = self._handle_response(response)

            user_data = result.get("user", {})
            metadata = user_data.get("data", {})
            refresh_token = result.get("refreshToken")
            if not refresh_token:
                logger.error("FusionAuth login response missing refresh token despite request")
                raise FusionAuthError("Login failed: refresh token not returned by FusionAuth", status_code=response.status)

            return {
                "accessToken": result.get("token"),
                "refreshToken": refresh_token,
                "userId": user_data.get("id"),
                "metadata": metadata
            }

        except FusionAuthError:
            raise
        except Exception as e:
            logger.error(f"Error during login: {e}")
            raise FusionAuthError(f"Login failed: {str(e)}")

    @retry(
        reraise=True,
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
    )
    def get_user(self, user_id: str) -> Dict[str, Any]:
        """Get user information by user ID"""
        try:
            response = self.client.retrieve_user(user_id)
            result = self._handle_response(response)
            return result.get("user", {})

        except FusionAuthError:
            raise
        except Exception as e:
            logger.error(f"Error retrieving user: {e}")
            raise FusionAuthError(f"Failed to retrieve user: {str(e)}")

    @retry(
        reraise=True,
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
    )
    def logout(self, refresh_token: Optional[str] = None) -> None:
        """Logout user and optionally revoke refresh token"""
        if not refresh_token:
            return

        try:
            # Try the correct FusionAuth client logout method with refresh token string
            response = self.client.logout_with_request({
                "refreshToken": refresh_token
            })
            self._handle_response(response)

        except FusionAuthError:
            raise
        except Exception as e:
            # If FusionAuth logout fails, log but don't fail the request
            # JWTs are stateless and will expire naturally
            logger.warning(f"Server-side logout failed, but client-side logout successful: {e}")
            # Don't raise exception - logout is considered successful

    @retry(
        reraise=True,
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
    )
    def delete_user(self, user_id: str) -> None:
        """Delete a user in FusionAuth by ID"""
        try:
            response = self.client.delete_user(user_id)
            self._handle_response(response)
        except FusionAuthError:
            raise
        except Exception as e:
            logger.error(f"Error deleting user: {e}")
            raise FusionAuthError(f"Failed to delete user: {str(e)}")


# Global adapter instance
fusionauth_adapter = FusionAuthAdapter()

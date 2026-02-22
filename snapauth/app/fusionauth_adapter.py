from typing import Optional, List, Dict, Any
from fusionauth.fusionauth_client import FusionAuthClient
from tenacity import retry, stop_after_attempt, wait_exponential
import logging

from .settings import settings

logger = logging.getLogger(__name__)


class FusionAuthError(Exception):
    """Custom exception for FusionAuth errors with structured error details"""
    def __init__(self, message: str, status_code: Optional[int] = None,
                 errors: Optional[List[Dict[str, Any]]] = None):
        self.message = message
        self.status_code = status_code
        self.errors = errors or [{"detail": message, "error_code": "AUTH_PROVIDER_ERROR",
                                   "field": None, "original_value": None}]
        super().__init__(self.message)


# FusionAuth field error codes → (domain_code, user-friendly message)
# Keys are composite: [errorType]field.path
FUSIONAUTH_FIELD_ERROR_MAP: Dict[str, tuple] = {
    # Username
    "[duplicate]user.username":  ("DUPLICATE_USER", "User with this phone number already exists"),
    "[blank]user.username":      ("MISSING_FIELD", "Username is required"),

    # Email
    "[duplicate]user.email":     ("DUPLICATE_EMAIL", "User with this email already exists"),
    "[blank]user.email":         ("MISSING_FIELD", "Email is required"),
    "[notEmail]user.email":      ("INVALID_EMAIL_FORMAT", "Invalid email address format"),
    "[blocked]user.email":       ("EMAIL_BLOCKED", "This email domain is not allowed"),

    # Password
    "[blank]user.password":                    ("MISSING_FIELD", "Password is required"),
    "[tooShort]user.password":                 ("PASSWORD_TOO_SHORT", "Password does not meet the minimum length requirement"),
    "[tooLong]user.password":                  ("PASSWORD_TOO_LONG", "Password exceeds the maximum length requirement"),
    "[singleCase]user.password":               ("PASSWORD_REQUIRES_MIXED_CASE", "Password must contain both upper and lowercase characters"),
    "[onlyAlpha]user.password":                ("PASSWORD_REQUIRES_NON_ALPHA", "Password must contain a non-alphabetic character"),
    "[requireNumber]user.password":            ("PASSWORD_REQUIRES_NUMBER", "Password must contain a number"),
    "[previouslyUsed]user.password":           ("PASSWORD_PREVIOUSLY_USED", "This password has been used recently"),
    "[tooYoung]user.password":                 ("PASSWORD_CHANGE_TOO_RECENT", "Password was changed too recently"),
    "[breachedCommonPassword]user.password":    ("PASSWORD_BREACHED", "This password is not secure enough"),
    "[breachedExactMatch]user.password":        ("PASSWORD_BREACHED", "This password is not secure enough"),
    "[breachedSubAddressMatch]user.password":   ("PASSWORD_BREACHED", "This password is not secure enough"),
    "[breachedPasswordOnly]user.password":      ("PASSWORD_BREACHED", "This password is not secure enough"),

    # Registration
    "[invalid]registration.roles": ("INVALID_ROLE", "The specified role does not exist"),
    "[duplicate]registration":     ("DUPLICATE_REGISTRATION", "User is already registered for this application"),

    # Login fields
    "[blank]loginId":   ("MISSING_FIELD", "Login ID is required"),
    "[blank]password":  ("MISSING_FIELD", "Password is required"),

    # User ID
    "[couldNotConvert]userId": ("INVALID_USER_ID", "Invalid user ID format"),

    # Refresh token
    "[invalid]refreshToken": ("INVALID_REFRESH_TOKEN", "Refresh token is invalid or expired"),
}

# FusionAuth general error codes → (domain_code, user-friendly message)
FUSIONAUTH_GENERAL_ERROR_MAP: Dict[str, tuple] = {
    "[LoginPreventedException]":              ("ACCOUNT_LOCKED", "Your account has been locked"),
    "[UserLockedException]":                  ("ACCOUNT_LOCKED", "Your account has been locked"),
    "[UserExpiredException]":                 ("ACCOUNT_EXPIRED", "Your account has expired"),
    "[UserAuthorizedNotRegisteredException]": ("NOT_REGISTERED", "Your account is not registered for this application"),
}


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

        error_data = response.error_response
        error_msg = f"FusionAuth API error (status: {response.status})"

        # Log the complete raw error payload before any parsing
        logger.error(f"FusionAuth raw error response: {error_data}")

        errors: List[Dict[str, Any]] = []

        if isinstance(error_data, dict):
            # Parse fieldErrors: Dict[field_path, List[{code, message, ...}]]
            field_errors = error_data.get('fieldErrors', {})
            for field_path, error_list in field_errors.items():
                for error_entry in error_list:
                    code = error_entry.get('code', '')
                    message = error_entry.get('message', error_msg)

                    # Look up the composite key in the field error map
                    mapping = FUSIONAUTH_FIELD_ERROR_MAP.get(code)
                    if mapping:
                        domain_code, default_message = mapping
                    else:
                        domain_code, default_message = "AUTH_PROVIDER_ERROR", message

                    # Extract domain field name from dotted path (last segment)
                    domain_field = field_path.rsplit('.', 1)[-1] if '.' in field_path else field_path

                    errors.append({
                        "detail": default_message,
                        "error_code": domain_code,
                        "field": domain_field,
                        "original_value": error_entry.get('value'),
                    })

            # Parse generalErrors: List[{code, message}]
            if not errors:
                general_errors = error_data.get('generalErrors', [])
                for error_entry in general_errors:
                    code = error_entry.get('code', '')
                    message = error_entry.get('message', error_msg)

                    mapping = FUSIONAUTH_GENERAL_ERROR_MAP.get(code)
                    if mapping:
                        domain_code, default_message = mapping
                    else:
                        domain_code, default_message = "AUTH_PROVIDER_ERROR", message

                    errors.append({
                        "detail": default_message,
                        "error_code": domain_code,
                        "field": None,
                        "original_value": None,
                    })

        # Fallback: no parseable errors found
        if not errors:
            errors.append({
                "detail": error_msg,
                "error_code": "AUTH_PROVIDER_ERROR",
                "field": None,
                "original_value": None,
            })

        raise FusionAuthError(
            message=error_msg,
            status_code=response.status,
            errors=errors,
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
            raise FusionAuthError(f"Failed to create user: {str(e)}", status_code=500)

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
            raise FusionAuthError(f"Failed to register user: {str(e)}", status_code=500)

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
                raise FusionAuthError("Login failed: refresh token not returned by FusionAuth", status_code=response.status or 500)

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
            raise FusionAuthError(f"Login failed: {str(e)}", status_code=500)

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
            raise FusionAuthError(f"Failed to retrieve user: {str(e)}", status_code=500)

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
            raise FusionAuthError(f"Failed to delete user: {str(e)}", status_code=500)

    @retry(
        reraise=True,
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
    )
    def update_user(
        self,
        user_id: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        metadata: Optional[Dict[str, Optional[str]]] = None
    ) -> Dict[str, Any]:
        """
        Update user information in FusionAuth using PATCH.

        Args:
            user_id: The UUID of the user to update
            username: New username (optional)
            password: New password (optional)
            metadata: Metadata dict to merge (optional, null values remove keys)

        Returns:
            Dict containing updated user information

        Raises:
            FusionAuthError: If the update fails
        """
        try:
            # Build the user update object with only provided fields
            user_update: Dict[str, Any] = {}

            if username is not None:
                user_update["username"] = username

            if password is not None:
                user_update["password"] = password

            if metadata is not None:
                user_update["data"] = metadata

            # FusionAuth expects request wrapped in "user" key
            request = {"user": user_update}

            # Use patch_user for partial updates
            response = self.client.patch_user(user_id, request)
            result = self._handle_response(response)

            return result.get("user", {})

        except FusionAuthError:
            raise
        except Exception as e:
            logger.error(f"Error updating user: {e}")
            raise FusionAuthError(f"Failed to update user: {str(e)}", status_code=500)


# Global adapter instance
fusionauth_adapter = FusionAuthAdapter()

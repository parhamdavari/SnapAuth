import re
from typing import List, Optional, Dict
from pydantic import BaseModel, Field, field_validator, model_validator

# Iran mobile phone number pattern: starts with 09, total 11 digits
IRAN_PHONE_PATTERN = re.compile(r'^09\d{9}$')


class UserCreateRequest(BaseModel):
    username: str = Field(..., description="Username (Iran mobile number: 09XXXXXXXXX)")
    password: str = Field(..., min_length=8, description="User password")
    roles: Optional[List[str]] = Field(default=["user"], description="User roles")
    metadata: Dict[str, str] = Field(default_factory=dict, description="User metadata (database_user_id, department, phone_number, full_name, etc.)")

    @field_validator('username')
    @classmethod
    def validate_username_iran_phone(cls, v: str) -> str:
        if not IRAN_PHONE_PATTERN.match(v):
            raise ValueError('Username must be an Iran mobile number (09XXXXXXXXX)')
        return v


class UserCreateResponse(BaseModel):
    userId: str = Field(..., description="Created user ID")


class UserUpdateRequest(BaseModel):
    """Request schema for updating user information via PATCH"""
    username: Optional[str] = Field(None, description="New username (Iran mobile number: 09XXXXXXXXX)")
    password: Optional[str] = Field(None, min_length=8, description="New password")
    metadata: Optional[Dict[str, Optional[str]]] = Field(
        None, description="Metadata to merge (set value to null to remove a key)"
    )

    @field_validator('username')
    @classmethod
    def validate_username_iran_phone(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not IRAN_PHONE_PATTERN.match(v):
            raise ValueError('Username must be an Iran mobile number (09XXXXXXXXX)')
        return v

    @model_validator(mode='after')
    def check_at_least_one_field(self) -> 'UserUpdateRequest':
        """Ensure at least one field is provided for update"""
        if self.username is None and self.password is None and self.metadata is None:
            raise ValueError('At least one field must be provided for update')
        return self


class UserUpdateResponse(BaseModel):
    """Response schema for successful user update"""
    userId: str = Field(..., description="Updated user ID")
    username: Optional[str] = Field(None, description="Updated username")
    metadata: Optional[Dict[str, str]] = Field(None, description="Updated metadata")


class LoginRequest(BaseModel):
    username: str = Field(..., description="Username")
    password: str = Field(..., description="User password")


class TokenResponse(BaseModel):
    accessToken: Optional[str] = Field(None, description="JWT access token")
    refreshToken: Optional[str] = Field(None, description="Refresh token")
    userId: Optional[str] = Field(None, description="User ID")
    metadata: Optional[Dict[str, str]] = Field(None, description="User metadata")


class RefreshTokenRequest(BaseModel):
    refresh_token: str = Field(..., description="Refresh token")


class RefreshTokenResponse(BaseModel):
    accessToken: str = Field(..., description="New JWT access token")
    refreshToken: str = Field(..., description="New refresh token")


class UserInfoResponse(BaseModel):
    sub: str = Field(..., description="Subject (user ID)")
    username: Optional[str] = Field(None, description="Username")
    roles: Optional[List[str]] = Field(None, description="User roles")
    metadata: Optional[Dict[str, str]] = Field(None, description="User metadata")


class LogoutRequest(BaseModel):
    refresh_token: Optional[str] = Field(None, description="Refresh token to revoke")


class ErrorResponse(BaseModel):
    error: str = Field(..., description="Error message")
    details: Optional[str] = Field(None, description="Error details")


class HealthResponse(BaseModel):
    status: str = Field(..., description="Service status")
    timestamp: str = Field(..., description="Health check timestamp")
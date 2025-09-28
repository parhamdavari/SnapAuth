from typing import List, Optional, Dict
from pydantic import BaseModel, Field


class UserCreateRequest(BaseModel):
    username: str = Field(..., min_length=3, description="Username")
    password: str = Field(..., min_length=8, description="User password")
    roles: Optional[List[str]] = Field(default=["user"], description="User roles")
    metadata: Dict[str, str] = Field(default_factory=dict, description="User metadata (database_user_id, department, phone_number, full_name, etc.)")


class UserCreateResponse(BaseModel):
    userId: str = Field(..., description="Created user ID")


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
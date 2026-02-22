import httpx
import logging
from uuid import UUID
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Dict, Any
from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded

from .schemas import (
    UserCreateRequest, UserCreateResponse, LoginRequest, TokenResponse,
    RefreshTokenRequest, RefreshTokenResponse, UserInfoResponse,
    LogoutRequest, HealthResponse, UserUpdateRequest, UserUpdateResponse
)
from .fusionauth_adapter import fusionauth_adapter, FusionAuthError
from .jwks import jwks_manager, JWTVerificationError, JWKSError
from .settings import settings
from .security.middleware import SecurityHeadersMiddleware
from .security.rate_limit import limiter, rate_limit_auth, rate_limit_admin, rate_limit_authenticated
from .security.dependencies import require_admin_access, require_self_or_admin
from .security.audit import log_audit_event

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle application lifespan events"""
    # Startup
    try:
        logger.info("Validating JWT configuration against FusionAuth...")

        # Fetch OIDC configuration from FusionAuth
        oidc_config = await jwks_manager._fetch_oidc_configuration()
        fusionauth_issuer = oidc_config.get("issuer")

        # Validate that FusionAuth is responding correctly
        if not fusionauth_issuer:
            error_msg = "Could not fetch issuer from FusionAuth OIDC configuration"
            logger.error(error_msg)
            raise RuntimeError(error_msg)

        logger.info(f"JWT configuration validated successfully. FusionAuth issuer: {fusionauth_issuer}")

    except Exception as e:
        logger.error(f"JWT configuration validation failed: {e}")
        raise RuntimeError(f"Service startup failed due to JWT configuration error: {e}")

    yield

    # Shutdown (cleanup if needed)
    logger.info("Application shutting down...")


# FastAPI app
app = FastAPI(
    title="SnapAuth",
    description="Minimal authentication and authorization facade for FusionAuth",
    version="1.0.0",
    lifespan=lifespan,
    # Disable Swagger UI and ReDoc in production for security
    docs_url="/docs" if settings.environment != "production" else None,
    redoc_url="/redoc" if settings.environment != "production" else None,
)

# Add security headers middleware
app.add_middleware(SecurityHeadersMiddleware)

# CORS middleware - allows frontend to call auth endpoints
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=settings.cors_methods_list,
    allow_headers=settings.cors_headers_list,
)

# Register rate limiter with app
app.state.limiter = limiter

# Security scheme
security = HTTPBearer()


@app.exception_handler(FusionAuthError)
async def fusionauth_exception_handler(_request, exc: FusionAuthError):
    return JSONResponse(
        status_code=exc.status_code or 500,
        content={"errors": exc.errors}
    )


@app.exception_handler(JWTVerificationError)
async def jwt_verification_exception_handler(_request, exc: JWTVerificationError):
    return JSONResponse(
        status_code=401,
        content={"error": "Invalid token", "details": str(exc)}
    )


@app.exception_handler(JWKSError)
async def jwks_exception_handler(_request, exc: JWKSError):
    return JSONResponse(
        status_code=503,
        content={"error": "Service temporarily unavailable", "details": str(exc)}
    )


@app.exception_handler(RateLimitExceeded)
async def rate_limit_exception_handler(request: Request, exc: RateLimitExceeded):
    """Handle rate limit exceeded errors"""
    return JSONResponse(
        status_code=429,
        content={
            "error": "Rate limit exceeded",
            "detail": "Too many requests. Please try again later."
        },
        headers={"Retry-After": str(60)}  # Suggest retry after 60 seconds
    )


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    """Extract and verify JWT token from Authorization header"""
    try:
        token = credentials.credentials
        # SECURITY: Never log token content
        logger.info("Attempting JWT verification")
        payload = await jwks_manager.verify_jwt(token)
        logger.info(f"JWT verified successfully for user: {payload.get('sub')}")
        return payload
    except JWTVerificationError as e:
        logger.error(f"JWT verification failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}"
        )
    except Exception as e:
        logger.error(f"Unexpected error in get_current_user: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed"
        )


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    return HealthResponse(
        status="healthy",
        timestamp=datetime.now(timezone.utc).isoformat()
    )


@app.get("/health/jwt-config")
async def jwt_config_health_check():
    """Health check for JWT configuration"""
    try:
        # Validate JWT configuration against FusionAuth
        oidc_config = await jwks_manager._fetch_oidc_configuration()
        fusionauth_issuer = oidc_config.get("issuer")

        if fusionauth_issuer != settings.jwt_expected_iss:
            return JSONResponse(
                status_code=503,
                content={
                    "status": "unhealthy",
                    "error": "JWT issuer mismatch",
                    "fusionauth_issuer": fusionauth_issuer,
                    "expected_issuer": settings.jwt_expected_iss,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            )

        return {
            "status": "healthy",
            "issuer": fusionauth_issuer,
            "audience": settings.jwt_expected_aud,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    except Exception as e:
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        )


@app.post("/v1/users", response_model=UserCreateResponse, status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_admin_access)])
@rate_limit_admin()
async def create_user(request: Request, user_request: UserCreateRequest, admin_access: Dict = Depends(require_admin_access)):
    """Create a new user and optionally register to application with roles

    REQUIRES: Admin API key authentication (X-SnapAuth-API-Key header)
    """
    try:
        # Create user in FusionAuth
        user_id = fusionauth_adapter.create_user(
            username=user_request.username,
            password=user_request.password,
            metadata=user_request.metadata
        )

        # Register user to application with roles if application ID is configured
        if settings.fusionauth_application_id and user_request.roles:
            fusionauth_adapter.register_user(user_id, user_request.roles)

        # Audit log: user creation
        log_audit_event(
            event_type="user.created",
            request=request,
            user_id=user_id,
            success=True,
            details={
                "username": user_request.username,
                "roles": user_request.roles or [],
                "admin_ip": admin_access.get("client_ip")
            }
        )

        return UserCreateResponse(userId=user_id)

    except FusionAuthError:
        raise
    except Exception as e:
        logger.error(f"Unexpected error creating user: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@app.delete("/v1/users/{user_id}", response_model=None, status_code=status.HTTP_204_NO_CONTENT)
@rate_limit_authenticated()
async def delete_user(request: Request, user_id: UUID):
    """Delete a user from FusionAuth by ID

    AUTHORIZATION: Users can only delete their own account, OR admin API key required
    """
    try:
        # Check authorization: self-service OR admin
        auth_info = await require_self_or_admin(request, str(user_id))

        fusionauth_adapter.delete_user(str(user_id))

        # Audit log: user deletion
        log_audit_event(
            event_type="user.deleted",
            request=request,
            user_id=str(user_id),
            success=True,
            details={
                "auth_type": auth_info.get("auth_type"),  # "self" or "admin"
            }
        )

    except FusionAuthError:
        raise
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error deleting user: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@app.delete("/v1/admin/users/{user_id}", response_model=None, status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require_admin_access)])
@rate_limit_admin()
async def admin_delete_user(request: Request, user_id: UUID, admin_access: Dict = Depends(require_admin_access)):
    """Admin force delete: Delete any user by ID

    REQUIRES: Admin API key authentication (X-SnapAuth-API-Key header)
    """
    try:
        fusionauth_adapter.delete_user(str(user_id))

        # Audit log: admin force deletion
        log_audit_event(
            event_type="user.deleted",
            request=request,
            user_id=str(user_id),
            success=True,
            details={
                "type": "admin_force",
                "admin_ip": admin_access.get("client_ip")
            }
        )

    except FusionAuthError:
        raise
    except Exception as e:
        logger.error(f"Unexpected error deleting user: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@app.patch("/v1/users/{user_id}", response_model=UserUpdateResponse)
async def update_user(
    user_id: UUID,
    update_request: UserUpdateRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Update user information (self-only).

    Users can only update their own profile. Supports partial updates
    for username, password, and metadata fields.
    """
    try:
        # Authorization: users can only update themselves
        if str(user_id) != current_user.get("sub"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only update your own profile"
            )

        # Perform the update
        updated_user = fusionauth_adapter.update_user(
            user_id=str(user_id),
            username=update_request.username,
            password=update_request.password,
            metadata=update_request.metadata
        )

        return UserUpdateResponse(
            userId=updated_user.get("id"),
            username=updated_user.get("username"),
            metadata=updated_user.get("data", {})
        )

    except FusionAuthError:
        raise
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error updating user: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@app.post("/v1/auth/login", response_model=TokenResponse)
@rate_limit_auth()
async def login(request: Request, login_request: LoginRequest):
    """Authenticate user and return JWT tokens

    RATE LIMITED: 10 requests per minute to prevent brute force attacks
    """
    try:
        result = fusionauth_adapter.login(
            username=login_request.username,
            password=login_request.password
        )

        # Audit log: successful login
        log_audit_event(
            event_type="user.login",
            request=request,
            user_id=result.get("userId"),
            success=True,
            details={"username": login_request.username}
        )

        return TokenResponse(**result)

    except FusionAuthError as e:
        # Audit log: failed login attempt
        log_audit_event(
            event_type="auth.failed",
            request=request,
            success=False,
            details={"username": login_request.username, "reason": "invalid_credentials"}
        )
        raise
    except Exception as e:
        logger.error(f"Unexpected error during login: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@app.post("/v1/auth/refresh", response_model=RefreshTokenResponse)
async def refresh_token(refresh_request: RefreshTokenRequest):
    """Refresh access token using refresh token via OIDC"""
    try:
        # Get OIDC configuration
        oidc_config = await jwks_manager._fetch_oidc_configuration()
        token_endpoint = oidc_config.get("token_endpoint")

        if not token_endpoint:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Token endpoint not available"
            )

        # Prepare token refresh request
        token_data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_request.refresh_token,
            "client_id": settings.fusionauth_application_id,
            "client_secret": settings.fusionauth_client_secret,
        }

        # Make token refresh request
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                token_endpoint,
                data=token_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )

            if response.status_code != 200:
                error_details = response.text
                logger.error(f"Token refresh failed with status {response.status_code}: {error_details}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid refresh token"
                )

            token_response = response.json()

        return RefreshTokenResponse(
            accessToken=token_response["access_token"],
            refreshToken=token_response.get("refresh_token", refresh_request.refresh_token)
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error during token refresh: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@app.get("/v1/auth/me", response_model=UserInfoResponse)
async def get_user_info(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get user information from verified JWT token"""
    username = current_user.get("preferred_username")
    metadata = None

    # If username not in JWT, fetch from FusionAuth API using user ID
    if not username and current_user.get("sub"):
        try:
            user_info = fusionauth_adapter.get_user(current_user["sub"])
            username = user_info.get("username")
            metadata = user_info.get("data", {})
        except Exception as e:
            logger.warning(f"Could not fetch user info from FusionAuth: {e}")
            username = None

    sub = current_user.get("sub")
    if not sub:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token: missing subject"
        )

    return UserInfoResponse(
        sub=sub,
        username=username,
        roles=current_user.get("roles", []),
        metadata=metadata
    )


@app.post("/v1/auth/logout", status_code=status.HTTP_200_OK)
async def logout(logout_request: LogoutRequest):
    """Logout user and optionally revoke refresh token"""
    try:
        # Attempt server-side token revocation if refresh token is provided
        if logout_request.refresh_token:
            fusionauth_adapter.logout(logout_request.refresh_token)

        # Logout is always considered successful for stateless JWTs
        return {"message": "Logout successful"}

    except Exception as e:
        # Log unexpected errors but still return success
        # Client-side logout (discarding tokens) is sufficient for JWTs
        logger.warning(f"Server-side logout warning: {e}")
        return {"message": "Logout successful"}


@app.get("/v1/.well-known/jwks.json")
async def get_jwks():
    """Proxy FusionAuth JWKS for consuming services"""
    try:
        jwks = await jwks_manager.get_jwks()
        return jwks

    except JWKSError:
        raise
    except Exception as e:
        logger.error(f"Unexpected error getting JWKS: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)

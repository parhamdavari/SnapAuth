import httpx
import logging
from datetime import datetime
from typing import Dict, Any
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse

from .schemas import (
    UserCreateRequest, UserCreateResponse, LoginRequest, TokenResponse,
    RefreshTokenRequest, RefreshTokenResponse, UserInfoResponse,
    LogoutRequest, ErrorResponse, HealthResponse
)
from .fusionauth_adapter import fusionauth_adapter, FusionAuthError
from .jwks import jwks_manager, JWTVerificationError, JWKSError
from .settings import settings

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# FastAPI app
app = FastAPI(
    title="AAA Service",
    description="Minimal Authentication and Authorization microservice with FusionAuth",
    version="1.0.0"
)

# Security scheme
security = HTTPBearer()


@app.exception_handler(FusionAuthError)
async def fusionauth_exception_handler(request, exc: FusionAuthError):
    return JSONResponse(
        status_code=exc.status_code or 500,
        content={"error": exc.message, "details": exc.details}
    )


@app.exception_handler(JWTVerificationError)
async def jwt_verification_exception_handler(request, exc: JWTVerificationError):
    return JSONResponse(
        status_code=401,
        content={"error": "Invalid token", "details": str(exc)}
    )


@app.exception_handler(JWKSError)
async def jwks_exception_handler(request, exc: JWKSError):
    return JSONResponse(
        status_code=503,
        content={"error": "Service temporarily unavailable", "details": str(exc)}
    )


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    """Extract and verify JWT token from Authorization header"""
    try:
        token = credentials.credentials
        logger.info(f"Attempting JWT verification for token: {token[:20]}...")
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
        timestamp=datetime.utcnow().isoformat()
    )


@app.post("/v1/users", response_model=UserCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_user(user_request: UserCreateRequest):
    """Create a new user and optionally register to application with roles"""
    try:
        # Create user in FusionAuth
        user_id = fusionauth_adapter.create_user(
            username=user_request.username,
            password=user_request.password
        )

        # Register user to application with roles if application ID is configured
        if settings.fusionauth_application_id and user_request.roles:
            fusionauth_adapter.register_user(user_id, user_request.roles)

        return UserCreateResponse(userId=user_id)

    except FusionAuthError:
        raise
    except Exception as e:
        logger.error(f"Unexpected error creating user: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@app.post("/v1/auth/login", response_model=TokenResponse)
async def login(login_request: LoginRequest):
    """Authenticate user and return JWT tokens"""
    try:
        result = fusionauth_adapter.login(
            username=login_request.username,
            password=login_request.password
        )

        return TokenResponse(**result)

    except FusionAuthError:
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
            "client_secret": "n_KKk2DB3vkNPvUr-dgwc5HLG_QsI22Urj0s7Jq1JEE"
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
    return UserInfoResponse(
        sub=current_user.get("sub"),
        username=current_user.get("preferred_username"),
        roles=current_user.get("roles", [])
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
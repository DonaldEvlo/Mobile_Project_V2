from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.core.security import create_access_token, revoke_token, get_current_user
from app.core.config import get_settings

router = APIRouter(prefix="/api/auth", tags=["Authentication"])
settings = get_settings()

# Simple API key authentication — in production, use a proper auth provider
VALID_API_KEYS = {"mobile-client-key-2026"}


class TokenRequest(BaseModel):
    api_key: str
    device_id: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class RevokeRequest(BaseModel):
    token: str


@router.post("/token", response_model=TokenResponse)
async def issue_token(request: TokenRequest):
    """
    Issue a JWT access token for a mobile client.
    Validates the API key and associates the token with a device.
    """
    if request.api_key not in VALID_API_KEYS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )

    token = create_access_token(
        data={
            "sub": request.device_id,
            "type": "mobile_client",
        }
    )

    return TokenResponse(
        access_token=token,
        expires_in=settings.JWT_EXPIRATION_MINUTES * 60,
    )


@router.delete("/revoke")
async def revoke_user_token(
    request: RevokeRequest,
    current_user: dict = Depends(get_current_user),
):
    """
    Revoke a JWT token. Used when a critical threat is detected
    to force the mobile client to re-authenticate.
    """
    revoke_token(request.token)
    return {"status": "revoked", "message": "Token has been revoked"}


@router.get("/verify")
async def verify_current_token(
    current_user: dict = Depends(get_current_user),
):
    """Verify that the current token is valid and not revoked."""
    return {
        "status": "valid",
        "device_id": current_user.get("sub"),
        "type": current_user.get("type"),
    }

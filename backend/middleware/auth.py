"""Authentication middleware using JWT tokens."""
import logging
import os
import uuid
from typing import Optional

from fastapi import Request, HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from database.models import User
from services.auth_service import auth_service

logger = logging.getLogger(__name__)

security = HTTPBearer(auto_error=False)


class AuthContext(BaseModel):
    """Authentication context for requests."""
    user_id: Optional[uuid.UUID] = None
    username: Optional[str] = None
    is_authenticated: bool = False

    class Config:
        arbitrary_types_allowed = True


async def get_auth_context(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> AuthContext:
    """
    Get authentication context from request.
    Requires JWT Bearer token authentication.
    """
    if credentials:
        payload = auth_service.decode_token(credentials.credentials)
        if payload and payload.get("type") == "access":
            user_id = uuid.UUID(payload["sub"])
            user = await auth_service.get_user_by_id(db, user_id)
            if user and user.is_active:
                return AuthContext(
                    user_id=user.id,
                    username=user.username,
                    is_authenticated=True
                )

    return AuthContext(is_authenticated=False)


async def require_auth(
    auth_context: AuthContext = Depends(get_auth_context)
) -> AuthContext:
    """Dependency that requires authentication."""
    if not auth_context.is_authenticated:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return auth_context


async def get_current_user_from_context(
    auth_context: AuthContext = Depends(require_auth),
    db: AsyncSession = Depends(get_db)
) -> Optional[User]:
    """Get User object from auth context."""
    if not auth_context.user_id:
        return None
    return await auth_service.get_user_by_id(db, auth_context.user_id)


def verify_ws_token(token: str) -> bool:
    """Verify a WebSocket JWT access token."""
    if not token:
        return False

    payload = auth_service.decode_token(token)
    return bool(payload and payload.get("type") == "access")


async def get_user_api_key_for_provider(
    provider: str,
    auth_context: AuthContext,
    db: AsyncSession
) -> Optional[str]:
    """Get the decrypted API key for a user and provider."""
    provider = (provider or "").strip().lower()

    # Get per-user keys for authenticated users
    if auth_context.user_id:
        try:
            key = await auth_service.get_user_api_key(db, auth_context.user_id, provider)
            if key:
                return key
        except Exception as e:
            # Log actual errors (not just "key not found")
            logger.warning(f"Error retrieving user API key for {provider}: {type(e).__name__}: {e}")

    # Fall back to app-level settings
    try:
        from services.settings_service import settings_service

        app_settings = await settings_service.get_settings()
        provider_settings = app_settings.providers.get(provider)
        if provider_settings and provider_settings.api_key:
            return provider_settings.api_key
    except Exception as e:
        # Log actual errors (not just "settings not found")
        logger.warning(f"Error retrieving app-level API key for {provider}: {type(e).__name__}: {e}")

    # Final fallback: environment variables
    if provider == "anthropic":
        return os.environ.get("ANTHROPIC_API_KEY")
    if provider == "openai":
        return os.environ.get("OPENAI_API_KEY")
    return None

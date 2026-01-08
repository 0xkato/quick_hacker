"""Authentication middleware supporting both legacy tokens and JWT."""
import os
import secrets
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from fastapi import Request, HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from database.models import User
from services.auth_service import auth_service


security = HTTPBearer(auto_error=False)


class AuthContext(BaseModel):
    """Authentication context for requests."""
    user_id: Optional[uuid.UUID] = None
    username: Optional[str] = None
    is_authenticated: bool = False
    is_legacy_token: bool = False

    class Config:
        arbitrary_types_allowed = True


async def get_auth_context(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> AuthContext:
    """
    Get authentication context from request.
    Supports both JWT Bearer tokens and legacy X-Session-Token header.
    """
    # Try JWT Bearer token first
    if credentials:
        payload = auth_service.decode_token(credentials.credentials)
        if payload and payload.get("type") == "access":
            user_id = uuid.UUID(payload["sub"])
            user = await auth_service.get_user_by_id(db, user_id)
            if user and user.is_active:
                return AuthContext(
                    user_id=user.id,
                    username=user.username,
                    is_authenticated=True,
                    is_legacy_token=False
                )

    # Fall back to legacy X-Session-Token (for backwards compatibility during migration)
    legacy_token = request.headers.get("X-Session-Token")
    if legacy_token:
        # Validate against master token (legacy behavior)
        master_token = _get_master_token()
        if master_token and secrets.compare_digest(legacy_token, master_token):
            return AuthContext(
                is_authenticated=True,
                is_legacy_token=True
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
    """Get User object from auth context (None for legacy tokens)."""
    if auth_context.is_legacy_token or not auth_context.user_id:
        return None
    return await auth_service.get_user_by_id(db, auth_context.user_id)


def _get_master_token() -> Optional[str]:
    """Get master token from file (legacy support)."""
    data_dir = Path(os.environ.get("DATA_DIR", "data"))
    token_file = data_dir / ".session_token"
    try:
        if token_file.exists() and not token_file.is_symlink():
            return token_file.read_text().strip()
    except Exception:
        pass
    return None


# Helper to get user's API key for a provider
async def get_user_api_key_for_provider(
    provider: str,
    auth_context: AuthContext,
    db: AsyncSession
) -> Optional[str]:
    """Get the decrypted API key for a user and provider."""
    if auth_context.is_legacy_token or not auth_context.user_id:
        # For legacy tokens, fall back to environment variables
        if provider == "anthropic":
            return os.environ.get("ANTHROPIC_API_KEY")
        elif provider == "openai":
            return os.environ.get("OPENAI_API_KEY")
        return None

    return await auth_service.get_user_api_key(db, auth_context.user_id, provider)

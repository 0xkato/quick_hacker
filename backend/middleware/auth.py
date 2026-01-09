"""Authentication middleware supporting both legacy tokens and JWT."""
import os
import secrets
import threading
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

_MASTER_TOKEN_CACHE: Optional[str] = None
_LEGACY_SESSION_TOKENS: dict[str, datetime] = {}
_LEGACY_LOCK = threading.Lock()
_LEGACY_SESSION_TTL = timedelta(hours=24)


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
        # Validate against master token or active sessions (legacy behavior)
        if verify_session(legacy_token):
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


def get_session_token() -> str:
    """
    Get (and if needed, create) the legacy master session token.

    This supports the existing frontend bootstrapping flow while JWT auth is being adopted.
    """
    global _MASTER_TOKEN_CACHE
    if _MASTER_TOKEN_CACHE:
        return _MASTER_TOKEN_CACHE

    token = _get_master_token()
    if token:
        _MASTER_TOKEN_CACHE = token
        return token

    # Best-effort: create and persist a token; fall back to in-memory token if writes are blocked.
    token = secrets.token_urlsafe(32)
    data_dir = Path(os.environ.get("DATA_DIR", "data"))
    token_file = data_dir / ".session_token"
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        if token_file.exists() and token_file.is_symlink():
            # Refuse to follow symlinks for token files.
            _MASTER_TOKEN_CACHE = token
            return token
        token_file.write_text(token)
    except Exception:
        pass

    _MASTER_TOKEN_CACHE = token
    return token


def create_new_session(expires_in: timedelta = _LEGACY_SESSION_TTL) -> str:
    """Create a new legacy session token (ephemeral, in-memory)."""
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + expires_in
    with _LEGACY_LOCK:
        _LEGACY_SESSION_TOKENS[token] = expires_at
    return token


def verify_session(token: str) -> bool:
    """Verify a legacy session token (master token or ephemeral session)."""
    if not token:
        return False

    master = get_session_token()
    if master and secrets.compare_digest(token, master):
        return True

    now = datetime.utcnow()
    with _LEGACY_LOCK:
        expires_at = _LEGACY_SESSION_TOKENS.get(token)
        if not expires_at:
            return False
        if expires_at <= now:
            _LEGACY_SESSION_TOKENS.pop(token, None)
            return False
        return True


def verify_ws_token(token: str) -> bool:
    """Verify a WebSocket auth token (legacy session token or JWT access token)."""
    if not token:
        return False

    if verify_session(token):
        return True

    payload = auth_service.decode_token(token)
    return bool(payload and payload.get("type") == "access")


# Helper to get user's API key for a provider
async def get_user_api_key_for_provider(
    provider: str,
    auth_context: AuthContext,
    db: AsyncSession
) -> Optional[str]:
    """Get the decrypted API key for a user and provider."""
    provider = (provider or "").strip().lower()

    # Prefer per-user keys for JWT-authenticated users.
    if not auth_context.is_legacy_token and auth_context.user_id:
        try:
            key = await auth_service.get_user_api_key(db, auth_context.user_id, provider)
            if key:
                return key
        except Exception:
            # Corrupt/legacy encrypted keys shouldn't block falling back to app settings.
            pass

    # Fall back to app-level settings (what the Settings UI currently edits).
    try:
        from services.settings_service import settings_service

        app_settings = await settings_service.get_settings()
        provider_settings = app_settings.providers.get(provider)
        if provider_settings and provider_settings.api_key:
            return provider_settings.api_key
    except Exception:
        # Settings are optional; ignore and continue to env fallbacks.
        pass

    # Final fallback: environment variables.
    if provider == "anthropic":
        return os.environ.get("ANTHROPIC_API_KEY")
    if provider == "openai":
        return os.environ.get("OPENAI_API_KEY")
    return None

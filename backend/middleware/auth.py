"""
Simple session-based authentication for quick_hack.

This provides basic protection against unauthorized access.
For a local development tool, this prevents casual attackers from:
- Modifying API keys
- Viewing security findings
- Controlling agents

In production, consider implementing proper JWT-based auth.
"""

import os
import secrets
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from fastapi import HTTPException, Header
from fastapi.security import HTTPBearer
from pydantic import BaseModel


# Token file path - persists across restarts
TOKEN_FILE = Path(os.environ.get("DATA_DIR", "data")) / ".session_token"


class SessionStore:
    """Session storage with persistent master token."""

    def __init__(self):
        self._sessions: dict[str, datetime] = {}
        self._master_token: Optional[str] = None
        self._session_duration = timedelta(hours=24)
        # Load or generate master token on init
        self._load_or_generate_master_token()

    def _load_or_generate_master_token(self):
        """Load master token from file or generate new one."""
        try:
            TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
            try:
                TOKEN_FILE.parent.chmod(0o700)
            except Exception:
                pass

            if TOKEN_FILE.exists():
                if TOKEN_FILE.is_symlink():
                    raise RuntimeError("Refusing to read session token from symlink")
                self._master_token = TOKEN_FILE.read_text().strip()
                if self._master_token:
                    print(f"[Auth] Loaded existing session token")
                    return
        except Exception as e:
            print(f"[Auth] Error loading token: {e}")

        # Generate new token
        self._master_token = secrets.token_urlsafe(32)
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(str(TOKEN_FILE), flags, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(self._master_token)
            try:
                TOKEN_FILE.chmod(0o600)
            except Exception:
                pass
            print(f"[Auth] Generated new session token")
        except Exception as e:
            print(f"[Auth] Warning: Could not persist token: {e}")

    def generate_master_token(self) -> str:
        """Get the master token (already loaded/generated in __init__)."""
        if self._master_token is None:
            self._load_or_generate_master_token()
        return self._master_token

    def get_master_token(self) -> Optional[str]:
        """Get the current master token."""
        return self._master_token

    def create_session(self) -> str:
        """Create a new session token."""
        token = secrets.token_urlsafe(32)
        self._sessions[token] = datetime.utcnow()
        return token

    def validate_session(self, token: str) -> bool:
        """Validate a session token."""
        if not token:
            return False

        # Check if it's the master token
        if self._master_token and secrets.compare_digest(token, self._master_token):
            return True

        # Check session tokens
        if token in self._sessions:
            created_at = self._sessions[token]
            if datetime.utcnow() - created_at < self._session_duration:
                return True
            else:
                # Expired - remove it
                del self._sessions[token]

        return False

    def revoke_session(self, token: str) -> bool:
        """Revoke a session token."""
        if token in self._sessions:
            del self._sessions[token]
            return True
        return False

    def cleanup_expired(self):
        """Remove expired sessions."""
        now = datetime.utcnow()
        expired = [
            token for token, created_at in self._sessions.items()
            if now - created_at >= self._session_duration
        ]
        for token in expired:
            del self._sessions[token]


# Global session store
_session_store = SessionStore()


def get_session_token() -> str:
    """Get or generate the master session token."""
    return _session_store.generate_master_token()


def verify_session(token: str) -> bool:
    """Verify a session token is valid."""
    return _session_store.validate_session(token)


def create_new_session() -> str:
    """Create a new session token."""
    return _session_store.create_session()


class SessionAuth:
    """FastAPI dependency for session authentication."""

    def __init__(self, optional: bool = False):
        self.optional = optional

    async def __call__(
        self,
        x_session_token: Optional[str] = Header(None, alias="X-Session-Token"),
    ) -> Optional[str]:
        """
        Validate session token from header.

        Header: X-Session-Token: <token>
        """
        auth_token = x_session_token

        if not auth_token:
            if self.optional:
                return None
            raise HTTPException(
                status_code=401,
                detail="Missing authentication token. Use X-Session-Token header.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not verify_session(auth_token):
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired session token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return auth_token


# Dependency instances
require_auth = SessionAuth(optional=False)
optional_auth = SessionAuth(optional=True)

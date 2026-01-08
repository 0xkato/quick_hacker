# Authentication & LLM API Refactor Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace token-file authentication with proper username/password login using PostgreSQL and JWT, enable multi-user support with per-user LLM API keys, and fix LLM API call issues.

**Architecture:** Multi-user system with PostgreSQL for user data, JWT tokens for stateless auth, per-user encrypted API key storage. Fix provider error handling and add proper validation.

**Tech Stack:** PostgreSQL, SQLAlchemy (async), python-jose (JWT), passlib (bcrypt), React hooks for auth state

---

## Phase 1: Database Setup

### Task 1: Add PostgreSQL Dependencies

**Files:**
- Modify: `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend/requirements.txt`
- Modify: `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/docker-compose.yml`

**Step 1: Add Python dependencies**

Add to `requirements.txt`:
```
sqlalchemy[asyncio]>=2.0.25
asyncpg>=0.29.0
python-jose[cryptography]>=3.3.0
passlib[bcrypt]>=1.7.4
python-multipart>=0.0.6
```

**Step 2: Add PostgreSQL to docker-compose.yml**

Add this service after the `redis` service:
```yaml
  postgres:
    image: postgres:16-alpine
    container_name: quick_hack_postgres
    restart: unless-stopped
    ports:
      - "127.0.0.1:5432:5432"
    environment:
      POSTGRES_USER: quickhack
      POSTGRES_PASSWORD: quickhack_dev
      POSTGRES_DB: quickhack
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U quickhack"]
      interval: 5s
      timeout: 5s
      retries: 5
```

Add `postgres_data:` to the `volumes:` section at the bottom.

Add to backend service `depends_on`:
```yaml
    depends_on:
      - redis
      - postgres
```

Add to backend `environment`:
```yaml
      - DATABASE_URL=postgresql+asyncpg://quickhack:quickhack_dev@postgres:5432/quickhack
```

**Step 3: Run docker-compose to verify**

Run: `docker-compose up -d postgres`
Expected: PostgreSQL container starts successfully

**Step 4: Commit**

```bash
git add requirements.txt docker-compose.yml
git commit -m "chore: add PostgreSQL and auth dependencies"
```

---

### Task 2: Create Database Models

**Files:**
- Create: `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend/database/__init__.py`
- Create: `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend/database/connection.py`
- Create: `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend/database/models.py`

**Step 1: Create database package init**

Create `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend/database/__init__.py`:
```python
from .connection import get_db, engine, AsyncSessionLocal
from .models import Base, User, UserAPIKey

__all__ = ["get_db", "engine", "AsyncSessionLocal", "Base", "User", "UserAPIKey"]
```

**Step 2: Create database connection module**

Create `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend/database/connection.py`:
```python
"""Database connection and session management."""
import os
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import declarative_base

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://quickhack:quickhack_dev@localhost:5432/quickhack"
)

engine = create_async_engine(
    DATABASE_URL,
    echo=os.environ.get("DEBUG", "false").lower() == "true",
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

Base = declarative_base()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency that provides a database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """Initialize database tables."""
    from .models import Base
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
```

**Step 3: Create database models**

Create `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend/database/models.py`:
```python
"""Database models for user authentication and API keys."""
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import String, DateTime, Boolean, ForeignKey, Text, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from .connection import Base


class User(Base):
    """User account model."""
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )
    username: Mapped[str] = mapped_column(
        String(50),
        unique=True,
        nullable=False,
        index=True
    )
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True
    )
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False
    )

    # Relationships
    api_keys: Mapped[list["UserAPIKey"]] = relationship(
        "UserAPIKey",
        back_populates="user",
        cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<User(id={self.id}, username={self.username})>"


class UserAPIKey(Base):
    """User's LLM provider API keys."""
    __tablename__ = "user_api_keys"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False
    )
    provider: Mapped[str] = mapped_column(
        String(50),
        nullable=False
    )  # anthropic, openai, ollama
    api_key_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    is_valid: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    last_validated_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False
    )

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="api_keys")

    # Composite unique constraint
    __table_args__ = (
        Index("ix_user_provider", "user_id", "provider", unique=True),
    )

    def __repr__(self) -> str:
        return f"<UserAPIKey(id={self.id}, provider={self.provider})>"
```

**Step 4: Run to verify models compile**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -c "from database.models import User, UserAPIKey; print('Models OK')"`
Expected: "Models OK" printed

**Step 5: Commit**

```bash
git add backend/database/
git commit -m "feat: add PostgreSQL database models for users and API keys"
```

---

## Phase 2: Authentication Service

### Task 3: Create JWT Authentication Service

**Files:**
- Create: `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend/services/auth_service.py`
- Modify: `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend/config.py`

**Step 1: Add auth config to config.py**

Add these to the `Settings` class in `config.py`:
```python
    # JWT Auth
    jwt_secret_key: str = Field(
        default="CHANGE_ME_IN_PRODUCTION_USE_RANDOM_64_CHAR_STRING",
        description="Secret key for JWT encoding"
    )
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 60 * 24  # 24 hours
    jwt_refresh_token_expire_days: int = 30
```

**Step 2: Create auth service**

Create `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend/services/auth_service.py`:
```python
"""Authentication service for JWT-based user authentication."""
import hashlib
import os
from datetime import datetime, timedelta
from typing import Optional
import uuid

from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database.models import User, UserAPIKey

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class AuthService:
    """Service for user authentication and JWT management."""

    def __init__(self):
        self.secret_key = settings.jwt_secret_key
        self.algorithm = settings.jwt_algorithm
        self.access_token_expire = timedelta(minutes=settings.jwt_access_token_expire_minutes)
        self.refresh_token_expire = timedelta(days=settings.jwt_refresh_token_expire_days)
        self._encryption_key = hashlib.sha256(
            settings.jwt_secret_key.encode()
        ).digest()

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash."""
        return pwd_context.verify(plain_password, hashed_password)

    def hash_password(self, password: str) -> str:
        """Hash a password."""
        return pwd_context.hash(password)

    def create_access_token(
        self,
        user_id: uuid.UUID,
        username: str,
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """Create a JWT access token."""
        expire = datetime.utcnow() + (expires_delta or self.access_token_expire)
        to_encode = {
            "sub": str(user_id),
            "username": username,
            "exp": expire,
            "type": "access"
        }
        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)

    def create_refresh_token(self, user_id: uuid.UUID) -> str:
        """Create a JWT refresh token."""
        expire = datetime.utcnow() + self.refresh_token_expire
        to_encode = {
            "sub": str(user_id),
            "exp": expire,
            "type": "refresh"
        }
        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)

    def decode_token(self, token: str) -> Optional[dict]:
        """Decode and validate a JWT token."""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except JWTError:
            return None

    def encrypt_api_key(self, api_key: str) -> str:
        """Encrypt an API key for storage."""
        if not api_key:
            return ""
        encrypted = bytes([
            b ^ self._encryption_key[i % len(self._encryption_key)]
            for i, b in enumerate(api_key.encode())
        ])
        return encrypted.hex()

    def decrypt_api_key(self, encrypted_key: str) -> str:
        """Decrypt a stored API key."""
        if not encrypted_key:
            return ""
        try:
            decrypted = bytes([
                b ^ self._encryption_key[i % len(self._encryption_key)]
                for i, b in enumerate(bytes.fromhex(encrypted_key))
            ])
            return decrypted.decode()
        except (ValueError, UnicodeDecodeError) as e:
            raise ValueError(f"Failed to decrypt API key: {e}")

    async def create_user(
        self,
        db: AsyncSession,
        username: str,
        email: str,
        password: str
    ) -> User:
        """Create a new user."""
        # Check if username or email already exists
        stmt = select(User).where(
            (User.username == username) | (User.email == email)
        )
        result = await db.execute(stmt)
        existing = result.scalar_one_or_none()
        if existing:
            if existing.username == username:
                raise ValueError("Username already taken")
            raise ValueError("Email already registered")

        user = User(
            username=username,
            email=email,
            password_hash=self.hash_password(password)
        )
        db.add(user)
        await db.flush()
        await db.refresh(user)
        return user

    async def authenticate_user(
        self,
        db: AsyncSession,
        username: str,
        password: str
    ) -> Optional[User]:
        """Authenticate a user by username/email and password."""
        stmt = select(User).where(
            (User.username == username) | (User.email == username)
        )
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()

        if not user or not self.verify_password(password, user.password_hash):
            return None
        if not user.is_active:
            return None
        return user

    async def get_user_by_id(
        self,
        db: AsyncSession,
        user_id: uuid.UUID
    ) -> Optional[User]:
        """Get a user by ID."""
        stmt = select(User).where(User.id == user_id)
        result = await db.execute(stmt)
        return result.scalar_one_or_none()

    async def set_user_api_key(
        self,
        db: AsyncSession,
        user_id: uuid.UUID,
        provider: str,
        api_key: str
    ) -> UserAPIKey:
        """Set or update a user's API key for a provider."""
        # Check if key already exists
        stmt = select(UserAPIKey).where(
            UserAPIKey.user_id == user_id,
            UserAPIKey.provider == provider
        )
        result = await db.execute(stmt)
        existing = result.scalar_one_or_none()

        encrypted = self.encrypt_api_key(api_key)

        if existing:
            existing.api_key_encrypted = encrypted
            existing.is_valid = None  # Reset validation status
            existing.last_validated_at = None
            await db.flush()
            return existing

        api_key_record = UserAPIKey(
            user_id=user_id,
            provider=provider,
            api_key_encrypted=encrypted
        )
        db.add(api_key_record)
        await db.flush()
        await db.refresh(api_key_record)
        return api_key_record

    async def get_user_api_key(
        self,
        db: AsyncSession,
        user_id: uuid.UUID,
        provider: str
    ) -> Optional[str]:
        """Get a user's decrypted API key for a provider."""
        stmt = select(UserAPIKey).where(
            UserAPIKey.user_id == user_id,
            UserAPIKey.provider == provider
        )
        result = await db.execute(stmt)
        record = result.scalar_one_or_none()

        if not record:
            return None
        return self.decrypt_api_key(record.api_key_encrypted)

    async def get_all_user_api_keys(
        self,
        db: AsyncSession,
        user_id: uuid.UUID
    ) -> dict[str, bool]:
        """Get status of all user's API keys (provider -> has_key)."""
        stmt = select(UserAPIKey).where(UserAPIKey.user_id == user_id)
        result = await db.execute(stmt)
        records = result.scalars().all()
        return {r.provider: bool(r.api_key_encrypted) for r in records}

    async def delete_user_api_key(
        self,
        db: AsyncSession,
        user_id: uuid.UUID,
        provider: str
    ) -> bool:
        """Delete a user's API key for a provider."""
        stmt = select(UserAPIKey).where(
            UserAPIKey.user_id == user_id,
            UserAPIKey.provider == provider
        )
        result = await db.execute(stmt)
        record = result.scalar_one_or_none()

        if record:
            await db.delete(record)
            return True
        return False


# Global instance
auth_service = AuthService()
```

**Step 3: Run to verify service compiles**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -c "from services.auth_service import auth_service; print('Auth service OK')"`
Expected: "Auth service OK" printed

**Step 4: Commit**

```bash
git add backend/services/auth_service.py backend/config.py
git commit -m "feat: add JWT authentication service with password hashing"
```

---

### Task 4: Create Auth API Router

**Files:**
- Create: `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend/routers/auth.py`
- Modify: `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend/main.py`

**Step 1: Create auth router**

Create `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend/routers/auth.py`:
```python
"""Authentication API routes."""
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from database.models import User
from services.auth_service import auth_service

router = APIRouter(prefix="/api/auth", tags=["auth"])
security = HTTPBearer(auto_error=False)


# Request/Response Models
class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=100)


class LoginRequest(BaseModel):
    username: str  # Can be username or email
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    is_active: bool
    is_admin: bool

    class Config:
        from_attributes = True


class APIKeyRequest(BaseModel):
    provider: str = Field(..., pattern="^(anthropic|openai|ollama)$")
    api_key: str = Field(..., min_length=1)


class APIKeyStatusResponse(BaseModel):
    provider: str
    has_key: bool


# Dependency to get current user
async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> User:
    """Get the current authenticated user from JWT token."""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = auth_service.decode_token(credentials.credentials)
    if not payload or payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = uuid.UUID(payload["sub"])
    user = await auth_service.get_user_by_id(db, user_id)
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )
    return user


# Optional auth - returns None if not authenticated
async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> Optional[User]:
    """Get current user if authenticated, None otherwise."""
    if not credentials:
        return None
    try:
        return await get_current_user(credentials, db)
    except HTTPException:
        return None


# Routes
@router.post("/register", response_model=TokenResponse)
async def register(
    request: RegisterRequest,
    db: AsyncSession = Depends(get_db)
):
    """Register a new user account."""
    try:
        user = await auth_service.create_user(
            db,
            username=request.username,
            email=request.email,
            password=request.password
        )
        await db.commit()
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

    return TokenResponse(
        access_token=auth_service.create_access_token(user.id, user.username),
        refresh_token=auth_service.create_refresh_token(user.id)
    )


@router.post("/login", response_model=TokenResponse)
async def login(
    request: LoginRequest,
    db: AsyncSession = Depends(get_db)
):
    """Login with username/email and password."""
    user = await auth_service.authenticate_user(
        db,
        username=request.username,
        password=request.password
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )

    return TokenResponse(
        access_token=auth_service.create_access_token(user.id, user.username),
        refresh_token=auth_service.create_refresh_token(user.id)
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    request: RefreshRequest,
    db: AsyncSession = Depends(get_db)
):
    """Refresh access token using refresh token."""
    payload = auth_service.decode_token(request.refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )

    user_id = uuid.UUID(payload["sub"])
    user = await auth_service.get_user_by_id(db, user_id)
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )

    return TokenResponse(
        access_token=auth_service.create_access_token(user.id, user.username),
        refresh_token=auth_service.create_refresh_token(user.id)
    )


@router.get("/me", response_model=UserResponse)
async def get_me(user: User = Depends(get_current_user)):
    """Get current user profile."""
    return UserResponse(
        id=str(user.id),
        username=user.username,
        email=user.email,
        is_active=user.is_active,
        is_admin=user.is_admin
    )


@router.put("/api-keys")
async def set_api_key(
    request: APIKeyRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Set or update an API key for a provider."""
    await auth_service.set_user_api_key(
        db,
        user_id=user.id,
        provider=request.provider,
        api_key=request.api_key
    )
    await db.commit()
    return {"status": "ok", "provider": request.provider}


@router.get("/api-keys", response_model=list[APIKeyStatusResponse])
async def get_api_keys(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get status of all API keys for current user."""
    keys = await auth_service.get_all_user_api_keys(db, user.id)
    # Include all providers with their status
    providers = ["anthropic", "openai", "ollama"]
    return [
        APIKeyStatusResponse(provider=p, has_key=keys.get(p, False))
        for p in providers
    ]


@router.delete("/api-keys/{provider}")
async def delete_api_key(
    provider: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Delete an API key for a provider."""
    if provider not in ["anthropic", "openai", "ollama"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid provider"
        )

    deleted = await auth_service.delete_user_api_key(db, user.id, provider)
    await db.commit()
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found"
        )
    return {"status": "ok"}
```

**Step 2: Register auth router in main.py**

Add import at top of `main.py`:
```python
from routers import auth
```

Add after existing router includes:
```python
app.include_router(auth.router)
```

Add database initialization in startup event (add/modify the startup event):
```python
from database import init_db

@app.on_event("startup")
async def startup_event():
    await init_db()
```

**Step 3: Run to verify router compiles**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -c "from routers.auth import router; print('Auth router OK')"`
Expected: "Auth router OK" printed

**Step 4: Commit**

```bash
git add backend/routers/auth.py backend/main.py
git commit -m "feat: add auth API router with register, login, and API key management"
```

---

## Phase 3: Update Existing Endpoints to Use New Auth

### Task 5: Create Auth Middleware Helper

**Files:**
- Modify: `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend/middleware/auth.py`

**Step 1: Add JWT auth support to existing middleware**

Replace the entire contents of `middleware/auth.py` with:
```python
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
```

**Step 2: Run to verify middleware compiles**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -c "from middleware.auth import get_auth_context, require_auth; print('Middleware OK')"`
Expected: "Middleware OK" printed

**Step 3: Commit**

```bash
git add backend/middleware/auth.py
git commit -m "feat: update auth middleware to support both JWT and legacy tokens"
```

---

### Task 6: Update Agent Orchestrator to Use User API Keys

**Files:**
- Modify: `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend/services/agent_orchestrator.py`

**Step 1: Update orchestrator to accept user context**

Find the `create_agent` method and update its signature to include auth context.

Add imports at top:
```python
from middleware.auth import AuthContext, get_user_api_key_for_provider
from sqlalchemy.ext.asyncio import AsyncSession
```

Find the section where API key is resolved (around line 98-117) and replace with:
```python
async def create_agent(
    self,
    request: AgentCreateRequest,
    auth_context: AuthContext,
    db: AsyncSession
) -> Agent:
    """Create a new agent instance."""
    # Resolve API key from user's stored keys
    provider_config = request.provider_config
    if provider_config and not provider_config.api_key:
        provider_name = (
            provider_config.provider.value
            if hasattr(provider_config.provider, 'value')
            else str(provider_config.provider)
        )

        # Get API key from user's stored keys
        api_key = await get_user_api_key_for_provider(
            provider_name,
            auth_context,
            db
        )

        if not api_key and provider_name != "ollama":
            raise ValueError(
                f"No {provider_name.capitalize()} API key found. "
                f"Please add your API key in Settings."
            )

        if api_key:
            request.provider_config = ProviderConfig(
                provider=provider_config.provider,
                model=provider_config.model,
                api_key=api_key,
                base_url=provider_config.base_url
            )

    # ... rest of create_agent method
```

**Step 2: Run to verify orchestrator compiles**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -c "from services.agent_orchestrator import AgentOrchestrator; print('Orchestrator OK')"`
Expected: "Orchestrator OK" printed

**Step 3: Commit**

```bash
git add backend/services/agent_orchestrator.py
git commit -m "feat: update agent orchestrator to use per-user API keys"
```

---

### Task 7: Update Agents Router

**Files:**
- Modify: `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend/routers/agents.py`

**Step 1: Update imports**

Add at top:
```python
from middleware.auth import AuthContext, require_auth, get_auth_context
from database import get_db
```

**Step 2: Update create_agent endpoint**

Find the POST `/` endpoint and update to include auth:
```python
@router.post("/")
async def create_agent(
    request: AgentCreateRequest,
    auth_context: AuthContext = Depends(require_auth),
    db: AsyncSession = Depends(get_db)
):
    """Create a new agent."""
    try:
        agent = await orchestrator.create_agent(request, auth_context, db)
        return AgentResponse.from_agent(agent)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
```

**Step 3: Run to verify agents router compiles**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -c "from routers.agents import router; print('Agents router OK')"`
Expected: "Agents router OK" printed

**Step 4: Commit**

```bash
git add backend/routers/agents.py
git commit -m "feat: update agents router to use new auth system"
```

---

## Phase 4: Fix LLM Provider Error Handling

### Task 8: Add Proper Error Handling to Anthropic Provider

**Files:**
- Modify: `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend/providers/anthropic_provider.py`

**Step 1: Add imports for error handling**

Add at top after existing imports:
```python
import logging
from anthropic import APIError, AuthenticationError, RateLimitError, APIConnectionError

logger = logging.getLogger(__name__)
```

**Step 2: Wrap generate method with error handling**

Find the `generate` method and wrap the API call:
```python
async def generate(
    self,
    messages: list[dict],
    system_prompt: Optional[str] = None
) -> str:
    """Generate a response from the model."""
    kwargs = self._build_request_kwargs(messages, system_prompt)

    try:
        response = await self.client.messages.create(**kwargs)
        return response.content[0].text
    except AuthenticationError as e:
        logger.error(f"Anthropic authentication failed: {e}")
        raise ValueError(
            "Invalid Anthropic API key. Please check your API key in Settings."
        ) from e
    except RateLimitError as e:
        logger.warning(f"Anthropic rate limit hit: {e}")
        raise ValueError(
            "Rate limit exceeded. Please wait a moment and try again."
        ) from e
    except APIConnectionError as e:
        logger.error(f"Anthropic connection error: {e}")
        raise ValueError(
            "Failed to connect to Anthropic API. Please check your internet connection."
        ) from e
    except APIError as e:
        logger.error(f"Anthropic API error: {e}")
        raise ValueError(f"Anthropic API error: {e.message}") from e
```

**Step 3: Apply same error handling to generate_with_thinking and generate_stream**

Wrap all `self.client.messages.create` calls with the same try-except pattern.

**Step 4: Run to verify provider compiles**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -c "from providers.anthropic_provider import AnthropicProvider; print('Anthropic provider OK')"`
Expected: "Anthropic provider OK" printed

**Step 5: Commit**

```bash
git add backend/providers/anthropic_provider.py
git commit -m "fix: add proper error handling to Anthropic provider"
```

---

### Task 9: Add Proper Error Handling to OpenAI Provider

**Files:**
- Modify: `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend/providers/openai_provider.py`

**Step 1: Add imports for error handling**

Add at top:
```python
import logging
from openai import APIError, AuthenticationError, RateLimitError, APIConnectionError

logger = logging.getLogger(__name__)
```

**Step 2: Wrap generate method with error handling**

Same pattern as Anthropic:
```python
async def generate(
    self,
    messages: list[dict],
    system_prompt: Optional[str] = None
) -> str:
    """Generate a response from the model."""
    formatted_messages = self._format_messages(messages, system_prompt)

    try:
        response = await self.client.chat.completions.create(
            model=self.model,
            messages=formatted_messages,
            max_tokens=self.max_tokens,
            temperature=self.temperature
        )
        return response.choices[0].message.content
    except AuthenticationError as e:
        logger.error(f"OpenAI authentication failed: {e}")
        raise ValueError(
            "Invalid OpenAI API key. Please check your API key in Settings."
        ) from e
    except RateLimitError as e:
        logger.warning(f"OpenAI rate limit hit: {e}")
        raise ValueError(
            "Rate limit exceeded. Please wait a moment and try again."
        ) from e
    except APIConnectionError as e:
        logger.error(f"OpenAI connection error: {e}")
        raise ValueError(
            "Failed to connect to OpenAI API. Please check your internet connection."
        ) from e
    except APIError as e:
        logger.error(f"OpenAI API error: {e}")
        raise ValueError(f"OpenAI API error: {e.message}") from e
```

**Step 3: Apply same pattern to generate_stream and chat_with_tools**

**Step 4: Run to verify provider compiles**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -c "from providers.openai_provider import OpenAIProvider; print('OpenAI provider OK')"`
Expected: "OpenAI provider OK" printed

**Step 5: Commit**

```bash
git add backend/providers/openai_provider.py
git commit -m "fix: add proper error handling to OpenAI provider"
```

---

### Task 10: Add API Key Validation Endpoint

**Files:**
- Modify: `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend/routers/auth.py`

**Step 1: Add validation endpoint**

Add this endpoint to `auth.py`:
```python
@router.post("/api-keys/validate")
async def validate_api_key(
    request: APIKeyRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Validate an API key by making a minimal API call."""
    from providers import get_provider
    from providers.base_provider import ProviderConfig

    config = ProviderConfig(
        provider=request.provider,
        model=None,  # Will use default
        api_key=request.api_key
    )

    try:
        provider = get_provider(config)
        # Make minimal API call to validate
        await provider.count_tokens("test")
        return {"valid": True, "provider": request.provider}
    except ValueError as e:
        return {"valid": False, "provider": request.provider, "error": str(e)}
    except Exception as e:
        return {"valid": False, "provider": request.provider, "error": f"Validation failed: {e}"}
```

**Step 2: Run to verify**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -c "from routers.auth import router; print('Validation endpoint OK')"`
Expected: "Validation endpoint OK" printed

**Step 3: Commit**

```bash
git add backend/routers/auth.py
git commit -m "feat: add API key validation endpoint"
```

---

## Phase 5: Frontend Authentication

### Task 11: Create Auth Context and Hooks

**Files:**
- Create: `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/frontend/contexts/AuthContext.tsx`
- Create: `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/frontend/hooks/useAuth.ts`

**Step 1: Create contexts directory**

Run: `mkdir -p /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/frontend/contexts`

**Step 2: Create AuthContext**

Create `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/frontend/contexts/AuthContext.tsx`:
```tsx
'use client';

import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';

interface User {
  id: string;
  username: string;
  email: string;
  is_active: boolean;
  is_admin: boolean;
}

interface AuthContextType {
  user: User | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (username: string, password: string) => Promise<void>;
  register: (username: string, email: string, password: string) => Promise<void>;
  logout: () => void;
  refreshToken: () => Promise<boolean>;
  getAccessToken: () => string | null;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
const ACCESS_TOKEN_KEY = 'quick_hack_access_token';
const REFRESH_TOKEN_KEY = 'quick_hack_refresh_token';

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const getAccessToken = useCallback(() => {
    if (typeof window === 'undefined') return null;
    return localStorage.getItem(ACCESS_TOKEN_KEY);
  }, []);

  const setTokens = useCallback((access: string, refresh: string) => {
    localStorage.setItem(ACCESS_TOKEN_KEY, access);
    localStorage.setItem(REFRESH_TOKEN_KEY, refresh);
  }, []);

  const clearTokens = useCallback(() => {
    localStorage.removeItem(ACCESS_TOKEN_KEY);
    localStorage.removeItem(REFRESH_TOKEN_KEY);
  }, []);

  const fetchUser = useCallback(async (token: string): Promise<User | null> => {
    try {
      const response = await fetch(`${API_BASE}/api/auth/me`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (response.ok) {
        return await response.json();
      }
    } catch (error) {
      console.error('Failed to fetch user:', error);
    }
    return null;
  }, []);

  const refreshToken = useCallback(async (): Promise<boolean> => {
    const refresh = localStorage.getItem(REFRESH_TOKEN_KEY);
    if (!refresh) return false;

    try {
      const response = await fetch(`${API_BASE}/api/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: refresh })
      });

      if (response.ok) {
        const data = await response.json();
        setTokens(data.access_token, data.refresh_token);
        const user = await fetchUser(data.access_token);
        setUser(user);
        return true;
      }
    } catch (error) {
      console.error('Failed to refresh token:', error);
    }

    clearTokens();
    setUser(null);
    return false;
  }, [setTokens, clearTokens, fetchUser]);

  const login = useCallback(async (username: string, password: string) => {
    const response = await fetch(`${API_BASE}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Login failed');
    }

    const data = await response.json();
    setTokens(data.access_token, data.refresh_token);
    const user = await fetchUser(data.access_token);
    setUser(user);
  }, [setTokens, fetchUser]);

  const register = useCallback(async (username: string, email: string, password: string) => {
    const response = await fetch(`${API_BASE}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, email, password })
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Registration failed');
    }

    const data = await response.json();
    setTokens(data.access_token, data.refresh_token);
    const user = await fetchUser(data.access_token);
    setUser(user);
  }, [setTokens, fetchUser]);

  const logout = useCallback(() => {
    clearTokens();
    setUser(null);
  }, [clearTokens]);

  // Initialize auth state on mount
  useEffect(() => {
    const initAuth = async () => {
      const token = getAccessToken();
      if (token) {
        const user = await fetchUser(token);
        if (user) {
          setUser(user);
        } else {
          // Token might be expired, try refresh
          await refreshToken();
        }
      }
      setIsLoading(false);
    };

    initAuth();
  }, [getAccessToken, fetchUser, refreshToken]);

  return (
    <AuthContext.Provider
      value={{
        user,
        isLoading,
        isAuthenticated: !!user,
        login,
        register,
        logout,
        refreshToken,
        getAccessToken
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
```

**Step 3: Create useAuth hook file**

Create `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/frontend/hooks/useAuth.ts`:
```typescript
export { useAuth } from '../contexts/AuthContext';
```

**Step 4: Commit**

```bash
git add frontend/contexts/ frontend/hooks/useAuth.ts
git commit -m "feat: add React auth context and hooks for JWT authentication"
```

---

### Task 12: Create Login/Register Components

**Files:**
- Create: `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/frontend/components/Auth/LoginForm.tsx`
- Create: `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/frontend/components/Auth/RegisterForm.tsx`
- Create: `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/frontend/components/Auth/AuthModal.tsx`
- Create: `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/frontend/components/Auth/index.ts`

**Step 1: Create Auth components directory**

Run: `mkdir -p /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/frontend/components/Auth`

**Step 2: Create LoginForm**

Create `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/frontend/components/Auth/LoginForm.tsx`:
```tsx
'use client';

import React, { useState } from 'react';
import { useAuth } from '../../hooks/useAuth';

interface LoginFormProps {
  onSwitchToRegister: () => void;
  onSuccess?: () => void;
}

export function LoginForm({ onSwitchToRegister, onSuccess }: LoginFormProps) {
  const { login } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    try {
      await login(username, password);
      onSuccess?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <h2 className="text-xl font-bold text-white mb-4">Login</h2>

      {error && (
        <div className="bg-red-500/10 border border-red-500 text-red-500 px-4 py-2 rounded">
          {error}
        </div>
      )}

      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">
          Username or Email
        </label>
        <input
          type="text"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white focus:outline-none focus:border-blue-500"
          required
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">
          Password
        </label>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white focus:outline-none focus:border-blue-500"
          required
        />
      </div>

      <button
        type="submit"
        disabled={isLoading}
        className="w-full py-2 px-4 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 text-white rounded font-medium transition-colors"
      >
        {isLoading ? 'Logging in...' : 'Login'}
      </button>

      <p className="text-center text-gray-400 text-sm">
        Don't have an account?{' '}
        <button
          type="button"
          onClick={onSwitchToRegister}
          className="text-blue-400 hover:text-blue-300"
        >
          Register
        </button>
      </p>
    </form>
  );
}
```

**Step 3: Create RegisterForm**

Create `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/frontend/components/Auth/RegisterForm.tsx`:
```tsx
'use client';

import React, { useState } from 'react';
import { useAuth } from '../../hooks/useAuth';

interface RegisterFormProps {
  onSwitchToLogin: () => void;
  onSuccess?: () => void;
}

export function RegisterForm({ onSwitchToLogin, onSuccess }: RegisterFormProps) {
  const { register } = useAuth();
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    if (password.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }

    setIsLoading(true);

    try {
      await register(username, email, password);
      onSuccess?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Registration failed');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <h2 className="text-xl font-bold text-white mb-4">Create Account</h2>

      {error && (
        <div className="bg-red-500/10 border border-red-500 text-red-500 px-4 py-2 rounded">
          {error}
        </div>
      )}

      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">
          Username
        </label>
        <input
          type="text"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white focus:outline-none focus:border-blue-500"
          required
          minLength={3}
          maxLength={50}
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">
          Email
        </label>
        <input
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white focus:outline-none focus:border-blue-500"
          required
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">
          Password
        </label>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white focus:outline-none focus:border-blue-500"
          required
          minLength={8}
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">
          Confirm Password
        </label>
        <input
          type="password"
          value={confirmPassword}
          onChange={(e) => setConfirmPassword(e.target.value)}
          className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white focus:outline-none focus:border-blue-500"
          required
        />
      </div>

      <button
        type="submit"
        disabled={isLoading}
        className="w-full py-2 px-4 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 text-white rounded font-medium transition-colors"
      >
        {isLoading ? 'Creating account...' : 'Register'}
      </button>

      <p className="text-center text-gray-400 text-sm">
        Already have an account?{' '}
        <button
          type="button"
          onClick={onSwitchToLogin}
          className="text-blue-400 hover:text-blue-300"
        >
          Login
        </button>
      </p>
    </form>
  );
}
```

**Step 4: Create AuthModal**

Create `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/frontend/components/Auth/AuthModal.tsx`:
```tsx
'use client';

import React, { useState } from 'react';
import { X } from 'lucide-react';
import { LoginForm } from './LoginForm';
import { RegisterForm } from './RegisterForm';

interface AuthModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export function AuthModal({ isOpen, onClose }: AuthModalProps) {
  const [mode, setMode] = useState<'login' | 'register'>('login');

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg p-6 w-full max-w-md relative">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-gray-400 hover:text-white"
        >
          <X size={20} />
        </button>

        {mode === 'login' ? (
          <LoginForm
            onSwitchToRegister={() => setMode('register')}
            onSuccess={onClose}
          />
        ) : (
          <RegisterForm
            onSwitchToLogin={() => setMode('login')}
            onSuccess={onClose}
          />
        )}
      </div>
    </div>
  );
}
```

**Step 5: Create index export**

Create `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/frontend/components/Auth/index.ts`:
```typescript
export { LoginForm } from './LoginForm';
export { RegisterForm } from './RegisterForm';
export { AuthModal } from './AuthModal';
```

**Step 6: Commit**

```bash
git add frontend/components/Auth/
git commit -m "feat: add Login, Register, and AuthModal components"
```

---

### Task 13: Update Frontend API Client

**Files:**
- Modify: `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/frontend/lib/api.ts`

**Step 1: Update api.ts to use JWT tokens**

Replace the token handling section with:
```typescript
// Token management
let getAccessToken: (() => string | null) | null = null;
let refreshTokenFn: (() => Promise<boolean>) | null = null;

export function setAuthFunctions(
  getToken: () => string | null,
  refresh: () => Promise<boolean>
) {
  getAccessToken = getToken;
  refreshTokenFn = refresh;
}

async function fetchWithAuth(
  url: string,
  options: RequestInit = {}
): Promise<Response> {
  const token = getAccessToken?.();
  const headers: HeadersInit = {
    ...options.headers,
  };

  if (token) {
    (headers as Record<string, string>)['Authorization'] = `Bearer ${token}`;
  }

  let response = await fetch(url, { ...options, headers });

  // If unauthorized, try to refresh token and retry
  if (response.status === 401 && refreshTokenFn) {
    const refreshed = await refreshTokenFn();
    if (refreshed) {
      const newToken = getAccessToken?.();
      if (newToken) {
        (headers as Record<string, string>)['Authorization'] = `Bearer ${newToken}`;
        response = await fetch(url, { ...options, headers });
      }
    }
  }

  return response;
}
```

Then update all `fetch` calls in the file to use `fetchWithAuth` instead.

**Step 2: Commit**

```bash
git add frontend/lib/api.ts
git commit -m "feat: update API client to use JWT authentication with refresh"
```

---

### Task 14: Update App Layout with AuthProvider

**Files:**
- Modify: `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/frontend/app/layout.tsx`

**Step 1: Wrap app with AuthProvider**

Add import:
```tsx
import { AuthProvider } from '../contexts/AuthContext';
```

Wrap children with AuthProvider:
```tsx
export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <AuthProvider>
          {children}
        </AuthProvider>
      </body>
    </html>
  );
}
```

**Step 2: Commit**

```bash
git add frontend/app/layout.tsx
git commit -m "feat: add AuthProvider to app layout"
```

---

### Task 15: Add Auth UI to Main Page

**Files:**
- Modify: `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/frontend/app/page.tsx`

**Step 1: Add auth imports and state**

Add imports:
```tsx
import { useAuth } from '../hooks/useAuth';
import { AuthModal } from '../components/Auth';
import { setAuthFunctions } from '../lib/api';
```

**Step 2: Add auth UI to header**

In the main component, add:
```tsx
const { user, isAuthenticated, isLoading, logout, getAccessToken, refreshToken } = useAuth();
const [showAuthModal, setShowAuthModal] = useState(false);

// Set up API auth functions
useEffect(() => {
  setAuthFunctions(getAccessToken, refreshToken);
}, [getAccessToken, refreshToken]);
```

Add to the header section:
```tsx
{isAuthenticated ? (
  <div className="flex items-center gap-4">
    <span className="text-gray-400">
      {user?.username}
    </span>
    <button
      onClick={logout}
      className="px-3 py-1 text-sm bg-gray-700 hover:bg-gray-600 rounded"
    >
      Logout
    </button>
  </div>
) : (
  <button
    onClick={() => setShowAuthModal(true)}
    className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded font-medium"
  >
    Login
  </button>
)}

<AuthModal
  isOpen={showAuthModal}
  onClose={() => setShowAuthModal(false)}
/>
```

**Step 3: Commit**

```bash
git add frontend/app/page.tsx
git commit -m "feat: add authentication UI to main page"
```

---

## Phase 6: Update Settings for API Keys

### Task 16: Update Settings Modal for Per-User API Keys

**Files:**
- Modify: `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/frontend/components/SettingsModal/SettingsModal.tsx` (or similar)

**Step 1: Update to use new auth endpoints**

Update the API key saving logic to use `/api/auth/api-keys` instead of the old settings endpoint:
```typescript
const saveApiKey = async (provider: string, apiKey: string) => {
  const response = await fetchWithAuth(`${API_BASE}/api/auth/api-keys`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ provider, api_key: apiKey })
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Failed to save API key');
  }
};
```

Add validation before saving:
```typescript
const validateApiKey = async (provider: string, apiKey: string): Promise<boolean> => {
  const response = await fetchWithAuth(`${API_BASE}/api/auth/api-keys/validate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ provider, api_key: apiKey })
  });

  if (response.ok) {
    const result = await response.json();
    return result.valid;
  }
  return false;
};
```

**Step 2: Commit**

```bash
git add frontend/components/SettingsModal/
git commit -m "feat: update settings modal to use per-user API key storage"
```

---

## Phase 7: Environment and Documentation

### Task 17: Update Environment Configuration

**Files:**
- Modify: `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/.env.example`

**Step 1: Update .env.example**

Add new variables:
```ini
# Database
DATABASE_URL=postgresql+asyncpg://quickhack:quickhack_dev@localhost:5432/quickhack

# JWT Authentication
JWT_SECRET_KEY=CHANGE_ME_IN_PRODUCTION_USE_RANDOM_64_CHAR_STRING

# Legacy auth (deprecated, will be removed in future version)
AUTH_BOOTSTRAP_ALLOW_REMOTE=false
```

**Step 2: Commit**

```bash
git add .env.example
git commit -m "docs: update .env.example with new auth configuration"
```

---

### Task 18: Update Documentation

**Files:**
- Modify: `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/README.md`

**Step 1: Add auth section to README**

Add a section explaining:
- How to register/login
- How to add API keys
- Migration from legacy token auth

**Step 2: Commit**

```bash
git add README.md
git commit -m "docs: update README with authentication instructions"
```

---

## Phase 8: Testing

### Task 19: Add Auth Service Tests

**Files:**
- Create: `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend/tests/test_auth_service.py`

**Step 1: Create test file**

```python
"""Tests for authentication service."""
import pytest
from unittest.mock import AsyncMock, MagicMock
import uuid

from services.auth_service import AuthService


@pytest.fixture
def auth_service():
    return AuthService()


class TestPasswordHashing:
    def test_hash_password(self, auth_service):
        password = "test_password_123"
        hashed = auth_service.hash_password(password)
        assert hashed != password
        assert auth_service.verify_password(password, hashed)

    def test_verify_wrong_password(self, auth_service):
        password = "correct_password"
        hashed = auth_service.hash_password(password)
        assert not auth_service.verify_password("wrong_password", hashed)


class TestJWTTokens:
    def test_create_access_token(self, auth_service):
        user_id = uuid.uuid4()
        token = auth_service.create_access_token(user_id, "testuser")
        assert token is not None
        payload = auth_service.decode_token(token)
        assert payload["sub"] == str(user_id)
        assert payload["username"] == "testuser"
        assert payload["type"] == "access"

    def test_create_refresh_token(self, auth_service):
        user_id = uuid.uuid4()
        token = auth_service.create_refresh_token(user_id)
        payload = auth_service.decode_token(token)
        assert payload["sub"] == str(user_id)
        assert payload["type"] == "refresh"

    def test_decode_invalid_token(self, auth_service):
        assert auth_service.decode_token("invalid_token") is None


class TestAPIKeyEncryption:
    def test_encrypt_decrypt_api_key(self, auth_service):
        api_key = "sk-test-1234567890abcdef"
        encrypted = auth_service.encrypt_api_key(api_key)
        assert encrypted != api_key
        decrypted = auth_service.decrypt_api_key(encrypted)
        assert decrypted == api_key

    def test_encrypt_empty_key(self, auth_service):
        assert auth_service.encrypt_api_key("") == ""
        assert auth_service.decrypt_api_key("") == ""
```

**Step 2: Run tests**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && pytest tests/test_auth_service.py -v`
Expected: All tests pass

**Step 3: Commit**

```bash
git add backend/tests/test_auth_service.py
git commit -m "test: add authentication service unit tests"
```

---

### Task 20: Add Provider Error Handling Tests

**Files:**
- Create: `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend/tests/providers/test_error_handling.py`

**Step 1: Create test file**

```python
"""Tests for provider error handling."""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from providers.anthropic_provider import AnthropicProvider
from providers.openai_provider import OpenAIProvider
from providers.base_provider import ProviderConfig


@pytest.fixture
def anthropic_config():
    return ProviderConfig(
        provider="anthropic",
        model="claude-3-haiku-20240307",
        api_key="test-key"
    )


@pytest.fixture
def openai_config():
    return ProviderConfig(
        provider="openai",
        model="gpt-4",
        api_key="test-key"
    )


class TestAnthropicErrorHandling:
    @pytest.mark.asyncio
    async def test_authentication_error(self, anthropic_config):
        from anthropic import AuthenticationError

        provider = AnthropicProvider(anthropic_config)
        provider.client = MagicMock()
        provider.client.messages.create = AsyncMock(
            side_effect=AuthenticationError("Invalid API key")
        )

        with pytest.raises(ValueError) as exc_info:
            await provider.generate([{"role": "user", "content": "test"}])

        assert "Invalid Anthropic API key" in str(exc_info.value)


class TestOpenAIErrorHandling:
    @pytest.mark.asyncio
    async def test_authentication_error(self, openai_config):
        from openai import AuthenticationError

        provider = OpenAIProvider(openai_config)
        provider.client = MagicMock()
        provider.client.chat.completions.create = AsyncMock(
            side_effect=AuthenticationError("Invalid API key")
        )

        with pytest.raises(ValueError) as exc_info:
            await provider.generate([{"role": "user", "content": "test"}])

        assert "Invalid OpenAI API key" in str(exc_info.value)
```

**Step 2: Run tests**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && pytest tests/providers/test_error_handling.py -v`
Expected: All tests pass

**Step 3: Commit**

```bash
git add backend/tests/providers/test_error_handling.py
git commit -m "test: add provider error handling tests"
```

---

### Task 21: Integration Test

**Files:**
- None (manual testing)

**Step 1: Start the services**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack && docker-compose up -d`
Expected: All services start (backend, frontend, postgres, redis)

**Step 2: Test registration**

Run:
```bash
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","email":"test@example.com","password":"testpass123"}'
```
Expected: Returns access_token and refresh_token

**Step 3: Test login**

Run:
```bash
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"testpass123"}'
```
Expected: Returns access_token and refresh_token

**Step 4: Test protected endpoint**

Run:
```bash
curl http://localhost:8000/api/auth/me \
  -H "Authorization: Bearer <access_token>"
```
Expected: Returns user info

**Step 5: Test API key storage**

Run:
```bash
curl -X PUT http://localhost:8000/api/auth/api-keys \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"provider":"anthropic","api_key":"sk-ant-test-key"}'
```
Expected: Returns {"status": "ok", "provider": "anthropic"}

**Step 6: Test frontend login**

Open http://localhost:3000, click Login, register a new user, verify you can access the app.

**Step 7: Document any issues found**

If issues are found, create follow-up tasks to address them.

---

## Summary

This plan implements:

1. **PostgreSQL database** with SQLAlchemy async ORM for user and API key storage
2. **JWT-based authentication** with access and refresh tokens
3. **Per-user API key storage** with encryption
4. **Proper error handling** for LLM providers with specific error messages
5. **Frontend auth UI** with login, registration, and auth state management
6. **Backwards compatibility** with legacy token auth during migration
7. **Comprehensive tests** for auth service and provider error handling

Total tasks: 21
Estimated complexity: Medium-High

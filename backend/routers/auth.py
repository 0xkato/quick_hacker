"""Authentication API routes."""
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from database.models import User
from services.auth_service import auth_service

router = APIRouter(prefix="/api/auth", tags=["auth"])
security = HTTPBearer(auto_error=False)


# Request/Response Models
class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., min_length=1, max_length=255)
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
        # Development-friendly behavior: if the account already exists, treat register as login
        # to avoid forcing users to switch forms.
        for identifier in (request.username, request.email):
            existing_user = await auth_service.authenticate_user(
                db,
                username=identifier,
                password=request.password,
            )
            if existing_user:
                return TokenResponse(
                    access_token=auth_service.create_access_token(existing_user.id, existing_user.username),
                    refresh_token=auth_service.create_refresh_token(existing_user.id),
                )

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


@router.post("/api-keys/validate")
async def validate_api_key(
    request: APIKeyRequest,
    user: User = Depends(get_current_user),
):
    """Validate an API key by making an actual API call."""
    from providers import get_provider
    from providers.base_provider import Message
    from models.schemas import ProviderConfig, ProviderType

    # Default models for validation (lightweight options)
    default_models = {
        "anthropic": "claude-3-5-haiku-20241022",
        "openai": "gpt-4o-mini",
        "ollama": "llama3.2:3b",
    }

    config = ProviderConfig(
        provider=ProviderType(request.provider),
        model=default_models[request.provider],
        api_key=request.api_key,
        max_tokens=1,  # Minimal response to reduce cost
    )

    try:
        provider = get_provider(config)
        # Make actual API call to validate the key
        await provider.generate([Message(role="user", content="Hi")])
        return {"valid": True, "provider": request.provider}
    except ValueError as e:
        return {"valid": False, "provider": request.provider, "error": str(e)}
    except Exception as e:
        return {"valid": False, "provider": request.provider, "error": f"Validation failed: {e}"}

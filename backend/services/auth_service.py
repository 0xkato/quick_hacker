"""Authentication service for JWT-based user authentication."""
import base64
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Optional
import uuid

from cryptography.fernet import Fernet, InvalidToken
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database.models import User, UserAPIKey

logger = logging.getLogger(__name__)

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class AuthService:
    """Service for user authentication and JWT management."""

    def __init__(self):
        self.secret_key = settings.jwt_secret_key
        self.algorithm = settings.jwt_algorithm
        self.access_token_expire = timedelta(minutes=settings.jwt_access_token_expire_minutes)
        self.refresh_token_expire = timedelta(days=settings.jwt_refresh_token_expire_days)

        # Fernet key: URL-safe base64-encoded 32-byte key derived from SHA256 of secret
        encryption_key = hashlib.sha256(settings.jwt_secret_key.encode()).digest()
        fernet_key = base64.urlsafe_b64encode(encryption_key)
        self._fernet = Fernet(fernet_key)

    def _truncate_password(self, password: str) -> str:
        """Truncate password to 72 bytes (bcrypt limit)."""
        # Bcrypt only uses the first 72 bytes of a password
        return password.encode('utf-8')[:72].decode('utf-8', errors='ignore')

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash."""
        return pwd_context.verify(self._truncate_password(plain_password), hashed_password)

    def hash_password(self, password: str) -> str:
        """Hash a password (truncated to 72 bytes for bcrypt)."""
        return pwd_context.hash(self._truncate_password(password))

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
        """Encrypt an API key for storage using Fernet (authenticated encryption)."""
        if not api_key:
            return ""
        # Fernet returns URL-safe base64 encoded ciphertext
        encrypted = self._fernet.encrypt(api_key.encode())
        return encrypted.decode()

    def decrypt_api_key(self, encrypted_key: str) -> str:
        """Decrypt a stored API key using Fernet."""
        if not encrypted_key:
            return ""

        try:
            decrypted = self._fernet.decrypt(encrypted_key.encode())
            return decrypted.decode()
        except InvalidToken as e:
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

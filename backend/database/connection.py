"""Database connection and session management."""
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import declarative_base

# Database URL configuration
# Priority: DATABASE_URL env var > SQLite fallback
_env_db_url = os.environ.get("DATABASE_URL")

if _env_db_url:
    DATABASE_URL = _env_db_url
else:
    # Use SQLite as default for local development
    # This ensures data persists across restarts without needing PostgreSQL
    db_path = Path(os.environ.get("DATA_DIR", "./data")) / "quick_hack.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    DATABASE_URL = f"sqlite+aiosqlite:///{db_path.absolute()}"
    print(f"[Database] Using SQLite at {db_path.absolute()}")

# Separate DB_ECHO flag - defaults to False even in debug mode
# SQL logging can expose sensitive data (API keys, tokens, etc.)
# Only enable explicitly when needed for debugging
DB_ECHO = os.environ.get("DB_ECHO", "false").lower() == "true"

# Configure engine based on database type
_is_sqlite = DATABASE_URL.startswith("sqlite")

if _is_sqlite:
    # SQLite doesn't support connection pooling the same way
    engine = create_async_engine(
        DATABASE_URL,
        echo=DB_ECHO,
        connect_args={"check_same_thread": False},  # Required for SQLite with async
    )
else:
    # PostgreSQL/MySQL with connection pooling
    engine = create_async_engine(
        DATABASE_URL,
        echo=DB_ECHO,
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


@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Async context manager for a database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


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

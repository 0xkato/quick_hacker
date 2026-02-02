"""Database schema compatibility checker for triage system.

Detects if triage columns exist and automatically disables triage if not present.
This ensures seamless operation without requiring migrations in production.
"""
import time
from typing import Optional, Set
import logging
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

logger = logging.getLogger(__name__)


# Schema check cache with TTL
_TRIAGE_COLUMNS_AVAILABLE: bool = False
_LAST_CHECK_TIME: float = 0.0
_CHECK_TTL_SECONDS: float = 300.0  # Re-check every 5 minutes
_ENGINE_REF: Optional[AsyncEngine] = None  # Store engine reference for lazy re-checks

# Required triage columns for full functionality
REQUIRED_TRIAGE_COLUMNS = {
    "batch_id",
    "disposition",
    "classification_confidence",
    "exploit_confidence",
    "proof_checklist",
    "reasoning",
    "triage_policy_version",
    "triaged_at",
    "category"
}


async def check_triage_columns_exist(engine: AsyncEngine) -> bool:
    """
    Check if all required triage columns exist in findings table.

    Args:
        engine: SQLAlchemy async engine

    Returns:
        True if all triage columns exist, False otherwise
    """
    try:
        async with engine.connect() as conn:
            # Query information_schema to check for column existence
            result = await conn.execute(
                text("""
                    SELECT column_name
                    FROM information_schema.columns
                    WHERE table_name = 'findings'
                    AND column_name = ANY(:column_names)
                """),
                {"column_names": list(REQUIRED_TRIAGE_COLUMNS)}
            )

            existing_columns: Set[str] = {row[0] for row in result}
            missing_columns = REQUIRED_TRIAGE_COLUMNS - existing_columns

            if missing_columns:
                logger.warning(
                    f"Triage columns missing from findings table: {missing_columns}. "
                    f"Triage system will be disabled. Run migration to enable: "
                    f"psql $DATABASE_URL < backend/migrations/add_triage_columns.sql"
                )
                return False

            logger.info("All triage columns present. Triage system available.")
            return True

    except Exception as e:
        logger.error(f"Failed to check triage columns: {e}. Disabling triage system.")
        return False


async def check_evidence_blobs_table_exists(engine: AsyncEngine) -> bool:
    """
    Check if evidence_blobs table exists.

    Args:
        engine: SQLAlchemy async engine

    Returns:
        True if table exists, False otherwise
    """
    try:
        async with engine.connect() as conn:
            result = await conn.execute(
                text("""
                    SELECT EXISTS (
                        SELECT FROM information_schema.tables
                        WHERE table_name = 'evidence_blobs'
                    )
                """)
            )
            exists = result.scalar()

            if not exists:
                logger.warning(
                    "evidence_blobs table missing. "
                    "Run migration to enable triage: "
                    "psql $DATABASE_URL < backend/migrations/add_triage_columns.sql"
                )

            return exists

    except Exception as e:
        logger.error(f"Failed to check evidence_blobs table: {e}")
        return False


async def initialize_triage_availability(engine: AsyncEngine) -> bool:
    """
    Initialize triage system availability based on database schema.

    This checks if the required schema is present and sets the global
    cache accordingly. The engine reference is stored for periodic re-checks.

    Args:
        engine: SQLAlchemy async engine

    Returns:
        True if triage is available, False otherwise
    """
    global _TRIAGE_COLUMNS_AVAILABLE, _LAST_CHECK_TIME, _ENGINE_REF

    _ENGINE_REF = engine  # Store for lazy re-checks

    logger.info("Checking triage system database schema compatibility...")

    columns_exist = await check_triage_columns_exist(engine)
    table_exists = await check_evidence_blobs_table_exists(engine)

    _TRIAGE_COLUMNS_AVAILABLE = columns_exist and table_exists
    _LAST_CHECK_TIME = time.monotonic()

    if _TRIAGE_COLUMNS_AVAILABLE:
        logger.info("✓ Triage system database schema is available")
    else:
        logger.warning(
            "✗ Triage system database schema is NOT available. "
            "Triage features will be disabled. "
            "To enable, run: psql $DATABASE_URL < backend/migrations/add_triage_columns.sql"
        )

    return _TRIAGE_COLUMNS_AVAILABLE


def is_triage_available() -> bool:
    """
    Check if triage system is available based on cached database schema check.

    Note: This returns the cached value. For runtime schema changes, use
    check_triage_available_async() which re-validates if TTL has expired.

    Returns:
        True if triage columns exist and triage can be used
    """
    return _TRIAGE_COLUMNS_AVAILABLE


async def check_triage_available_async() -> bool:
    """
    Check if triage system is available, re-validating if cache has expired.

    This should be used in async contexts where you want to detect runtime
    schema changes (e.g., migrations applied while server is running).

    Returns:
        True if triage columns exist and triage can be used
    """
    global _TRIAGE_COLUMNS_AVAILABLE, _LAST_CHECK_TIME

    # Check if cache has expired
    if _ENGINE_REF is not None:
        elapsed = time.monotonic() - _LAST_CHECK_TIME
        if elapsed > _CHECK_TTL_SECONDS:
            logger.debug(f"Triage schema cache expired ({elapsed:.1f}s > {_CHECK_TTL_SECONDS}s), re-checking...")
            columns_exist = await check_triage_columns_exist(_ENGINE_REF)
            table_exists = await check_evidence_blobs_table_exists(_ENGINE_REF)
            new_value = columns_exist and table_exists

            # Log if status changed
            if new_value != _TRIAGE_COLUMNS_AVAILABLE:
                if new_value:
                    logger.info("Triage schema now available (detected at runtime)")
                else:
                    logger.warning("Triage schema no longer available (detected at runtime)")

            _TRIAGE_COLUMNS_AVAILABLE = new_value
            _LAST_CHECK_TIME = time.monotonic()

    return _TRIAGE_COLUMNS_AVAILABLE


async def force_recheck_triage_availability() -> bool:
    """
    Force an immediate re-check of triage schema availability.

    Use this after running migrations to immediately detect schema changes.

    Returns:
        True if triage is now available, False otherwise
    """
    global _LAST_CHECK_TIME
    _LAST_CHECK_TIME = 0.0  # Invalidate cache
    return await check_triage_available_async()

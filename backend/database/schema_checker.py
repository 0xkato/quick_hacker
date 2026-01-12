"""Database schema compatibility checker for triage system.

Detects if triage columns exist and automatically disables triage if not present.
This ensures seamless operation without requiring migrations in production.
"""
from typing import Set
import logging
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

logger = logging.getLogger(__name__)


# Global flag indicating if triage columns are available
TRIAGE_COLUMNS_AVAILABLE = False

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
    TRIAGE_COLUMNS_AVAILABLE flag accordingly.

    Args:
        engine: SQLAlchemy async engine

    Returns:
        True if triage is available, False otherwise
    """
    global TRIAGE_COLUMNS_AVAILABLE

    logger.info("Checking triage system database schema compatibility...")

    columns_exist = await check_triage_columns_exist(engine)
    table_exists = await check_evidence_blobs_table_exists(engine)

    TRIAGE_COLUMNS_AVAILABLE = columns_exist and table_exists

    if TRIAGE_COLUMNS_AVAILABLE:
        logger.info("✓ Triage system database schema is available")
    else:
        logger.warning(
            "✗ Triage system database schema is NOT available. "
            "Triage features will be disabled. "
            "To enable, run: psql $DATABASE_URL < backend/migrations/add_triage_columns.sql"
        )

    return TRIAGE_COLUMNS_AVAILABLE


def is_triage_available() -> bool:
    """
    Check if triage system is available based on database schema.

    Returns:
        True if triage columns exist and triage can be used
    """
    return TRIAGE_COLUMNS_AVAILABLE

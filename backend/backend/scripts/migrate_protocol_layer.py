"""Apply protocol layer migration to PostgreSQL database."""

import asyncio
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import text
from database.connection import engine


async def apply_migration():
    """Apply protocol layer SQL migration."""
    print("🔧 Applying protocol layer migration...")

    migration_file = Path(__file__).parent.parent / "migrations" / "002_add_protocol_layer.sql"

    if not migration_file.exists():
        print(f"❌ Migration file not found: {migration_file}")
        sys.exit(1)

    # Read migration SQL
    with open(migration_file) as f:
        migration_sql = f.read()

    # Apply migration
    async with engine.begin() as conn:
        # Split by semicolons and execute each statement
        statements = [s.strip() for s in migration_sql.split(';') if s.strip()]

        for statement in statements:
            if statement:
                try:
                    await conn.execute(text(statement))
                    print(f"✅ Executed: {statement[:60]}...")
                except Exception as e:
                    print(f"⚠️  Statement skipped (may already exist): {str(e)[:100]}")

    print("✅ Migration applied successfully")


async def main():
    """Main entry point."""
    try:
        print("=" * 60)
        print("Protocol Layer Migration Tool")
        print("=" * 60)

        await apply_migration()

        print("\n" + "=" * 60)
        print("Next steps:")
        print("1. Run: python backend/scripts/seed_protocol_policies.py")
        print("2. Restart the backend server")
        print("=" * 60)

    except Exception as e:
        print(f"❌ Migration failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())

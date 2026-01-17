"""Migrate existing database to protocol layer schema."""

import asyncio
import aiosqlite
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from services.protocol_policies import ProtocolPolicyLoader


async def migrate_database(db_path: Path):
    """Run protocol layer migration on existing database."""
    print(f"🔧 Migrating database: {db_path}")

    async with aiosqlite.connect(db_path) as db:
        # Step 1: Run schema migration
        print("📋 Applying schema changes...")
        migration_path = Path(__file__).parent.parent / "migrations" / "002_add_protocol_layer.sql"

        with open(migration_path) as f:
            sql = f.read()

        try:
            await db.executescript(sql)
            await db.commit()
            print("✅ Schema migration complete")
        except Exception as e:
            print(f"⚠️  Schema migration (may already be applied): {e}")

        # Step 2: Seed protocol policies
        print("📦 Seeding default protocol policies...")
        loader = ProtocolPolicyLoader(db)
        await loader.seed_default_policies()
        print("✅ Protocol policies seeded")

        # Step 3: Set default protocol for existing projects
        print("🔧 Setting default protocol for existing projects...")
        await db.execute("""
            UPDATE projects
            SET protocol_id = 'internal'
            WHERE protocol_id IS NULL OR protocol_id = ''
        """)
        await db.commit()
        print("✅ Projects updated with default protocol")

        # Step 4: Verify migration
        print("🔍 Verifying migration...")

        cursor = await db.execute("SELECT COUNT(*) FROM protocol_policies")
        policy_count = (await cursor.fetchone())[0]

        cursor = await db.execute("SELECT COUNT(*) FROM projects WHERE protocol_id IS NOT NULL")
        project_count = (await cursor.fetchone())[0]

        print(f"✅ {policy_count} protocol policies installed")
        print(f"✅ {project_count} projects configured")

        print("\n🎉 Migration complete!")


async def main():
    db_path = Path(__file__).parent.parent / "data" / "quickhack.db"

    if not db_path.exists():
        print(f"❌ Database not found: {db_path}")
        sys.exit(1)

    # Backup database
    import shutil
    backup_path = db_path.with_suffix(".db.backup")
    print(f"💾 Creating backup: {backup_path}")
    shutil.copy(db_path, backup_path)

    await migrate_database(db_path)


if __name__ == "__main__":
    asyncio.run(main())

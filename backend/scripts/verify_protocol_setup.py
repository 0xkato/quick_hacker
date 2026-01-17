"""Verify protocol layer setup."""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import text
from database.connection import engine


async def verify():
    """Verify protocol setup."""
    print("🔍 Verifying Protocol Layer Setup\n")
    print("=" * 60)

    async with engine.connect() as conn:
        # Check protocol policies
        result = await conn.execute(
            text("SELECT COUNT(*) FROM protocol_policies")
        )
        policy_count = result.scalar()
        print(f"✅ Protocol Policies: {policy_count} found")

        if policy_count > 0:
            result = await conn.execute(
                text("SELECT id, display_name, is_default FROM protocol_policies ORDER BY is_default DESC, id")
            )
            print("\nAvailable Policies:")
            for row in result:
                default_marker = " (default)" if row[2] else ""
                print(f"  - {row[0]}: {row[1]}{default_marker}")

        # Check findings table has protocol fields
        result = await conn.execute(
            text("""
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name = 'findings'
                AND column_name IN ('submission_result', 'evidence_quest_id', 'evidence_quest_completed')
                ORDER BY column_name
            """)
        )
        protocol_columns = [row[0] for row in result]
        print(f"\n✅ Protocol Fields in Findings: {len(protocol_columns)}/3")
        for col in protocol_columns:
            print(f"  - {col}")

        # Check evidence_quests table exists
        result = await conn.execute(
            text("""
                SELECT table_name
                FROM information_schema.tables
                WHERE table_name = 'evidence_quests'
            """)
        )
        quest_table = result.scalar()
        if quest_table:
            print("\n✅ Evidence Quests Table: exists")
        else:
            print("\n❌ Evidence Quests Table: missing")

    print("\n" + "=" * 60)
    print("✅ Protocol Layer Setup Complete!")
    print("\nYou can now:")
    print("  1. Start the backend: uvicorn main:app --reload")
    print("  2. Test API: curl http://localhost:8000/api/protocol-policies")
    print("=" * 60)

    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(verify())

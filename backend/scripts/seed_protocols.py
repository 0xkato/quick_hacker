"""Seed default protocol policies."""
import asyncio
import aiosqlite
from pathlib import Path
import sys

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from services.protocol_policies import ProtocolPolicyLoader


async def main():
    db_path = Path(__file__).parent.parent / "data" / "quickhack.db"

    async with aiosqlite.connect(db_path) as db:
        loader = ProtocolPolicyLoader(db)
        await loader.seed_default_policies()
        print("✅ Seeded 5 default protocol policies")


if __name__ == "__main__":
    asyncio.run(main())

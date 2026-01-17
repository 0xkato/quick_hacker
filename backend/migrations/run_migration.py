"""Database migration runner."""
import sqlite3
import sys
from pathlib import Path

def run_migration(db_path: str, migration_file: str):
    """Run a SQL migration file."""
    migration_path = Path(__file__).parent / migration_file

    if not migration_path.exists():
        print(f"❌ Migration file not found: {migration_file}")
        sys.exit(1)

    with open(migration_path) as f:
        sql = f.read()

    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(sql)
        conn.commit()
        print(f"✅ Migration applied: {migration_file}")
    except Exception as e:
        conn.rollback()
        print(f"❌ Migration failed: {e}")
        sys.exit(1)
    finally:
        conn.close()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python run_migration.py <db_path> <migration_file>")
        sys.exit(1)

    run_migration(sys.argv[1], sys.argv[2])

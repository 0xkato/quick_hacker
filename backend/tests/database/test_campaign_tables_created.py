import pytest
from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import create_async_engine

from database.connection import Base

# Force campaign models to register with Base via the __init__ import
import database  # noqa: F401


EXPECTED = {
    "campaigns", "targets", "lane_specs", "execution_bundles",
    "run_lanes", "artifacts", "artifact_buckets", "issues",
    "regression_tests", "campaign_plans", "steering_decisions",
    "harnesses", "oracle_packs", "seed_sets", "dictionaries",
    "mutators", "runner_jobs", "env_snapshots",
    "coverage_snapshots", "coverage_rollups", "corpora",
    "corpus_items", "replay_runs", "research_leads",
}


def test_campaign_tables_in_metadata():
    """All 24 campaign tables are registered in Base.metadata after import."""
    registered = set(Base.metadata.tables.keys())
    assert EXPECTED.issubset(registered), f"Missing tables: {EXPECTED - registered}"


@pytest.mark.asyncio
async def test_campaign_tables_created():
    """Campaign tables can be physically created via create_all()."""
    # Use a private in-memory SQLite engine so existing JSONB models
    # (which are incompatible with SQLite) don't block creation.
    # We only create the 24 campaign tables.
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)
    campaign_tables = [Base.metadata.tables[t] for t in EXPECTED]

    async with engine.begin() as conn:
        await conn.run_sync(
            lambda c: Base.metadata.create_all(c, tables=campaign_tables)
        )

    async with engine.connect() as conn:
        def get_tables(connection):
            inspector = inspect(connection)
            return set(inspector.get_table_names())
        tables = await conn.run_sync(get_tables)

    assert EXPECTED.issubset(tables), f"Missing tables: {EXPECTED - tables}"

    await engine.dispose()

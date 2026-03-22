"""Tests for campaign SQLAlchemy model declarations (24 tables)."""

import importlib

import pytest


# ---------------------------------------------------------------------------
# Expected table names (24 total)
# ---------------------------------------------------------------------------
EXPECTED_TABLES = sorted([
    # Core chain (7)
    "campaigns",
    "targets",
    "lane_specs",
    "execution_bundles",
    "run_lanes",
    "artifacts",
    "issues",
    # Supporting (17)
    "artifact_buckets",
    "regression_tests",
    "campaign_plans",
    "steering_decisions",
    "harnesses",
    "oracle_packs",
    "seed_sets",
    "dictionaries",
    "mutators",
    "runner_jobs",
    "env_snapshots",
    "coverage_snapshots",
    "coverage_rollups",
    "corpora",
    "corpus_items",
    "replay_runs",
    "research_leads",
])

# Model class names mapped to their table names
MODEL_TABLE_MAP = {
    "Campaign": "campaigns",
    "Target": "targets",
    "LaneSpec": "lane_specs",
    "ExecutionBundle": "execution_bundles",
    "RunLane": "run_lanes",
    "Artifact": "artifacts",
    "Issue": "issues",
    "ArtifactBucket": "artifact_buckets",
    "RegressionTest": "regression_tests",
    "CampaignPlan": "campaign_plans",
    "SteeringDecision": "steering_decisions",
    "Harness": "harnesses",
    "OraclePack": "oracle_packs",
    "SeedSet": "seed_sets",
    "Dictionary": "dictionaries",
    "Mutator": "mutators",
    "RunnerJob": "runner_jobs",
    "EnvSnapshot": "env_snapshots",
    "CoverageSnapshot": "coverage_snapshots",
    "CoverageRollup": "coverage_rollups",
    "Corpus": "corpora",
    "CorpusItem": "corpus_items",
    "ReplayRun": "replay_runs",
    "ResearchLead": "research_leads",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def campaign_models():
    """Import campaign_models module; fail with context on error."""
    try:
        return importlib.import_module("database.campaign_models")
    except Exception as exc:
        pytest.fail(f"Importing database.campaign_models raised {exc!r}")


@pytest.fixture(scope="module")
def base():
    """Import Base to inspect shared metadata."""
    from database.connection import Base
    return Base


# ---------------------------------------------------------------------------
# 1. Module is importable
# ---------------------------------------------------------------------------
def test_campaign_models_importable(campaign_models):
    """Module imports without declarative mapping errors."""
    assert campaign_models is not None


# ---------------------------------------------------------------------------
# 2. All 24 model classes are exported
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("class_name", sorted(MODEL_TABLE_MAP.keys()))
def test_model_class_exists(campaign_models, class_name):
    """Each model class is defined and accessible."""
    cls = getattr(campaign_models, class_name, None)
    assert cls is not None, f"Missing model class: {class_name}"


# ---------------------------------------------------------------------------
# 3. All 24 table names are correct
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("class_name,table_name", sorted(MODEL_TABLE_MAP.items()))
def test_table_name(campaign_models, class_name, table_name):
    """__tablename__ matches specification."""
    cls = getattr(campaign_models, class_name)
    assert cls.__tablename__ == table_name


# ---------------------------------------------------------------------------
# 4. All tables registered in shared Base metadata
# ---------------------------------------------------------------------------
def test_all_tables_in_metadata(campaign_models, base):
    """All 24 campaign tables appear in Base.metadata."""
    table_names = set(base.metadata.tables.keys())
    for name in EXPECTED_TABLES:
        assert name in table_names, f"Table '{name}' not found in Base.metadata"


def test_exactly_24_campaign_tables(campaign_models):
    """We have exactly 24 campaign tables."""
    assert len(EXPECTED_TABLES) == 24


# ---------------------------------------------------------------------------
# 5. Core chain FK relationships
# ---------------------------------------------------------------------------
def _fk_targets(table):
    """Return set of FK target strings like 'campaigns.id' for a table."""
    return {
        list(fk.target_fullname for fk in col.foreign_keys)[0]
        for col in table.columns
        if col.foreign_keys
    }


def test_fk_campaign_to_target(campaign_models):
    """Target has FK to campaigns."""
    table = campaign_models.Target.__table__
    assert "campaigns.id" in _fk_targets(table)


def test_fk_target_to_lane_spec(campaign_models):
    """LaneSpec has FK to targets."""
    table = campaign_models.LaneSpec.__table__
    assert "targets.id" in _fk_targets(table)


def test_fk_execution_bundle_fks(campaign_models):
    """ExecutionBundle has FKs to campaigns and lane_specs."""
    table = campaign_models.ExecutionBundle.__table__
    targets = _fk_targets(table)
    assert "campaigns.id" in targets
    assert "lane_specs.id" in targets


def test_fk_run_lane(campaign_models):
    """RunLane has FKs to lane_specs and execution_bundles."""
    table = campaign_models.RunLane.__table__
    targets = _fk_targets(table)
    assert "lane_specs.id" in targets
    assert "execution_bundles.id" in targets


def test_fk_artifact(campaign_models):
    """Artifact has FK to run_lanes."""
    table = campaign_models.Artifact.__table__
    assert "run_lanes.id" in _fk_targets(table)


def test_fk_issue(campaign_models):
    """Issue has FK to artifacts."""
    table = campaign_models.Issue.__table__
    assert "artifacts.id" in _fk_targets(table)


# ---------------------------------------------------------------------------
# 6. Every model has a String(64) primary key named 'id'
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("class_name", sorted(MODEL_TABLE_MAP.keys()))
def test_id_column(campaign_models, class_name):
    """Every model has a String primary key named 'id'."""
    cls = getattr(campaign_models, class_name)
    table = cls.__table__
    id_col = table.c.id
    assert id_col is not None
    assert id_col.primary_key


# ---------------------------------------------------------------------------
# 7. JSON columns use JSON type (not JSONB -- portable)
# ---------------------------------------------------------------------------
JSON_COLUMNS = {
    "Campaign": ["config"],
    "Target": ["schemas", "actors"],
    "LaneSpec": ["feedback_models", "oracle_packs", "seed_sources"],
    "ExecutionBundle": [],
    "Artifact": ["replay_recipe", "evidence_refs"],
    "Issue": ["proof"],
    "CampaignPlan": ["plan_data"],
    "SteeringDecision": ["triggering_metrics", "decision"],
    "Harness": ["validation_results"],
    "OraclePack": ["config"],
    "SeedSet": ["sources"],
    "Mutator": ["config"],
    "EnvSnapshot": ["config"],
    "CoverageSnapshot": ["snapshot_data"],
    "CoverageRollup": ["rollup_data"],
    "ReplayRun": ["result"],
}


@pytest.mark.parametrize(
    "class_name,json_cols",
    [(k, v) for k, v in JSON_COLUMNS.items() if v],
)
def test_json_columns(campaign_models, class_name, json_cols):
    """JSON columns use the JSON type."""
    from sqlalchemy import JSON as SA_JSON

    cls = getattr(campaign_models, class_name)
    table = cls.__table__
    for col_name in json_cols:
        col = table.c[col_name]
        assert isinstance(col.type, SA_JSON), (
            f"{class_name}.{col_name} should be JSON, got {col.type!r}"
        )


# ---------------------------------------------------------------------------
# 8. Supporting model FK sanity checks
# ---------------------------------------------------------------------------
def test_fk_artifact_bucket(campaign_models):
    table = campaign_models.ArtifactBucket.__table__
    assert "campaigns.id" in _fk_targets(table)


def test_fk_regression_test(campaign_models):
    table = campaign_models.RegressionTest.__table__
    assert "issues.id" in _fk_targets(table)


def test_fk_campaign_plan(campaign_models):
    table = campaign_models.CampaignPlan.__table__
    assert "campaigns.id" in _fk_targets(table)


def test_fk_steering_decision(campaign_models):
    table = campaign_models.SteeringDecision.__table__
    assert "campaigns.id" in _fk_targets(table)


def test_fk_harness(campaign_models):
    table = campaign_models.Harness.__table__
    assert "lane_specs.id" in _fk_targets(table)


def test_fk_oracle_pack(campaign_models):
    table = campaign_models.OraclePack.__table__
    assert "lane_specs.id" in _fk_targets(table)


def test_fk_seed_set(campaign_models):
    table = campaign_models.SeedSet.__table__
    assert "lane_specs.id" in _fk_targets(table)


def test_fk_runner_job(campaign_models):
    table = campaign_models.RunnerJob.__table__
    targets = _fk_targets(table)
    assert "campaigns.id" in targets


def test_fk_env_snapshot(campaign_models):
    table = campaign_models.EnvSnapshot.__table__
    assert "campaigns.id" in _fk_targets(table)


def test_fk_coverage_snapshot(campaign_models):
    table = campaign_models.CoverageSnapshot.__table__
    assert "run_lanes.id" in _fk_targets(table)


def test_fk_coverage_rollup(campaign_models):
    table = campaign_models.CoverageRollup.__table__
    assert "campaigns.id" in _fk_targets(table)


def test_fk_corpus(campaign_models):
    table = campaign_models.Corpus.__table__
    assert "lane_specs.id" in _fk_targets(table)


def test_fk_corpus_item(campaign_models):
    table = campaign_models.CorpusItem.__table__
    assert "corpora.id" in _fk_targets(table)


def test_fk_replay_run(campaign_models):
    table = campaign_models.ReplayRun.__table__
    assert "artifacts.id" in _fk_targets(table)


def test_fk_research_lead(campaign_models):
    table = campaign_models.ResearchLead.__table__
    targets = _fk_targets(table)
    assert "campaigns.id" in targets

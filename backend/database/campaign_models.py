"""SQLAlchemy models for the campaign platform (24 tables).

All models share the same Base (from database.connection) so that
create_all() picks them up alongside existing tables.

Conventions:
  - String(64) for IDs and FK references
  - String(32) for status/enum fields (store .value strings)
  - JSON for all JSONB-style columns (portable across SQLite and PostgreSQL)
  - DateTime with func.now() server-defaults for timestamps
  - Integer with default=1 for revision fields
  - Composite indexes for common query patterns
"""

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    Boolean,
    func,
)

from .connection import Base


# ═══════════════════════════════════════════════════════════════════════════
# Core Chain (7)
# ═══════════════════════════════════════════════════════════════════════════


class Campaign(Base):
    """Top-level campaign definition."""

    __tablename__ = "campaigns"

    id = Column(String(64), primary_key=True)
    repo_id = Column(String(64), nullable=False, index=True)
    status = Column(String(32), nullable=False, default="created", index=True)
    preset = Column(String(32), nullable=False)
    budget_seconds = Column(Integer, nullable=True)
    max_parallel_lanes = Column(Integer, nullable=True)
    lm_provider = Column(String(64), nullable=True)
    lm_model = Column(String(128), nullable=True)
    config = Column(JSON, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)

    __table_args__ = (
        Index("ix_campaigns_repo_status", "repo_id", "status"),
    )


class Target(Base):
    """Fuzz/test target extracted from repository analysis."""

    __tablename__ = "targets"

    id = Column(String(64), primary_key=True)
    campaign_id = Column(
        String(64), ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False, index=True
    )
    kind = Column(String(32), nullable=False)
    entrypoint = Column(Text, nullable=False)
    language = Column(String(32), nullable=True)
    schemas = Column(JSON, nullable=True)
    stateful = Column(Boolean, default=False, nullable=False)
    actors = Column(JSON, nullable=True)
    reset_strategy = Column(String(64), nullable=True)
    priority_score = Column(Float, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)

    __table_args__ = (
        Index("ix_targets_campaign_kind", "campaign_id", "kind"),
    )


class LaneSpec(Base):
    """Specification for a fuzzing/testing lane."""

    __tablename__ = "lane_specs"

    id = Column(String(64), primary_key=True)
    target_id = Column(
        String(64), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    revision = Column(Integer, default=1, nullable=False)
    structure_model = Column(String(32), nullable=True)
    input_producer = Column(String(32), nullable=True)
    feedback_models = Column(JSON, nullable=True)
    oracle_packs = Column(JSON, nullable=True)
    engine = Column(String(64), nullable=True)
    budget_seconds = Column(Integer, nullable=True)
    seed_sources = Column(JSON, nullable=True)
    status = Column(String(32), nullable=False, default="planned")
    created_at = Column(DateTime, server_default=func.now(), nullable=False)

    __table_args__ = (
        Index("ix_lane_specs_target_status", "target_id", "status"),
    )


class ExecutionBundle(Base):
    """Frozen snapshot of all inputs for a lane run."""

    __tablename__ = "execution_bundles"

    id = Column(String(64), primary_key=True)
    campaign_id = Column(
        String(64), ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False, index=True
    )
    campaign_plan_revision = Column(Integer, nullable=True)
    lane_spec_id = Column(
        String(64), ForeignKey("lane_specs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    lane_spec_revision = Column(Integer, nullable=True)
    harness_id = Column(
        String(64), ForeignKey("harnesses.id", ondelete="CASCADE"), nullable=True
    )
    harness_revision = Column(Integer, nullable=True)
    oracle_pack_id = Column(
        String(64), ForeignKey("oracle_packs.id", ondelete="CASCADE"), nullable=True
    )
    oracle_pack_revision = Column(Integer, nullable=True)
    seed_set_id = Column(
        String(64), ForeignKey("seed_sets.id", ondelete="CASCADE"), nullable=True
    )
    dictionary_id = Column(
        String(64), ForeignKey("dictionaries.id", ondelete="CASCADE"), nullable=True
    )
    mutator_id = Column(
        String(64), ForeignKey("mutators.id", ondelete="CASCADE"), nullable=True
    )
    build_artifact_ref = Column(Text, nullable=True)
    env_snapshot_id = Column(
        String(64), ForeignKey("env_snapshots.id", ondelete="CASCADE"), nullable=True
    )
    created_at = Column(DateTime, server_default=func.now(), nullable=False)


class RunLane(Base):
    """A single execution of a lane spec with a specific bundle."""

    __tablename__ = "run_lanes"

    id = Column(String(64), primary_key=True)
    lane_spec_id = Column(
        String(64), ForeignKey("lane_specs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    execution_bundle_id = Column(
        String(64), ForeignKey("execution_bundles.id", ondelete="CASCADE"), nullable=False, index=True
    )
    status = Column(String(32), nullable=False, default="queued")
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    cpu_limit = Column(Float, nullable=True)
    memory_limit_mb = Column(Integer, nullable=True)
    disk_limit_mb = Column(Integer, nullable=True)
    timeout_seconds = Column(Integer, nullable=True)
    resource_profile = Column(String(32), nullable=True)

    __table_args__ = (
        Index("ix_run_lanes_spec_status", "lane_spec_id", "status"),
    )


class Artifact(Base):
    """Raw output from a fuzzing lane (crash, hang, oracle hit)."""

    __tablename__ = "artifacts"

    id = Column(String(64), primary_key=True)
    run_lane_id = Column(
        String(64), ForeignKey("run_lanes.id", ondelete="CASCADE"), nullable=False, index=True
    )
    type = Column(String(32), nullable=False)
    bucket_key = Column(String(128), nullable=True, index=True)
    artifact_classification = Column(String(32), nullable=True)
    analysis_outcome = Column(String(32), nullable=True)
    reproducible = Column(Boolean, nullable=True)
    stability_score = Column(Float, nullable=True)
    minimized = Column(Boolean, default=False, nullable=False)
    replay_recipe = Column(JSON, nullable=True)
    evidence_refs = Column(JSON, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)

    __table_args__ = (
        Index("ix_artifacts_lane_created", "run_lane_id", "created_at"),
    )


class Issue(Base):
    """Confirmed or candidate security/quality issue from an artifact."""

    __tablename__ = "issues"

    id = Column(String(64), primary_key=True)
    artifact_id = Column(
        String(64), ForeignKey("artifacts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    severity = Column(String(32), nullable=False)
    title = Column(Text, nullable=False)
    description = Column(Text, nullable=True)
    category = Column(String(64), nullable=True)
    cwe_id = Column(String(20), nullable=True)
    disposition = Column(String(64), nullable=True)
    proof = Column(JSON, nullable=True)
    root_cause = Column(Text, nullable=True)
    recommended_fix = Column(Text, nullable=True)
    regression_test_id = Column(
        String(64), ForeignKey("regression_tests.id", ondelete="SET NULL"), nullable=True
    )
    created_at = Column(DateTime, server_default=func.now(), nullable=False)


# ═══════════════════════════════════════════════════════════════════════════
# Supporting Tables (17)
# ═══════════════════════════════════════════════════════════════════════════


class ArtifactBucket(Base):
    """De-duplication bucket for artifacts by crash signature."""

    __tablename__ = "artifact_buckets"

    id = Column(String(64), primary_key=True)
    campaign_id = Column(
        String(64), ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False, index=True
    )
    bucket_key = Column(String(128), nullable=False, index=True)
    artifact_count = Column(Integer, default=0, nullable=False)
    first_seen_at = Column(DateTime, server_default=func.now(), nullable=False)
    last_seen_at = Column(DateTime, server_default=func.now(), nullable=False)

    __table_args__ = (
        Index("ix_artifact_buckets_campaign_key", "campaign_id", "bucket_key"),
    )


class RegressionTest(Base):
    """Auto-generated regression test for a confirmed issue."""

    __tablename__ = "regression_tests"

    id = Column(String(64), primary_key=True)
    issue_id = Column(String(64), nullable=False, index=True)
    file_ref = Column(Text, nullable=False)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)


class CampaignPlan(Base):
    """Versioned campaign execution plan."""

    __tablename__ = "campaign_plans"

    id = Column(String(64), primary_key=True)
    campaign_id = Column(
        String(64), ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False, index=True
    )
    revision = Column(Integer, default=1, nullable=False)
    plan_data = Column(JSON, nullable=False)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)

    __table_args__ = (
        Index("ix_campaign_plans_campaign_rev", "campaign_id", "revision"),
    )


class SteeringDecision(Base):
    """Record of an automated steering decision."""

    __tablename__ = "steering_decisions"

    id = Column(String(64), primary_key=True)
    campaign_id = Column(
        String(64), ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False, index=True
    )
    triggering_metrics = Column(JSON, nullable=True)
    decision = Column(JSON, nullable=True)
    expected_effect = Column(Text, nullable=True)
    actual_effect = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)


class Harness(Base):
    """Test harness code for a lane spec."""

    __tablename__ = "harnesses"

    id = Column(String(64), primary_key=True)
    lane_spec_id = Column(
        String(64), ForeignKey("lane_specs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    revision = Column(Integer, default=1, nullable=False)
    code_ref = Column(Text, nullable=True)
    validation_results = Column(JSON, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)


class OraclePack(Base):
    """Oracle configuration for a lane spec."""

    __tablename__ = "oracle_packs"

    id = Column(String(64), primary_key=True)
    lane_spec_id = Column(
        String(64), ForeignKey("lane_specs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    revision = Column(Integer, default=1, nullable=False)
    config = Column(JSON, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)


class SeedSet(Base):
    """Seed corpus configuration for a lane spec."""

    __tablename__ = "seed_sets"

    id = Column(String(64), primary_key=True)
    lane_spec_id = Column(
        String(64), ForeignKey("lane_specs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    sources = Column(JSON, nullable=True)
    item_count = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)


class Dictionary(Base):
    """Fuzzing dictionary for a lane spec."""

    __tablename__ = "dictionaries"

    id = Column(String(64), primary_key=True)
    lane_spec_id = Column(
        String(64), ForeignKey("lane_specs.id", ondelete="CASCADE"), nullable=True
    )
    content_ref = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)


class Mutator(Base):
    """Mutator configuration for a lane spec."""

    __tablename__ = "mutators"

    id = Column(String(64), primary_key=True)
    lane_spec_id = Column(
        String(64), ForeignKey("lane_specs.id", ondelete="CASCADE"), nullable=True
    )
    config = Column(JSON, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)


class RunnerJob(Base):
    """Job record for the task runner (build, run, replay, etc.)."""

    __tablename__ = "runner_jobs"

    id = Column(String(64), primary_key=True)
    campaign_id = Column(
        String(64), ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False, index=True
    )
    run_lane_id = Column(
        String(64), ForeignKey("run_lanes.id", ondelete="CASCADE"), nullable=True
    )
    job_type = Column(String(32), nullable=False)
    status = Column(String(32), nullable=False, default="queued")
    queue_name = Column(String(64), nullable=True)
    enqueued_at = Column(DateTime, server_default=func.now(), nullable=False)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)

    __table_args__ = (
        Index("ix_runner_jobs_campaign_status", "campaign_id", "status"),
    )


class EnvSnapshot(Base):
    """Environment snapshot for target execution."""

    __tablename__ = "env_snapshots"

    id = Column(String(64), primary_key=True)
    campaign_id = Column(
        String(64), ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_base_url = Column(Text, nullable=True)
    network_name = Column(String(128), nullable=True)
    reset_command = Column(Text, nullable=True)
    config = Column(JSON, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)


class CoverageSnapshot(Base):
    """Point-in-time coverage data for a run lane."""

    __tablename__ = "coverage_snapshots"

    id = Column(String(64), primary_key=True)
    run_lane_id = Column(
        String(64), ForeignKey("run_lanes.id", ondelete="CASCADE"), nullable=False, index=True
    )
    snapshot_data = Column(JSON, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)

    __table_args__ = (
        Index("ix_coverage_snapshots_lane_created", "run_lane_id", "created_at"),
    )


class CoverageRollup(Base):
    """Aggregated coverage across lanes for a campaign or target."""

    __tablename__ = "coverage_rollups"

    id = Column(String(64), primary_key=True)
    campaign_id = Column(
        String(64), ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_id = Column(
        String(64), ForeignKey("targets.id", ondelete="CASCADE"), nullable=True
    )
    rollup_data = Column(JSON, nullable=True)
    updated_at = Column(
        DateTime, server_default=func.now(), onupdate=func.now(), nullable=False
    )


class Corpus(Base):
    """Managed corpus for a lane spec."""

    __tablename__ = "corpora"

    id = Column(String(64), primary_key=True)
    lane_spec_id = Column(
        String(64), ForeignKey("lane_specs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    item_count = Column(Integer, default=0, nullable=False)
    total_bytes = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime, server_default=func.now(), onupdate=func.now(), nullable=False
    )


class CorpusItem(Base):
    """Individual item in a corpus."""

    __tablename__ = "corpus_items"

    id = Column(String(64), primary_key=True)
    corpus_id = Column(
        String(64), ForeignKey("corpora.id", ondelete="CASCADE"), nullable=False, index=True
    )
    content_ref = Column(Text, nullable=True)
    size_bytes = Column(Integer, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)


class ReplayRun(Base):
    """Replay attempt for artifact reproduction."""

    __tablename__ = "replay_runs"

    id = Column(String(64), primary_key=True)
    artifact_id = Column(
        String(64), ForeignKey("artifacts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    status = Column(String(32), nullable=False, default="queued")
    stability_score = Column(Float, nullable=True)
    attempts = Column(Integer, default=0, nullable=False)
    result = Column(JSON, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)


class ResearchLead(Base):
    """Research lead generated from artifact analysis."""

    __tablename__ = "research_leads"

    id = Column(String(64), primary_key=True)
    campaign_id = Column(
        String(64), ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False, index=True
    )
    artifact_id = Column(
        String(64), ForeignKey("artifacts.id", ondelete="CASCADE"), nullable=True
    )
    title = Column(Text, nullable=False)
    description = Column(Text, nullable=True)
    reason = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)

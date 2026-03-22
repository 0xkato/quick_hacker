"""Pydantic request/response schemas for the campaign platform.

All enum types are imported from models.campaign_enums.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel

from models.campaign_enums import (
    ArtifactClassification,
    ArtifactType,
    AnalysisOutcome,
    CampaignPreset,
    CampaignStatus,
    FeedbackModel,
    InputProducer,
    IssueDisposition,
    IssueSeverity,
    LaneSpecStatus,
    ResourceProfile,
    RunLaneStatus,
    StructureModel,
    TargetKind,
)


# ---------------------------------------------------------------------------
# Utility models
# ---------------------------------------------------------------------------


class ProofChecklist(BaseModel):
    """10-gate proof checklist for artifact-to-issue promotion.

    7 core gates must pass before an artifact can be promoted to an issue.
    security_impact_confirmed is required on top of core gates for a
    confirmed security issue.
    """

    target_real: bool = False
    harness_validated: bool = False
    real_code_reached: bool = False
    external_input_controlled: bool = False
    oracle_triggered_or_sanitizer_hit: bool = False
    reproduced_cleanly: bool = False
    artifact_minimization_attempted: bool = False
    not_harness_artifact: bool = False
    not_test_only: bool = False
    security_impact_confirmed: bool = False

    def core_gates_pass(self) -> bool:
        """Return True if all 7 core gates pass."""
        return all([
            self.target_real,
            self.harness_validated,
            self.real_code_reached,
            self.reproduced_cleanly,
            self.artifact_minimization_attempted,
            self.not_harness_artifact,
            self.not_test_only,
        ])

    def is_security_issue(self) -> bool:
        """Return True if core gates pass AND security_impact_confirmed."""
        return self.core_gates_pass() and self.security_impact_confirmed


class ReplayRecipe(BaseModel):
    """Structured replay recipe for reproducing an artifact.

    Uses typed fields (not a shell string) so replay is deterministic
    and machine-parseable.
    """

    runner: str
    entrypoint: str
    args: list[str]
    env_snapshot_id: str
    artifact_inputs: list[str]


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class CampaignCreateRequest(BaseModel):
    """All configuration parameters for creating a new campaign."""

    repo_id: str

    # Preset & scope
    campaign_preset: str = "quick"
    target_scope: str | None = None
    methodology_overrides: dict[str, Any] | None = None

    # LM configuration
    lm_provider: str = "claude_cli"
    lm_model: str = "claude-opus-4-6"

    # Engine configuration
    enabled_engines: list[str] = ["schemathesis"]
    max_parallel_lanes: int = 2
    max_lm_jobs: int = 2

    # Seed & corpus
    seed_sources: list[str] | None = None
    corpus_reuse_policy: str | None = None

    # Actor & environment
    actor_profiles: list[str] | None = None
    env_profile: dict[str, Any] | None = None

    # Targeting
    directed_targets: list[str] | None = None
    custom_oracles: list[str] | None = None
    target_filters: dict[str, Any] | None = None

    # Budget & steering
    budget_seconds: int | None = None
    steering_interval_seconds: int = 120
    plateau_window_seconds: int = 300
    max_compilation_failures_per_lane: int = 3
    max_steering_cycles: int | None = None

    # Reproduction & minimization
    repro_attempts: int | None = None
    minimization_budget_seconds: int | None = None


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class CampaignResponse(BaseModel):
    """Campaign summary returned by the API."""

    id: str
    repo_id: str
    status: CampaignStatus
    preset: CampaignPreset
    budget_seconds: int | None = None
    max_parallel_lanes: int
    lm_provider: str
    lm_model: str
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error_message: str | None = None
    target_count: int = 0
    lane_count: int = 0
    issue_count: int = 0


class TargetResponse(BaseModel):
    """Target extracted from a campaign's repository."""

    id: str
    campaign_id: str
    kind: TargetKind
    entrypoint: str
    language: str | None = None
    schemas: dict[str, Any] | None = None
    stateful: bool = False
    actors: list[str] | None = None
    reset_strategy: str | None = None
    priority_score: float = 0.0
    created_at: datetime


class LaneSpecResponse(BaseModel):
    """Lane specification describing how a target is fuzzed."""

    id: str
    target_id: str
    revision: int
    structure_model: StructureModel
    input_producer: InputProducer
    feedback_models: list[FeedbackModel]
    oracle_packs: list[str]
    engine: str
    budget_seconds: int | None = None
    seed_sources: list[str] | None = None
    status: LaneSpecStatus
    created_at: datetime


class ExecutionBundleResponse(BaseModel):
    """Immutable snapshot of everything needed to run a lane."""

    id: str
    campaign_id: str
    campaign_plan_revision: int
    lane_spec_id: str
    lane_spec_revision: int
    harness_id: str
    harness_revision: int
    oracle_pack_id: str
    oracle_pack_revision: int
    seed_set_id: str | None = None
    dictionary_id: str | None = None
    mutator_id: str | None = None
    build_artifact_ref: str | None = None
    env_snapshot_id: str | None = None
    created_at: datetime


class RunLaneResponse(BaseModel):
    """A single execution run of a lane specification."""

    id: str
    lane_spec_id: str
    execution_bundle_id: str
    status: RunLaneStatus
    started_at: datetime | None = None
    completed_at: datetime | None = None
    cpu_limit: float | None = None
    memory_limit_mb: int | None = None
    disk_limit_mb: int | None = None
    timeout_seconds: int | None = None
    resource_profile: ResourceProfile | None = None


class ArtifactResponse(BaseModel):
    """An artifact produced by a lane run (crash, hang, oracle hit, etc.)."""

    id: str
    run_lane_id: str
    type: ArtifactType
    bucket_key: str
    artifact_classification: ArtifactClassification | None = None
    analysis_outcome: AnalysisOutcome | None = None
    reproducible: bool | None = None
    stability_score: float | None = None
    minimized: bool = False
    replay_recipe: ReplayRecipe | None = None
    evidence_refs: list[str] | None = None
    created_at: datetime


class IssueResponse(BaseModel):
    """A confirmed issue promoted from an artifact after proof gating."""

    id: str
    artifact_id: str
    severity: IssueSeverity
    title: str
    description: str | None = None
    category: str | None = None
    cwe_id: str | None = None
    disposition: IssueDisposition | None = None
    proof: ProofChecklist | None = None
    root_cause: str | None = None
    recommended_fix: str | None = None
    regression_test_id: str | None = None
    created_at: datetime

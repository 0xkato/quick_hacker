"""Tests for campaign Pydantic request/response schemas."""

import pytest
from datetime import datetime, timezone
from uuid import uuid4

from models.campaign_schemas import (
    CampaignCreateRequest,
    CampaignResponse,
    TargetResponse,
    LaneSpecResponse,
    ExecutionBundleResponse,
    RunLaneResponse,
    ArtifactResponse,
    IssueResponse,
    ProofChecklist,
    ReplayRecipe,
)
from models.campaign_enums import (
    CampaignPreset,
    CampaignStatus,
    TargetKind,
    LaneSpecStatus,
    RunLaneStatus,
    ArtifactType,
    ArtifactClassification,
    AnalysisOutcome,
    IssueDisposition,
    IssueSeverity,
    ResourceProfile,
    StructureModel,
    InputProducer,
    FeedbackModel,
)


# ---------------------------------------------------------------------------
# CampaignCreateRequest
# ---------------------------------------------------------------------------


class TestCampaignCreateRequestMinimal:
    """CampaignCreateRequest with only required fields (repo_id)."""

    def test_minimal_creates_successfully(self):
        req = CampaignCreateRequest(repo_id="org/my-repo")
        assert req.repo_id == "org/my-repo"

    def test_defaults(self):
        req = CampaignCreateRequest(repo_id="org/my-repo")
        assert req.campaign_preset == "quick"
        assert req.target_scope is None
        assert req.methodology_overrides is None
        assert req.lm_provider == "claude_cli"
        assert req.lm_model == "claude-opus-4-6"
        assert req.enabled_engines == ["schemathesis"]
        assert req.max_parallel_lanes == 2
        assert req.max_lm_jobs == 2
        assert req.seed_sources is None
        assert req.corpus_reuse_policy is None
        assert req.actor_profiles is None
        assert req.env_profile is None
        assert req.directed_targets is None
        assert req.custom_oracles is None
        assert req.target_filters is None
        assert req.budget_seconds is None
        assert req.steering_interval_seconds == 120
        assert req.plateau_window_seconds == 300
        assert req.max_compilation_failures_per_lane == 3
        assert req.max_steering_cycles is None
        assert req.repro_attempts is None
        assert req.minimization_budget_seconds is None

    def test_requires_repo_id(self):
        with pytest.raises(Exception):
            CampaignCreateRequest()  # type: ignore[call-arg]


class TestCampaignCreateRequestFull:
    """CampaignCreateRequest with all fields populated."""

    def test_full_params(self):
        req = CampaignCreateRequest(
            repo_id="org/big-app",
            campaign_preset="evil",
            target_scope="backend/**/*.py",
            methodology_overrides={"skip_tls": True},
            lm_provider="anthropic_sdk",
            lm_model="claude-sonnet-4-20250514",
            enabled_engines=["schemathesis", "atheris"],
            max_parallel_lanes=8,
            max_lm_jobs=4,
            seed_sources=["corpus/v1", "corpus/v2"],
            corpus_reuse_policy="merge",
            actor_profiles=["admin", "guest"],
            env_profile={"DB_HOST": "localhost"},
            directed_targets=["POST /api/login", "GET /api/users"],
            custom_oracles=["oracle_auth_bypass"],
            target_filters={"language": "python"},
            budget_seconds=7200,
            steering_interval_seconds=60,
            plateau_window_seconds=600,
            max_compilation_failures_per_lane=5,
            max_steering_cycles=10,
            repro_attempts=3,
            minimization_budget_seconds=300,
        )
        assert req.repo_id == "org/big-app"
        assert req.campaign_preset == "evil"
        assert req.target_scope == "backend/**/*.py"
        assert req.methodology_overrides == {"skip_tls": True}
        assert req.lm_provider == "anthropic_sdk"
        assert req.lm_model == "claude-sonnet-4-20250514"
        assert req.enabled_engines == ["schemathesis", "atheris"]
        assert req.max_parallel_lanes == 8
        assert req.max_lm_jobs == 4
        assert req.seed_sources == ["corpus/v1", "corpus/v2"]
        assert req.corpus_reuse_policy == "merge"
        assert req.actor_profiles == ["admin", "guest"]
        assert req.env_profile == {"DB_HOST": "localhost"}
        assert req.directed_targets == ["POST /api/login", "GET /api/users"]
        assert req.custom_oracles == ["oracle_auth_bypass"]
        assert req.target_filters == {"language": "python"}
        assert req.budget_seconds == 7200
        assert req.steering_interval_seconds == 60
        assert req.plateau_window_seconds == 600
        assert req.max_compilation_failures_per_lane == 5
        assert req.max_steering_cycles == 10
        assert req.repro_attempts == 3
        assert req.minimization_budget_seconds == 300


# ---------------------------------------------------------------------------
# ProofChecklist
# ---------------------------------------------------------------------------


class TestProofChecklistCoreGates:
    """ProofChecklist.core_gates_pass() — 7 core gates must all be True."""

    ALL_CORE_GATES = [
        "target_real",
        "harness_validated",
        "real_code_reached",
        "reproduced_cleanly",
        "artifact_minimization_attempted",
        "not_harness_artifact",
        "not_test_only",
    ]

    def test_all_core_gates_true(self):
        proof = ProofChecklist(
            target_real=True,
            harness_validated=True,
            real_code_reached=True,
            external_input_controlled=True,
            oracle_triggered_or_sanitizer_hit=True,
            reproduced_cleanly=True,
            artifact_minimization_attempted=True,
            not_harness_artifact=True,
            not_test_only=True,
            security_impact_confirmed=True,
        )
        assert proof.core_gates_pass() is True

    @pytest.mark.parametrize("failing_gate", [
        "target_real",
        "harness_validated",
        "real_code_reached",
        "reproduced_cleanly",
        "artifact_minimization_attempted",
        "not_harness_artifact",
        "not_test_only",
    ])
    def test_fails_when_any_core_gate_false(self, failing_gate: str):
        kwargs = {gate: True for gate in self.ALL_CORE_GATES}
        kwargs["external_input_controlled"] = True
        kwargs["oracle_triggered_or_sanitizer_hit"] = True
        kwargs["security_impact_confirmed"] = True
        # Set the failing gate to False
        kwargs[failing_gate] = False
        proof = ProofChecklist(**kwargs)
        assert proof.core_gates_pass() is False

    def test_non_core_gates_dont_affect_core(self):
        """external_input_controlled and oracle_triggered_or_sanitizer_hit are NOT core gates."""
        proof = ProofChecklist(
            target_real=True,
            harness_validated=True,
            real_code_reached=True,
            external_input_controlled=False,
            oracle_triggered_or_sanitizer_hit=False,
            reproduced_cleanly=True,
            artifact_minimization_attempted=True,
            not_harness_artifact=True,
            not_test_only=True,
            security_impact_confirmed=False,
        )
        assert proof.core_gates_pass() is True


class TestProofChecklistIsSecurityIssue:
    """ProofChecklist.is_security_issue() — core gates AND security_impact_confirmed."""

    def test_true_when_core_passes_and_security_confirmed(self):
        proof = ProofChecklist(
            target_real=True,
            harness_validated=True,
            real_code_reached=True,
            external_input_controlled=True,
            oracle_triggered_or_sanitizer_hit=True,
            reproduced_cleanly=True,
            artifact_minimization_attempted=True,
            not_harness_artifact=True,
            not_test_only=True,
            security_impact_confirmed=True,
        )
        assert proof.is_security_issue() is True

    def test_false_when_core_passes_but_security_not_confirmed(self):
        proof = ProofChecklist(
            target_real=True,
            harness_validated=True,
            real_code_reached=True,
            external_input_controlled=True,
            oracle_triggered_or_sanitizer_hit=True,
            reproduced_cleanly=True,
            artifact_minimization_attempted=True,
            not_harness_artifact=True,
            not_test_only=True,
            security_impact_confirmed=False,
        )
        assert proof.is_security_issue() is False

    def test_false_when_security_confirmed_but_core_fails(self):
        proof = ProofChecklist(
            target_real=False,
            harness_validated=True,
            real_code_reached=True,
            external_input_controlled=True,
            oracle_triggered_or_sanitizer_hit=True,
            reproduced_cleanly=True,
            artifact_minimization_attempted=True,
            not_harness_artifact=True,
            not_test_only=True,
            security_impact_confirmed=True,
        )
        assert proof.is_security_issue() is False


# ---------------------------------------------------------------------------
# ReplayRecipe
# ---------------------------------------------------------------------------


class TestReplayRecipe:
    """ReplayRecipe has structured fields, not a shell string."""

    def test_structured_fields(self):
        recipe = ReplayRecipe(
            runner="docker",
            entrypoint="/usr/bin/test-harness",
            args=["--input", "crash-001.bin", "--timeout", "30"],
            env_snapshot_id="env-snap-abc",
            artifact_inputs=["artifact/crash-001.bin", "artifact/crash-002.bin"],
        )
        assert recipe.runner == "docker"
        assert recipe.entrypoint == "/usr/bin/test-harness"
        assert isinstance(recipe.args, list)
        assert len(recipe.args) == 4
        assert recipe.env_snapshot_id == "env-snap-abc"
        assert isinstance(recipe.artifact_inputs, list)
        assert len(recipe.artifact_inputs) == 2

    def test_args_is_list_not_string(self):
        recipe = ReplayRecipe(
            runner="docker",
            entrypoint="/bin/run",
            args=["--flag"],
            env_snapshot_id="snap-1",
            artifact_inputs=[],
        )
        assert isinstance(recipe.args, list)
        assert not isinstance(recipe.args, str)


# ---------------------------------------------------------------------------
# Response models — correct field existence
# ---------------------------------------------------------------------------


class TestCampaignResponse:
    def test_fields(self):
        now = datetime.now(tz=timezone.utc)
        resp = CampaignResponse(
            id="camp-1",
            repo_id="org/repo",
            status=CampaignStatus.RUNNING,
            preset=CampaignPreset.QUICK,
            budget_seconds=3600,
            max_parallel_lanes=4,
            lm_provider="claude_cli",
            lm_model="claude-opus-4-6",
            created_at=now,
            started_at=now,
            completed_at=None,
            error_message=None,
        )
        assert resp.id == "camp-1"
        assert resp.repo_id == "org/repo"
        assert resp.status == CampaignStatus.RUNNING
        assert resp.preset == CampaignPreset.QUICK
        assert resp.budget_seconds == 3600
        assert resp.max_parallel_lanes == 4
        assert resp.lm_provider == "claude_cli"
        assert resp.lm_model == "claude-opus-4-6"
        assert resp.created_at == now
        assert resp.started_at == now
        assert resp.completed_at is None
        assert resp.error_message is None
        assert resp.target_count == 0
        assert resp.lane_count == 0
        assert resp.issue_count == 0


class TestTargetResponse:
    def test_fields(self):
        now = datetime.now(tz=timezone.utc)
        resp = TargetResponse(
            id="tgt-1",
            campaign_id="camp-1",
            kind=TargetKind.API_ROUTE,
            entrypoint="POST /api/users",
            language="python",
            schemas={"openapi": "3.0"},
            stateful=True,
            actors=["admin", "user"],
            reset_strategy="db_rollback",
            priority_score=0.85,
            created_at=now,
        )
        assert resp.id == "tgt-1"
        assert resp.campaign_id == "camp-1"
        assert resp.kind == TargetKind.API_ROUTE
        assert resp.entrypoint == "POST /api/users"
        assert resp.language == "python"
        assert resp.schemas == {"openapi": "3.0"}
        assert resp.stateful is True
        assert resp.actors == ["admin", "user"]
        assert resp.reset_strategy == "db_rollback"
        assert resp.priority_score == 0.85
        assert resp.created_at == now


class TestLaneSpecResponse:
    def test_fields(self):
        now = datetime.now(tz=timezone.utc)
        resp = LaneSpecResponse(
            id="lane-1",
            target_id="tgt-1",
            revision=1,
            structure_model=StructureModel.SCHEMA,
            input_producer=InputProducer.MUTATION,
            feedback_models=[FeedbackModel.API_SURFACE, FeedbackModel.DIRECTED],
            oracle_packs=["oracle-auth", "oracle-sqli"],
            engine="schemathesis",
            budget_seconds=1800,
            seed_sources=["corpus/v1"],
            status=LaneSpecStatus.PLANNED,
            created_at=now,
        )
        assert resp.id == "lane-1"
        assert resp.target_id == "tgt-1"
        assert resp.revision == 1
        assert resp.structure_model == StructureModel.SCHEMA
        assert resp.input_producer == InputProducer.MUTATION
        assert resp.feedback_models == [FeedbackModel.API_SURFACE, FeedbackModel.DIRECTED]
        assert resp.oracle_packs == ["oracle-auth", "oracle-sqli"]
        assert resp.engine == "schemathesis"
        assert resp.budget_seconds == 1800
        assert resp.seed_sources == ["corpus/v1"]
        assert resp.status == LaneSpecStatus.PLANNED
        assert resp.created_at == now


class TestExecutionBundleResponse:
    def test_fields(self):
        now = datetime.now(tz=timezone.utc)
        resp = ExecutionBundleResponse(
            id="bundle-1",
            campaign_id="camp-1",
            campaign_plan_revision=2,
            lane_spec_id="lane-1",
            lane_spec_revision=1,
            harness_id="harness-1",
            harness_revision=3,
            oracle_pack_id="oracle-1",
            oracle_pack_revision=1,
            seed_set_id="seeds-1",
            dictionary_id="dict-1",
            mutator_id="mut-1",
            build_artifact_ref="s3://bucket/build.tar.gz",
            env_snapshot_id="env-snap-1",
            created_at=now,
        )
        assert resp.id == "bundle-1"
        assert resp.campaign_id == "camp-1"
        assert resp.campaign_plan_revision == 2
        assert resp.lane_spec_id == "lane-1"
        assert resp.lane_spec_revision == 1
        assert resp.harness_id == "harness-1"
        assert resp.harness_revision == 3
        assert resp.oracle_pack_id == "oracle-1"
        assert resp.oracle_pack_revision == 1
        assert resp.seed_set_id == "seeds-1"
        assert resp.dictionary_id == "dict-1"
        assert resp.mutator_id == "mut-1"
        assert resp.build_artifact_ref == "s3://bucket/build.tar.gz"
        assert resp.env_snapshot_id == "env-snap-1"
        assert resp.created_at == now


class TestRunLaneResponse:
    def test_fields(self):
        now = datetime.now(tz=timezone.utc)
        resp = RunLaneResponse(
            id="run-1",
            lane_spec_id="lane-1",
            execution_bundle_id="bundle-1",
            status=RunLaneStatus.RUNNING,
            started_at=now,
            completed_at=None,
            cpu_limit=2.0,
            memory_limit_mb=4096,
            disk_limit_mb=10240,
            timeout_seconds=3600,
            resource_profile=ResourceProfile.MEDIUM,
        )
        assert resp.id == "run-1"
        assert resp.lane_spec_id == "lane-1"
        assert resp.execution_bundle_id == "bundle-1"
        assert resp.status == RunLaneStatus.RUNNING
        assert resp.started_at == now
        assert resp.completed_at is None
        assert resp.cpu_limit == 2.0
        assert resp.memory_limit_mb == 4096
        assert resp.disk_limit_mb == 10240
        assert resp.timeout_seconds == 3600
        assert resp.resource_profile == ResourceProfile.MEDIUM


class TestArtifactResponse:
    def test_fields(self):
        now = datetime.now(tz=timezone.utc)
        recipe = ReplayRecipe(
            runner="docker",
            entrypoint="/bin/harness",
            args=["--crash"],
            env_snapshot_id="snap-1",
            artifact_inputs=["input.bin"],
        )
        resp = ArtifactResponse(
            id="art-1",
            run_lane_id="run-1",
            type=ArtifactType.CRASH,
            bucket_key="artifacts/crash-001",
            artifact_classification=ArtifactClassification.ISSUE_CANDIDATE,
            analysis_outcome=AnalysisOutcome.NONE,
            reproducible=True,
            stability_score=0.95,
            minimized=True,
            replay_recipe=recipe,
            evidence_refs=["log-1", "screenshot-1"],
            created_at=now,
        )
        assert resp.id == "art-1"
        assert resp.run_lane_id == "run-1"
        assert resp.type == ArtifactType.CRASH
        assert resp.bucket_key == "artifacts/crash-001"
        assert resp.artifact_classification == ArtifactClassification.ISSUE_CANDIDATE
        assert resp.analysis_outcome == AnalysisOutcome.NONE
        assert resp.reproducible is True
        assert resp.stability_score == 0.95
        assert resp.minimized is True
        assert resp.replay_recipe == recipe
        assert resp.evidence_refs == ["log-1", "screenshot-1"]
        assert resp.created_at == now


class TestIssueResponse:
    def test_fields(self):
        now = datetime.now(tz=timezone.utc)
        proof = ProofChecklist(
            target_real=True,
            harness_validated=True,
            real_code_reached=True,
            external_input_controlled=True,
            oracle_triggered_or_sanitizer_hit=True,
            reproduced_cleanly=True,
            artifact_minimization_attempted=True,
            not_harness_artifact=True,
            not_test_only=True,
            security_impact_confirmed=True,
        )
        resp = IssueResponse(
            id="issue-1",
            artifact_id="art-1",
            severity=IssueSeverity.CRITICAL,
            title="SQL Injection in /api/users",
            description="User-controlled input flows into raw SQL query.",
            category="injection",
            cwe_id="CWE-89",
            disposition=IssueDisposition.CONFIRMED_SECURITY_ISSUE,
            proof=proof,
            root_cause="Missing parameterized query in user_repository.py:42",
            recommended_fix="Use parameterized queries via SQLAlchemy text() bindings.",
            regression_test_id="regtest-1",
            created_at=now,
        )
        assert resp.id == "issue-1"
        assert resp.artifact_id == "art-1"
        assert resp.severity == IssueSeverity.CRITICAL
        assert resp.title == "SQL Injection in /api/users"
        assert resp.description == "User-controlled input flows into raw SQL query."
        assert resp.category == "injection"
        assert resp.cwe_id == "CWE-89"
        assert resp.disposition == IssueDisposition.CONFIRMED_SECURITY_ISSUE
        assert resp.proof == proof
        assert resp.root_cause == "Missing parameterized query in user_repository.py:42"
        assert resp.recommended_fix == "Use parameterized queries via SQLAlchemy text() bindings."
        assert resp.regression_test_id == "regtest-1"
        assert resp.created_at == now

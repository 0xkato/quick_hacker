"""Tests for campaign platform enums."""

import pytest

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
    RunnerJobStatus,
    StructureModel,
    TargetKind,
)


class TestCampaignStatus:
    def test_values(self):
        expected = {
            "created",
            "planning",
            "extracting",
            "compiling",
            "running",
            "paused",
            "completed",
            "failed",
            "cancelled",
        }
        assert {s.value for s in CampaignStatus} == expected

    def test_is_str_enum(self):
        assert isinstance(CampaignStatus.CREATED, str)
        assert CampaignStatus.RUNNING == "running"


class TestCampaignPreset:
    def test_values(self):
        expected = {"quick", "medium", "advanced", "pro", "ultra", "evil"}
        assert {p.value for p in CampaignPreset} == expected


class TestTargetKind:
    def test_values(self):
        expected = {
            "api_route",
            "parser",
            "workflow",
            "browser",
            "cli",
            "message_consumer",
            "native_function",
        }
        assert {k.value for k in TargetKind} == expected


class TestLaneSpecStatus:
    def test_values(self):
        expected = {"planned", "compiled", "validated", "retired"}
        assert {s.value for s in LaneSpecStatus} == expected

    def test_no_running(self):
        """LaneSpecStatus should NOT have 'running' — that belongs to RunLaneStatus."""
        values = {s.value for s in LaneSpecStatus}
        assert "running" not in values


class TestRunLaneStatus:
    def test_values(self):
        expected = {
            "queued",
            "running",
            "stalled",
            "completed",
            "failed",
            "cancelled",
            "superseded",
        }
        assert {s.value for s in RunLaneStatus} == expected

    def test_no_retired(self):
        """RunLaneStatus should NOT have 'retired' — that belongs to LaneSpecStatus."""
        values = {s.value for s in RunLaneStatus}
        assert "retired" not in values


class TestLaneSpecAndRunLaneSeparation:
    """LaneSpecStatus and RunLaneStatus must remain separate enums with distinct semantics."""

    def test_no_running_in_lane_spec(self):
        assert "running" not in {s.value for s in LaneSpecStatus}

    def test_no_retired_in_run_lane(self):
        assert "retired" not in {s.value for s in RunLaneStatus}

    def test_different_enum_types(self):
        assert LaneSpecStatus is not RunLaneStatus


class TestRunnerJobStatus:
    def test_values(self):
        expected = {
            "queued",
            "running",
            "completed",
            "failed",
            "cancelled",
            "superseded",
        }
        assert {s.value for s in RunnerJobStatus} == expected


class TestArtifactType:
    def test_values(self):
        expected = {"crash", "hang", "oracle_hit", "differential_failure"}
        assert {t.value for t in ArtifactType} == expected


class TestArtifactClassification:
    def test_values(self):
        expected = {"issue_candidate", "harness_artifact", "flaky_unconfirmed"}
        assert {c.value for c in ArtifactClassification} == expected


class TestAnalysisOutcome:
    def test_values(self):
        expected = {"by_design", "research_lead", "none"}
        assert {o.value for o in AnalysisOutcome} == expected


class TestIssueDisposition:
    def test_values(self):
        expected = {
            "confirmed_security_issue",
            "confirmed_non_security_bug",
            "hardening_observation",
        }
        assert {d.value for d in IssueDisposition} == expected


class TestArtifactClassificationAndIssueDispositionSeparation:
    """ArtifactClassification and IssueDisposition are separate systems with no value overlap."""

    def test_no_overlap(self):
        artifact_values = {c.value for c in ArtifactClassification}
        disposition_values = {d.value for d in IssueDisposition}
        assert artifact_values.isdisjoint(disposition_values)

    def test_different_enum_types(self):
        assert ArtifactClassification is not IssueDisposition


class TestIssueSeverity:
    def test_values(self):
        expected = {"critical", "high", "medium", "low", "info"}
        assert {s.value for s in IssueSeverity} == expected


class TestResourceProfile:
    def test_values(self):
        expected = {"light", "medium", "heavy"}
        assert {p.value for p in ResourceProfile} == expected


class TestStructureModel:
    def test_values(self):
        expected = {"schema", "state_machine", "grammar", "raw", "typed"}
        assert {m.value for m in StructureModel} == expected


class TestInputProducer:
    def test_values(self):
        expected = {"mutation", "generation", "hybrid"}
        assert {p.value for p in InputProducer} == expected


class TestFeedbackModel:
    def test_values(self):
        expected = {"api_surface", "state_depth", "directed", "differential"}
        assert {m.value for m in FeedbackModel} == expected


class TestAllEnumsAreStrEnum:
    """Every campaign enum must be (str, Enum) so values serialize naturally."""

    @pytest.mark.parametrize(
        "enum_cls",
        [
            CampaignStatus,
            CampaignPreset,
            TargetKind,
            LaneSpecStatus,
            RunLaneStatus,
            RunnerJobStatus,
            ArtifactType,
            ArtifactClassification,
            AnalysisOutcome,
            IssueDisposition,
            IssueSeverity,
            ResourceProfile,
            StructureModel,
            InputProducer,
            FeedbackModel,
        ],
    )
    def test_str_enum(self, enum_cls):
        for member in enum_cls:
            assert isinstance(member, str)

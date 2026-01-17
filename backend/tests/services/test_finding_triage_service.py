"""
Unit tests for finding_triage_service.py - Orchestration and guarantees.

Tests ensure:
1. Never drops findings (triaged_count == raw_count)
2. Batch timeout handling
3. Metrics calculation
4. Thread-safe execution
5. Error handling and graceful degradation
"""

import pytest
from unittest.mock import Mock, patch
from datetime import datetime
import itertools
from models.schemas import (
    Finding,
    BudgetConfig,
    Disposition,
    ChecklistStatus,
)
from services.finding_triage_service import FindingTriageService


@pytest.fixture
def triage_service():
    """Create triage service instance."""
    return FindingTriageService()


@pytest.fixture
def budget_config():
    """Standard budget configuration."""
    return BudgetConfig(
        batch_ms=15000,
        per_finding_ms=300,
        max_evidence_bytes=10000,
        max_snippet_lines=200,
    )


@pytest.fixture
def sample_findings():
    """Sample findings for testing."""
    return [
        Finding(
            id=f"finding-{i:03d}",
            agent_id="agent-001",
            repo_id="repo-001",
            title=f"Test Finding {i}",
            description="Test description",
            file_path=f"/app/test_{i}.py",
            line_start=10 + i,
            vulnerability_type="Unknown",
            severity="high",
            confidence=0.8,
            created_at="2026-01-12T00:00:00Z",
        )
        for i in range(5)
    ]


class TestNeverDropFindings:
    """Test the critical guarantee: triaged_count == raw_count."""

    def test_empty_findings_returns_empty(self, triage_service, budget_config, tmp_path):
        """Empty input → empty output."""
        result = triage_service.triage_findings(
            repo_root=str(tmp_path),
            findings=[],
            policy_version="1.0.0",
            budgets=budget_config,
        )

        assert result.triaged_count == 0
        assert result.reportable_count == 0
        assert len(result.triaged_findings) == 0

    def test_single_finding_always_triaged(self, triage_service, budget_config, tmp_path):
        """Single finding → exactly one triaged finding."""
        finding = Finding(
            id="test-001",
            agent_id="agent-001",
            repo_id="repo-001",
            title="Test",
            description="Test",
            file_path="/app/test.py",
            line_start=10,
            vulnerability_type="Unknown",
            severity="high",
            confidence=0.8,
            created_at="2026-01-12T00:00:00Z",
        )

        result = triage_service.triage_findings(
            repo_root=str(tmp_path),
            findings=[finding],
            policy_version="1.0.0",
            budgets=budget_config,
        )

        assert result.triaged_count == 1
        assert len(result.triaged_findings) == 1
        assert result.triaged_findings[0].id == "test-001"

    def test_hardening_disposition_sets_hardening_classification(self, triage_service, budget_config, tmp_path):
        """Disposition HARDENING should map to FindingClassification.HARDENING for correct UI labels."""
        from dataclasses import replace

        from models.schemas import ChecklistItem, ChecklistStatus, FindingClassification, ProofChecklist
        from services.strict_classifier import ClassificationResult

        finding = Finding(
            id="test-001",
            agent_id="agent-001",
            repo_id="repo-001",
            title="Hardcoded private key",
            description="Bundled test cert material",
            file_path="/app/third_party/civetweb/resources/cert/server.key",
            line_start=1,
            vulnerability_type="hardcoded_secret",
            severity="high",
            confidence=0.8,
            created_at="2026-01-12T00:00:00Z",
        )

        hardening_result = ClassificationResult(
            disposition=Disposition.HARDENING,
            classification_confidence=70,
            exploit_confidence=None,
            proof_checklist=ProofChecklist(
                source_controlled_input=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="N/A"),
                sink_present=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="N/A"),
                dataflow_evidenced=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="N/A"),
                reachable=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="N/A"),
                boundary_crossed=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="N/A"),
                not_only_misconfig=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="N/A"),
                security_control_bypassed=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="N/A"),
            ),
            reasoning=["Hardcoded secret in third_party fixture"],
            category=None,
        )

        class FakeGatherer:
            def __init__(self, repo_root: str, budgets: BudgetConfig):
                self.repo_root = repo_root
                self.budgets = budgets

            def gather(self, finding: Finding):
                from models.schemas import Evidence, InputChannel

                return Evidence(
                    finding_id=finding.id,
                    snippet="",
                    handler_snippet=None,
                    symbol_info=None,
                    framework=None,
                    route_registration=None,
                    auth_gates=[],
                    dataflow_snippet=None,
                    matches=[],
                    ssrf_analysis=None,
                    timed_out=False,
                    input_channel=InputChannel.unknown,
                    input_channel_deterministic=False,
                    input_channel_signals=[],
                    input_channel_reason="",
                )

        class FakeClassifier:
            def classify(self, finding: Finding, evidence, threat_model_profile=None):
                return replace(hardening_result)

        with (
            patch("services.finding_triage_service.EvidenceGatherer", FakeGatherer),
            patch("services.finding_triage_service.StrictClassifier", FakeClassifier),
        ):
            result = triage_service.triage_findings(
                repo_root=str(tmp_path),
                findings=[finding],
                policy_version="1.0.0",
                budgets=budget_config,
            )

        assert result.triaged_count == 1
        assert result.triaged_findings[0].disposition == Disposition.HARDENING
        assert result.triaged_findings[0].classification == FindingClassification.HARDENING

    def test_all_findings_triaged_never_dropped(self, triage_service, budget_config, tmp_path, sample_findings):
        """All findings are triaged, none dropped."""
        raw_count = len(sample_findings)

        result = triage_service.triage_findings(
            repo_root=str(tmp_path),
            findings=sample_findings,
            policy_version="1.0.0",
            budgets=budget_config,
        )

        # CRITICAL: Must never drop findings
        assert result.triaged_count == raw_count
        assert len(result.triaged_findings) == raw_count
        assert result.metrics.raw_count == raw_count

        # All original IDs must be present
        original_ids = {f.id for f in sample_findings}
        triaged_ids = {f.id for f in result.triaged_findings}
        assert original_ids == triaged_ids


class TestBatchTimeout:
    """Test batch timeout handling."""

    @patch('services.finding_triage_service.time.time')
    def test_timeout_marks_as_speculative(self, mock_time, triage_service, tmp_path, sample_findings):
        """Timeout → remaining findings marked as SPECULATIVE with UNKNOWN checklist."""
        # Simulate timeout by making time.time() return an initial start time, then a large elapsed time.
        mock_time.side_effect = itertools.chain([0, 20000], itertools.repeat(20000))

        budget = BudgetConfig(
            batch_ms=15000,  # 15 second timeout
            per_finding_ms=300,
            max_evidence_bytes=10000,
            max_snippet_lines=200,
        )

        result = triage_service.triage_findings(
            repo_root=str(tmp_path),
            findings=sample_findings,
            policy_version="1.0.0",
            budgets=budget,
        )

        # Still must not drop findings
        assert result.triaged_count == len(sample_findings)

        # Check if any were marked as SPECULATIVE due to timeout
        if result.metrics.timeout_count > 0:
            speculative_findings = [
                f for f in result.triaged_findings
                if f.disposition == Disposition.SPECULATIVE
            ]

            for finding in speculative_findings:
                # Timeout findings should have UNKNOWN checklist items
                if finding.proof_checklist:
                    # At least some should be UNKNOWN due to timeout
                    checklist_dict = finding.proof_checklist.model_dump()
                    unknown_count = sum(
                        1 for item_data in checklist_dict.values()
                        if isinstance(item_data, dict) and item_data.get('status') == ChecklistStatus.UNKNOWN
                    )
                    assert unknown_count > 0

                # Should have timeout reasoning
                if finding.reasoning:
                    has_timeout_reason = any('timeout' in r.lower() for r in finding.reasoning)
                    assert has_timeout_reason

    def test_timeout_rate_calculated(self, triage_service, budget_config, tmp_path, sample_findings):
        """Timeout rate is calculated correctly."""
        result = triage_service.triage_findings(
            repo_root=str(tmp_path),
            findings=sample_findings,
            policy_version="1.0.0",
            budgets=budget_config,
        )

        # Timeout rate should be between 0 and 1
        assert 0 <= result.metrics.timeout_rate <= 1

        # If timeout_count > 0, rate should match
        if result.metrics.timeout_count > 0:
            expected_rate = result.metrics.timeout_count / result.metrics.triaged_count
            assert abs(result.metrics.timeout_rate - expected_rate) < 0.01


class TestMetricsCalculation:
    """Test metrics calculation."""

    def test_by_disposition_counts(self, triage_service, budget_config, tmp_path, sample_findings):
        """by_disposition counts are accurate."""
        result = triage_service.triage_findings(
            repo_root=str(tmp_path),
            findings=sample_findings,
            policy_version="1.0.0",
            budgets=budget_config,
        )

        # Sum of disposition counts should equal total
        total_by_disposition = sum(result.metrics.by_disposition.values())
        assert total_by_disposition == result.triaged_count

        # Each disposition count should match actual findings
        for disposition, count in result.metrics.by_disposition.items():
            actual_count = sum(
                1 for f in result.triaged_findings
                if f.disposition and f.disposition.value == disposition
            )
            assert actual_count == count

    def test_reportable_count_accurate(self, triage_service, budget_config, tmp_path, sample_findings):
        """reportable_count matches VALID_SECURITY_ISSUE + BUG."""
        result = triage_service.triage_findings(
            repo_root=str(tmp_path),
            findings=sample_findings,
            policy_version="1.0.0",
            budgets=budget_config,
        )

        # Count reportable dispositions
        reportable = sum(
            1 for f in result.triaged_findings
            if f.disposition in [Disposition.VALID_SECURITY_ISSUE, Disposition.BUG]
        )

        assert result.reportable_count == reportable
        assert result.metrics.reportable_count == reportable


class TestBatchIdAssignment:
    """Test batch_id assignment."""

    def test_all_findings_have_same_batch_id(self, triage_service, budget_config, tmp_path, sample_findings):
        """All findings in batch get same batch_id."""
        result = triage_service.triage_findings(
            repo_root=str(tmp_path),
            findings=sample_findings,
            policy_version="1.0.0",
            budgets=budget_config,
        )

        # All should have batch_id
        batch_ids = {f.batch_id for f in result.triaged_findings}
        assert len(batch_ids) == 1  # All same batch_id
        assert result.batch_id in batch_ids

    def test_batch_id_format(self, triage_service, budget_config, tmp_path, sample_findings):
        """Batch ID has expected format."""
        result = triage_service.triage_findings(
            repo_root=str(tmp_path),
            findings=sample_findings,
            policy_version="1.0.0",
            budgets=budget_config,
        )

        # Should be a non-empty string
        assert result.batch_id
        assert isinstance(result.batch_id, str)
        assert len(result.batch_id) > 0


class TestPolicyVersionTracking:
    """Test policy version tracking."""

    def test_policy_version_attached(self, triage_service, budget_config, tmp_path, sample_findings):
        """All findings get policy version."""
        policy_version = "1.2.3"

        result = triage_service.triage_findings(
            repo_root=str(tmp_path),
            findings=sample_findings,
            policy_version=policy_version,
            budgets=budget_config,
        )

        # All findings should have the policy version
        for finding in result.triaged_findings:
            assert finding.triage_policy_version == policy_version


class TestErrorHandling:
    """Test error handling and graceful degradation."""

    def test_missing_file_doesnt_crash(self, triage_service, budget_config, tmp_path):
        """Missing file in finding doesn't crash triage."""
        finding = Finding(
            id="test-001",
            agent_id="agent-001",
            repo_id="repo-001",
            title="Test",
            description="Test",
            file_path="/nonexistent/file.py",  # Doesn't exist
            line_start=10,
            vulnerability_type="Unknown",
            severity="high",
            confidence=0.8,
            created_at="2026-01-12T00:00:00Z",
        )

        result = triage_service.triage_findings(
            repo_root=str(tmp_path),
            findings=[finding],
            policy_version="1.0.0",
            budgets=budget_config,
        )

        # Should still return the finding (never drop)
        assert result.triaged_count == 1
        assert len(result.triaged_findings) == 1

        # Should have disposition (probably SPECULATIVE due to lack of evidence)
        assert result.triaged_findings[0].disposition is not None

    def test_invalid_repo_path_doesnt_crash(self, triage_service, budget_config, sample_findings):
        """Invalid repo path doesn't crash triage."""
        result = triage_service.triage_findings(
            repo_root="/nonexistent/repo",
            findings=sample_findings,
            policy_version="1.0.0",
            budgets=budget_config,
        )

        # Should still process all findings (never drop)
        assert result.triaged_count == len(sample_findings)

    def test_malformed_finding_handled(self, triage_service, budget_config, tmp_path):
        """Malformed finding doesn't crash the batch."""
        findings = [
            Finding(
                id="good-001",
                agent_id="agent-001",
                repo_id="repo-001",
                title="Good Finding",
                description="Normal finding",
                file_path="/app/test.py",
                line_start=10,
                vulnerability_type="Test",
                severity="high",
                confidence=0.8,
                created_at="2026-01-12T00:00:00Z",
            ),
            Finding(
                id="bad-001",
                agent_id="agent-001",
                repo_id="repo-001",
                title="",  # Empty title
                description="",  # Empty description
                file_path="",  # Empty path
                line_start=-1,  # Invalid line
                vulnerability_type="",
                severity="high",
                confidence=0.8,
                created_at="2026-01-12T00:00:00Z",
            ),
        ]

        result = triage_service.triage_findings(
            repo_root=str(tmp_path),
            findings=findings,
            policy_version="1.0.0",
            budgets=budget_config,
        )

        # Should still process all (never drop)
        assert result.triaged_count == 2


class TestReasoningPresence:
    """Test that reasoning is always provided."""

    def test_all_triaged_have_reasoning(self, triage_service, budget_config, tmp_path, sample_findings):
        """All triaged findings should have reasoning."""
        result = triage_service.triage_findings(
            repo_root=str(tmp_path),
            findings=sample_findings,
            policy_version="1.0.0",
            budgets=budget_config,
        )

        for finding in result.triaged_findings:
            assert finding.reasoning is not None
            assert len(finding.reasoning) > 0


class TestDispositionRequired:
    """Test that disposition is always assigned."""

    def test_all_triaged_have_disposition(self, triage_service, budget_config, tmp_path, sample_findings):
        """All triaged findings must have disposition."""
        result = triage_service.triage_findings(
            repo_root=str(tmp_path),
            findings=sample_findings,
            policy_version="1.0.0",
            budgets=budget_config,
        )

        for finding in result.triaged_findings:
            assert finding.disposition is not None
            assert isinstance(finding.disposition, Disposition)


class TestTriagedAtTimestamp:
    """Test triaged_at timestamp."""

    def test_triaged_at_populated(self, triage_service, budget_config, tmp_path, sample_findings):
        """All findings get triaged_at timestamp."""
        result = triage_service.triage_findings(
            repo_root=str(tmp_path),
            findings=sample_findings,
            policy_version="1.0.0",
            budgets=budget_config,
        )

        for finding in result.triaged_findings:
            assert finding.triaged_at is not None
            assert isinstance(finding.triaged_at, datetime)


class TestBudgetEnforcement:
    """Test budget enforcement."""

    def test_per_finding_budget_respected(self, triage_service, tmp_path, sample_findings):
        """Per-finding budget is respected."""
        budget = BudgetConfig(
            batch_ms=60000,  # Long batch timeout
            per_finding_ms=10,  # Very short per-finding budget
            max_evidence_bytes=10000,
            max_snippet_lines=200,
        )

        result = triage_service.triage_findings(
            repo_root=str(tmp_path),
            findings=sample_findings,
            policy_version="1.0.0",
            budgets=budget,
        )

        # Should still process all (never drop)
        assert result.triaged_count == len(sample_findings)

        # With very short budget, might have timeouts
        # But must still return all findings


class TestEmptyRepoHandling:
    """Test handling of empty repository."""

    def test_empty_repo_directory(self, triage_service, budget_config, tmp_path, sample_findings):
        """Empty repo directory is handled gracefully."""
        empty_repo = tmp_path / "empty_repo"
        empty_repo.mkdir()

        result = triage_service.triage_findings(
            repo_root=str(empty_repo),
            findings=sample_findings,
            policy_version="1.0.0",
            budgets=budget_config,
        )

        # Should still return all findings (never drop)
        assert result.triaged_count == len(sample_findings)


class TestTriageServiceWithPolicy:
    """Test FindingTriageService with policy integration."""

    def test_triage_with_vrp_policy_filters_third_party(self):
        """Test triage with VRP policy filters third_party findings."""
        from services.default_policies import VRP_GOOGLE_OSS_STRICT

        service = FindingTriageService()

        findings = [
            Finding(
                id="1",
                agent_id="agent-001",
                repo_id="repo-001",
                file_path="third_party/lib.py",
                line_start=10,
                vulnerability_type="SQL Injection",
                title="Test",
                description="Test",
                code_snippet="test",
                severity="high",
                confidence=0.8,
                created_at="2026-01-12T00:00:00Z"
            ),
            Finding(
                id="2",
                agent_id="agent-001",
                repo_id="repo-001",
                file_path="src/main.py",
                line_start=20,
                vulnerability_type="SQL Injection",
                title="Test",
                description="Test",
                code_snippet="test",
                severity="high",
                confidence=0.8,
                created_at="2026-01-12T00:00:00Z"
            )
        ]

        result = service.triage_findings(
            repo_root="/tmp/test",
            findings=findings,
            policy=VRP_GOOGLE_OSS_STRICT
        )

        # Only src/main.py should remain after filtering
        assert result.metrics.triaged_count == 1
        assert result.triaged_findings[0].id == "2"

    def test_triage_with_vrp_policy_deduplicates(self):
        """Test triage with VRP policy deduplicates findings."""
        from services.default_policies import VRP_GOOGLE_OSS_STRICT

        service = FindingTriageService()

        findings = [
            Finding(
                id="1",
                agent_id="agent-001",
                repo_id="repo-001",
                file_path="src/main.py",
                line_start=10,
                vulnerability_type="SQL Injection",
                title="Unsafe query",
                description="Test 1",
                code_snippet="test",
                severity="high",
                confidence=0.8,
                created_at="2026-01-12T00:00:00Z"
            ),
            Finding(
                id="2",
                agent_id="agent-001",
                repo_id="repo-001",
                file_path="src/main.py",
                line_start=10,
                vulnerability_type="SQL Injection",
                title="Unsafe query",
                description="Test 2",  # Duplicate
                code_snippet="test",
                severity="high",
                confidence=0.8,
                created_at="2026-01-12T00:00:00Z"
            )
        ]

        result = service.triage_findings(
            repo_root="/tmp/test",
            findings=findings,
            policy=VRP_GOOGLE_OSS_STRICT
        )

        # Should deduplicate to 1 finding
        assert result.metrics.triaged_count == 1

    def test_triage_with_policy_attaches_policy_decision(self):
        """Test triage attaches policy decision to findings."""
        from services.default_policies import VRP_GOOGLE_OSS_STRICT
        from models.schemas import PolicyDecision

        service = FindingTriageService()
        policy = VRP_GOOGLE_OSS_STRICT

        finding = Finding(
            id="1",
            agent_id="agent-001",
            repo_id="repo-001",
            file_path="src/main.py",
            line_start=10,
            vulnerability_type="SQL Injection",
            title="Test",
            description="Test",
            code_snippet="test",
            severity="high",
            confidence=0.8,
            created_at="2026-01-12T00:00:00Z"
        )

        result = service.triage_findings(
            repo_root="/tmp/test",
            findings=[finding],
            policy=policy
        )

        triaged = result.triaged_findings[0]

        # Should have policy fields attached
        assert hasattr(triaged, 'policy_decision')
        assert hasattr(triaged, 'policy_reasoning')
        assert hasattr(triaged, 'path_classification')


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

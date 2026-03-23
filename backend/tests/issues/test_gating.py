"""Unit tests for issue gating logic.

Tests cover each disposition path and each individual core gate failure.
"""

from __future__ import annotations

import pytest

from issues.gating import evaluate_proof, IssueGatingResult
from models.campaign_schemas import ProofChecklist


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _all_core_pass(**overrides) -> ProofChecklist:
    """Return a ProofChecklist with all 7 core gates passing."""
    defaults = dict(
        target_real=True,
        harness_validated=True,
        real_code_reached=True,
        external_input_controlled=True,
        oracle_triggered_or_sanitizer_hit=False,
        reproduced_cleanly=True,
        artifact_minimization_attempted=True,
        not_harness_artifact=True,
        not_test_only=True,
        security_impact_confirmed=False,
    )
    defaults.update(overrides)
    return ProofChecklist(**defaults)


def _all_pass_security() -> ProofChecklist:
    """Return a ProofChecklist that is a confirmed security issue."""
    return _all_core_pass(security_impact_confirmed=True)


# ---------------------------------------------------------------------------
# Disposition: confirmed_security_issue
# ---------------------------------------------------------------------------


class TestConfirmedSecurityIssue:
    def test_all_gates_and_security_confirmed(self):
        """Core gates pass + security_impact_confirmed -> confirmed_security_issue."""
        checklist = _all_pass_security()
        result = evaluate_proof(checklist)

        assert result.disposition == "confirmed_security_issue"
        assert result.is_issue is True
        assert any("core gates passed" in r for r in result.reasoning)
        assert any("security_impact_confirmed" in r for r in result.reasoning)


# ---------------------------------------------------------------------------
# Disposition: confirmed_non_security_bug
# ---------------------------------------------------------------------------


class TestConfirmedNonSecurityBug:
    def test_core_pass_no_security_no_oracle(self):
        """Core pass, no security impact, no oracle -> confirmed_non_security_bug."""
        checklist = _all_core_pass(
            security_impact_confirmed=False,
            oracle_triggered_or_sanitizer_hit=False,
        )
        result = evaluate_proof(checklist)

        assert result.disposition == "confirmed_non_security_bug"
        assert result.is_issue is True


# ---------------------------------------------------------------------------
# Disposition: hardening_observation
# ---------------------------------------------------------------------------


class TestHardeningObservation:
    def test_core_pass_oracle_triggered_no_security(self):
        """Core pass, oracle triggered, no security -> hardening_observation."""
        checklist = _all_core_pass(
            security_impact_confirmed=False,
            oracle_triggered_or_sanitizer_hit=True,
        )
        result = evaluate_proof(checklist)

        assert result.disposition == "hardening_observation"
        assert result.is_issue is True
        assert any("oracle" in r or "sanitizer" in r for r in result.reasoning)


# ---------------------------------------------------------------------------
# Disposition: research_lead (core gates fail)
# ---------------------------------------------------------------------------


class TestResearchLead:
    def test_target_not_real(self):
        """target_real=False -> research_lead (non-issue)."""
        checklist = _all_core_pass(target_real=False)
        result = evaluate_proof(checklist)

        assert result.disposition is None
        assert result.analysis_outcome == "research_lead"
        assert result.is_issue is False
        assert any("target_real" in r for r in result.reasoning)

    def test_harness_not_validated(self):
        """harness_validated=False -> research_lead (non-issue)."""
        checklist = _all_core_pass(harness_validated=False)
        result = evaluate_proof(checklist)

        assert result.disposition is None
        assert result.analysis_outcome == "research_lead"
        assert result.is_issue is False
        assert any("harness_validated" in r for r in result.reasoning)

    def test_real_code_not_reached(self):
        """real_code_reached=False -> research_lead (non-issue)."""
        checklist = _all_core_pass(real_code_reached=False)
        result = evaluate_proof(checklist)

        assert result.disposition is None
        assert result.analysis_outcome == "research_lead"
        assert result.is_issue is False
        assert any("real_code_reached" in r for r in result.reasoning)

    def test_not_reproduced_cleanly(self):
        """reproduced_cleanly=False -> research_lead (non-issue)."""
        checklist = _all_core_pass(reproduced_cleanly=False)
        result = evaluate_proof(checklist)

        assert result.disposition is None
        assert result.analysis_outcome == "research_lead"
        assert result.is_issue is False
        assert any("reproduced_cleanly" in r for r in result.reasoning)

    def test_minimization_not_attempted(self):
        """artifact_minimization_attempted=False -> research_lead (non-issue)."""
        checklist = _all_core_pass(artifact_minimization_attempted=False)
        result = evaluate_proof(checklist)

        assert result.disposition is None
        assert result.analysis_outcome == "research_lead"
        assert result.is_issue is False
        assert any("artifact_minimization_attempted" in r for r in result.reasoning)

    def test_is_harness_artifact(self):
        """not_harness_artifact=False -> research_lead (non-issue)."""
        checklist = _all_core_pass(not_harness_artifact=False)
        result = evaluate_proof(checklist)

        assert result.disposition is None
        assert result.analysis_outcome == "research_lead"
        assert result.is_issue is False
        assert any("not_harness_artifact" in r for r in result.reasoning)

    def test_is_test_only(self):
        """not_test_only=False -> research_lead (non-issue)."""
        checklist = _all_core_pass(not_test_only=False)
        result = evaluate_proof(checklist)

        assert result.disposition is None
        assert result.analysis_outcome == "research_lead"
        assert result.is_issue is False
        assert any("not_test_only" in r for r in result.reasoning)

    def test_multiple_core_gates_fail(self):
        """Multiple core gates failing -> research_lead with multiple reasons."""
        checklist = ProofChecklist(
            target_real=False,
            harness_validated=False,
            real_code_reached=False,
            reproduced_cleanly=False,
            artifact_minimization_attempted=False,
            not_harness_artifact=False,
            not_test_only=False,
        )
        result = evaluate_proof(checklist)

        assert result.disposition is None
        assert result.analysis_outcome == "research_lead"
        assert result.is_issue is False
        assert len(result.reasoning) == 7

    def test_security_confirmed_but_core_fails(self):
        """Even with security_impact_confirmed, failing core -> research_lead."""
        checklist = _all_core_pass(
            target_real=False,
            security_impact_confirmed=True,
        )
        result = evaluate_proof(checklist)

        assert result.disposition is None
        assert result.analysis_outcome == "research_lead"
        assert result.is_issue is False

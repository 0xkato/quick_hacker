from __future__ import annotations

from dataclasses import replace

from unittest.mock import patch

import pytest

from models.schemas import ChecklistItem, ChecklistStatus, Disposition, Finding, ProofChecklist
from services.finding_triage_service import FindingTriageService
from services.strict_classifier import ClassificationResult


def test_triage_gates_repo_checkout_when_untrusted_repo_content_disabled(tmp_path):
    triage_service = FindingTriageService()

    finding = Finding(
        id="f-1",
        agent_id="agent-1",
        repo_id="proj-1",
        severity="high",
        title="Command injection via shell=True",
        description="Tooling uses shell=True with repo-derived input.",
        file_path="scripts/build.sh",
        line_start=10,
        vulnerability_type="command_injection",
        confidence=0.9,
        created_at="2026-01-12T00:00:00Z",
        metadata={
            "context": {
                "input_channel": "repo_checkout",
                "input_channel_deterministic": True,
            }
        },
    )

    classification = ClassificationResult(
        disposition=Disposition.VALID_SECURITY_ISSUE,
        classification_confidence=90,
        exploit_confidence=90,
        proof_checklist=ProofChecklist(
            source_controlled_input=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="test"),
            sink_present=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="test"),
            dataflow_evidenced=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="test"),
            reachable=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="test"),
            boundary_crossed=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="test"),
            not_only_misconfig=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="test"),
            security_control_bypassed=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="test"),
        ),
        reasoning=["ok"],
        category=None,
    )

    class FakeGatherer:
        def __init__(self, repo_root: str, budgets):
            self.repo_root = repo_root
            self.budgets = budgets

        def gather(self, finding: Finding):
            from services.evidence_gatherer import EvidenceResult

            return EvidenceResult(
                snippet="",
                symbol_info=None,
                framework=None,
                matches=[],
                ssrf_analysis=None,
                timed_out=False,
            )

    class FakeClassifier:
        def classify(self, finding: Finding, evidence):
            return replace(classification)

    threat_model_profile = {
        "execution_contexts": ["product_runtime", "server_runtime"],
        "attacker_capabilities": ["remote_network", "remote_web_content", "untrusted_file_input"],
        "assets": ["user_data"],
    }

    with (
        patch("services.finding_triage_service.EvidenceGatherer", FakeGatherer),
        patch("services.finding_triage_service.StrictClassifier", FakeClassifier),
    ):
        result = triage_service.triage_findings(
            repo_root=str(tmp_path),
            findings=[finding],
            policy_version="1.0.0",
            budgets=None,
            threat_model_profile=threat_model_profile,
        )

    triaged = result.triaged_findings[0]
    assert triaged.disposition == Disposition.HARDENING
    assert triaged.proof_checklist is not None
    assert triaged.proof_checklist.source_controlled_input.status == ChecklistStatus.DISPROVEN
    assert "disabled_by_profile" in triaged.proof_checklist.source_controlled_input.reason


from __future__ import annotations

from dataclasses import replace

from unittest.mock import patch

import pytest

from models.schemas import ChecklistItem, ChecklistStatus, Disposition, Finding, ProofChecklist, InputChannel
from services.finding_triage_service import FindingTriageService
from services.strict_classifier import ClassificationResult
from services.threat_model_gating import derive_allowed_input_channels


# === Unit Tests for derive_allowed_input_channels ===

def test_derive_allowed_no_profile_allows_all():
    """No threat model profile = no gating, all channels allowed."""
    allowed = derive_allowed_input_channels(None)
    assert allowed == set(InputChannel)


def test_derive_allowed_empty_profile_only_unknown():
    """Empty profile (no capabilities) = only unknown allowed."""
    profile = {"attacker_capabilities": []}
    allowed = derive_allowed_input_channels(profile)
    assert allowed == {InputChannel.unknown}


def test_derive_allowed_remote_network():
    """remote_network capability enables network channel."""
    profile = {"attacker_capabilities": ["remote_network"]}
    allowed = derive_allowed_input_channels(profile)
    assert InputChannel.network in allowed
    assert InputChannel.unknown in allowed
    assert InputChannel.repo_checkout not in allowed


def test_derive_allowed_untrusted_file_input():
    """untrusted_file_input capability enables file_input channel."""
    profile = {"attacker_capabilities": ["untrusted_file_input"]}
    allowed = derive_allowed_input_channels(profile)
    assert InputChannel.file_input in allowed
    assert InputChannel.unknown in allowed
    assert InputChannel.network not in allowed


def test_derive_allowed_untrusted_repo_content():
    """untrusted_repo_content capability enables repo_checkout channel."""
    profile = {"attacker_capabilities": ["untrusted_repo_content"]}
    allowed = derive_allowed_input_channels(profile)
    assert InputChannel.repo_checkout in allowed
    assert InputChannel.unknown in allowed
    assert InputChannel.network not in allowed


def test_derive_allowed_multiple_capabilities():
    """Multiple capabilities enable multiple channels."""
    profile = {
        "attacker_capabilities": [
            "remote_network",
            "untrusted_file_input",
            "remote_web_content",
        ]
    }
    allowed = derive_allowed_input_channels(profile)
    assert InputChannel.network in allowed
    assert InputChannel.file_input in allowed
    assert InputChannel.web_content in allowed
    assert InputChannel.unknown in allowed
    assert InputChannel.repo_checkout not in allowed
    assert InputChannel.ci_artifact not in allowed


def test_derive_allowed_unknown_capability_ignored():
    """Unknown capabilities are silently ignored."""
    profile = {
        "attacker_capabilities": [
            "remote_network",
            "made_up_capability",
        ]
    }
    allowed = derive_allowed_input_channels(profile)
    assert InputChannel.network in allowed
    assert InputChannel.unknown in allowed
    assert len(allowed) == 2  # network + unknown


def test_derive_allowed_local_unprivileged():
    """local_unprivileged_user capability enables local_unprivileged channel."""
    profile = {"attacker_capabilities": ["local_unprivileged_user"]}
    allowed = derive_allowed_input_channels(profile)
    assert InputChannel.local_unprivileged in allowed
    assert InputChannel.unknown in allowed
    assert len(allowed) == 2


# === Integration Test ===

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
            from models.schemas import Evidence

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
                # Set input_channel to repo_checkout (deterministic)
                input_channel=InputChannel.repo_checkout,
                input_channel_deterministic=True,
                input_channel_signals=["repo_content_ingested", "repo_content_read_as_data"],
                input_channel_reason="Repo checkout detected",
            )

    threat_model_profile = {
        "execution_contexts": ["product_runtime", "server_runtime"],
        "attacker_capabilities": ["remote_network", "remote_web_content", "untrusted_file_input"],
        "assets": ["user_data"],
    }

    # Use real StrictClassifier so gating actually happens
    with patch("services.finding_triage_service.EvidenceGatherer", FakeGatherer):
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


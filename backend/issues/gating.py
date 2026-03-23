"""Issue gating -- evaluate proof checklists to determine issue disposition.

Takes a ProofChecklist (from campaign schemas) and returns a gating result
indicating whether the artifact should be promoted to a confirmed issue,
a non-security bug, a hardening observation, or a research lead.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from models.campaign_schemas import ProofChecklist


@dataclass
class IssueGatingResult:
    """Result of evaluating a proof checklist for issue promotion.

    When ``is_issue`` is True, ``disposition`` is set to a valid
    IssueDisposition value (confirmed_security_issue,
    confirmed_non_security_bug, hardening_observation).

    When ``is_issue`` is False, ``disposition`` is None and
    ``analysis_outcome`` carries the non-issue classification
    (e.g. "research_lead", "by_design").
    """

    disposition: str | None
    # One of: confirmed_security_issue, confirmed_non_security_bug,
    #         hardening_observation -- or None if not an issue.

    analysis_outcome: str | None = None
    # "research_lead" or "by_design" for non-issues; None for issues.

    reasoning: list[str] = field(default_factory=list)

    is_issue: bool = False
    # True if disposition is one of: confirmed_security_issue,
    #   confirmed_non_security_bug, hardening_observation


def evaluate_proof(checklist: ProofChecklist) -> IssueGatingResult:
    """Evaluate a ProofChecklist and return the gating result.

    Decision logic:
    1. If core gates do not pass -> research_lead (not yet an issue)
    2. If core gates pass AND security_impact_confirmed -> confirmed_security_issue
    3. If core gates pass AND security_impact_confirmed=False
       AND oracle_triggered_or_sanitizer_hit -> hardening_observation
    4. If core gates pass AND security_impact_confirmed=False -> confirmed_non_security_bug
    """
    reasoning: list[str] = []

    # Gate 1: Check core gates
    if not checklist.core_gates_pass():
        # Report which core gates failed
        if not checklist.target_real:
            reasoning.append("target_real gate failed: target not validated as real")
        if not checklist.harness_validated:
            reasoning.append("harness_validated gate failed: harness not validated")
        if not checklist.real_code_reached:
            reasoning.append("real_code_reached gate failed: real code path not confirmed")
        if not checklist.reproduced_cleanly:
            reasoning.append("reproduced_cleanly gate failed: artifact not cleanly reproduced")
        if not checklist.artifact_minimization_attempted:
            reasoning.append("artifact_minimization_attempted gate failed: minimization not attempted")
        if not checklist.not_harness_artifact:
            reasoning.append("not_harness_artifact gate failed: appears to be a harness artifact")
        if not checklist.not_test_only:
            reasoning.append("not_test_only gate failed: appears to be test-only code")

        return IssueGatingResult(
            disposition=None,
            analysis_outcome="research_lead",
            reasoning=reasoning,
            is_issue=False,
        )

    # Gate 2: Core gates pass -- check security impact
    reasoning.append("all 7 core gates passed")

    if checklist.is_security_issue():
        reasoning.append("security_impact_confirmed: true -> confirmed security issue")
        return IssueGatingResult(
            disposition="confirmed_security_issue",
            reasoning=reasoning,
            is_issue=True,
        )

    # Gate 3: Core passes, no security impact, but oracle triggered
    if checklist.oracle_triggered_or_sanitizer_hit:
        reasoning.append(
            "security_impact_confirmed: false, but oracle/sanitizer triggered "
            "-> hardening observation"
        )
        return IssueGatingResult(
            disposition="hardening_observation",
            reasoning=reasoning,
            is_issue=True,
        )

    # Gate 4: Core passes, no security impact, no oracle trigger
    reasoning.append(
        "security_impact_confirmed: false, no oracle/sanitizer trigger "
        "-> confirmed non-security bug"
    )
    return IssueGatingResult(
        disposition="confirmed_non_security_bug",
        reasoning=reasoning,
        is_issue=True,
    )

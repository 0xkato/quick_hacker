"""Policy evaluation for VRP acceptance criteria."""
import re
from models.schemas import (
    Finding, Evidence, TriagePolicy, PolicyDecision, PathClassification,
    Disposition, VulnerabilityCategory, ChecklistStatus, InputChannel,
    PolicyEvaluationResult
)
from services.strict_classifier import ClassificationResult


class PolicyEvaluator:
    """
    Evaluate findings against TriagePolicy.

    Runs after StrictClassifier to apply VRP-specific gates and overrides.
    """

    def evaluate(
        self,
        finding: Finding,
        evidence: Evidence,
        classification: ClassificationResult,
        policy: TriagePolicy
    ) -> PolicyEvaluationResult:
        """
        Evaluate finding against policy.

        Args:
            finding: Finding with path_classification attached
            evidence: Evidence bundle
            classification: Classification result from StrictClassifier
            policy: Triage policy

        Returns:
            PolicyEvaluationResult with decision and reasoning
        """
        gate_results = {}
        reasoning = []

        # Get path classification (from pre-filter)
        path_class = getattr(finding, 'path_classification', PathClassification.unknown)

        # For now, just map disposition to decision
        # Gates will be added in next tasks
        decision = self._map_disposition_to_decision(
            classification.disposition, policy, gate_results
        )

        if not reasoning:
            reasoning = ["Classification matches policy criteria"]

        return PolicyEvaluationResult(
            decision=decision,
            path_classification=path_class,
            gate_results=gate_results,
            reasoning=reasoning,
            original_disposition=classification.disposition,
            overridden=False
        )

    def _map_disposition_to_decision(
        self,
        disposition: Disposition,
        policy: TriagePolicy,
        gate_results: dict[str, bool]
    ) -> PolicyDecision:
        """Map StrictClassifier disposition to PolicyDecision."""
        # VALID → REPORT_VRP (high confidence)
        if disposition == Disposition.VALID_SECURITY_ISSUE:
            return PolicyDecision.REPORT_SECURITY_VRP

        # BUG → REPORT_LOW (valid but lower confidence)
        if disposition == Disposition.BUG:
            return PolicyDecision.REPORT_SECURITY_LOW_CONFIDENCE

        # HARDENING → check policy
        if disposition == Disposition.HARDENING:
            if policy.report_hardening:
                return PolicyDecision.HARDENING_ONLY
            return PolicyDecision.DO_NOT_REPORT

        # BY_DESIGN → check policy
        if disposition == Disposition.BY_DESIGN:
            if policy.report_by_design:
                return PolicyDecision.HARDENING_ONLY
            return PolicyDecision.DO_NOT_REPORT

        # SPECULATIVE, MISCONFIGURATION → DO_NOT_REPORT
        return PolicyDecision.DO_NOT_REPORT

"""Protocol-aware reportability evaluation service."""

from dataclasses import dataclass
from typing import Optional
import re

from models.schemas import (
    Finding,
    Evidence,
    ProtocolPolicy,
    SubmissionResult,
    SubmissionDecision,
    Disposition,
    VulnerabilityCategory,
    InputChannel,
    ChecklistStatus,
)

# Import ClassificationResult from strict_classifier
from services.strict_classifier import ClassificationResult


@dataclass
class EvaluationContext:
    """Bundled context for protocol evaluation."""
    finding: Finding
    evidence: Evidence
    classification: ClassificationResult
    policy: ProtocolPolicy


class ProtocolEvaluator:
    """
    Protocol-aware reportability evaluation.

    Applies protocol-specific quality gates to determine if findings
    are worth submitting to bug bounties, VRPs, or disclosure programs.
    """

    def __init__(self):
        # Category-specific evaluators
        self.category_evaluators = {
            VulnerabilityCategory.COMMAND_INJECTION: self._evaluate_command_injection,
            VulnerabilityCategory.SQL_INJECTION: self._evaluate_sql_injection,
        }

    def evaluate(
        self,
        finding: Finding,
        evidence: Evidence,
        classification: ClassificationResult,
        policy: ProtocolPolicy
    ) -> tuple[SubmissionResult, Optional[Disposition]]:
        """
        Evaluate finding for reportability under protocol rules.

        Returns:
            (SubmissionResult, Optional[new_disposition])
            If new_disposition is not None, caller should update Finding.disposition
        """
        ctx = EvaluationContext(finding, evidence, classification, policy)

        # Gate 1: Disposition filtering
        if classification.disposition not in policy.min_disposition_to_submit:
            return self._reject_by_disposition(ctx)

        # Gate 2: Proof checklist completeness
        checklist_gate = self._check_checklist_quality(ctx)
        if checklist_gate is not None:
            return checklist_gate

        # Gate 3: Attacker model realism
        attacker_model_gate = self._check_attacker_model(ctx)
        if attacker_model_gate is not None:
            return attacker_model_gate

        # Gate 4: Category-specific validation
        category_gate = self._apply_category_rules(ctx)
        if category_gate is not None:
            return category_gate

        # Gate 5: Local-only bug filtering
        local_bug_gate = self._check_local_boundary(ctx)
        if local_bug_gate is not None:
            return local_bug_gate

        # All gates passed
        return self._accept_for_submission(ctx)

    def _reject_by_disposition(
        self, ctx: EvaluationContext
    ) -> tuple[SubmissionResult, None]:
        """Gate 1: Disposition doesn't meet protocol threshold."""
        # Placeholder - will be implemented in Task 2.2
        pass

    def _check_checklist_quality(
        self, ctx: EvaluationContext
    ) -> Optional[tuple[SubmissionResult, Optional[Disposition]]]:
        """Gate 2: Verify proof checklist has sufficient PROVEN items."""
        # Placeholder - will be implemented in Task 2.2
        pass

    def _check_attacker_model(
        self, ctx: EvaluationContext
    ) -> Optional[tuple[SubmissionResult, Optional[Disposition]]]:
        """Gate 3: Verify realistic attacker model."""
        # Placeholder - will be implemented in Task 2.2
        pass

    def _apply_category_rules(
        self, ctx: EvaluationContext
    ) -> Optional[tuple[SubmissionResult, Optional[Disposition]]]:
        """Gate 4: Apply category-specific validation rules."""
        # Placeholder - will be implemented in Task 2.3
        pass

    def _check_local_boundary(
        self, ctx: EvaluationContext
    ) -> Optional[tuple[SubmissionResult, Optional[Disposition]]]:
        """Gate 5: Check if local-only bugs have automation boundary."""
        # Placeholder - will be implemented in Task 2.2
        pass

    def _accept_for_submission(
        self, ctx: EvaluationContext
    ) -> tuple[SubmissionResult, None]:
        """All gates passed - recommend submission."""
        # Placeholder - will be implemented in Task 2.2
        pass

    def _evaluate_command_injection(
        self, ctx: EvaluationContext
    ) -> Optional[tuple[SubmissionResult, Optional[Disposition]]]:
        """Command injection specific rules."""
        # Placeholder - will be implemented in Task 2.3
        pass

    def _evaluate_sql_injection(
        self, ctx: EvaluationContext
    ) -> Optional[tuple[SubmissionResult, Optional[Disposition]]]:
        """SQL injection specific rules."""
        # Placeholder - will be implemented in Task 2.3
        pass

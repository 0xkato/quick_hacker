"""Protocol-aware reportability evaluation service."""

from dataclasses import dataclass
from typing import Optional

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
    ) -> Optional[tuple[SubmissionResult, Optional[Disposition]]]:
        """Gate 1: Disposition doesn't meet protocol threshold."""
        result = SubmissionResult(
            protocol_id=ctx.policy.id,
            decision=SubmissionDecision.DONT_SUBMIT,
            reasons=[
                f"Disposition is {ctx.classification.disposition.value}",
                f"Protocol requires: {[d.value for d in ctx.policy.min_disposition_to_submit]}",
                "Not meeting reportability bar for this protocol"
            ],
            missing_evidence=[],
            suggested_next_steps=[
                "Review finding manually if you believe it's reportable",
                "Consider switching to a more permissive protocol"
            ]
        )
        return (result, None)

    def _check_checklist_quality(
        self, ctx: EvaluationContext
    ) -> Optional[tuple[SubmissionResult, Optional[Disposition]]]:
        """Gate 2: Verify proof checklist has sufficient PROVEN items."""
        checklist = ctx.classification.proof_checklist

        # Count PROVEN items
        proven_count = sum(1 for item in [
            checklist.source_controlled_input,
            checklist.sink_present,
            checklist.dataflow_evidenced,
            checklist.reachable,
            checklist.boundary_crossed,
            checklist.not_only_misconfig,
        ] if item.status == ChecklistStatus.PROVEN and item.value)

        # Check if meets minimum
        if proven_count < ctx.policy.min_checklist_proven_count:
            # Downgrade disposition
            new_disposition = Disposition.HARDENING
            result = SubmissionResult(
                protocol_id=ctx.policy.id,
                decision=SubmissionDecision.DONT_SUBMIT,
                reasons=[
                    f"Only {proven_count}/{ctx.policy.min_checklist_proven_count} checklist items proven",
                    "Insufficient evidence for submission under this protocol",
                    f"Disposition downgraded: {ctx.classification.disposition.value} → {new_disposition.value}"
                ],
                disposition_modified=True,
                disposition_reason="Insufficient proof for protocol requirements"
            )
            return (result, new_disposition)

        # Check for UNKNOWN items if policy is strict
        if not ctx.policy.allow_unknown_in_checklist:
            unknown_items = [
                name for name, item in [
                    ("source", checklist.source_controlled_input),
                    ("sink", checklist.sink_present),
                    ("dataflow", checklist.dataflow_evidenced),
                    ("reachability", checklist.reachable),
                    ("boundary", checklist.boundary_crossed),
                    ("not_misconfig", checklist.not_only_misconfig),
                ] if item.status == ChecklistStatus.UNKNOWN
            ]

            if unknown_items:
                result = SubmissionResult(
                    protocol_id=ctx.policy.id,
                    decision=SubmissionDecision.NEEDS_MORE_INFO,
                    reasons=[
                        f"Protocol requires all items proven",
                        f"Unknown items: {', '.join(unknown_items)}"
                    ],
                    missing_evidence=unknown_items,
                    suggested_next_steps=["Run evidence quest to gather missing proof"],
                    quest_run=True
                )
                return (result, None)

        return None  # Passed this gate

    def _check_attacker_model(
        self, ctx: EvaluationContext
    ) -> Optional[tuple[SubmissionResult, Optional[Disposition]]]:
        """Gate 3: Verify realistic attacker model."""
        if not ctx.policy.require_realistic_attacker_model:
            return None

        # Check for social engineering markers
        description_lower = ctx.finding.description.lower()
        social_eng_markers = [
            "user must paste",
            "trick the user",
            "convince user to",
            "user needs to manually",
            "requires user to open",
            "phishing",
            "social engineering"
        ]

        if any(marker in description_lower for marker in social_eng_markers):
            if ctx.policy.reject_social_engineering_only:
                new_disposition = Disposition.HARDENING
                result = SubmissionResult(
                    protocol_id=ctx.policy.id,
                    decision=SubmissionDecision.DONT_SUBMIT,
                    reasons=[
                        "Attack requires social engineering / user cooperation",
                        "No realistic remote attacker scenario",
                        f"Disposition downgraded: {ctx.classification.disposition.value} → {new_disposition.value}"
                    ],
                    disposition_modified=True,
                    disposition_reason="Social engineering dependency - not reportable"
                )
                return (result, new_disposition)

        return None

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
        if not ctx.policy.require_cross_boundary_for_local_bugs:
            return None

        # Check if input channel is local without automation
        if ctx.evidence.input_channel == InputChannel.LOCAL_UNPRIVILEGED:
            # Look for automation signals
            automation_signals = [
                "route_registration",
                "ci_artifact",
                "repo_checkout",
                "webhook",
                "scheduled_task"
            ]

            has_automation = any(
                signal in ctx.evidence.input_channel_signals
                for signal in automation_signals
            )

            if not has_automation:
                result = SubmissionResult(
                    protocol_id=ctx.policy.id,
                    decision=SubmissionDecision.NEEDS_MORE_INFO,
                    reasons=[
                        "Input channel is local_unprivileged without automation boundary",
                        "Need evidence that this is reachable from untrusted context"
                    ],
                    missing_evidence=[
                        "Is this tool invoked automatically (CI/build farm/hooks)?",
                        "Is the input sourced from untrusted repo content or artifacts?",
                        "Show the call path where untrusted data reaches this sink"
                    ],
                    suggested_next_steps=[
                        "Run evidence quest to trace call paths",
                        "Check CI/CD configuration for automatic invocations"
                    ],
                    quest_run=True
                )
                return (result, None)

        return None

    def _accept_for_submission(
        self, ctx: EvaluationContext
    ) -> Optional[tuple[SubmissionResult, Optional[Disposition]]]:
        """All gates passed - recommend submission."""
        result = SubmissionResult(
            protocol_id=ctx.policy.id,
            decision=SubmissionDecision.SUBMIT,
            reasons=[
                f"All protocol gates passed for {ctx.policy.display_name}",
                f"Disposition: {ctx.classification.disposition.value}",
                f"Classification confidence: {ctx.classification.classification_confidence}%",
                "Ready for disclosure/reporting"
            ],
            missing_evidence=[],
            suggested_next_steps=[
                "Generate final report with proof checklist",
                "Include attack scenario and prerequisites"
            ]
        )
        return (result, None)

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

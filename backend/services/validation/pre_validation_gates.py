"""Pre-validation gates to filter findings before expensive LLM validation.

These fast, rule-based gates catch obvious rejects to save API costs:
1. Disposition filter: Skip findings with low-severity dispositions
2. Checklist quality: Require minimum PROVEN items in proof checklist
3. Social engineering detection: Filter social-engineering-only findings if policy requires
"""
from typing import Optional
from datetime import UTC, datetime

from models.schemas import (
    Finding,
    Evidence,
    ValidationResult,
    ProtocolPolicy,
    Disposition,
    ChecklistStatus,
)
from services.classification.classifier import ClassificationResult


class PreValidationGates:
    """
    Pre-validation gates that filter findings with fast rule-based checks.

    These gates run BEFORE expensive LLM validation to save API costs.
    Returns ValidationResult if finding should be filtered, None if it passes.
    """

    def check_gates(
        self,
        finding: Finding,
        evidence: Evidence,
        classification: ClassificationResult,
        protocol_policy: ProtocolPolicy,
    ) -> Optional[ValidationResult]:
        """
        Run all pre-validation gates.

        Args:
            finding: The finding to check
            evidence: Evidence bundle for the finding
            classification: Classification result with disposition and checklist
            protocol_policy: Protocol policy with submission rules

        Returns:
            ValidationResult if finding should be filtered (rejected), None if passes all gates
        """
        # Gate 1: Disposition filter
        disposition_result = self._check_disposition_gate(classification, protocol_policy)
        if disposition_result:
            return disposition_result

        # Gate 2: Checklist quality
        checklist_result = self._check_checklist_quality_gate(classification, protocol_policy)
        if checklist_result:
            return checklist_result

        # Gate 3: Social engineering detection
        social_eng_result = self._check_social_engineering_gate(finding, classification, protocol_policy)
        if social_eng_result:
            return social_eng_result

        # All gates passed
        return None

    def _check_disposition_gate(
        self,
        classification: ClassificationResult,
        protocol_policy: ProtocolPolicy,
    ) -> Optional[ValidationResult]:
        """
        Gate 1: Filter findings with dispositions not eligible for submission.

        Args:
            classification: Classification result with disposition
            protocol_policy: Protocol policy with min_disposition_to_submit

        Returns:
            ValidationResult if filtered, None if passes
        """
        if classification.disposition not in protocol_policy.min_disposition_to_submit:
            return ValidationResult(
                is_valid=False,
                reasoning=[
                    f"Disposition '{classification.disposition.value}' is not eligible for submission",
                    f"Protocol '{protocol_policy.display_name}' requires one of: {', '.join(d.value for d in protocol_policy.min_disposition_to_submit)}",
                    "Filtered by pre-validation disposition gate",
                ],
                categories=["pre_validation_gate", "disposition_filter"],
                confidence=100,
                timestamp=datetime.now(UTC),
            )
        return None

    def _check_checklist_quality_gate(
        self,
        classification: ClassificationResult,
        protocol_policy: ProtocolPolicy,
    ) -> Optional[ValidationResult]:
        """
        Gate 2: Require minimum number of PROVEN checklist items.

        Args:
            classification: Classification result with proof checklist
            protocol_policy: Protocol policy with min_checklist_proven_count

        Returns:
            ValidationResult if filtered, None if passes
        """
        checklist = classification.proof_checklist

        # Count PROVEN items
        proven_count = sum(
            1 for item in [
                checklist.source_controlled_input,
                checklist.sink_present,
                checklist.dataflow_evidenced,
                checklist.reachable,
                checklist.boundary_crossed,
                checklist.not_only_misconfig,
            ]
            if item and item.status == ChecklistStatus.PROVEN
        )

        # Check if security_control_bypassed is PROVEN (if present)
        if checklist.security_control_bypassed and checklist.security_control_bypassed.status == ChecklistStatus.PROVEN:
            proven_count += 1

        min_required = protocol_policy.min_checklist_proven_count

        if proven_count < min_required:
            return ValidationResult(
                is_valid=False,
                reasoning=[
                    f"Insufficient evidence: only {proven_count} PROVEN checklist items (requires {min_required})",
                    "Finding lacks sufficient proof to meet submission standards",
                    "Filtered by pre-validation checklist quality gate",
                ],
                categories=["pre_validation_gate", "insufficient_evidence"],
                confidence=95,
                timestamp=datetime.now(UTC),
            )

        # Check for UNKNOWN items if policy doesn't allow them
        if not protocol_policy.allow_unknown_in_checklist:
            has_unknown = any(
                item and item.status == ChecklistStatus.UNKNOWN
                for item in [
                    checklist.source_controlled_input,
                    checklist.sink_present,
                    checklist.dataflow_evidenced,
                    checklist.reachable,
                    checklist.boundary_crossed,
                    checklist.not_only_misconfig,
                    checklist.security_control_bypassed,
                ]
            )

            if has_unknown:
                return ValidationResult(
                    is_valid=False,
                    reasoning=[
                        "Checklist contains UNKNOWN items",
                        f"Protocol '{protocol_policy.display_name}' requires all items to be PROVEN or DISPROVEN",
                        "Filtered by pre-validation checklist quality gate",
                    ],
                    categories=["pre_validation_gate", "unknown_evidence"],
                    confidence=95,
                    timestamp=datetime.now(UTC),
                )

        return None

    def _check_social_engineering_gate(
        self,
        finding: Finding,
        classification: ClassificationResult,
        protocol_policy: ProtocolPolicy,
    ) -> Optional[ValidationResult]:
        """
        Gate 3: Filter social-engineering-only findings if policy requires.

        Social engineering indicators:
        - Keywords like "phishing", "social engineering", "user trick", "user manipulation"
        - Requires user interaction without technical exploit

        Args:
            finding: The finding to check
            classification: Classification result
            protocol_policy: Protocol policy with reject_social_engineering_only

        Returns:
            ValidationResult if filtered, None if passes
        """
        if not protocol_policy.reject_social_engineering_only:
            return None

        # Check for social engineering keywords
        social_eng_keywords = [
            "social engineering",
            "phishing",
            "user trick",
            "user manipulation",
            "convince user",
            "trick user",
            "deceive user",
            "user deception",
        ]

        text_to_check = " ".join([
            finding.title.lower(),
            finding.description.lower(),
            finding.attack_scenario.lower() if finding.attack_scenario else "",
        ])

        has_social_eng_keywords = any(keyword in text_to_check for keyword in social_eng_keywords)

        if has_social_eng_keywords:
            # Check if there's a technical sink present
            checklist = classification.proof_checklist
            has_technical_sink = (
                checklist.sink_present and
                checklist.sink_present.status == ChecklistStatus.PROVEN
            )

            # If social engineering keywords present but no technical sink, filter it
            if not has_technical_sink:
                return ValidationResult(
                    is_valid=False,
                    reasoning=[
                        "Finding appears to be social-engineering-only (no technical sink)",
                        f"Protocol '{protocol_policy.display_name}' rejects social engineering vulnerabilities",
                        "Filtered by pre-validation social engineering gate",
                    ],
                    categories=["pre_validation_gate", "social_engineering"],
                    confidence=85,
                    timestamp=datetime.now(UTC),
                )

        return None

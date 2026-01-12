"""
Finding triage service - orchestrates the triage workflow.

Runs synchronously (called via asyncio.to_thread from agent orchestrator).
GUARANTEE: triaged_count == raw_count (never drops findings)
"""

import hashlib
import time
from datetime import datetime
from typing import Optional

from models.schemas import (
    Finding,
    Disposition,
    BudgetConfig,
    TriageResult,
    TriageMetrics,
    ChecklistStatus,
    ChecklistItem
)
from services.evidence_gatherer import EvidenceGatherer
from services.strict_classifier import StrictClassifier


class FindingTriageService:
    """
    Orchestrates the triage workflow.

    Responsibilities:
    - Batch processing with timeout
    - Coordinate gatherer + classifier
    - Generate batch_id
    - Guarantee: triaged_count == raw_count
    """

    def __init__(self):
        pass

    def triage_findings(
        self,
        repo_root: str,
        findings: list[Finding],
        policy_version: str = "1.0.0",
        budgets: Optional[BudgetConfig] = None
    ) -> TriageResult:
        """
        Triage a batch of findings.
        GUARANTEE: len(triaged_findings) == len(findings)
        """
        if not findings:
            return TriageResult(
                triaged_findings=[],
                reportable_findings=[],
                metrics=TriageMetrics(
                    raw_count=0,
                    triaged_count=0,
                    reportable_count=0,
                    by_disposition={},
                    timeout_count=0,
                    timeout_rate=0.0
                ),
                batch_id=self._generate_batch_id()
            )

        batch_id = self._generate_batch_id()
        batch_start = time.time()
        budgets = budgets or BudgetConfig()

        gatherer = EvidenceGatherer(repo_root, budgets)
        classifier = StrictClassifier()

        triaged = []
        reportable = []
        timeout_count = 0

        for idx, finding in enumerate(findings):
            # Check batch timeout
            elapsed_ms = (time.time() - batch_start) * 1000
            remaining_findings = len(findings) - len(triaged)

            if elapsed_ms > budgets.batch_ms:
                # Mark remaining findings as SPECULATIVE with timeout
                for remaining_finding in findings[idx:]:
                    triaged_finding = self._mark_as_timeout(
                        remaining_finding, batch_id, policy_version
                    )
                    triaged.append(triaged_finding)

                timeout_count += remaining_findings
                break

            try:
                # Gather evidence
                evidence = gatherer.gather(finding)

                # Classify
                classification = classifier.classify(finding, evidence)

                # Attach triage metadata
                triaged_finding = self._attach_triage_metadata(
                    finding, classification, batch_id, policy_version
                )
                triaged.append(triaged_finding)

                # Track reportable
                if classification.disposition in [
                    Disposition.VALID_SECURITY_ISSUE,
                    Disposition.BUG
                ]:
                    reportable.append(triaged_finding)

                # Track timeouts from evidence gathering
                if evidence.timed_out:
                    timeout_count += 1

            except Exception as e:
                # On error, mark as SPECULATIVE
                triaged_finding = self._mark_as_error(
                    finding, batch_id, policy_version, str(e)
                )
                triaged.append(triaged_finding)

        # Verify guarantee
        assert len(triaged) == len(findings), \
            f"Triage dropped findings: {len(findings)} input vs {len(triaged)} output"

        # Build metrics
        metrics = self._build_metrics(findings, triaged, reportable, timeout_count)

        return TriageResult(
            triaged_findings=triaged,
            reportable_findings=reportable,
            metrics=metrics,
            batch_id=batch_id
        )

    def _generate_batch_id(self) -> str:
        """Generate unique batch ID."""
        timestamp = datetime.utcnow().isoformat()
        hash_input = f"{timestamp}_{time.time()}"
        return hashlib.sha256(hash_input.encode()).hexdigest()[:16]

    def _mark_as_timeout(
        self,
        finding: Finding,
        batch_id: str,
        policy_version: str
    ) -> Finding:
        """Mark a finding as SPECULATIVE due to batch timeout."""
        # Create timeout checklist (all UNKNOWN)
        from models.schemas import ProofChecklist

        timeout_checklist = ProofChecklist(
            source_controlled_input=ChecklistItem(
                value=False,
                status=ChecklistStatus.UNKNOWN,
                reason="Triage timeout - insufficient time for analysis"
            ),
            sink_present=ChecklistItem(
                value=False,
                status=ChecklistStatus.UNKNOWN,
                reason="Triage timeout - insufficient time for analysis"
            ),
            dataflow_evidenced=ChecklistItem(
                value=False,
                status=ChecklistStatus.UNKNOWN,
                reason="Triage timeout - insufficient time for analysis"
            ),
            reachable=ChecklistItem(
                value=False,
                status=ChecklistStatus.UNKNOWN,
                reason="Triage timeout - insufficient time for analysis"
            ),
            boundary_crossed=ChecklistItem(
                value=False,
                status=ChecklistStatus.UNKNOWN,
                reason="Triage timeout - insufficient time for analysis"
            ),
            not_only_misconfig=ChecklistItem(
                value=False,
                status=ChecklistStatus.UNKNOWN,
                reason="Triage timeout - insufficient time for analysis"
            ),
            security_control_bypassed=ChecklistItem(
                value=False,
                status=ChecklistStatus.UNKNOWN,
                reason="Triage timeout - insufficient time for analysis"
            )
        )

        # Copy finding and add triage fields
        triaged = finding.model_copy(deep=True)
        triaged.batch_id = batch_id
        triaged.disposition = Disposition.SPECULATIVE
        triaged.classification_confidence = 0
        triaged.exploit_confidence = None
        triaged.proof_checklist = timeout_checklist
        triaged.reasoning = [
            "Batch timeout - insufficient time for analysis",
            "Marked as SPECULATIVE pending manual review"
        ]
        triaged.triage_policy_version = policy_version
        triaged.triaged_at = datetime.utcnow()

        return triaged

    def _mark_as_error(
        self,
        finding: Finding,
        batch_id: str,
        policy_version: str,
        error_message: str
    ) -> Finding:
        """Mark a finding as SPECULATIVE due to error."""
        from models.schemas import ProofChecklist

        error_checklist = ProofChecklist(
            source_controlled_input=ChecklistItem(
                value=False,
                status=ChecklistStatus.UNKNOWN,
                reason=f"Error during triage: {error_message[:100]}"
            ),
            sink_present=ChecklistItem(
                value=False,
                status=ChecklistStatus.UNKNOWN,
                reason=f"Error during triage: {error_message[:100]}"
            ),
            dataflow_evidenced=ChecklistItem(
                value=False,
                status=ChecklistStatus.UNKNOWN,
                reason=f"Error during triage: {error_message[:100]}"
            ),
            reachable=ChecklistItem(
                value=False,
                status=ChecklistStatus.UNKNOWN,
                reason=f"Error during triage: {error_message[:100]}"
            ),
            boundary_crossed=ChecklistItem(
                value=False,
                status=ChecklistStatus.UNKNOWN,
                reason=f"Error during triage: {error_message[:100]}"
            ),
            not_only_misconfig=ChecklistItem(
                value=False,
                status=ChecklistStatus.UNKNOWN,
                reason=f"Error during triage: {error_message[:100]}"
            )
        )

        triaged = finding.model_copy(deep=True)
        triaged.batch_id = batch_id
        triaged.disposition = Disposition.SPECULATIVE
        triaged.classification_confidence = 0
        triaged.exploit_confidence = None
        triaged.proof_checklist = error_checklist
        triaged.reasoning = [
            f"Error during triage: {error_message[:200]}",
            "Marked as SPECULATIVE pending manual review"
        ]
        triaged.triage_policy_version = policy_version
        triaged.triaged_at = datetime.utcnow()

        return triaged

    def _attach_triage_metadata(
        self,
        finding: Finding,
        classification,
        batch_id: str,
        policy_version: str
    ) -> Finding:
        """Attach triage metadata to finding."""
        triaged = finding.model_copy(deep=True)
        triaged.batch_id = batch_id
        triaged.disposition = classification.disposition
        triaged.classification_confidence = classification.classification_confidence
        triaged.exploit_confidence = classification.exploit_confidence
        triaged.proof_checklist = classification.proof_checklist
        triaged.reasoning = classification.reasoning
        triaged.triage_policy_version = policy_version
        triaged.triaged_at = datetime.utcnow()
        triaged.category = classification.category

        return triaged

    def _build_metrics(
        self,
        raw_findings: list[Finding],
        triaged_findings: list[Finding],
        reportable_findings: list[Finding],
        timeout_count: int
    ) -> TriageMetrics:
        """Build triage metrics."""
        # Count by disposition
        by_disposition = {}
        for finding in triaged_findings:
            disp = finding.disposition.value if finding.disposition else "unknown"
            by_disposition[disp] = by_disposition.get(disp, 0) + 1

        timeout_rate = timeout_count / len(raw_findings) if raw_findings else 0.0

        return TriageMetrics(
            raw_count=len(raw_findings),
            triaged_count=len(triaged_findings),
            reportable_count=len(reportable_findings),
            by_disposition=by_disposition,
            timeout_count=timeout_count,
            timeout_rate=timeout_rate
        )


# Singleton instance
triage_service = FindingTriageService()

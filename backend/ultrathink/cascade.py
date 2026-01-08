"""Ultrathink Hierarchical Verification Cascade orchestrator.

This is the main entry point for ultrathink analysis. It:
1. Takes a potential finding
2. Runs it through all verification gates in sequence
3. Captures full reasoning traces
4. Returns a final verdict with full transparency

The cascade is STRICT: findings must pass ALL gates to be reported.
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Any, Callable

from models.schemas import Finding, UltrathinkGate, Severity
from providers.base_provider import BaseProvider
from .config import UltrathinkConfig, GateConfig
from .thinking import ThinkingEngine
from .gates import (
    BaseGate,
    GateResult,
    TriageGate,
    DeepAnalysisGate,
    DevilsAdvocateGate,
    ProofGeneratorGate,
    FinalGate,
    create_gate,
)


@dataclass
class CascadeResult:
    """Complete result from ultrathink cascade."""

    # The finding being evaluated
    finding: Finding

    # Final verdict
    final_verdict: bool
    final_confidence: float

    # Gate results (in order)
    gate_results: list[GateResult] = field(default_factory=list)

    # Which gate rejected (if any)
    rejected_by: Optional[UltrathinkGate] = None
    rejection_reason: Optional[str] = None

    # Full reasoning traces from all gates
    reasoning_traces: list[str] = field(default_factory=list)

    # Aggregated metadata
    total_thinking_tokens: int = 0
    total_duration_ms: int = 0

    # Evidence collected
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_report(self) -> str:
        """Generate human-readable report of cascade evaluation."""
        lines = [
            "=" * 60,
            "ULTRATHINK CASCADE EVALUATION REPORT",
            "=" * 60,
            f"Finding: {self.finding.title}",
            f"File: {self.finding.file_path}:{self.finding.line_start}",
            f"Severity: {self.finding.severity.value}",
            "",
            "GATE RESULTS:",
            "-" * 40,
        ]

        for gr in self.gate_results:
            status = "PASS" if gr.passed else "FAIL"
            lines.append(f"  {gr.gate.value}: {status} (confidence: {gr.confidence:.2f})")
            lines.append(f"    Reasoning: {gr.reasoning[:100]}...")

        lines.extend([
            "",
            "-" * 40,
            f"FINAL VERDICT: {'REPORT' if self.final_verdict else 'DO NOT REPORT'}",
            f"Final Confidence: {self.final_confidence:.2f}",
        ])

        if self.rejected_by:
            lines.extend([
                f"Rejected By: {self.rejected_by.value}",
                f"Rejection Reason: {self.rejection_reason}",
            ])

        lines.extend([
            "",
            f"Total Thinking Tokens: {self.total_thinking_tokens:,}",
            f"Total Duration: {self.total_duration_ms:,}ms",
            "=" * 60,
        ])

        return "\n".join(lines)


class UltrathinkCascade:
    """Orchestrates the hierarchical verification cascade."""

    def __init__(
        self,
        config: Optional[UltrathinkConfig] = None,
        on_gate_start: Optional[Callable[[UltrathinkGate], None]] = None,
        on_gate_complete: Optional[Callable[[GateResult], None]] = None,
    ):
        self.config = config or UltrathinkConfig()
        self.thinking_engine = ThinkingEngine(config=self.config)
        self.on_gate_start = on_gate_start
        self.on_gate_complete = on_gate_complete

        # Initialize gates
        self.gates: list[BaseGate] = []
        for gate_config in self.config.gates:
            gate_type = UltrathinkGate(gate_config.name)
            gate = create_gate(
                gate_type=gate_type,
                config=gate_config,
                thinking_engine=self.thinking_engine,
            )
            self.gates.append(gate)

    async def evaluate(
        self,
        finding: Finding,
        code_context: str,
        provider: BaseProvider,
        model: str,
    ) -> CascadeResult:
        """
        Run a finding through the full verification cascade.

        Args:
            finding: The potential vulnerability to verify
            code_context: The relevant code
            provider: AI provider to use
            model: Model identifier

        Returns:
            CascadeResult with full evaluation details
        """
        start_time = datetime.utcnow()

        result = CascadeResult(
            finding=finding,
            final_verdict=False,
            final_confidence=0.0,
        )

        gate_results: list[GateResult] = []

        # Run through each gate in sequence
        for gate in self.gates:
            if self.on_gate_start:
                self.on_gate_start(gate.gate_type)

            # Run the gate
            gate_result = await self._run_gate(
                gate=gate,
                finding=finding,
                code_context=code_context,
                provider=provider,
                model=model,
                previous_results=gate_results,
            )

            gate_results.append(gate_result)
            result.gate_results.append(gate_result)

            # Capture reasoning trace
            if gate_result.full_trace:
                result.reasoning_traces.append(
                    f"=== {gate.gate_type.value.upper()} ===\n{gate_result.full_trace}"
                )

            # Track tokens
            if gate_result.thinking_result:
                result.total_thinking_tokens += gate_result.thinking_result.thinking_tokens_used

            if self.on_gate_complete:
                self.on_gate_complete(gate_result)

            # Stop if gate failed
            if not gate_result.passed:
                result.rejected_by = gate.gate_type
                result.rejection_reason = gate_result.reasoning
                break

            # Update evidence from gate metadata
            result.evidence.update(gate_result.metadata)

        # Calculate final verdict
        all_passed = all(gr.passed for gr in gate_results)

        if all_passed and gate_results:
            result.final_verdict = True
            # Final confidence is minimum across all gates
            result.final_confidence = min(gr.confidence for gr in gate_results)

        result.total_duration_ms = int(
            (datetime.utcnow() - start_time).total_seconds() * 1000
        )

        return result

    async def _run_gate(
        self,
        gate: BaseGate,
        finding: Finding,
        code_context: str,
        provider: BaseProvider,
        model: str,
        previous_results: list[GateResult],
    ) -> GateResult:
        """Run a single gate evaluation."""

        # Special handling for FinalGate which needs previous results
        if isinstance(gate, FinalGate):
            return await gate.evaluate(
                finding=finding,
                code_context=code_context,
                provider=provider,
                model=model,
                previous_gates=previous_results,
            )

        return await gate.evaluate(
            finding=finding,
            code_context=code_context,
            provider=provider,
            model=model,
        )

    async def evaluate_batch(
        self,
        findings: list[Finding],
        code_context: str,
        provider: BaseProvider,
        model: str,
        max_concurrent: int = 3,
    ) -> list[CascadeResult]:
        """
        Evaluate multiple findings through the cascade.

        Note: Each finding goes through the full cascade sequentially,
        but multiple findings can be processed concurrently.
        """
        semaphore = asyncio.Semaphore(max_concurrent)

        async def evaluate_with_semaphore(finding: Finding) -> CascadeResult:
            async with semaphore:
                return await self.evaluate(
                    finding=finding,
                    code_context=code_context,
                    provider=provider,
                    model=model,
                )

        tasks = [evaluate_with_semaphore(f) for f in findings]
        return await asyncio.gather(*tasks)

    def should_ultrathink(self, finding: Finding) -> bool:
        """Check if a finding should go through ultrathink cascade."""
        return self.config.should_ultrathink(finding.severity)


class UltrathinkAgent:
    """High-level agent that integrates ultrathink with existing analysis flow.

    This can be used as a drop-in replacement for StrictAnalysisAgent,
    but uses the ultrathink cascade for verification.
    """

    def __init__(
        self,
        config: Optional[UltrathinkConfig] = None,
        on_cascade_start: Optional[Callable[[Finding], None]] = None,
        on_cascade_complete: Optional[Callable[[CascadeResult], None]] = None,
    ):
        self.config = config or UltrathinkConfig()
        self.cascade = UltrathinkCascade(config=self.config)
        self.on_cascade_start = on_cascade_start
        self.on_cascade_complete = on_cascade_complete

    async def verify_finding(
        self,
        finding: Finding,
        code_context: str,
        provider: BaseProvider,
        model: str,
    ) -> tuple[bool, CascadeResult]:
        """
        Verify a single finding through ultrathink cascade.

        Returns:
            Tuple of (should_report, cascade_result)
        """
        if self.on_cascade_start:
            self.on_cascade_start(finding)

        result = await self.cascade.evaluate(
            finding=finding,
            code_context=code_context,
            provider=provider,
            model=model,
        )

        if self.on_cascade_complete:
            self.on_cascade_complete(result)

        return result.final_verdict, result

    async def verify_findings(
        self,
        findings: list[Finding],
        code_contexts: dict[str, str],  # file_path -> code
        provider: BaseProvider,
        model: str,
    ) -> list[tuple[Finding, CascadeResult]]:
        """
        Verify multiple findings, returning only those that pass.

        Args:
            findings: List of potential findings
            code_contexts: Map of file paths to code content
            provider: AI provider
            model: Model to use

        Returns:
            List of (finding, cascade_result) for findings that passed
        """
        verified = []

        for finding in findings:
            # Skip low-severity if not in ultrathink severities
            if not self.cascade.should_ultrathink(finding):
                continue

            code = code_contexts.get(finding.file_path, "")

            should_report, result = await self.verify_finding(
                finding=finding,
                code_context=code,
                provider=provider,
                model=model,
            )

            if should_report:
                verified.append((finding, result))

        return verified

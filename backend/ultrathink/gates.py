"""Hierarchical verification gates for ultrathink cascade.

Each gate has a specific adversarial objective:
1. TRIAGE: Quick filter for obvious non-issues
2. DEEP_ANALYSIS: Thorough source-to-sink analysis with extended thinking
3. DEVILS_ADVOCATE: Actively argue against the finding
4. PROOF_GENERATOR: Generate concrete exploit proof
5. FINAL_GATE: Stake reputation check

Findings must pass ALL gates to be reported.
"""

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Any

from models.schemas import Finding, UltrathinkGate
from .config import GateConfig
from .thinking import ThinkingEngine, ThinkingResult


@dataclass
class GateResult:
    """Result from a gate evaluation."""

    gate: UltrathinkGate
    passed: bool
    confidence: float
    reasoning: str
    thinking_result: Optional[ThinkingResult] = None

    # Gate-specific metadata
    metadata: dict[str, Any] = field(default_factory=dict)

    # Timing
    duration_ms: int = 0

    # For transparency
    full_trace: Optional[str] = None


class BaseGate(ABC):
    """Abstract base class for verification gates."""

    gate_type: UltrathinkGate

    def __init__(
        self,
        config: GateConfig,
        thinking_engine: ThinkingEngine,
    ):
        self.config = config
        self.thinking_engine = thinking_engine

    @abstractmethod
    async def evaluate(
        self,
        finding: Finding,
        code_context: str,
        provider: Any = None,
        model: str = "",
    ) -> GateResult:
        """Evaluate a finding through this gate."""
        pass

    @abstractmethod
    def get_prompt(self, finding: Finding, code_context: str) -> str:
        """Get the evaluation prompt for this gate."""
        pass

    def _parse_json_response(self, response: str) -> dict:
        """Parse JSON from model response."""
        # Try to find JSON in response
        json_match = re.search(r'\{[\s\S]*\}', response)
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError:
                pass
        return {}

    def _format_finding(self, finding: Finding) -> str:
        """Format finding for prompts."""
        return f"""
FINDING:
  Title: {finding.title}
  Severity: {finding.severity.value}
  File: {finding.file_path}
  Line: {finding.line_start}
  Type: {finding.vulnerability_type}
  Description: {finding.description}
  Current Confidence: {finding.confidence}
  Attack Scenario: {finding.attack_scenario or 'Not provided'}
"""


class TriageGate(BaseGate):
    """Quick triage to filter obvious non-issues.

    Objective: Identify findings worth investigating deeper.
    This gate should be FAST and filter obvious false positives.
    """

    gate_type = UltrathinkGate.TRIAGE

    async def evaluate(
        self,
        finding: Finding,
        code_context: str,
        provider: Any = None,
        model: str = "",
    ) -> GateResult:
        start = datetime.utcnow()

        prompt = self.get_prompt(finding, code_context)

        thinking_result = await self.thinking_engine.think(
            prompt=prompt,
            context=code_context,
            provider=provider,
            model=model,
            thinking_budget=self.config.thinking_budget_tokens,
        )

        # Parse response
        data = self._parse_json_response(thinking_result.output)

        verdict = data.get("verdict", "").lower()
        priority = data.get("priority", 0)
        reasoning = data.get("reasoning", "")

        # Calculate confidence from priority (1-5 -> 0.2-1.0)
        confidence = min(priority / 5.0, 1.0) if priority else 0.0

        passed = verdict == "investigate" and confidence >= self.config.confidence_threshold

        return GateResult(
            gate=self.gate_type,
            passed=passed,
            confidence=confidence,
            reasoning=reasoning,
            thinking_result=thinking_result,
            metadata={
                "verdict": verdict,
                "priority": priority,
            },
            duration_ms=int((datetime.utcnow() - start).total_seconds() * 1000),
            full_trace=thinking_result.thinking_trace,
        )

    def get_prompt(self, finding: Finding, code_context: str) -> str:
        return f"""TRIAGE GATE: Quick assessment of potential vulnerability.

{self._format_finding(finding)}

CODE:
```
{code_context[:2000]}
```

TASK: Quickly assess if this finding is worth investigating.

Consider:
1. Is this clearly test code or example code?
2. Is this a common safe pattern misidentified?
3. Does the framework likely handle this automatically?
4. Is there a plausible attack scenario?

OUTPUT (JSON):
{{
  "verdict": "investigate" | "discard",
  "priority": 1-5 (5 = most likely real),
  "reasoning": "brief explanation"
}}"""


class DeepAnalysisGate(BaseGate):
    """Thorough source-to-sink analysis with extended thinking.

    Objective: Verify the vulnerability through rigorous analysis.
    This gate uses MAXIMUM thinking budget for deep reasoning.
    """

    gate_type = UltrathinkGate.DEEP_ANALYSIS

    async def evaluate(
        self,
        finding: Finding,
        code_context: str,
        provider: Any = None,
        model: str = "",
    ) -> GateResult:
        start = datetime.utcnow()

        prompt = self.get_prompt(finding, code_context)

        thinking_result = await self.thinking_engine.think(
            prompt=prompt,
            context=code_context,
            provider=provider,
            model=model,
            thinking_budget=self.config.thinking_budget_tokens,
        )

        data = self._parse_json_response(thinking_result.output)

        source_verified = data.get("source_verified", False)
        sink_verified = data.get("sink_verified", False)
        path_verified = data.get("path_verified", False)
        confidence = data.get("confidence", 0.0)

        # Must verify all three components
        passed = (
            source_verified and
            sink_verified and
            path_verified and
            confidence >= self.config.confidence_threshold
        )

        return GateResult(
            gate=self.gate_type,
            passed=passed,
            confidence=confidence,
            reasoning=data.get("analysis_summary", ""),
            thinking_result=thinking_result,
            metadata={
                "source_verified": source_verified,
                "sink_verified": sink_verified,
                "path_verified": path_verified,
                "source_location": data.get("source_location"),
                "sink_location": data.get("sink_location"),
                "trace_steps": data.get("trace_steps", []),
            },
            duration_ms=int((datetime.utcnow() - start).total_seconds() * 1000),
            full_trace=thinking_result.thinking_trace,
        )

    def get_prompt(self, finding: Finding, code_context: str) -> str:
        return f"""DEEP ANALYSIS GATE: Rigorous source-to-sink verification.

{self._format_finding(finding)}

CODE:
```
{code_context}
```

TASK: Perform thorough source-to-sink analysis.

You have extended time to think. Use it to:
1. Identify the EXACT source of attacker input
2. Trace the data flow step-by-step
3. Verify no sanitization exists in the path
4. Confirm the sink is actually reachable
5. Consider edge cases and error paths

BE RIGOROUS. Don't assume - verify with code references.

OUTPUT (JSON):
{{
  "source_verified": true/false,
  "source_location": "file:line - exact location",
  "source_description": "how attacker controls this",

  "sink_verified": true/false,
  "sink_location": "file:line - exact location",
  "sink_description": "why this sink is dangerous",

  "path_verified": true/false,
  "trace_steps": [
    "Step 1: Input enters at line X",
    "Step 2: Passed to function Y",
    "Step 3: Reaches sink at line Z"
  ],

  "sanitization_found": true/false,
  "sanitization_details": "description if found",

  "confidence": 0.0-1.0,
  "analysis_summary": "detailed summary of findings"
}}"""


class DevilsAdvocateGate(BaseGate):
    """Actively argue against the finding.

    Objective: Find every reason the finding might be WRONG.
    This gate is ADVERSARIAL - it tries to disprove vulnerabilities.
    """

    gate_type = UltrathinkGate.DEVILS_ADVOCATE

    async def evaluate(
        self,
        finding: Finding,
        code_context: str,
        provider: Any = None,
        model: str = "",
    ) -> GateResult:
        start = datetime.utcnow()

        prompt = self.get_prompt(finding, code_context)

        thinking_result = await self.thinking_engine.think(
            prompt=prompt,
            context=code_context,
            provider=provider,
            model=model,
            thinking_budget=self.config.thinking_budget_tokens,
            system_prompt="""You are a skeptical security reviewer. Your job is to DISPROVE findings.
Think like a defense attorney - find every hole in the argument.
Be harsh. Better to reject a real finding than accept a false one.""",
        )

        data = self._parse_json_response(thinking_result.output)

        verdict = data.get("verdict", "").lower()
        revised_confidence = data.get("revised_confidence", 0.0)
        counter_arguments = data.get("counter_arguments", [])

        # Finding survives if verdict is not "reject" and confidence stays high
        passed = verdict != "reject" and revised_confidence >= self.config.confidence_threshold

        return GateResult(
            gate=self.gate_type,
            passed=passed,
            confidence=revised_confidence,
            reasoning=data.get("strongest_counter_argument", ""),
            thinking_result=thinking_result,
            metadata={
                "verdict": verdict,
                "counter_arguments": counter_arguments,
                "original_confidence": finding.confidence,
                "revised_confidence": revised_confidence,
                "remaining_certainty": data.get("remaining_certainty", ""),
            },
            duration_ms=int((datetime.utcnow() - start).total_seconds() * 1000),
            full_trace=thinking_result.thinking_trace,
        )

    def get_prompt(self, finding: Finding, code_context: str) -> str:
        return f"""DEVIL'S ADVOCATE GATE: Argue AGAINST this finding.

{self._format_finding(finding)}

CODE:
```
{code_context}
```

TASK: Try to DISPROVE this vulnerability.

Pretend you're a developer who wrote this code and believes it's secure.
Find every reason this finding might be WRONG:

1. ALTERNATIVE EXPLANATION
   Why might this NOT be a vulnerability?

2. MISSING CONTEXT
   What code/configuration might exist that makes this safe?

3. FRAMEWORK PROTECTION
   How might the framework handle this securely by default?

4. ATTACK BARRIERS
   What would prevent an attacker from actually exploiting this?

5. FALSE POSITIVE INDICATORS
   What signs suggest this might be a false positive?

BE HARSH. Your job is to find problems with this finding.

OUTPUT (JSON):
{{
  "verdict": "confirmed" | "weakened" | "reject",
  "counter_arguments": [
    "argument 1",
    "argument 2"
  ],
  "strongest_counter_argument": "the best argument against this",
  "revised_confidence": 0.0-1.0,
  "remaining_certainty": "why you still believe it's real (if applicable)"
}}"""


class ProofGeneratorGate(BaseGate):
    """Generate concrete proof of exploit.

    Objective: Create a working exploit or admit you can't.
    If you can't prove it works, don't report it.
    """

    gate_type = UltrathinkGate.PROOF_GENERATOR

    async def evaluate(
        self,
        finding: Finding,
        code_context: str,
        provider: Any = None,
        model: str = "",
    ) -> GateResult:
        start = datetime.utcnow()

        prompt = self.get_prompt(finding, code_context)

        thinking_result = await self.thinking_engine.think(
            prompt=prompt,
            context=code_context,
            provider=provider,
            model=model,
            thinking_budget=self.config.thinking_budget_tokens,
        )

        data = self._parse_json_response(thinking_result.output)

        can_prove = data.get("can_prove", False)
        payload = data.get("payload")
        expected_result = data.get("expected_result")

        # Only pass if we have concrete proof
        passed = can_prove and payload is not None

        confidence = 0.9 if passed else 0.3

        return GateResult(
            gate=self.gate_type,
            passed=passed,
            confidence=confidence,
            reasoning=data.get("verification_method", data.get("reason", "")),
            thinking_result=thinking_result,
            metadata={
                "can_prove": can_prove,
                "payload": payload,
                "expected_result": expected_result,
                "entry_point": data.get("entry_point"),
                "execution_trace": data.get("execution_trace", []),
            },
            duration_ms=int((datetime.utcnow() - start).total_seconds() * 1000),
            full_trace=thinking_result.thinking_trace,
        )

    def get_prompt(self, finding: Finding, code_context: str) -> str:
        return f"""PROOF GENERATOR GATE: Create concrete exploit proof.

{self._format_finding(finding)}

CODE:
```
{code_context}
```

TASK: Generate a CONCRETE proof of exploit.

This is not theoretical. Provide:

1. EXACT PAYLOAD
   The precise input an attacker would send.
   Not "malicious input" - the ACTUAL string/data.

2. ENTRY POINT
   Exactly how this payload reaches the application.
   HTTP request? Function call? File input?

3. EXECUTION TRACE
   Step by step, what happens when payload is processed.

4. OBSERVABLE RESULT
   What would the attacker see/achieve?

5. VERIFICATION METHOD
   How could someone verify this works?

If you CANNOT provide concrete proof, be honest about it.

OUTPUT (JSON):
{{
  "can_prove": true/false,
  "payload": "exact malicious input (if can_prove)",
  "entry_point": "how payload enters",
  "execution_trace": ["step1", "step2"],
  "expected_result": "what attacker achieves",
  "verification_method": "how to test this",
  "reason": "why you can't prove (if can_prove=false)"
}}"""


class FinalGate(BaseGate):
    """Final reputation-stake check.

    Objective: Would you stake your professional reputation on this?
    Last chance to reject a questionable finding.
    """

    gate_type = UltrathinkGate.FINAL_GATE

    async def evaluate(
        self,
        finding: Finding,
        code_context: str,
        provider: Any = None,
        model: str = "",
        previous_gates: list[GateResult] = None,
    ) -> GateResult:
        start = datetime.utcnow()

        # Include previous gate results in the prompt
        gate_summary = ""
        if previous_gates:
            gate_summary = "\nPREVIOUS GATE RESULTS:\n"
            for gr in previous_gates:
                gate_summary += f"- {gr.gate.value}: {'PASSED' if gr.passed else 'FAILED'} (confidence: {gr.confidence:.2f})\n"
                gate_summary += f"  Reasoning: {gr.reasoning[:200]}...\n"

        prompt = self.get_prompt(finding, code_context) + gate_summary

        thinking_result = await self.thinking_engine.think(
            prompt=prompt,
            context=code_context,
            provider=provider,
            model=model,
            thinking_budget=self.config.thinking_budget_tokens,
            system_prompt="""You are making a final decision about reporting a vulnerability.
Your professional reputation is on the line.
Be conservative - only approve findings you are genuinely certain about.""",
        )

        data = self._parse_json_response(thinking_result.output)

        stake_reputation = data.get("stake_reputation", False)
        final_decision = data.get("final_decision", "").upper()
        confidence_pct = data.get("confidence_percentage", 0)

        confidence = confidence_pct / 100.0 if confidence_pct else 0.0

        passed = (
            stake_reputation and
            final_decision == "REPORT" and
            confidence >= self.config.confidence_threshold
        )

        return GateResult(
            gate=self.gate_type,
            passed=passed,
            confidence=confidence,
            reasoning=data.get("reasoning", ""),
            thinking_result=thinking_result,
            metadata={
                "stake_reputation": stake_reputation,
                "final_decision": final_decision,
                "strongest_evidence": data.get("strongest_evidence"),
                "biggest_doubt": data.get("biggest_doubt"),
            },
            duration_ms=int((datetime.utcnow() - start).total_seconds() * 1000),
            full_trace=thinking_result.thinking_trace,
        )

    def get_prompt(self, finding: Finding, code_context: str) -> str:
        return f"""FINAL GATE: Stake your reputation.

{self._format_finding(finding)}

This finding has passed multiple verification gates.

ONE LAST CHECK before it goes in the report:

Would you stake your professional reputation on this finding?

Consider:
1. If this is wrong, your credibility is damaged
2. The client will investigate this thoroughly
3. Other security researchers will review your work
4. False positives waste everyone's time and money

Answer honestly.

OUTPUT (JSON):
{{
  "stake_reputation": true/false,
  "confidence_percentage": 0-100,
  "strongest_evidence": "the single best proof this is real",
  "biggest_doubt": "your remaining uncertainty, if any",
  "final_decision": "REPORT" | "DO_NOT_REPORT",
  "reasoning": "one sentence explaining your decision"
}}"""


# Gate registry for easy lookup
GATE_REGISTRY = {
    UltrathinkGate.TRIAGE: TriageGate,
    UltrathinkGate.DEEP_ANALYSIS: DeepAnalysisGate,
    UltrathinkGate.DEVILS_ADVOCATE: DevilsAdvocateGate,
    UltrathinkGate.PROOF_GENERATOR: ProofGeneratorGate,
    UltrathinkGate.FINAL_GATE: FinalGate,
}


def create_gate(
    gate_type: UltrathinkGate,
    config: GateConfig,
    thinking_engine: ThinkingEngine,
) -> BaseGate:
    """Factory function to create a gate."""
    gate_class = GATE_REGISTRY.get(gate_type)
    if not gate_class:
        raise ValueError(f"Unknown gate type: {gate_type}")
    return gate_class(config=config, thinking_engine=thinking_engine)

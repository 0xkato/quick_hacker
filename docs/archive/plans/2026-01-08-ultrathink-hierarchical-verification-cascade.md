# Ultrathink Hierarchical Verification Cascade Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement a provider-agnostic "ultrathink" architecture that maximizes model cognitive depth for security vulnerability research through a hierarchical verification cascade with full reasoning transparency.

**Architecture:** Sequential multi-gate pipeline where each finding must survive progressively harder scrutiny: Triage → Deep Analysis (with extended thinking) → Devil's Advocate → Proof Generator → Final Gate. Each gate uses maximum reasoning depth, with full thinking traces exposed for human audit. Provider-agnostic design works across Claude (native extended thinking), GPT-4 (simulated CoT), and open-source models (structured reasoning prompts).

**Tech Stack:** Python 3.11+, FastAPI, Pydantic, asyncio, existing providers (Anthropic, OpenAI, Ollama)

---

## Overview: The Ultrathink Philosophy

Standard inference gives the model ~500ms to "think" before outputting. Ultrathink gives it **60+ seconds of cognitive runway** to:
- Generate and test hypotheses
- Backtrack when reasoning hits dead ends
- Verify its own claims against evidence
- Argue against itself before committing

This implementation creates a **Hierarchical Verification Cascade** where:
1. Each gate has a specific adversarial objective
2. Full reasoning traces are captured and exposed
3. Findings must survive ALL gates to be reported
4. Provider-agnostic design adapts to model capabilities

---

## Task 1: Create Ultrathink Configuration Schema

**Files:**
- Modify: `backend/models/schemas.py` (add new types)
- Create: `backend/ultrathink/config.py`

**Step 1: Write the test for ultrathink config validation**

```python
# tests/ultrathink/test_config.py
import pytest
from ultrathink.config import UltrathinkConfig, ThinkingMode, GateConfig

def test_ultrathink_config_defaults():
    config = UltrathinkConfig()
    assert config.thinking_mode == ThinkingMode.AUTO
    assert config.min_thinking_tokens == 10000
    assert config.max_thinking_tokens == 50000
    assert len(config.gates) == 5

def test_gate_config_thresholds():
    gate = GateConfig(
        name="test_gate",
        confidence_threshold=0.85,
        thinking_budget_tokens=15000,
    )
    assert gate.confidence_threshold == 0.85
    assert gate.thinking_budget_tokens == 15000

def test_thinking_mode_auto_selects_native_for_claude():
    config = UltrathinkConfig(thinking_mode=ThinkingMode.AUTO)
    assert config.resolve_thinking_mode("claude-opus-4-5-20251101") == ThinkingMode.NATIVE
    assert config.resolve_thinking_mode("gpt-4o") == ThinkingMode.SIMULATED
    assert config.resolve_thinking_mode("llama3.3") == ThinkingMode.STRUCTURED
```

**Step 2: Run test to verify it fails**

Run: `cd backend && python -m pytest tests/ultrathink/test_config.py -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'ultrathink'"

**Step 3: Add ultrathink enums to schemas.py**

```python
# Add to backend/models/schemas.py after existing enums

class ThinkingMode(str, Enum):
    """How to invoke extended thinking."""
    NATIVE = "native"      # Use provider's native extended thinking (Claude)
    SIMULATED = "simulated"  # Simulate via chain-of-thought prompting (GPT-4)
    STRUCTURED = "structured"  # Structured reasoning prompts (open source)
    AUTO = "auto"          # Auto-detect based on model


class UltrathinkGate(str, Enum):
    """Gates in the hierarchical verification cascade."""
    TRIAGE = "triage"
    DEEP_ANALYSIS = "deep_analysis"
    DEVILS_ADVOCATE = "devils_advocate"
    PROOF_GENERATOR = "proof_generator"
    FINAL_GATE = "final_gate"
```

**Step 4: Create ultrathink config module**

```python
# backend/ultrathink/__init__.py
from .config import UltrathinkConfig, GateConfig
from .cascade import UltrathinkCascade
from .thinking import ThinkingEngine

__all__ = [
    "UltrathinkConfig",
    "GateConfig",
    "UltrathinkCascade",
    "ThinkingEngine",
]
```

```python
# backend/ultrathink/config.py
"""Configuration for ultrathink hierarchical verification cascade."""

from dataclasses import dataclass, field
from typing import Optional
from models.schemas import ThinkingMode, UltrathinkGate, Severity


# Models known to support native extended thinking
NATIVE_THINKING_MODELS = {
    "claude-opus-4-5-20251101",
    "claude-sonnet-4-20250514",
    # Add future Claude models with extended thinking
}

# Models that work well with simulated CoT
SIMULATED_THINKING_MODELS = {
    "gpt-4o",
    "gpt-4-turbo",
    "gpt-4o-mini",
}


@dataclass
class GateConfig:
    """Configuration for a single verification gate."""

    name: str
    confidence_threshold: float = 0.85
    thinking_budget_tokens: int = 15000
    timeout_seconds: int = 120
    required: bool = True

    # Gate-specific settings
    adversarial_strength: float = 0.8  # How hard to argue against (0-1)
    require_evidence: bool = True
    require_code_refs: bool = True


@dataclass
class UltrathinkConfig:
    """Master configuration for ultrathink cascade."""

    # Thinking mode
    thinking_mode: ThinkingMode = ThinkingMode.AUTO
    min_thinking_tokens: int = 10000
    max_thinking_tokens: int = 50000

    # Reasoning transparency
    capture_full_trace: bool = True
    expose_thinking_to_user: bool = True

    # Severity triggers (which severities always get ultrathink)
    ultrathink_severities: set[Severity] = field(default_factory=lambda: {
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
    })

    # Gate configurations
    gates: list[GateConfig] = field(default_factory=lambda: [
        GateConfig(
            name=UltrathinkGate.TRIAGE.value,
            confidence_threshold=0.60,
            thinking_budget_tokens=5000,
            timeout_seconds=30,
            adversarial_strength=0.3,
        ),
        GateConfig(
            name=UltrathinkGate.DEEP_ANALYSIS.value,
            confidence_threshold=0.75,
            thinking_budget_tokens=25000,
            timeout_seconds=180,
            adversarial_strength=0.5,
        ),
        GateConfig(
            name=UltrathinkGate.DEVILS_ADVOCATE.value,
            confidence_threshold=0.80,
            thinking_budget_tokens=20000,
            timeout_seconds=120,
            adversarial_strength=0.9,  # Maximum adversarial
        ),
        GateConfig(
            name=UltrathinkGate.PROOF_GENERATOR.value,
            confidence_threshold=0.85,
            thinking_budget_tokens=15000,
            timeout_seconds=90,
            adversarial_strength=0.7,
        ),
        GateConfig(
            name=UltrathinkGate.FINAL_GATE.value,
            confidence_threshold=0.90,
            thinking_budget_tokens=10000,
            timeout_seconds=60,
            adversarial_strength=0.8,
        ),
    ])

    def resolve_thinking_mode(self, model: str) -> ThinkingMode:
        """Resolve AUTO thinking mode based on model."""
        if self.thinking_mode != ThinkingMode.AUTO:
            return self.thinking_mode

        if model in NATIVE_THINKING_MODELS:
            return ThinkingMode.NATIVE
        elif model in SIMULATED_THINKING_MODELS:
            return ThinkingMode.SIMULATED
        else:
            return ThinkingMode.STRUCTURED

    def get_gate(self, gate: UltrathinkGate) -> GateConfig:
        """Get config for a specific gate."""
        for g in self.gates:
            if g.name == gate.value:
                return g
        raise ValueError(f"Unknown gate: {gate}")

    def should_ultrathink(self, severity: Severity) -> bool:
        """Check if this severity should trigger ultrathink."""
        return severity in self.ultrathink_severities
```

**Step 5: Run test to verify it passes**

Run: `cd backend && python -m pytest tests/ultrathink/test_config.py -v`
Expected: PASS

**Step 6: Commit**

```bash
git add backend/models/schemas.py backend/ultrathink/ tests/ultrathink/
git commit -m "feat: add ultrathink configuration schema with gate configs"
```

---

## Task 2: Create Thinking Engine (Provider-Agnostic Extended Thinking)

**Files:**
- Create: `backend/ultrathink/thinking.py`
- Create: `tests/ultrathink/test_thinking.py`

**Step 1: Write the test for thinking engine**

```python
# tests/ultrathink/test_thinking.py
import pytest
from unittest.mock import AsyncMock, MagicMock
from ultrathink.thinking import ThinkingEngine, ThinkingResult
from ultrathink.config import UltrathinkConfig
from models.schemas import ThinkingMode, ProviderConfig, ProviderType


@pytest.fixture
def mock_provider():
    provider = MagicMock()
    provider.generate = AsyncMock(return_value="Test response")
    return provider


@pytest.mark.asyncio
async def test_thinking_engine_native_mode(mock_provider):
    """Test native extended thinking with Claude."""
    engine = ThinkingEngine(
        config=UltrathinkConfig(thinking_mode=ThinkingMode.NATIVE)
    )

    result = await engine.think(
        prompt="Analyze this code for vulnerabilities",
        context="def login(user, pwd): return db.query(f'SELECT * FROM users WHERE u={user}')",
        provider=mock_provider,
        model="claude-opus-4-5-20251101",
        thinking_budget=10000,
    )

    assert isinstance(result, ThinkingResult)
    assert result.thinking_trace is not None


@pytest.mark.asyncio
async def test_thinking_engine_simulated_mode(mock_provider):
    """Test simulated CoT with GPT-4."""
    engine = ThinkingEngine(
        config=UltrathinkConfig(thinking_mode=ThinkingMode.SIMULATED)
    )

    result = await engine.think(
        prompt="Analyze this code",
        context="code here",
        provider=mock_provider,
        model="gpt-4o",
        thinking_budget=10000,
    )

    assert isinstance(result, ThinkingResult)
    # Simulated mode should have CoT in output
    mock_provider.generate.assert_called_once()


@pytest.mark.asyncio
async def test_thinking_engine_structured_mode(mock_provider):
    """Test structured reasoning with open source models."""
    engine = ThinkingEngine(
        config=UltrathinkConfig(thinking_mode=ThinkingMode.STRUCTURED)
    )

    result = await engine.think(
        prompt="Analyze this code",
        context="code here",
        provider=mock_provider,
        model="llama3.3",
        thinking_budget=10000,
    )

    assert isinstance(result, ThinkingResult)
```

**Step 2: Run test to verify it fails**

Run: `cd backend && python -m pytest tests/ultrathink/test_thinking.py -v`
Expected: FAIL with "cannot import name 'ThinkingEngine'"

**Step 3: Implement the ThinkingEngine**

```python
# backend/ultrathink/thinking.py
"""Provider-agnostic extended thinking engine.

This module provides a unified interface for invoking "deep thinking" across
different AI providers:

- NATIVE: Uses Claude's native extended thinking (thinking blocks)
- SIMULATED: Simulates extended thinking via chain-of-thought prompting (GPT-4)
- STRUCTURED: Uses structured reasoning prompts for open-source models

The goal is to give the model maximum cognitive runway to:
- Generate and test hypotheses
- Backtrack when reasoning fails
- Self-verify claims against evidence
- Argue against its own conclusions
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Any
import json
import re

from models.schemas import ThinkingMode
from providers.base_provider import BaseProvider, Message
from .config import UltrathinkConfig


@dataclass
class ThinkingStep:
    """A single step in the reasoning trace."""
    step_number: int
    thought: str
    evidence: Optional[str] = None
    confidence: float = 0.0
    is_backtrack: bool = False
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ThinkingResult:
    """Result from extended thinking."""

    # The final output after thinking
    output: str

    # Full thinking trace (if captured)
    thinking_trace: Optional[str] = None

    # Structured reasoning steps (parsed from trace)
    steps: list[ThinkingStep] = field(default_factory=list)

    # Metrics
    thinking_tokens_used: int = 0
    output_tokens_used: int = 0
    duration_ms: int = 0

    # Mode used
    mode: ThinkingMode = ThinkingMode.AUTO

    # Raw provider response (for debugging)
    raw_response: Optional[Any] = None


class ThinkingEngine:
    """Provider-agnostic extended thinking engine."""

    def __init__(self, config: Optional[UltrathinkConfig] = None):
        self.config = config or UltrathinkConfig()

    async def think(
        self,
        prompt: str,
        context: str,
        provider: BaseProvider,
        model: str,
        thinking_budget: int = 10000,
        system_prompt: Optional[str] = None,
    ) -> ThinkingResult:
        """
        Invoke extended thinking on the given prompt.

        Args:
            prompt: The task/question to think about
            context: Code or data context
            provider: The AI provider to use
            model: Model identifier
            thinking_budget: Token budget for thinking
            system_prompt: Optional system prompt override

        Returns:
            ThinkingResult with output and reasoning trace
        """
        mode = self.config.resolve_thinking_mode(model)

        start_time = datetime.utcnow()

        if mode == ThinkingMode.NATIVE:
            result = await self._think_native(
                prompt, context, provider, model, thinking_budget, system_prompt
            )
        elif mode == ThinkingMode.SIMULATED:
            result = await self._think_simulated(
                prompt, context, provider, model, thinking_budget, system_prompt
            )
        else:  # STRUCTURED
            result = await self._think_structured(
                prompt, context, provider, model, thinking_budget, system_prompt
            )

        result.mode = mode
        result.duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)

        # Parse structured steps from trace if available
        if result.thinking_trace:
            result.steps = self._parse_thinking_steps(result.thinking_trace)

        return result

    async def _think_native(
        self,
        prompt: str,
        context: str,
        provider: BaseProvider,
        model: str,
        thinking_budget: int,
        system_prompt: Optional[str],
    ) -> ThinkingResult:
        """Use Claude's native extended thinking."""

        # Build the full prompt
        full_prompt = self._build_thinking_prompt(prompt, context, "native")

        messages = [Message(role="user", content=full_prompt)]

        # For Claude with extended thinking, we use special parameters
        # Note: This requires the Anthropic provider to support extended_thinking
        try:
            # Try to use extended thinking if provider supports it
            if hasattr(provider, 'generate_with_thinking'):
                response, thinking = await provider.generate_with_thinking(
                    messages=messages,
                    system_prompt=system_prompt or self._get_thinking_system_prompt(),
                    thinking_budget=thinking_budget,
                )
                return ThinkingResult(
                    output=response,
                    thinking_trace=thinking,
                    thinking_tokens_used=len(thinking) // 4 if thinking else 0,
                    output_tokens_used=len(response) // 4,
                )
            else:
                # Fallback to simulated if provider doesn't support native thinking
                return await self._think_simulated(
                    prompt, context, provider, model, thinking_budget, system_prompt
                )
        except Exception as e:
            # Fallback on error
            return await self._think_simulated(
                prompt, context, provider, model, thinking_budget, system_prompt
            )

    async def _think_simulated(
        self,
        prompt: str,
        context: str,
        provider: BaseProvider,
        model: str,
        thinking_budget: int,
        system_prompt: Optional[str],
    ) -> ThinkingResult:
        """Simulate extended thinking via chain-of-thought prompting."""

        # Build a prompt that forces explicit reasoning
        full_prompt = self._build_thinking_prompt(prompt, context, "simulated")

        messages = [Message(role="user", content=full_prompt)]

        response = await provider.generate(
            messages=messages,
            system_prompt=system_prompt or self._get_cot_system_prompt(),
        )

        # Parse thinking from response (look for <thinking> tags or reasoning sections)
        thinking_trace, output = self._extract_thinking_from_response(response)

        return ThinkingResult(
            output=output,
            thinking_trace=thinking_trace,
            thinking_tokens_used=len(thinking_trace) // 4 if thinking_trace else 0,
            output_tokens_used=len(output) // 4,
            raw_response=response,
        )

    async def _think_structured(
        self,
        prompt: str,
        context: str,
        provider: BaseProvider,
        model: str,
        thinking_budget: int,
        system_prompt: Optional[str],
    ) -> ThinkingResult:
        """Use structured reasoning prompts for open-source models."""

        # Build a highly structured prompt that guides reasoning step-by-step
        full_prompt = self._build_thinking_prompt(prompt, context, "structured")

        messages = [Message(role="user", content=full_prompt)]

        response = await provider.generate(
            messages=messages,
            system_prompt=system_prompt or self._get_structured_system_prompt(),
        )

        # Parse structured output
        thinking_trace, output = self._extract_structured_thinking(response)

        return ThinkingResult(
            output=output,
            thinking_trace=thinking_trace,
            thinking_tokens_used=len(thinking_trace) // 4 if thinking_trace else 0,
            output_tokens_used=len(output) // 4,
            raw_response=response,
        )

    def _build_thinking_prompt(self, prompt: str, context: str, mode: str) -> str:
        """Build the thinking prompt based on mode."""

        if mode == "native":
            # Native mode - minimal scaffolding, let the model think naturally
            return f"""{prompt}

CODE CONTEXT:
```
{context}
```

Take your time to thoroughly analyze this. Consider multiple hypotheses,
verify each claim against the code, and be willing to backtrack if your
reasoning leads to a dead end."""

        elif mode == "simulated":
            # Simulated mode - explicit CoT structure
            return f"""{prompt}

CODE CONTEXT:
```
{context}
```

IMPORTANT: Think through this step-by-step before giving your final answer.

<thinking>
1. First, I'll identify what I'm looking for...
2. Then, I'll examine the code systematically...
3. For each potential issue, I'll verify...
4. I'll consider counter-arguments...
5. Finally, I'll synthesize my conclusions...
</thinking>

After your thinking, provide your final answer."""

        else:  # structured
            # Structured mode - very explicit reasoning scaffold
            return f"""{prompt}

CODE CONTEXT:
```
{context}
```

You MUST follow this exact reasoning structure:

## STEP 1: UNDERSTAND THE TASK
What exactly am I being asked to analyze?

## STEP 2: IDENTIFY INPUTS
What are the potential sources of attacker-controlled data?

## STEP 3: IDENTIFY SINKS
What dangerous operations exist in this code?

## STEP 4: TRACE FLOWS
For each (input, sink) pair, trace the data flow:
- Does the input reach the sink?
- What transformations occur?
- Are there sanitization/validation steps?

## STEP 5: HYPOTHESIS
State your hypothesis about potential vulnerabilities.

## STEP 6: VERIFY
For each hypothesis:
- What evidence supports it?
- What evidence contradicts it?
- Can I prove exploitability?

## STEP 7: COUNTER-ARGUMENTS
Argue against your own conclusions. Why might you be wrong?

## STEP 8: FINAL VERDICT
After considering everything, what is your conclusion?

---

Now, execute this reasoning process:"""

    def _get_thinking_system_prompt(self) -> str:
        """System prompt for native extended thinking."""
        return """You are an elite security researcher performing deep vulnerability analysis.

Use your extended thinking capability to thoroughly analyze the code:
- Generate multiple hypotheses
- Test each hypothesis against the evidence
- Backtrack when reasoning fails
- Consider alternative explanations
- Verify every claim with specific code references

Your thinking should be rigorous and self-critical. Don't commit to conclusions
prematurely - explore the space of possibilities before deciding."""

    def _get_cot_system_prompt(self) -> str:
        """System prompt for simulated chain-of-thought."""
        return """You are an elite security researcher. You MUST think step-by-step
before providing any conclusions.

CRITICAL RULES:
1. Always show your reasoning in <thinking> tags
2. Consider multiple hypotheses before concluding
3. Verify claims against specific code references
4. Acknowledge uncertainty when it exists
5. Be willing to revise your thinking if evidence contradicts it

Your <thinking> section should be detailed and show genuine reasoning,
not just a summary of your conclusion."""

    def _get_structured_system_prompt(self) -> str:
        """System prompt for structured reasoning."""
        return """You are a security analyst following a strict reasoning protocol.

You MUST follow the exact structure provided in the prompt. Do not skip steps.
Each step must be completed before moving to the next.

Be explicit about:
- What you're looking for
- What you found (with line numbers)
- Why it matters (or doesn't)
- What you're uncertain about

If you cannot complete a step, explain why."""

    def _extract_thinking_from_response(self, response: str) -> tuple[str, str]:
        """Extract thinking trace and output from response."""

        # Try to find <thinking> tags
        thinking_match = re.search(r'<thinking>(.*?)</thinking>', response, re.DOTALL)

        if thinking_match:
            thinking = thinking_match.group(1).strip()
            # Remove thinking from response to get output
            output = re.sub(r'<thinking>.*?</thinking>', '', response, flags=re.DOTALL).strip()
            return thinking, output

        # No explicit thinking tags - try to find reasoning sections
        # Look for patterns like "Step 1:", "First,", etc.
        reasoning_patterns = [
            r'((?:Step \d+:.*?\n)+)',
            r'((?:First,.*?\n)(?:Second,.*?\n)?(?:Third,.*?\n)?(?:Finally,.*?\n)?)',
            r'((?:1\. .*?\n)+(?:2\. .*?\n)?(?:3\. .*?\n)?)',
        ]

        for pattern in reasoning_patterns:
            match = re.search(pattern, response, re.DOTALL)
            if match:
                # Found reasoning - use whole response as output, reasoning as trace
                return match.group(1), response

        # No clear reasoning found - return empty trace
        return "", response

    def _extract_structured_thinking(self, response: str) -> tuple[str, str]:
        """Extract thinking from structured response format."""

        # Look for our structured headers
        sections = {}
        current_section = None
        current_content = []

        for line in response.split('\n'):
            if line.startswith('## STEP'):
                if current_section:
                    sections[current_section] = '\n'.join(current_content)
                current_section = line
                current_content = []
            else:
                current_content.append(line)

        if current_section:
            sections[current_section] = '\n'.join(current_content)

        # Build thinking trace from sections
        if sections:
            thinking_trace = '\n\n'.join(f"{k}\n{v}" for k, v in sections.items())

            # Final verdict is the output
            output = sections.get('## STEP 8: FINAL VERDICT', response)
            return thinking_trace, output

        return "", response

    def _parse_thinking_steps(self, trace: str) -> list[ThinkingStep]:
        """Parse thinking trace into structured steps."""
        steps = []
        step_num = 0

        # Split by common step indicators
        step_patterns = [
            r'(?:Step \d+:)',
            r'(?:## STEP \d+:)',
            r'(?:\d+\. )',
        ]

        for pattern in step_patterns:
            parts = re.split(pattern, trace)
            if len(parts) > 1:
                for part in parts[1:]:  # Skip first empty part
                    step_num += 1
                    thought = part.strip()[:500]  # Truncate long thoughts

                    # Detect backtracking
                    is_backtrack = any(word in thought.lower() for word in [
                        'actually', 'wait', 'however', 'but', 'reconsider',
                        'on second thought', 'i was wrong', 'correction'
                    ])

                    steps.append(ThinkingStep(
                        step_number=step_num,
                        thought=thought,
                        is_backtrack=is_backtrack,
                    ))
                break

        return steps
```

**Step 4: Run test to verify it passes**

Run: `cd backend && python -m pytest tests/ultrathink/test_thinking.py -v`
Expected: PASS (with mocks)

**Step 5: Commit**

```bash
git add backend/ultrathink/thinking.py tests/ultrathink/test_thinking.py
git commit -m "feat: add provider-agnostic thinking engine with native/simulated/structured modes"
```

---

## Task 3: Create Gate System (Hierarchical Verification)

**Files:**
- Create: `backend/ultrathink/gates.py`
- Create: `tests/ultrathink/test_gates.py`

**Step 1: Write the test for gates**

```python
# tests/ultrathink/test_gates.py
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from ultrathink.gates import (
    BaseGate,
    TriageGate,
    DeepAnalysisGate,
    DevilsAdvocateGate,
    ProofGeneratorGate,
    FinalGate,
    GateResult,
)
from ultrathink.config import GateConfig
from models.schemas import Finding, Severity


@pytest.fixture
def sample_finding():
    return Finding(
        id="test-001",
        agent_id="agent-001",
        repo_id="repo-001",
        severity=Severity.HIGH,
        title="SQL Injection in login",
        description="User input concatenated into SQL query",
        file_path="app/auth.py",
        line_start=42,
        vulnerability_type="sqli",
        confidence=0.75,
        created_at="2024-01-01T00:00:00Z",
    )


@pytest.fixture
def mock_thinking_engine():
    engine = MagicMock()
    engine.think = AsyncMock()
    return engine


@pytest.mark.asyncio
async def test_triage_gate_passes_high_confidence(sample_finding, mock_thinking_engine):
    """Triage should pass findings with high initial signal."""
    mock_thinking_engine.think.return_value = MagicMock(
        output='{"verdict": "investigate", "priority": 5, "reasoning": "Clear SQL injection pattern"}',
        thinking_trace="Analyzed the finding...",
    )

    gate = TriageGate(
        config=GateConfig(name="triage", confidence_threshold=0.6),
        thinking_engine=mock_thinking_engine,
    )

    result = await gate.evaluate(sample_finding, code_context="SELECT * FROM users")

    assert result.passed == True
    assert result.confidence >= 0.6


@pytest.mark.asyncio
async def test_devils_advocate_rejects_weak_finding(sample_finding, mock_thinking_engine):
    """Devil's advocate should reject findings with weak evidence."""
    sample_finding.confidence = 0.65  # Weak

    mock_thinking_engine.think.return_value = MagicMock(
        output='{"verdict": "reject", "counter_arguments": ["Parameterized query might be used elsewhere"], "revised_confidence": 0.40}',
        thinking_trace="Argued against the finding...",
    )

    gate = DevilsAdvocateGate(
        config=GateConfig(name="devils_advocate", confidence_threshold=0.8),
        thinking_engine=mock_thinking_engine,
    )

    result = await gate.evaluate(sample_finding, code_context="SELECT * FROM users")

    assert result.passed == False
    assert "counter_arguments" in result.metadata


@pytest.mark.asyncio
async def test_proof_generator_requires_concrete_poc(sample_finding, mock_thinking_engine):
    """Proof generator should require concrete exploits."""
    mock_thinking_engine.think.return_value = MagicMock(
        output='{"can_prove": true, "payload": "admin\' OR 1=1--", "expected_result": "Auth bypass"}',
        thinking_trace="Generated proof...",
    )

    gate = ProofGeneratorGate(
        config=GateConfig(name="proof_generator", confidence_threshold=0.85),
        thinking_engine=mock_thinking_engine,
    )

    result = await gate.evaluate(sample_finding, code_context="query = f'SELECT * FROM users WHERE user={user}'")

    assert result.passed == True
    assert result.metadata.get("payload") is not None
```

**Step 2: Run test to verify it fails**

Run: `cd backend && python -m pytest tests/ultrathink/test_gates.py -v`
Expected: FAIL with "cannot import name 'BaseGate'"

**Step 3: Implement the gate system**

```python
# backend/ultrathink/gates.py
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
```

**Step 4: Run test to verify it passes**

Run: `cd backend && python -m pytest tests/ultrathink/test_gates.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add backend/ultrathink/gates.py tests/ultrathink/test_gates.py
git commit -m "feat: add hierarchical verification gates with adversarial objectives"
```

---

## Task 4: Create the Cascade Orchestrator

**Files:**
- Create: `backend/ultrathink/cascade.py`
- Create: `tests/ultrathink/test_cascade.py`

**Step 1: Write the test for cascade orchestration**

```python
# tests/ultrathink/test_cascade.py
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from ultrathink.cascade import UltrathinkCascade, CascadeResult
from ultrathink.config import UltrathinkConfig
from models.schemas import Finding, Severity


@pytest.fixture
def sample_finding():
    return Finding(
        id="test-001",
        agent_id="agent-001",
        repo_id="repo-001",
        severity=Severity.HIGH,
        title="SQL Injection in login",
        description="User input concatenated into SQL query",
        file_path="app/auth.py",
        line_start=42,
        vulnerability_type="sqli",
        confidence=0.75,
        created_at="2024-01-01T00:00:00Z",
    )


@pytest.fixture
def mock_provider():
    provider = MagicMock()
    provider.generate = AsyncMock(return_value='{"verdict": "investigate", "priority": 5}')
    return provider


@pytest.mark.asyncio
async def test_cascade_runs_all_gates(sample_finding, mock_provider):
    """Cascade should run all gates in order."""
    cascade = UltrathinkCascade(config=UltrathinkConfig())

    with patch.object(cascade, '_run_gate') as mock_gate:
        mock_gate.return_value = MagicMock(passed=True, confidence=0.9)

        result = await cascade.evaluate(
            finding=sample_finding,
            code_context="SELECT * FROM users WHERE id = " + user_id,
            provider=mock_provider,
            model="claude-opus-4-5-20251101",
        )

        # Should have run 5 gates
        assert mock_gate.call_count == 5


@pytest.mark.asyncio
async def test_cascade_stops_on_failed_gate(sample_finding, mock_provider):
    """Cascade should stop when a gate fails."""
    cascade = UltrathinkCascade(config=UltrathinkConfig())

    call_count = 0
    async def mock_run_gate(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 2:  # Fail on second gate
            return MagicMock(passed=False, confidence=0.3, gate=MagicMock(value="deep_analysis"))
        return MagicMock(passed=True, confidence=0.9, gate=MagicMock(value="triage"))

    with patch.object(cascade, '_run_gate', side_effect=mock_run_gate):
        result = await cascade.evaluate(
            finding=sample_finding,
            code_context="code",
            provider=mock_provider,
            model="claude-opus-4-5-20251101",
        )

        assert result.final_verdict == False
        assert call_count == 2  # Stopped after failure


@pytest.mark.asyncio
async def test_cascade_captures_full_reasoning_trace(sample_finding, mock_provider):
    """Cascade should capture full reasoning traces from all gates."""
    cascade = UltrathinkCascade(
        config=UltrathinkConfig(capture_full_trace=True)
    )

    with patch.object(cascade, '_run_gate') as mock_gate:
        mock_gate.return_value = MagicMock(
            passed=True,
            confidence=0.9,
            full_trace="Thinking about the vulnerability..."
        )

        result = await cascade.evaluate(
            finding=sample_finding,
            code_context="code",
            provider=mock_provider,
            model="claude-opus-4-5-20251101",
        )

        assert len(result.reasoning_traces) > 0
```

**Step 2: Run test to verify it fails**

Run: `cd backend && python -m pytest tests/ultrathink/test_cascade.py -v`
Expected: FAIL with "cannot import name 'UltrathinkCascade'"

**Step 3: Implement the cascade orchestrator**

```python
# backend/ultrathink/cascade.py
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
```

**Step 4: Run test to verify it passes**

Run: `cd backend && python -m pytest tests/ultrathink/test_cascade.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add backend/ultrathink/cascade.py tests/ultrathink/test_cascade.py
git commit -m "feat: add ultrathink cascade orchestrator with batch evaluation"
```

---

## Task 5: Add Extended Thinking Support to Anthropic Provider

**Files:**
- Modify: `backend/providers/anthropic_provider.py`
- Create: `tests/providers/test_anthropic_thinking.py`

**Step 1: Write the test for extended thinking**

```python
# tests/providers/test_anthropic_thinking.py
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from providers.anthropic_provider import AnthropicProvider
from models.schemas import ProviderConfig, ProviderType


@pytest.fixture
def anthropic_config():
    return ProviderConfig(
        provider=ProviderType.ANTHROPIC,
        model="claude-opus-4-5-20251101",
        api_key="test-key",
    )


@pytest.mark.asyncio
async def test_generate_with_thinking(anthropic_config):
    """Test extended thinking generation."""
    provider = AnthropicProvider(anthropic_config)

    mock_response = MagicMock()
    mock_response.content = [
        MagicMock(type="thinking", thinking="Internal reasoning here..."),
        MagicMock(type="text", text="Final answer here"),
    ]

    with patch.object(provider, '_client') as mock_client:
        mock_client.messages.create = AsyncMock(return_value=mock_response)

        response, thinking = await provider.generate_with_thinking(
            messages=[{"role": "user", "content": "Test"}],
            system_prompt="You are helpful",
            thinking_budget=10000,
        )

        assert thinking == "Internal reasoning here..."
        assert response == "Final answer here"


@pytest.mark.asyncio
async def test_generate_with_thinking_fallback(anthropic_config):
    """Test fallback when extended thinking not available."""
    anthropic_config.model = "claude-3-haiku"  # Doesn't support thinking
    provider = AnthropicProvider(anthropic_config)

    mock_response = MagicMock()
    mock_response.content = [
        MagicMock(type="text", text="Regular response"),
    ]

    with patch.object(provider, '_client') as mock_client:
        mock_client.messages.create = AsyncMock(return_value=mock_response)

        response, thinking = await provider.generate_with_thinking(
            messages=[{"role": "user", "content": "Test"}],
            system_prompt="You are helpful",
            thinking_budget=10000,
        )

        assert response == "Regular response"
        assert thinking is None  # No thinking block
```

**Step 2: Run test to verify it fails**

Run: `cd backend && python -m pytest tests/providers/test_anthropic_thinking.py -v`
Expected: FAIL with "has no attribute 'generate_with_thinking'"

**Step 3: Read current anthropic provider**

```bash
cat backend/providers/anthropic_provider.py
```

**Step 4: Add extended thinking support**

Add this method to `AnthropicProvider` class in `backend/providers/anthropic_provider.py`:

```python
    # Add to AnthropicProvider class

    # Models that support extended thinking
    THINKING_MODELS = {
        "claude-opus-4-5-20251101",
        "claude-sonnet-4-20250514",
    }

    async def generate_with_thinking(
        self,
        messages: list[Message],
        system_prompt: Optional[str] = None,
        thinking_budget: int = 10000,
    ) -> tuple[str, Optional[str]]:
        """
        Generate a completion with extended thinking.

        Args:
            messages: Conversation messages
            system_prompt: Optional system prompt
            thinking_budget: Token budget for thinking (default 10000)

        Returns:
            Tuple of (response_text, thinking_text)
            thinking_text is None if model doesn't support extended thinking
        """
        # Check if model supports extended thinking
        supports_thinking = self.model in self.THINKING_MODELS

        # Convert messages
        api_messages = [{"role": m.role, "content": m.content} for m in messages]

        try:
            if supports_thinking:
                # Use extended thinking parameters
                response = await asyncio.to_thread(
                    self._client.messages.create,
                    model=self.model,
                    max_tokens=self.max_tokens,
                    temperature=1.0,  # Extended thinking requires temp=1
                    system=system_prompt or "",
                    messages=api_messages,
                    thinking={
                        "type": "enabled",
                        "budget_tokens": thinking_budget,
                    },
                )
            else:
                # Regular generation
                response = await asyncio.to_thread(
                    self._client.messages.create,
                    model=self.model,
                    max_tokens=self.max_tokens,
                    temperature=self.temperature,
                    system=system_prompt or "",
                    messages=api_messages,
                )

            # Extract thinking and text from response
            thinking_text = None
            response_text = ""

            for block in response.content:
                if hasattr(block, 'type'):
                    if block.type == "thinking":
                        thinking_text = block.thinking
                    elif block.type == "text":
                        response_text = block.text

            return response_text, thinking_text

        except Exception as e:
            # Fallback to regular generation on error
            response = await self.generate(messages, system_prompt)
            return response, None
```

**Step 5: Run test to verify it passes**

Run: `cd backend && python -m pytest tests/providers/test_anthropic_thinking.py -v`
Expected: PASS

**Step 6: Commit**

```bash
git add backend/providers/anthropic_provider.py tests/providers/test_anthropic_thinking.py
git commit -m "feat: add extended thinking support to Anthropic provider"
```

---

## Task 6: Create Ultrathink WebSocket Events

**Files:**
- Modify: `backend/models/schemas.py` (add WSMessageTypes)
- Create: `backend/ultrathink/events.py`

**Step 1: Add new WebSocket message types to schemas.py**

```python
# Add to WSMessageType enum in backend/models/schemas.py

class WSMessageType(str, Enum):
    # ... existing types ...

    # Ultrathink events
    ULTRATHINK_CASCADE_START = "ultrathink_cascade_start"
    ULTRATHINK_GATE_START = "ultrathink_gate_start"
    ULTRATHINK_GATE_COMPLETE = "ultrathink_gate_complete"
    ULTRATHINK_THINKING_UPDATE = "ultrathink_thinking_update"
    ULTRATHINK_CASCADE_COMPLETE = "ultrathink_cascade_complete"
```

**Step 2: Create events module**

```python
# backend/ultrathink/events.py
"""WebSocket event emitters for ultrathink cascade."""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Callable, Any

from models.schemas import WSMessage, WSMessageType, UltrathinkGate
from .gates import GateResult
from .cascade import CascadeResult


@dataclass
class UltrathinkEventEmitter:
    """Emits WebSocket events for ultrathink cascade progress."""

    agent_id: str
    on_message: Optional[Callable[[WSMessage], None]] = None

    async def emit(self, msg_type: WSMessageType, data: dict):
        """Emit a WebSocket message."""
        if self.on_message:
            msg = WSMessage(
                type=msg_type,
                agent_id=self.agent_id,
                data=data,
                timestamp=datetime.utcnow(),
            )
            self.on_message(msg)

    async def emit_cascade_start(self, finding_id: str, finding_title: str):
        """Emit cascade start event."""
        await self.emit(
            WSMessageType.ULTRATHINK_CASCADE_START,
            {
                "finding_id": finding_id,
                "finding_title": finding_title,
                "gates": [g.value for g in UltrathinkGate],
            }
        )

    async def emit_gate_start(self, gate: UltrathinkGate, finding_id: str):
        """Emit gate start event."""
        await self.emit(
            WSMessageType.ULTRATHINK_GATE_START,
            {
                "gate": gate.value,
                "finding_id": finding_id,
            }
        )

    async def emit_gate_complete(self, result: GateResult, finding_id: str):
        """Emit gate completion event."""
        await self.emit(
            WSMessageType.ULTRATHINK_GATE_COMPLETE,
            {
                "gate": result.gate.value,
                "finding_id": finding_id,
                "passed": result.passed,
                "confidence": result.confidence,
                "reasoning": result.reasoning,
                "duration_ms": result.duration_ms,
                "thinking_preview": result.full_trace[:500] if result.full_trace else None,
            }
        )

    async def emit_thinking_update(
        self,
        gate: UltrathinkGate,
        finding_id: str,
        thinking_chunk: str,
        tokens_so_far: int,
    ):
        """Emit real-time thinking update (for streaming)."""
        await self.emit(
            WSMessageType.ULTRATHINK_THINKING_UPDATE,
            {
                "gate": gate.value,
                "finding_id": finding_id,
                "thinking_chunk": thinking_chunk,
                "tokens_so_far": tokens_so_far,
            }
        )

    async def emit_cascade_complete(self, result: CascadeResult):
        """Emit cascade completion event."""
        await self.emit(
            WSMessageType.ULTRATHINK_CASCADE_COMPLETE,
            {
                "finding_id": result.finding.id,
                "final_verdict": result.final_verdict,
                "final_confidence": result.final_confidence,
                "rejected_by": result.rejected_by.value if result.rejected_by else None,
                "rejection_reason": result.rejection_reason,
                "total_thinking_tokens": result.total_thinking_tokens,
                "total_duration_ms": result.total_duration_ms,
                "gates_passed": sum(1 for gr in result.gate_results if gr.passed),
                "gates_total": len(result.gate_results),
            }
        )
```

**Step 3: Commit**

```bash
git add backend/models/schemas.py backend/ultrathink/events.py
git commit -m "feat: add ultrathink WebSocket events for real-time cascade visibility"
```

---

## Task 7: Create Ultrathink Agent Integration

**Files:**
- Create: `backend/agents/ultrathink_agent.py`
- Modify: `backend/agents/__init__.py`

**Step 1: Create the ultrathink agent**

```python
# backend/agents/ultrathink_agent.py
"""Ultrathink Agent - Maximum cognitive depth security analysis.

This agent integrates the ultrathink cascade with the existing agent framework,
providing full reasoning transparency and hierarchical verification.
"""

import asyncio
import os
from datetime import datetime
from typing import Callable, Optional

from agents.base_agent import BaseAgent
from models.schemas import (
    Agent,
    AgentCreateRequest,
    AgentStatus,
    AgentType,
    Finding,
    Severity,
    WSMessage,
    WSMessageType,
)
from providers import get_provider
from services import file_service
from ultrathink import UltrathinkConfig, UltrathinkCascade
from ultrathink.cascade import CascadeResult
from ultrathink.events import UltrathinkEventEmitter
from ultrathink.gates import GateResult
from prompts.strict_prompts import get_strict_system_prompt


class UltrathinkAgent(BaseAgent):
    """
    Agent that uses ultrathink cascade for maximum precision security analysis.

    This agent:
    1. Performs initial analysis to identify candidate findings
    2. Runs each candidate through the full ultrathink cascade
    3. Emits real-time progress via WebSocket
    4. Only reports findings that pass ALL verification gates

    Key Features:
    - Provider-agnostic extended thinking
    - Full reasoning trace visibility
    - Hierarchical verification cascade
    - Zero false positive tolerance
    """

    agent_type = AgentType.ULTRATHINK

    def __init__(
        self,
        request: AgentCreateRequest,
        repo_path: str,
        on_message: Optional[Callable[[WSMessage], None]] = None,
        ultrathink_config: Optional[UltrathinkConfig] = None,
    ):
        super().__init__(request, repo_path, on_message)

        self.ultrathink_config = ultrathink_config or UltrathinkConfig()
        self.event_emitter = UltrathinkEventEmitter(
            agent_id=self.id,
            on_message=on_message,
        )

        # Initialize cascade with event callbacks
        self.cascade = UltrathinkCascade(
            config=self.ultrathink_config,
            on_gate_start=self._on_gate_start,
            on_gate_complete=self._on_gate_complete,
        )

        # Tracking
        self.candidate_findings: list[Finding] = []
        self.verified_findings: list[Finding] = []
        self.cascade_results: list[CascadeResult] = []
        self.discarded_count = 0

    def _on_gate_start(self, gate):
        """Callback when a gate starts."""
        if self._current_finding:
            asyncio.create_task(
                self.event_emitter.emit_gate_start(gate, self._current_finding.id)
            )

    def _on_gate_complete(self, result: GateResult):
        """Callback when a gate completes."""
        if self._current_finding:
            asyncio.create_task(
                self.event_emitter.emit_gate_complete(result, self._current_finding.id)
            )

    async def analyze(self):
        """Perform ultrathink security analysis."""
        await self.emit_log("Starting ULTRATHINK analysis. Maximum cognitive depth mode.")
        await self.emit_log(f"Thinking mode: {self.ultrathink_config.thinking_mode.value}")
        await self.emit_log(f"Gates: {[g.name for g in self.ultrathink_config.gates]}")

        # Get files to analyze
        file_tree = await file_service.get_file_tree(self.repo_path)
        all_files = self._get_analyzable_files(file_tree)

        if self.target_files:
            all_files = [f for f in all_files if any(
                t in f for t in self.target_files
            )]

        total_files = len(all_files)
        await self.emit_log(f"Found {total_files} files to analyze")

        # Phase 1: Initial analysis to find candidates
        await self.emit_log("=== PHASE 1: Initial Analysis (Finding Candidates) ===")

        for i, file_path in enumerate(all_files):
            if self._cancelled or self.status == AgentStatus.PAUSED:
                while self.status == AgentStatus.PAUSED:
                    await asyncio.sleep(0.5)
                if self._cancelled:
                    break

            await self.emit_progress(i + 1, total_files, file_path)
            self.files_analyzed += 1

            try:
                content = await file_service.read_file(
                    os.path.join(self.repo_path, file_path)
                )
                if not content.strip():
                    continue

                # Run initial analysis
                findings = await self._initial_analysis(file_path, content)

                for finding in findings:
                    # Check if severity triggers ultrathink
                    if self.cascade.should_ultrathink(finding):
                        self.candidate_findings.append(finding)
                        await self.emit_log(
                            f"Candidate: {finding.title} ({finding.file_path}:{finding.line_start}) "
                            f"- will verify via ultrathink"
                        )
                    else:
                        # Low severity - report directly without ultrathink
                        self.findings.append(finding)
                        await self.emit_finding(finding)

            except Exception as e:
                await self.emit_log(f"Error analyzing {file_path}: {e}")

        if not self.candidate_findings:
            await self.emit_log("No medium+ severity candidates found for ultrathink verification.")
            return

        # Phase 2: Ultrathink cascade verification
        await self.emit_log(
            f"=== PHASE 2: Ultrathink Cascade ({len(self.candidate_findings)} candidates) ==="
        )

        # Read all code contexts
        code_contexts = {}
        for finding in self.candidate_findings:
            try:
                code_contexts[finding.file_path] = await file_service.read_file(
                    os.path.join(self.repo_path, finding.file_path)
                )
            except Exception:
                code_contexts[finding.file_path] = ""

        # Run each candidate through cascade
        for i, finding in enumerate(self.candidate_findings):
            if self._cancelled:
                break

            await self.emit_log(
                f"Ultrathink {i+1}/{len(self.candidate_findings)}: {finding.title}"
            )

            # Store current finding for event callbacks
            self._current_finding = finding

            # Emit cascade start
            await self.event_emitter.emit_cascade_start(
                finding.id, finding.title
            )

            # Run cascade
            result = await self.cascade.evaluate(
                finding=finding,
                code_context=code_contexts.get(finding.file_path, ""),
                provider=self.provider,
                model=self.provider_config.model,
            )

            self.cascade_results.append(result)

            # Emit cascade complete
            await self.event_emitter.emit_cascade_complete(result)

            if result.final_verdict:
                # Update finding with cascade evidence
                finding.confidence = result.final_confidence
                finding.metadata["ultrathink"] = {
                    "gates_passed": len(result.gate_results),
                    "total_thinking_tokens": result.total_thinking_tokens,
                    "evidence": result.evidence,
                }

                self.verified_findings.append(finding)
                self.findings.append(finding)
                await self.emit_finding(finding)
                await self.emit_log(f"VERIFIED: {finding.title}")
            else:
                self.discarded_count += 1
                await self.emit_log(
                    f"DISCARDED: {finding.title} - "
                    f"rejected by {result.rejected_by.value}: {result.rejection_reason}"
                )

        # Summary
        await self._emit_summary()

    async def _initial_analysis(self, file_path: str, content: str) -> list[Finding]:
        """Perform initial analysis to identify candidate findings."""
        # Use strict analysis prompt for initial pass
        ext = os.path.splitext(file_path)[1].lower()
        lang_map = {
            ".py": "python", ".js": "javascript", ".ts": "typescript",
            ".java": "java", ".go": "go", ".rs": "rust",
        }
        language = lang_map.get(ext, "")

        system_prompt = get_strict_system_prompt(language)

        # Truncate large files
        max_lines = 1500
        lines = content.split("\n")
        if len(lines) > max_lines:
            content = "\n".join(lines[:max_lines])

        user_prompt = f"""Analyze this file for security vulnerabilities.

FILE: {file_path}
LANGUAGE: {language or 'auto-detect'}

CODE:
```
{content}
```

Identify ALL potential vulnerabilities. For each finding, assess:
- How confident you are (0.0-1.0)
- Whether it needs deeper investigation

Format each finding as:
===POTENTIAL VULNERABILITY===
SEVERITY: [CRITICAL|HIGH|MEDIUM|LOW]
TITLE: [Brief title]
FILE: {file_path}
LINE: [line number]
DESCRIPTION: [description]
CONFIDENCE: [0.0-1.0]
NEEDS_ULTRATHINK: [YES/NO]
===END===
"""

        from providers import Message
        messages = [Message(role="user", content=user_prompt)]

        full_response = ""
        async for chunk in self.provider.generate_stream(messages, system_prompt):
            full_response += chunk.content
            if chunk.is_complete:
                break

        return self._parse_initial_findings(full_response, file_path)

    def _parse_initial_findings(self, response: str, file_path: str) -> list[Finding]:
        """Parse initial analysis findings."""
        import re
        import uuid

        findings = []
        blocks = re.split(r'===POTENTIAL VULNERABILITY===', response)

        for block in blocks[1:]:
            try:
                severity_m = re.search(r'SEVERITY:\s*(CRITICAL|HIGH|MEDIUM|LOW)', block, re.I)
                title_m = re.search(r'TITLE:\s*(.+?)(?:\n|$)', block)
                line_m = re.search(r'LINE:\s*(\d+)', block)
                desc_m = re.search(r'DESCRIPTION:\s*(.+?)(?=\nCONFIDENCE|$)', block, re.S)
                conf_m = re.search(r'CONFIDENCE:\s*([\d.]+)', block)

                if not title_m or not severity_m:
                    continue

                finding = Finding(
                    id=str(uuid.uuid4())[:12],
                    agent_id=self.id,
                    repo_id=self.repo_id,
                    severity=Severity(severity_m.group(1).lower()),
                    title=title_m.group(1).strip(),
                    description=desc_m.group(1).strip() if desc_m else "",
                    file_path=file_path,
                    line_start=int(line_m.group(1)) if line_m else 1,
                    vulnerability_type="ultrathink_candidate",
                    confidence=float(conf_m.group(1)) if conf_m else 0.5,
                    created_at=datetime.utcnow(),
                    metadata={"stage": "initial"},
                )
                findings.append(finding)

            except Exception:
                continue

        return findings

    def _get_analyzable_files(self, tree: dict, prefix: str = "") -> list[str]:
        """Extract analyzable file paths from tree."""
        files = []
        analyzable_exts = {
            ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go",
            ".rs", ".c", ".cpp", ".h", ".hpp", ".rb", ".php",
            ".cs", ".swift", ".kt", ".scala", ".sol",
        }
        skip_dirs = {"node_modules", ".git", "__pycache__", "vendor", "dist", "build"}

        name = tree.get("name", "")
        path = f"{prefix}/{name}" if prefix else name

        if tree.get("is_dir"):
            if name in skip_dirs:
                return files
            for child in tree.get("children", []):
                files.extend(self._get_analyzable_files(child, path))
        else:
            ext = os.path.splitext(name)[1].lower()
            if ext in analyzable_exts:
                files.append(path.lstrip("/"))

        return files

    async def _emit_summary(self):
        """Emit analysis summary."""
        summary = f"""
=== ULTRATHINK ANALYSIS SUMMARY ===
Files Analyzed: {self.files_analyzed}
Initial Candidates: {len(self.candidate_findings)}
Verified (REPORTED): {len(self.verified_findings)}
Discarded: {self.discarded_count}
Verification Rate: {(len(self.verified_findings) / len(self.candidate_findings) * 100) if self.candidate_findings else 0:.1f}%

Total Thinking Tokens: {sum(r.total_thinking_tokens for r in self.cascade_results):,}
"""

        if self.verified_findings:
            summary += "\nVERIFIED FINDINGS:\n"
            for f in self.verified_findings:
                summary += f"  [{f.severity.value.upper()}] {f.title} ({f.file_path}:{f.line_start})\n"
        else:
            summary += "\nNO VERIFIED FINDINGS - All candidates rejected by ultrathink cascade.\n"

        await self.emit_log(summary)

    # Initialize tracking variable
    _current_finding: Optional[Finding] = None
```

**Step 2: Update agents __init__.py**

```python
# Add to backend/agents/__init__.py

from .ultrathink_agent import UltrathinkAgent

# Update AGENT_REGISTRY
AGENT_REGISTRY = {
    # ... existing agents ...
    AgentType.ULTRATHINK: UltrathinkAgent,
}
```

**Step 3: Add ULTRATHINK to AgentType enum**

```python
# Add to backend/models/schemas.py AgentType enum

class AgentType(str, Enum):
    # ... existing types ...
    ULTRATHINK = "ultrathink"  # Maximum cognitive depth with hierarchical cascade
```

**Step 4: Commit**

```bash
git add backend/agents/ultrathink_agent.py backend/agents/__init__.py backend/models/schemas.py
git commit -m "feat: add UltrathinkAgent with full cascade integration"
```

---

## Task 8: Create Frontend Ultrathink Visualization Component

**Files:**
- Create: `frontend/components/UltrathinkPanel/UltrathinkPanel.tsx`
- Create: `frontend/components/UltrathinkPanel/GateProgress.tsx`
- Create: `frontend/components/UltrathinkPanel/ThinkingTrace.tsx`

**Step 1: Create the main panel component**

```tsx
// frontend/components/UltrathinkPanel/UltrathinkPanel.tsx
import React, { useState, useEffect } from 'react';
import { GateProgress } from './GateProgress';
import { ThinkingTrace } from './ThinkingTrace';

interface UltrathinkPanelProps {
  findingId: string;
  findingTitle: string;
  cascadeEvents: CascadeEvent[];
  isActive: boolean;
}

interface CascadeEvent {
  type: string;
  data: any;
  timestamp: string;
}

interface GateStatus {
  name: string;
  status: 'pending' | 'running' | 'passed' | 'failed';
  confidence?: number;
  reasoning?: string;
  thinkingPreview?: string;
  durationMs?: number;
}

const GATES = ['triage', 'deep_analysis', 'devils_advocate', 'proof_generator', 'final_gate'];

export const UltrathinkPanel: React.FC<UltrathinkPanelProps> = ({
  findingId,
  findingTitle,
  cascadeEvents,
  isActive,
}) => {
  const [gateStatuses, setGateStatuses] = useState<Record<string, GateStatus>>(
    Object.fromEntries(GATES.map(g => [g, { name: g, status: 'pending' }]))
  );
  const [selectedGate, setSelectedGate] = useState<string | null>(null);
  const [finalVerdict, setFinalVerdict] = useState<boolean | null>(null);

  useEffect(() => {
    // Process cascade events
    for (const event of cascadeEvents) {
      if (event.data.finding_id !== findingId) continue;

      switch (event.type) {
        case 'ultrathink_gate_start':
          setGateStatuses(prev => ({
            ...prev,
            [event.data.gate]: { ...prev[event.data.gate], status: 'running' },
          }));
          setSelectedGate(event.data.gate);
          break;

        case 'ultrathink_gate_complete':
          setGateStatuses(prev => ({
            ...prev,
            [event.data.gate]: {
              ...prev[event.data.gate],
              status: event.data.passed ? 'passed' : 'failed',
              confidence: event.data.confidence,
              reasoning: event.data.reasoning,
              thinkingPreview: event.data.thinking_preview,
              durationMs: event.data.duration_ms,
            },
          }));
          break;

        case 'ultrathink_cascade_complete':
          setFinalVerdict(event.data.final_verdict);
          break;
      }
    }
  }, [cascadeEvents, findingId]);

  const selectedGateStatus = selectedGate ? gateStatuses[selectedGate] : null;

  return (
    <div className="ultrathink-panel bg-gray-900 rounded-lg p-4 border border-gray-700">
      <div className="header mb-4">
        <h3 className="text-lg font-bold text-white flex items-center gap-2">
          <span className="text-purple-400">⚡</span>
          Ultrathink Cascade
          {isActive && (
            <span className="animate-pulse text-yellow-400 text-sm">(Running)</span>
          )}
        </h3>
        <p className="text-gray-400 text-sm mt-1">{findingTitle}</p>
      </div>

      {/* Gate Progress */}
      <div className="gates-progress mb-4">
        <GateProgress
          gates={GATES}
          statuses={gateStatuses}
          selectedGate={selectedGate}
          onSelectGate={setSelectedGate}
        />
      </div>

      {/* Final Verdict */}
      {finalVerdict !== null && (
        <div className={`verdict p-3 rounded-lg mb-4 ${
          finalVerdict ? 'bg-green-900/50 border border-green-600' : 'bg-red-900/50 border border-red-600'
        }`}>
          <span className="font-bold text-lg">
            {finalVerdict ? '✅ VERIFIED - Will Report' : '❌ REJECTED - Will Not Report'}
          </span>
        </div>
      )}

      {/* Thinking Trace */}
      {selectedGateStatus && (
        <ThinkingTrace
          gate={selectedGate!}
          status={selectedGateStatus.status}
          confidence={selectedGateStatus.confidence}
          reasoning={selectedGateStatus.reasoning}
          thinkingPreview={selectedGateStatus.thinkingPreview}
          durationMs={selectedGateStatus.durationMs}
        />
      )}
    </div>
  );
};
```

**Step 2: Create GateProgress component**

```tsx
// frontend/components/UltrathinkPanel/GateProgress.tsx
import React from 'react';

interface GateStatus {
  name: string;
  status: 'pending' | 'running' | 'passed' | 'failed';
  confidence?: number;
}

interface GateProgressProps {
  gates: string[];
  statuses: Record<string, GateStatus>;
  selectedGate: string | null;
  onSelectGate: (gate: string) => void;
}

const GATE_LABELS: Record<string, string> = {
  triage: 'Triage',
  deep_analysis: 'Deep Analysis',
  devils_advocate: "Devil's Advocate",
  proof_generator: 'Proof Gen',
  final_gate: 'Final Gate',
};

const STATUS_COLORS = {
  pending: 'bg-gray-600',
  running: 'bg-yellow-500 animate-pulse',
  passed: 'bg-green-500',
  failed: 'bg-red-500',
};

export const GateProgress: React.FC<GateProgressProps> = ({
  gates,
  statuses,
  selectedGate,
  onSelectGate,
}) => {
  return (
    <div className="gate-progress">
      <div className="flex items-center justify-between gap-1">
        {gates.map((gate, index) => {
          const status = statuses[gate];
          const isSelected = selectedGate === gate;

          return (
            <React.Fragment key={gate}>
              {/* Gate node */}
              <button
                onClick={() => onSelectGate(gate)}
                className={`
                  flex flex-col items-center gap-1 p-2 rounded-lg transition-all
                  ${isSelected ? 'ring-2 ring-purple-400' : ''}
                  hover:bg-gray-800
                `}
              >
                <div className={`
                  w-8 h-8 rounded-full flex items-center justify-center
                  ${STATUS_COLORS[status.status]}
                `}>
                  {status.status === 'passed' && '✓'}
                  {status.status === 'failed' && '✗'}
                  {status.status === 'running' && '⟳'}
                  {status.status === 'pending' && '○'}
                </div>
                <span className="text-xs text-gray-400 whitespace-nowrap">
                  {GATE_LABELS[gate]}
                </span>
                {status.confidence !== undefined && (
                  <span className="text-xs text-gray-500">
                    {(status.confidence * 100).toFixed(0)}%
                  </span>
                )}
              </button>

              {/* Connector line */}
              {index < gates.length - 1 && (
                <div className={`
                  flex-1 h-0.5
                  ${statuses[gates[index + 1]].status !== 'pending' ? 'bg-gray-500' : 'bg-gray-700'}
                `} />
              )}
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
};
```

**Step 3: Create ThinkingTrace component**

```tsx
// frontend/components/UltrathinkPanel/ThinkingTrace.tsx
import React, { useState } from 'react';

interface ThinkingTraceProps {
  gate: string;
  status: 'pending' | 'running' | 'passed' | 'failed';
  confidence?: number;
  reasoning?: string;
  thinkingPreview?: string;
  durationMs?: number;
}

const GATE_DESCRIPTIONS: Record<string, string> = {
  triage: 'Quick filter for obvious non-issues',
  deep_analysis: 'Thorough source-to-sink verification',
  devils_advocate: 'Actively arguing against the finding',
  proof_generator: 'Generating concrete exploit proof',
  final_gate: 'Final reputation-stake decision',
};

export const ThinkingTrace: React.FC<ThinkingTraceProps> = ({
  gate,
  status,
  confidence,
  reasoning,
  thinkingPreview,
  durationMs,
}) => {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="thinking-trace bg-gray-800 rounded-lg p-4">
      <div className="header flex justify-between items-start mb-3">
        <div>
          <h4 className="font-semibold text-white capitalize">
            {gate.replace(/_/g, ' ')}
          </h4>
          <p className="text-gray-500 text-sm">{GATE_DESCRIPTIONS[gate]}</p>
        </div>
        <div className="text-right">
          {confidence !== undefined && (
            <div className="text-lg font-mono">
              <span className={confidence >= 0.8 ? 'text-green-400' : 'text-yellow-400'}>
                {(confidence * 100).toFixed(0)}%
              </span>
            </div>
          )}
          {durationMs !== undefined && (
            <div className="text-xs text-gray-500">
              {(durationMs / 1000).toFixed(1)}s
            </div>
          )}
        </div>
      </div>

      {/* Status indicator */}
      {status === 'running' && (
        <div className="mb-3 p-3 bg-yellow-900/30 rounded border border-yellow-700">
          <div className="flex items-center gap-2">
            <span className="animate-spin">⟳</span>
            <span className="text-yellow-400">Thinking deeply...</span>
          </div>
        </div>
      )}

      {/* Reasoning */}
      {reasoning && (
        <div className="mb-3">
          <h5 className="text-sm font-medium text-gray-400 mb-1">Reasoning:</h5>
          <p className="text-gray-300 text-sm">{reasoning}</p>
        </div>
      )}

      {/* Thinking preview (collapsible) */}
      {thinkingPreview && (
        <div className="thinking-preview">
          <button
            onClick={() => setExpanded(!expanded)}
            className="flex items-center gap-2 text-sm text-purple-400 hover:text-purple-300"
          >
            <span>{expanded ? '▼' : '▶'}</span>
            <span>View Thinking Trace</span>
          </button>

          {expanded && (
            <pre className="mt-2 p-3 bg-gray-900 rounded text-xs text-gray-400 overflow-x-auto max-h-64 overflow-y-auto">
              {thinkingPreview}
            </pre>
          )}
        </div>
      )}
    </div>
  );
};
```

**Step 4: Commit**

```bash
git add frontend/components/UltrathinkPanel/
git commit -m "feat: add frontend ultrathink visualization components"
```

---

## Task 9: Integration Test - End to End

**Files:**
- Create: `tests/integration/test_ultrathink_e2e.py`

**Step 1: Write integration test**

```python
# tests/integration/test_ultrathink_e2e.py
"""End-to-end integration test for ultrathink cascade."""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from ultrathink import UltrathinkConfig, UltrathinkCascade
from ultrathink.cascade import CascadeResult
from models.schemas import Finding, Severity, ThinkingMode


@pytest.fixture
def vulnerable_code():
    """Sample vulnerable code for testing."""
    return '''
def get_user(user_id):
    """Get user by ID - VULNERABLE TO SQL INJECTION."""
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)

def login(username, password):
    """Login function - uses vulnerable get_user."""
    user = get_user(username)
    if user and user.password == password:
        return create_session(user)
    return None
'''


@pytest.fixture
def sample_finding():
    """Sample finding to verify."""
    return Finding(
        id="sqli-001",
        agent_id="test-agent",
        repo_id="test-repo",
        severity=Severity.CRITICAL,
        title="SQL Injection in get_user function",
        description="User input directly concatenated into SQL query",
        file_path="app/auth.py",
        line_start=3,
        vulnerability_type="sqli",
        confidence=0.75,
        created_at="2024-01-01T00:00:00Z",
    )


@pytest.fixture
def mock_provider():
    """Mock provider that returns realistic responses."""
    provider = MagicMock()

    responses = {
        "triage": '{"verdict": "investigate", "priority": 5, "reasoning": "Clear SQL injection pattern with f-string"}',
        "deep_analysis": '{"source_verified": true, "sink_verified": true, "path_verified": true, "confidence": 0.92, "source_location": "app/auth.py:3", "sink_location": "app/auth.py:4", "trace_steps": ["Input at line 3", "Concat at line 4", "Execute at line 4"], "analysis_summary": "Confirmed SQL injection"}',
        "devils_advocate": '{"verdict": "confirmed", "counter_arguments": ["Could have input validation elsewhere"], "revised_confidence": 0.88, "strongest_counter_argument": "No evidence of parameterization", "remaining_certainty": "f-string clearly shows direct concatenation"}',
        "proof_generator": '{"can_prove": true, "payload": "1 OR 1=1", "entry_point": "get_user(user_id)", "execution_trace": ["user_id=1 OR 1=1", "query=SELECT * FROM users WHERE id = 1 OR 1=1", "Returns all users"], "expected_result": "Authentication bypass", "verification_method": "Call get_user(\"1 OR 1=1\")"}',
        "final_gate": '{"stake_reputation": true, "confidence_percentage": 92, "strongest_evidence": "f-string SQL concatenation without parameterization", "biggest_doubt": "None - classic SQL injection", "final_decision": "REPORT", "reasoning": "Textbook SQL injection vulnerability"}',
    }

    call_count = [0]
    gates = ["triage", "deep_analysis", "devils_advocate", "proof_generator", "final_gate"]

    async def mock_generate(messages, system_prompt=None):
        gate_idx = min(call_count[0], len(gates) - 1)
        response = responses[gates[gate_idx]]
        call_count[0] += 1
        return response

    provider.generate = mock_generate
    return provider


@pytest.mark.asyncio
async def test_ultrathink_cascade_verifies_real_vulnerability(
    sample_finding,
    vulnerable_code,
    mock_provider
):
    """Test that cascade correctly verifies a real vulnerability."""
    config = UltrathinkConfig(
        thinking_mode=ThinkingMode.SIMULATED,
        capture_full_trace=True,
    )

    cascade = UltrathinkCascade(config=config)

    # Patch the thinking engine to use our mock
    with patch.object(cascade.thinking_engine, 'think') as mock_think:
        # Set up mock to return appropriate responses for each gate
        responses = [
            ('{"verdict": "investigate", "priority": 5}', "Triage thinking..."),
            ('{"source_verified": true, "sink_verified": true, "path_verified": true, "confidence": 0.92}', "Deep analysis thinking..."),
            ('{"verdict": "confirmed", "revised_confidence": 0.88}', "Devils advocate thinking..."),
            ('{"can_prove": true, "payload": "1 OR 1=1"}', "Proof gen thinking..."),
            ('{"stake_reputation": true, "confidence_percentage": 92, "final_decision": "REPORT"}', "Final gate thinking..."),
        ]

        call_idx = [0]
        async def mock_think_fn(*args, **kwargs):
            idx = min(call_idx[0], len(responses) - 1)
            output, trace = responses[idx]
            call_idx[0] += 1
            return MagicMock(
                output=output,
                thinking_trace=trace,
                thinking_tokens_used=1000,
            )

        mock_think.side_effect = mock_think_fn

        result = await cascade.evaluate(
            finding=sample_finding,
            code_context=vulnerable_code,
            provider=mock_provider,
            model="test-model",
        )

        # Verify the cascade passed
        assert result.final_verdict == True
        assert result.final_confidence >= 0.85
        assert len(result.gate_results) == 5
        assert all(gr.passed for gr in result.gate_results)
        assert result.rejected_by is None


@pytest.mark.asyncio
async def test_ultrathink_cascade_rejects_false_positive(mock_provider):
    """Test that cascade correctly rejects a false positive."""
    # Create a questionable finding
    weak_finding = Finding(
        id="fp-001",
        agent_id="test-agent",
        repo_id="test-repo",
        severity=Severity.HIGH,
        title="Potential XSS in template",
        description="Variable used in template",
        file_path="app/views.py",
        line_start=10,
        vulnerability_type="xss",
        confidence=0.55,
        created_at="2024-01-01T00:00:00Z",
    )

    safe_code = '''
def render_user(user):
    """Render user - SAFE because Jinja2 autoescapes."""
    return render_template("user.html", name=user.name)
'''

    config = UltrathinkConfig(thinking_mode=ThinkingMode.SIMULATED)
    cascade = UltrathinkCascade(config=config)

    with patch.object(cascade.thinking_engine, 'think') as mock_think:
        # Devils advocate will reject this
        responses = [
            ('{"verdict": "investigate", "priority": 3}', "Triage..."),
            ('{"source_verified": true, "sink_verified": true, "path_verified": true, "confidence": 0.70}', "Analysis..."),
            ('{"verdict": "reject", "revised_confidence": 0.35, "strongest_counter_argument": "Jinja2 autoescapes by default"}', "Devils advocate rejects..."),
        ]

        call_idx = [0]
        async def mock_think_fn(*args, **kwargs):
            idx = min(call_idx[0], len(responses) - 1)
            output, trace = responses[idx]
            call_idx[0] += 1
            return MagicMock(
                output=output,
                thinking_trace=trace,
                thinking_tokens_used=500,
            )

        mock_think.side_effect = mock_think_fn

        result = await cascade.evaluate(
            finding=weak_finding,
            code_context=safe_code,
            provider=mock_provider,
            model="test-model",
        )

        # Verify rejection
        assert result.final_verdict == False
        assert result.rejected_by is not None
        assert "devils_advocate" in result.rejected_by.value or "deep_analysis" in result.rejected_by.value
```

**Step 2: Run integration test**

Run: `cd backend && python -m pytest tests/integration/test_ultrathink_e2e.py -v`
Expected: PASS

**Step 3: Commit**

```bash
git add tests/integration/test_ultrathink_e2e.py
git commit -m "test: add end-to-end integration tests for ultrathink cascade"
```

---

## Task 10: Documentation

**Files:**
- Create: `docs/ultrathink.md`

**Step 1: Write documentation**

```markdown
# Ultrathink: Hierarchical Verification Cascade

## Overview

Ultrathink is a provider-agnostic extended thinking architecture for security vulnerability research. It maximizes AI model cognitive depth through a hierarchical verification cascade where findings must survive progressively harder scrutiny.

## Philosophy

Standard inference gives the model ~500ms to "think" before outputting. Ultrathink gives it **60+ seconds of cognitive runway** to:

- Generate and test hypotheses
- Backtrack when reasoning hits dead ends
- Verify its own claims against evidence
- Argue against itself before committing

## The Cascade

```
Finding → Triage → Deep Analysis → Devil's Advocate → Proof Generator → Final Gate → Report
            ↓           ↓                ↓                 ↓              ↓
          FAST      THOROUGH        ADVERSARIAL        CONCRETE       REPUTATION
```

### Gate 1: Triage (5s)
Quick filter for obvious non-issues. Uses minimal thinking budget.

### Gate 2: Deep Analysis (180s)
Thorough source-to-sink verification with maximum thinking budget.

### Gate 3: Devil's Advocate (120s)
Actively argues AGAINST the finding. Maximum adversarial strength.

### Gate 4: Proof Generator (90s)
Must produce concrete exploit proof or admit inability.

### Gate 5: Final Gate (60s)
"Would you stake your professional reputation on this?"

## Thinking Modes

### Native (Claude)
Uses Claude's built-in extended thinking with `thinking` blocks.

### Simulated (GPT-4)
Simulates extended thinking via chain-of-thought prompting.

### Structured (Open Source)
Uses highly structured reasoning prompts for models without native thinking.

## Configuration

```python
from ultrathink import UltrathinkConfig, ThinkingMode

config = UltrathinkConfig(
    thinking_mode=ThinkingMode.AUTO,  # Auto-detect based on model
    min_thinking_tokens=10000,
    max_thinking_tokens=50000,
    capture_full_trace=True,
    expose_thinking_to_user=True,
)
```

## Usage

```python
from ultrathink import UltrathinkCascade
from models.schemas import Finding

cascade = UltrathinkCascade(config=config)

result = await cascade.evaluate(
    finding=finding,
    code_context=code,
    provider=provider,
    model="claude-opus-4-5-20251101",
)

if result.final_verdict:
    print(f"VERIFIED with {result.final_confidence:.0%} confidence")
else:
    print(f"REJECTED by {result.rejected_by}: {result.rejection_reason}")
```

## Transparency

Full reasoning traces are captured and exposed:

```python
for trace in result.reasoning_traces:
    print(trace)  # Full thinking from each gate
```

## Integration

Use `UltrathinkAgent` as a drop-in replacement for `StrictAnalysisAgent`:

```python
from agents import UltrathinkAgent

agent = UltrathinkAgent(request, repo_path, on_message=emit)
findings = await agent.run()
```
```

**Step 2: Commit**

```bash
git add docs/ultrathink.md
git commit -m "docs: add ultrathink architecture documentation"
```

---

## Summary

This plan implements a complete **Ultrathink Hierarchical Verification Cascade** with:

1. **Provider-agnostic thinking engine** - Works with Claude (native), GPT-4 (simulated), and open-source (structured)
2. **5-gate verification cascade** - Triage → Deep Analysis → Devil's Advocate → Proof Generator → Final Gate
3. **Full reasoning transparency** - Every thinking step captured and exposed
4. **WebSocket real-time updates** - Track cascade progress live
5. **Frontend visualization** - See gates pass/fail with reasoning
6. **Integration with existing agents** - Drop-in replacement for StrictAnalysisAgent

---

**Plan complete and saved to `docs/plans/2026-01-08-ultrathink-hierarchical-verification-cascade.md`.**

**Two execution options:**

**1. Subagent-Driven (this session)** - I dispatch fresh subagent per task, review between tasks, fast iteration

**2. Parallel Session (separate)** - Open new session with executing-plans, batch execution with checkpoints

**Which approach?**

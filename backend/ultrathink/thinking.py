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

"""Prompt refinement stage - self-critique and improvement."""

from typing import Tuple, Optional

from models.schemas import ProviderConfig, ProviderType
from providers import get_provider
from providers.base_provider import Message


REFINEMENT_SYSTEM_PROMPT = """You are a security analysis prompt refinement specialist.

Your job is to CRITIQUE and IMPROVE the given security analysis prompt by:
1. Identifying vague or ambiguous instructions
2. Adding missing specificity
3. Restructuring for clarity
4. Ensuring the prompt will elicit actionable findings

CRITIQUE CHECKLIST:
- Does it specify what vulnerability types to look for?
- Does it mention how to report findings (severity, confidence)?
- Does it specify depth of analysis needed?
- Are there specific attack vectors mentioned?
- Is it clear what format the output should be?

After critiquing, output an IMPROVED version of the prompt that addresses the issues.

Output ONLY the refined prompt, nothing else. Do not include meta-commentary."""


class PromptRefiner:
    """Refines security analysis prompts through self-critique."""

    async def refine(
        self,
        prompt: str,
        code_context: str,
        provider_config: Optional[ProviderConfig] = None,
    ) -> Tuple[str, int, int]:
        """
        Refine a security analysis prompt through self-critique.

        Args:
            prompt: The prompt to refine (possibly already enriched)
            code_context: Code snippet for context

        Returns:
            Tuple of (refined_prompt, tokens_in, tokens_out)
        """
        if provider_config is None:
            provider_config = ProviderConfig(
                provider=ProviderType.OPENAI,
                model="gpt-4o-mini",
                temperature=0.0,
                max_tokens=2000,
            )

        provider = get_provider(provider_config)

        # Build refinement request
        user_message = f"""Analyze and improve this security analysis prompt:

PROMPT TO REFINE:
{prompt}

CODE CONTEXT (abbreviated):
```
{code_context[:300]}...
```

Critique the prompt and output an improved version."""

        messages = [Message(role="user", content=user_message)]

        # Generate refined prompt
        refined = await provider.generate(messages, REFINEMENT_SYSTEM_PROMPT)

        # Estimate tokens
        tokens_in = len(user_message) // 4 + len(REFINEMENT_SYSTEM_PROMPT) // 4
        tokens_out = len(refined) // 4

        return refined.strip(), tokens_in, tokens_out

    def _add_output_format(self, prompt: str) -> str:
        """Ensure the prompt specifies output format."""
        if "format" not in prompt.lower() and "output" not in prompt.lower():
            prompt += """

For each finding, provide:
- Severity (critical/high/medium/low/info)
- Confidence score (0.0-1.0)
- CWE ID if applicable
- Specific line numbers
- Attack scenario
- Proof of concept if possible
- Recommended fix"""
        return prompt

"""Verification stage - validates findings and rates confidence."""

from typing import Tuple, Optional

from models.schemas import ProviderConfig, ProviderType
from providers import get_provider
from providers.base_provider import Message


VERIFICATION_SYSTEM_PROMPT = """You are a security finding verification specialist.

Your job is to VERIFY security findings by:
1. Checking if the vulnerability is real (not a false positive)
2. Validating the severity assessment
3. Verifying the exploit path is feasible
4. Confirming line numbers and code references are accurate
5. Adjusting confidence scores based on your verification

VERIFICATION CHECKLIST:
- [ ] Is this a real vulnerability or just suspicious code?
- [ ] Does the attack scenario actually work?
- [ ] Is user input actually reaching the vulnerable sink?
- [ ] Are there existing mitigations that weren't considered?
- [ ] Is the severity appropriate for the actual impact?

OUTPUT FORMAT:
For each finding in the analysis, output a verification summary:

### Finding: [title]
**Verified**: Yes/No/Partial
**Original Severity**: [severity]
**Verified Severity**: [adjusted severity if needed]
**Original Confidence**: [score]
**Verified Confidence**: [adjusted score]
**Verification Notes**: [explanation of your verification]
**False Positive Risk**: Low/Medium/High

Then provide an overall summary of verified vs unverified findings."""


class PromptVerifier:
    """Verifies security findings and adjusts confidence scores."""

    async def verify(
        self,
        analysis_output: str,
        code_context: str,
        provider_config: Optional[ProviderConfig] = None,
    ) -> Tuple[str, int, int]:
        """
        Verify security findings from the main analysis.

        Args:
            analysis_output: Output from the main analysis stage
            code_context: Original code for verification

        Returns:
            Tuple of (verification_report, tokens_in, tokens_out)
        """
        if provider_config is None:
            provider_config = ProviderConfig(
                provider=ProviderType.OPENAI,
                model="gpt-4o",  # Use a capable model for verification
                temperature=0.0,
                max_tokens=2000,
            )

        provider = get_provider(provider_config)

        # Build verification request
        user_message = f"""Verify the following security analysis findings:

ANALYSIS OUTPUT:
{analysis_output}

CODE FOR VERIFICATION:
```
{code_context[:2000]}
```

For each finding mentioned, verify if it's a true vulnerability and adjust confidence accordingly."""

        messages = [Message(role="user", content=user_message)]

        # Generate verification report
        verification = await provider.generate(messages, VERIFICATION_SYSTEM_PROMPT)

        # Estimate tokens
        tokens_in = len(user_message) // 4 + len(VERIFICATION_SYSTEM_PROMPT) // 4
        tokens_out = len(verification) // 4

        return verification.strip(), tokens_in, tokens_out

    def _extract_confidence_adjustments(self, verification: str) -> dict[str, float]:
        """Extract confidence adjustments from verification output."""
        adjustments = {}
        # Simple parsing - look for "Verified Confidence: X.X" patterns
        import re
        pattern = r"Finding:\s*(.+?)\n.*?Verified Confidence:\s*([\d.]+)"
        matches = re.findall(pattern, verification, re.DOTALL | re.IGNORECASE)
        for title, confidence in matches:
            try:
                adjustments[title.strip()] = float(confidence)
            except ValueError:
                pass
        return adjustments

    def _check_false_positive_indicators(self, finding: str, code: str) -> list[str]:
        """Check for common false positive indicators."""
        indicators = []

        # Check for sanitization functions
        sanitizers = ["escape", "sanitize", "encode", "clean", "filter", "validate"]
        for s in sanitizers:
            if s in code.lower():
                indicators.append(f"Possible sanitization present: {s}")

        # Check for framework protections
        frameworks = ["csrf_token", "xss_filter", "parameterized", "prepared"]
        for f in frameworks:
            if f in code.lower():
                indicators.append(f"Framework protection detected: {f}")

        return indicators

"""
Production Relevance Filter - LLM-based filtering for bug bounty triage.

Uses Claude to intelligently determine if a finding is relevant for bug bounty
submission based on file path, code context, and production impact.
"""

import warnings
from typing import Optional
from anthropic import Anthropic
from models.schemas import Finding, Disposition
from protocol_config.protocol_config import ProtocolConfig

# Deprecation warning
warnings.warn(
    "production_relevance_filter is deprecated. Use services.finding_filters.ProductionRelevanceFilter instead.",
    DeprecationWarning,
    stacklevel=2
)


class ProductionRelevanceFilter:
    """
    LLM-based filter to determine if a finding affects production code.

    This runs BEFORE detailed classification to quickly filter out:
    - Test code
    - Build tools and utilities
    - Third-party dependencies
    - Documentation and samples
    - Development-only code
    """

    def __init__(
        self,
        anthropic_api_key: str,
        model: Optional[str] = None,
        max_tokens: int = 300,
        temperature: float = 0
    ):
        self.client = Anthropic(api_key=anthropic_api_key)
        self.model = model or ProtocolConfig.QUEST_LLM_MODEL
        self.max_tokens = max_tokens
        self.temperature = temperature

    def is_production_relevant(self, finding: Finding) -> tuple[bool, str]:
        """
        Determine if finding is relevant for production/bug bounty.

        Returns:
            (is_relevant, reason)
        """

        prompt = self._build_prompt(finding)

        try:
            message = self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                messages=[{
                    "role": "user",
                    "content": prompt
                }]
            )

            response = message.content[0].text.strip()

            # Parse response
            if response.startswith("FILTER:"):
                reason = response.replace("FILTER:", "").strip()
                return (False, reason)
            elif response.startswith("KEEP:"):
                reason = response.replace("KEEP:", "").strip()
                return (True, reason)
            else:
                # Default to keeping if unclear
                return (True, "Could not determine relevance")

        except Exception as e:
            # On error, default to keeping finding
            return (True, f"Filter error: {str(e)}")

    def _build_prompt(self, finding: Finding) -> str:
        """Build LLM prompt for production relevance check and issue validation."""

        return f"""You are a bug bounty triage expert. This is a two-stage evaluation to determine if this finding should be reported.

## Finding Details
- **Title:** {finding.title}
- **File Path:** {finding.file_path}
- **Vulnerability Type:** {finding.vulnerability_type}
- **Severity:** {finding.severity}
- **Description:** {finding.description[:500]}

## STAGE 1: Production Relevance Filter

Determine if this code affects production users. Filter out code that only runs during development, testing, or build processes.

**FILTER OUT** (respond with "FILTER: <reason>"):
- Test code and test utilities
- Build tools and development scripts
- Third-party dependencies and vendored code
- Documentation and example code
- Configuration files for build systems
- Development-only utilities

**KEEP** (proceed to Stage 2):
- Production runtime code
- Libraries that ship to users
- API endpoints and server code
- Client-side code (web, mobile, desktop)
- Core application functionality

If filtered here, respond immediately with "FILTER: <reason>" and stop.

## STAGE 2: Issue Validation (for production code only)

Analyze if this is a real security issue worth reporting. Be VERY HARSH on distinguishing between "bug" and "security issue".

**FILTER OUT** (respond with "FILTER: <reason>"):
1. **Expected behavior** - Working as designed without security implications
2. **Configuration without impact** - Design choice that doesn't create exploitable conditions
3. **Bug but not security** - Functional issue without security exploitation path
4. **Theoretical only** - No realistic attack scenario or attacker capabilities
5. **Pattern match false positive** - Looks like a vulnerability type but isn't actually exploitable
6. **Unrealistic prerequisites** - Requires impossible attacker position or user actions

**KEEP** (respond with "KEEP: <reason>"):
1. **Exploitable vulnerability** - Real security issue with realistic attack scenario
2. **Risky configuration** - By-design but creates security-exploitable condition
3. **Documented but dangerous** - Known issue that still has valid security impact

## Validation Criteria

For the specific vulnerability type, verify:
- **Attacker control**: Can an attacker actually control the dangerous input?
- **Sink execution**: Does the code path actually execute the dangerous operation?
- **Prerequisites**: Are the conditions for exploitation realistic?
- **Impact**: Would successful exploitation have security consequences?

## Your Response

Respond with EXACTLY one line:
- "FILTER: <brief reason>" if this should NOT be reported
- "KEEP: <brief reason>" if this SHOULD be reported

Focus on: Is this a real security issue with realistic exploitation?"""

    def get_filter_disposition(self) -> Disposition:
        """Return the disposition to use for filtered findings."""
        return Disposition.HARDENING

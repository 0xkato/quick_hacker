"""
Production Relevance Filter - LLM-based filtering for bug bounty triage.

Uses Claude to intelligently determine if a finding is relevant for bug bounty
submission based on file path, code context, and production impact.
"""

from typing import Optional
from anthropic import Anthropic
from models.schemas import Finding, Disposition

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

    def __init__(self, anthropic_api_key: str):
        self.client = Anthropic(api_key=anthropic_api_key)

    def is_production_relevant(self, finding: Finding) -> tuple[bool, str]:
        """
        Determine if finding is relevant for production/bug bounty.

        Returns:
            (is_relevant, reason)
        """

        prompt = self._build_prompt(finding)

        try:
            message = self.client.messages.create(
                model="claude-3-5-haiku-20241022",  # Fast, cheap model
                max_tokens=200,
                temperature=0,
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

**FILTER OUT (respond with "FILTER: <reason>"):**
1. **Test code** - Files in test/, tests/, __tests__/, spec/, *_test.*, *Test.*, test_*
2. **Build tools** - Files in tools/, scripts/, build/, utils/, bin/, dev-tools/
3. **Third-party code** - Files in third_party/, vendor/, node_modules/, external/, deps/
4. **Documentation** - Files in docs/, documentation/, examples/, samples/, tutorials/
5. **Config files** - Dockerfiles, docker-compose.yml, .sh scripts, Makefiles, build.gradle
6. **Development utilities** - Code that only runs during development/build, not in production

If filtered here, respond immediately with "FILTER: <reason>" and stop.

## STAGE 2: Issue Validation (for production code only)

The report below is an issue. I want you to do research to figure out if this is something that is:
- **Expected behavior** - Specifically allowed or by-design
- **Configuration issue** - Could have larger implications as described in the report
- **Actual security problem** - Real vulnerability worth reporting

**CRITICAL: Be VERY HARSH on distinguishing between "bug" and "security issue".**

**FILTER OUT (respond with "FILTER: <reason>"):**
1. **Expected behavior** - Documented as working as intended
2. **By-design configuration** - Intentional design choice without security implications
3. **Bug but not security** - Functional issue without exploitable security impact
4. **Theoretical only** - No realistic attack scenario or attacker model
5. **Invalid sink** - Pattern matches vulnerability type but isn't exploitable (e.g., command injection without shell=True)
6. **Missing prerequisites** - Requires unrealistic attacker capabilities or user actions

**KEEP (respond with "KEEP: <reason>"):**
1. **Real security issue** - Exploitable vulnerability with realistic attack scenario
2. **Configuration with security implications** - By-design but creates exploitable condition
3. **Documented but still exploitable** - Known issue that's still a valid security concern

## Special Cases for Production Code
- **Command injection** - Must use shell=True or equivalent, not just argv parsing
- **Buffer overflow** - Must show attacker-controlled size/input reaching unsafe function
- **Path traversal** - Must show user input flowing to file operations
- **XSS/injection** - Must show user input rendered/executed without sanitization
- **Stack protection disabled** - Only if paired with actual memory corruption vulnerability

## Your Response
Respond with EXACTLY one line:
- "FILTER: <brief reason>" if this should NOT be reported
- "KEEP: <brief reason>" if this SHOULD be reported

Focus on: Is this a real security issue with realistic exploitation, or is it expected behavior/bug/theoretical concern?"""

    def get_filter_disposition(self) -> Disposition:
        """Return the disposition to use for filtered findings."""
        return Disposition.HARDENING

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
        """Build LLM prompt for production relevance check."""

        return f"""You are a bug bounty triage expert. Determine if this security finding should be reported to a bug bounty program.

## Finding Details
- **Title:** {finding.title}
- **File Path:** {finding.file_path}
- **Vulnerability Type:** {finding.vulnerability_type}
- **Severity:** {finding.severity}
- **Description:** {finding.description[:500]}

## Bug Bounty Filtering Criteria

**FILTER OUT (respond with "FILTER: <reason>"):**
1. **Test code** - Files in test/, tests/, __tests__/, spec/, *_test.*, *Test.*, test_*
2. **Build tools** - Files in tools/, scripts/, build/, utils/, bin/, dev-tools/
3. **Third-party code** - Files in third_party/, vendor/, node_modules/, external/, deps/
4. **Documentation** - Files in docs/, documentation/, examples/, samples/, tutorials/
5. **Config files** - Dockerfiles, docker-compose.yml, .sh scripts, Makefiles, build.gradle
6. **Development utilities** - Code that only runs during development/build, not in production

**KEEP (respond with "KEEP: <reason>"):**
1. **Production libraries** - Code in libs/, src/, app/, core/ that ships to users
2. **Runtime code** - Code that executes when the application runs for end users
3. **API endpoints** - Server code that handles user requests
4. **Client code** - JavaScript/Android/iOS code that runs on user devices
5. **Core functionality** - Any code that affects actual users of the product

## Special Cases
- android/**/*.cpp or android/**/*.java in src/main/java → **KEEP** (production Android code)
- android/build.gradle → **FILTER** (build configuration)
- libs/**/*.cpp or libs/**/*.h → **KEEP** (production libraries)
- web/samples/** → **FILTER** (example code)
- docs/** → **FILTER** (documentation)

## Your Response
Respond with EXACTLY one line:
- "FILTER: <brief reason>" if this should NOT be reported
- "KEEP: <brief reason>" if this SHOULD be reported

Focus on: Does this affect end users of the production application?"""

    def get_filter_disposition(self) -> Disposition:
        """Return the disposition to use for filtered findings."""
        return Disposition.HARDENING

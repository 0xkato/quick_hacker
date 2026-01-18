"""Authentication Bypass classification gate."""
from models.schemas import Finding, Evidence, Disposition
from .base import BaseGate, GateResult


class AuthBypassGate(BaseGate):
    """Authentication bypass classification gate."""

    def get_category_name(self) -> str:
        return "AUTHENTICATION_BYPASS"

    def evaluate(self, finding: Finding, evidence: Evidence) -> GateResult:
        """Evaluate authentication bypass finding."""
        reasoning = []
        passed = False

        # Collect code snippets
        code_snippets = []
        if evidence.snippet:
            code_snippets.append(evidence.snippet)

        route_matches = [m for m in evidence.matches if m.get("match_type") == "route_registration"]
        for match in route_matches:
            code_snippets.append(match.get("snippet", ""))

        auth_matches = [m for m in evidence.matches if m.get("match_type") == "auth_gate"]
        for match in auth_matches:
            code_snippets.append(match.get("snippet", ""))

        combined = " ".join(code_snippets).lower()

        # Check for explicit bypass markers
        bypass_markers = [
            "bypass_auth=true", "require_auth=false",
            "public=true", "skip_auth=true",
            "@public_endpoint", "@no_auth_required",
            "@unauthenticated", "@allow_anonymous"
        ]

        has_bypass = any(marker in combined for marker in bypass_markers)

        if has_bypass:
            reasoning.append("Explicit authentication bypass marker found in code")
            passed = True
        else:
            reasoning.append("No explicit bypass marker in code")

            # Check if auth gates are present
            if auth_matches:
                reasoning.append(f"Found {len(auth_matches)} auth gates - may be protected")
            else:
                reasoning.append("No auth gates found - unclear if protected")

        return GateResult(
            passed=passed,
            reasoning=reasoning,
            proof_items={"has_bypass": has_bypass}
        )

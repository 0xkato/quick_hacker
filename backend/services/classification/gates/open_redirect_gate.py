"""Open Redirect classification gate."""
from models.schemas import Finding, Evidence, Disposition
from .base import BaseGate, GateResult


class OpenRedirectGate(BaseGate):
    """Open redirect classification gate."""

    def get_category_name(self) -> str:
        return "OPEN_REDIRECT"

    def evaluate(self, finding: Finding, evidence: Evidence) -> GateResult:
        """Evaluate open redirect finding."""
        reasoning = []
        passed = False

        snippet_lower = (evidence.snippet or "").lower()

        # Check for redirect sinks
        redirect_sinks = [
            "redirect(", "return redirect", "response.redirect",
            "location.href", "window.location", "header('location:",
            "httpresponse(status=302", "httpresponse(status=301"
        ]

        has_sink = any(sink in snippet_lower for sink in redirect_sinks)
        if has_sink:
            reasoning.append("Redirect sink detected")

            # Check for URL validation
            validation_markers = [
                "is_safe_url", "validate_redirect", "allowed_hosts",
                "url_validator", "urlparse", "is_internal_url"
            ]
            has_validation = any(marker in snippet_lower for marker in validation_markers)

            if has_validation:
                reasoning.append("URL validation present")
                passed = False
            else:
                reasoning.append("No URL validation detected")
                passed = True
        else:
            reasoning.append("No redirect sink found")

        return GateResult(
            passed=passed,
            reasoning=reasoning,
            proof_items={"has_sink": has_sink}
        )

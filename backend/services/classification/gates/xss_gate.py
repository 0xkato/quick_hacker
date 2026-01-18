"""XSS classification gate."""
from models.schemas import Finding, Evidence, Disposition
from .base import BaseGate, GateResult


class XSSGate(BaseGate):
    """Cross-Site Scripting classification gate."""

    def get_category_name(self) -> str:
        return "XSS"

    def evaluate(self, finding: Finding, evidence: Evidence) -> GateResult:
        """Evaluate XSS finding."""
        reasoning = []
        passed = False

        snippet_lower = (evidence.snippet or "").lower()

        # Check for output sinks
        xss_sinks = [
            ".innerhtml", "document.write", ".outerhtml",
            "dangerouslysetinnerhtml", "v-html", "ng-bind-html"
        ]

        has_sink = any(sink in snippet_lower for sink in xss_sinks)
        if has_sink:
            reasoning.append("XSS sink detected (dangerous DOM manipulation)")
            passed = True
        else:
            # Check for template injection patterns
            if "{{ " in (evidence.snippet or "") and "}}" in (evidence.snippet or ""):
                reasoning.append("Template expression detected")
                passed = True
            else:
                reasoning.append("No clear XSS sink found")

        # Check for sanitization
        sanitization_markers = [
            "sanitize", "escape", "dompurify", "htmlencode", "html_safe"
        ]
        has_sanitization = any(marker in snippet_lower for marker in sanitization_markers)

        if has_sanitization:
            reasoning.append("Sanitization detected - may be mitigated")

        return GateResult(
            passed=passed,
            reasoning=reasoning,
            proof_items={
                "has_sink": has_sink,
                "has_sanitization": has_sanitization
            }
        )

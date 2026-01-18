"""Cross-Site WebSocket Hijacking (CSWSH) classification gate."""
from models.schemas import Finding, Evidence, Disposition
from .base import BaseGate, GateResult


class CSWSHGate(BaseGate):
    """Cross-Site WebSocket Hijacking classification gate."""

    def get_category_name(self) -> str:
        return "CSWSH"

    def evaluate(self, finding: Finding, evidence: Evidence) -> GateResult:
        """Evaluate CSWSH finding."""
        reasoning = []
        passed = True
        disposition = None

        snippet_lower = (evidence.snippet or "").lower()

        # Check for check_origin implementation
        has_check_origin = "check_origin" in snippet_lower

        if has_check_origin:
            # Origin checking is present - check if there's evidence of credential abuse
            has_credentials = ("cookie" in snippet_lower or
                              "session" in snippet_lower or
                              "authentication" in snippet_lower)

            if has_credentials:
                reasoning.append("check_origin present with credential/session usage")
                passed = True
            else:
                reasoning.append("check_origin present but no ambient credential evidence")
                passed = False
                disposition = Disposition.HARDENING
        else:
            reasoning.append("No check_origin validation found")
            passed = True

        return GateResult(
            passed=passed,
            reasoning=reasoning,
            proof_items={
                "has_check_origin": has_check_origin
            },
            disposition=disposition
        )

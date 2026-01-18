"""SSRF classification gate."""
from models.schemas import Finding, Evidence, Disposition
from .base import BaseGate, GateResult


class SSRFGate(BaseGate):
    """Server-Side Request Forgery classification gate."""

    def get_category_name(self) -> str:
        return "SSRF"

    def evaluate(self, finding: Finding, evidence: Evidence) -> GateResult:
        """Evaluate SSRF finding with constant URL detection."""
        reasoning = []
        passed = True
        disposition = None

        # Check for constant or config-based URLs
        if evidence.ssrf_analysis:
            if evidence.ssrf_analysis.get("url_is_constant"):
                reasoning.append("URL is hardcoded constant")
                passed = False
                disposition = Disposition.SPECULATIVE
            elif evidence.ssrf_analysis.get("url_from_config"):
                reasoning.append("URL comes from configuration file")
                passed = False
                disposition = Disposition.SPECULATIVE
            else:
                reasoning.append("URL appears to be user-controlled")
                passed = True
        else:
            reasoning.append("No SSRF analysis available")
            passed = False

        return GateResult(
            passed=passed,
            reasoning=reasoning,
            proof_items={"ssrf_analysis": evidence.ssrf_analysis if evidence.ssrf_analysis else {}},
            disposition=disposition
        )

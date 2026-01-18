"""XXE classification gate."""
from models.schemas import Finding, Evidence, Disposition
from .base import BaseGate, GateResult


class XXEGate(BaseGate):
    """XML External Entity classification gate."""

    def get_category_name(self) -> str:
        return "XXE"

    def evaluate(self, finding: Finding, evidence: Evidence) -> GateResult:
        """Evaluate XXE finding."""
        reasoning = []
        passed = False

        snippet_lower = (evidence.snippet or "").lower()

        # Check for XML parsing sinks
        xml_sinks = [
            "etree.parse", "etree.fromstring", "etree.xml",
            "xml.etree", "lxml.etree", "minidom.parse",
            "xml.dom", "xml.sax", "xmlparser"
        ]

        has_sink = any(sink in snippet_lower for sink in xml_sinks)
        if has_sink:
            reasoning.append("XML parsing sink detected")

            # Check for secure configuration
            secure_markers = [
                "resolve_entities=false", "resolve_entities = false",
                "no_network=true", "no_network = true",
                "dtd_validation=false", "load_dtd=false",
                "defusedxml"
            ]
            has_secure_config = any(marker in snippet_lower for marker in secure_markers)

            if has_secure_config:
                reasoning.append("Secure XML parser configuration detected")
                passed = False
            else:
                reasoning.append("No secure parser configuration found")
                passed = True
        else:
            reasoning.append("No XML parsing sink found")

        return GateResult(
            passed=passed,
            reasoning=reasoning,
            proof_items={"has_sink": has_sink}
        )

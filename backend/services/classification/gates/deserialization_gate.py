"""Deserialization classification gate."""
from models.schemas import Finding, Evidence, Disposition, ChecklistStatus
from .base import BaseGate, GateResult


class DeserializationGate(BaseGate):
    """Deserialization vulnerability classification gate."""

    def get_category_name(self) -> str:
        return "DESERIALIZATION"

    def evaluate(self, finding: Finding, evidence: Evidence) -> GateResult:
        """Evaluate deserialization finding."""
        reasoning = []
        passed = False
        disposition = None

        # Check for deserialization sinks
        snippet_lower = (evidence.snippet or "").lower()
        deserialization_sinks = [
            "pickle.load", "yaml.load", "yaml.unsafe_load",
            "marshal.load", "jsonpickle", "dill.load"
        ]

        has_sink = any(sink in snippet_lower for sink in deserialization_sinks)
        if has_sink:
            reasoning.append("Deserialization sink detected")

            # Check for attacker-controlled source
            # Must have proven source control for this to be exploitable
            has_source = False
            if evidence.matches:
                source_matches = [m for m in evidence.matches if m.get("match_type") == "source"]
                if source_matches:
                    has_source = True
                    reasoning.append(f"Found {len(source_matches)} user input sources")

            if has_source:
                passed = True
                reasoning.append("Attacker-controlled deserialization")
            else:
                reasoning.append("No attacker-controlled source detected")
                disposition = Disposition.HARDENING
        else:
            reasoning.append("No dangerous deserialization sink found")

        return GateResult(
            passed=passed,
            reasoning=reasoning,
            proof_items={"has_sink": has_sink},
            disposition=disposition
        )

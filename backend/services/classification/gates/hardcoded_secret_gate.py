"""Hardcoded Secret classification gate."""
from models.schemas import Finding, Evidence, Disposition
from .base import BaseGate, GateResult


class HardcodedSecretGate(BaseGate):
    """Hardcoded secret classification gate."""

    def get_category_name(self) -> str:
        return "HARDCODED_SECRET"

    def evaluate(self, finding: Finding, evidence: Evidence) -> GateResult:
        """Evaluate hardcoded secret finding."""
        reasoning = []
        passed = True
        disposition = None

        # Check if this is in test/example/sample files
        path_lower = finding.file_path.lower()
        test_markers = [
            "test", "example", "sample", "demo", "docker-compose", ".env.example",
            # Vendored / third-party bundles often include demo certs/keys
            "third_party", "third-party", "/vendor/", "vendored",
            # Common cert fixture locations in embedded servers
            "resources/cert", "resources/certs", "resources/ssl_cert",
            # Build tools, utilities, docs, samples often have example/test code
            "/tools/", "tools/", "/docs/", "docs/", "samples/", "/samples/",
            "_obsolete",
        ]

        is_test_file = any(marker in path_lower for marker in test_markers)

        if is_test_file:
            reasoning.append(f"Found in test/example/sample context: {finding.file_path}")
            passed = False
            disposition = Disposition.HARDENING
        else:
            reasoning.append("Hardcoded secret in production code")
            passed = True

        return GateResult(
            passed=passed,
            reasoning=reasoning,
            proof_items={"is_test_file": is_test_file},
            disposition=disposition
        )

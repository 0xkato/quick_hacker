"""Path Traversal classification gate."""
from models.schemas import Finding, Evidence, Disposition
from .base import BaseGate, GateResult


class PathTraversalGate(BaseGate):
    """Path traversal classification gate."""

    def get_category_name(self) -> str:
        return "PATH_TRAVERSAL"

    def evaluate(self, finding: Finding, evidence: Evidence) -> GateResult:
        """Evaluate path traversal finding."""
        reasoning = []
        passed = False

        snippet_lower = (evidence.snippet or "").lower()

        # Check for file operation sinks
        file_sinks = [
            "open(", "file(", "os.path.join",
            "pathlib.path", "send_file", "send_from_directory",
            "os.remove", "os.unlink", "shutil.rmtree"
        ]

        has_sink = any(sink in snippet_lower for sink in file_sinks)
        if has_sink:
            reasoning.append("File operation sink detected")

            # Check for path validation
            validation_markers = [
                "os.path.abspath", "path.resolve", "realpath",
                "normpath", "secure_filename", "safe_join"
            ]
            has_validation = any(marker in snippet_lower for marker in validation_markers)

            if has_validation:
                reasoning.append("Path validation present")
                passed = False
            else:
                reasoning.append("No path validation detected")
                passed = True
        else:
            reasoning.append("No clear file operation sink found")

        return GateResult(
            passed=passed,
            reasoning=reasoning,
            proof_items={"has_sink": has_sink}
        )

"""Command Injection classification gate."""
from models.schemas import Finding, Evidence, Disposition, ChecklistStatus
from .base import BaseGate, GateResult


class CommandInjectionGate(BaseGate):
    """Command injection classification gate."""

    def get_category_name(self) -> str:
        return "COMMAND_INJECTION"

    def evaluate(self, finding: Finding, evidence: Evidence) -> GateResult:
        """Evaluate command injection finding."""
        reasoning = []
        passed = False

        # Check for command execution sinks
        snippet_lower = (evidence.snippet or finding.code_snippet or "").lower()
        command_sinks = [
            "subprocess.popen", "subprocess.call", "subprocess.run",
            "os.system", "os.popen", "commands.getoutput",
            "subprocess.check_output", "subprocess.getstatusoutput"
        ]

        has_sink = any(sink in snippet_lower for sink in command_sinks)
        if has_sink:
            reasoning.append("Command execution sink detected")

            # Check for shell=True (makes it more dangerous)
            if "shell=true" in snippet_lower or "shell = true" in snippet_lower:
                reasoning.append("shell=True detected - dangerous configuration")
                passed = True
            else:
                reasoning.append("Command sink present (check if array-based or string)")
                passed = True
        else:
            reasoning.append("No clear command execution sink found")

        # Check for test/tools context
        path_lower = finding.file_path.lower()
        if any(marker in path_lower for marker in [
            "tools/", "/tools/", "test/", "/test/", "docs/", "/docs/",
            "samples/", "/samples/", "dockerfile", ".sh", "scripts/"
        ]):
            reasoning.append("Found in tools/test/docs/scripts context")

        return GateResult(
            passed=passed,
            reasoning=reasoning,
            proof_items={"has_sink": has_sink}
        )

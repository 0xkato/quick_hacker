"""
Critic/Refuter loop service for vulnerability triage.

Implements the feedback mechanism that decides whether to:
- READY_TO_REPORT: All evidence is sufficient, proceed to report
- CONTINUE: Blocking gaps remain, recommend tool calls to fill them
- STOP_FILTERED: Finding filtered out (e.g., misconfiguration-only)
- STOP_SPECULATIVE: Pass limit reached with insufficient evidence

Key Logic:
1. Fast-track VALID_SECURITY_ISSUE/BUG dispositions (skip critic)
2. Filter misconfiguration-only findings (not_only_misconfig == DISPROVEN)
3. Pass 1: Always continue if blocking gaps exist
4. Pass 2+: Stop speculative by default
5. Pass 3 exception: Continue if exactly 1 gap + 3+ tool calls remaining ("one more push")
"""

from dataclasses import dataclass
from typing import Optional

from models.schemas import Finding, ProofChecklist, Disposition, ChecklistStatus, VulnerabilityCategory
from services.evidence_gatherer import EvidenceResult
from services.blocking_gaps import get_blocking_gaps_for_category


@dataclass
class CriticInput:
    """Input to the critic evaluation."""
    finding: Finding
    evidence: EvidenceResult
    checklist: ProofChecklist
    preliminary_disposition: Disposition
    pass_number: int  # 1, 2, 3, ...
    remaining_tool_calls: int
    hypothesis_span_id: str


@dataclass
class CriticDecision:
    """Output from critic evaluation."""
    decision: str  # "READY_TO_REPORT" | "CONTINUE" | "STOP_FILTERED" | "STOP_SPECULATIVE"
    blocking_gaps: list[str]  # List of checklist field names that are blocking
    recommended_tool_calls: list[str]  # Recommended tool names to fill gaps
    disposition_hint: Optional[str] = None  # e.g., "MISCONFIGURATION" for STOP_FILTERED
    reasoning: Optional[str] = None  # Human-readable explanation


class CriticLoop:
    """
    Critic/Refuter feedback loop for evidence gap identification.

    Responsibilities:
    - Evaluate whether evidence is sufficient to report finding
    - Identify blocking gaps in proof checklist
    - Recommend specific tool calls to fill gaps
    - Apply pass number logic to prevent infinite loops
    """

    def evaluate(self, critic_input: CriticInput) -> CriticDecision:
        """
        Evaluate a finding and decide next action.

        Args:
            critic_input: CriticInput containing finding, evidence, checklist, etc.

        Returns:
            CriticDecision with decision, gaps, and recommendations
        """
        # Fast-track: VALID_SECURITY_ISSUE or BUG dispositions skip critic
        if critic_input.preliminary_disposition in [Disposition.VALID_SECURITY_ISSUE, Disposition.BUG]:
            return CriticDecision(
                decision="READY_TO_REPORT",
                blocking_gaps=[],
                recommended_tool_calls=[],
                reasoning="Fast-tracked: Disposition is already VALID_SECURITY_ISSUE or BUG"
            )

        # Filter: Misconfiguration-only findings (not_only_misconfig == DISPROVEN)
        if critic_input.checklist.not_only_misconfig.status == ChecklistStatus.DISPROVEN:
            return CriticDecision(
                decision="STOP_FILTERED",
                blocking_gaps=[],
                recommended_tool_calls=[],
                disposition_hint="MISCONFIGURATION",
                reasoning="Filtered out: Finding is only a misconfiguration"
            )

        # Get blocking gaps for this category
        category = self._normalize_category(critic_input.finding)
        blocking_gaps = get_blocking_gaps_for_category(category, critic_input.checklist)

        # No blocking gaps: Ready to report
        if len(blocking_gaps) == 0:
            return CriticDecision(
                decision="READY_TO_REPORT",
                blocking_gaps=[],
                recommended_tool_calls=[],
                reasoning="All required evidence gathered, no blocking gaps"
            )

        # Pass number logic
        pass_number = critic_input.pass_number

        # Pass 1: Always continue if blocking gaps exist
        if pass_number == 1:
            return CriticDecision(
                decision="CONTINUE",
                blocking_gaps=blocking_gaps,
                recommended_tool_calls=self._recommend_tool_calls(blocking_gaps, critic_input.finding),
                reasoning=f"Pass 1: {len(blocking_gaps)} blocking gap(s) remain"
            )

        # Pass 2+: Default to STOP_SPECULATIVE
        # Exception: Pass 3 with exactly 1 gap + 3+ tool calls remaining ("one more push")
        if pass_number >= 3 and len(blocking_gaps) == 1 and critic_input.remaining_tool_calls >= 3:
            return CriticDecision(
                decision="CONTINUE",
                blocking_gaps=blocking_gaps,
                recommended_tool_calls=self._recommend_tool_calls(blocking_gaps, critic_input.finding),
                reasoning=f"Pass {pass_number}: One more push exception (1 gap, {critic_input.remaining_tool_calls} tool calls remaining)"
            )

        # Otherwise: Stop speculative
        return CriticDecision(
            decision="STOP_SPECULATIVE",
            blocking_gaps=blocking_gaps,
            recommended_tool_calls=[],
            reasoning=f"Pass {pass_number}: Insufficient evidence after multiple attempts"
        )

    def _normalize_category(self, finding: Finding) -> str:
        """
        Normalize finding category to a string used by blocking_gaps service.

        Args:
            finding: Finding with category or vulnerability_type

        Returns:
            Category string like "SQL_INJECTION", "CODE_INJECTION", etc.
        """
        # Prefer category field if present
        if finding.category:
            return finding.category.value.upper()

        # Fallback: Infer from vulnerability_type
        vuln_type_lower = finding.vulnerability_type.lower()

        if "sql" in vuln_type_lower and "injection" in vuln_type_lower:
            return "SQL_INJECTION"
        elif "code" in vuln_type_lower and "injection" in vuln_type_lower:
            return "CODE_INJECTION"
        elif "command" in vuln_type_lower and "injection" in vuln_type_lower:
            return "COMMAND_INJECTION"
        elif "ssrf" in vuln_type_lower:
            return "SSRF"
        elif "xss" in vuln_type_lower:
            return "XSS"
        elif "secret" in vuln_type_lower or "credential" in vuln_type_lower:
            return "SECRETS"
        elif "path" in vuln_type_lower and "traversal" in vuln_type_lower:
            return "PATH_TRAVERSAL"
        elif "deserialization" in vuln_type_lower:
            return "DESERIALIZATION"
        elif "xxe" in vuln_type_lower:
            return "XXE"
        elif "csrf" in vuln_type_lower:
            return "CSRF"
        elif "open" in vuln_type_lower and "redirect" in vuln_type_lower:
            return "OPEN_REDIRECT"
        elif "auth" in vuln_type_lower and "bypass" in vuln_type_lower:
            return "AUTHENTICATION_BYPASS"
        else:
            return "GENERIC"

    def _recommend_tool_calls(self, blocking_gaps: list[str], finding: Finding) -> list[str]:
        """
        Recommend specific tool calls to fill blocking gaps.

        Args:
            blocking_gaps: List of checklist field names that are blocking
            finding: The finding being analyzed

        Returns:
            List of tool names (snake_case) to call
        """
        recommendations = []

        for gap in blocking_gaps:
            if gap == "source_controlled_input":
                # Search for user input sources
                recommendations.append("search_code")  # Search for request.*, input(), etc.

            elif gap == "sink_present":
                # Search for dangerous sinks
                recommendations.append("search_code")  # Search for exec(), eval(), SQL, etc.
                recommendations.append("read_file")  # Read the file to confirm

            elif gap == "dataflow_evidenced":
                # Trace data flow from source to sink
                recommendations.append("search_code")  # Search for variable propagation
                recommendations.append("read_file")  # Read function bodies

            elif gap == "reachable":
                # Check if endpoint/function is reachable
                recommendations.append("search_code")  # Search for route registrations
                recommendations.append("list_directory")  # Check for routing files

            elif gap == "boundary_crossed":
                # Verify boundary crossing (network, file system, etc.)
                recommendations.append("read_file")  # Read code to understand boundaries
                recommendations.append("search_code")  # Search for network/file operations

            elif gap == "not_only_misconfig":
                # Distinguish code vulnerability from configuration issue
                recommendations.append("read_file")  # Read to understand if code or config
                recommendations.append("search_code")  # Search for configuration files

            elif gap == "security_control_bypassed":
                # Check if security controls (auth, escaping, etc.) are bypassed
                recommendations.append("search_code")  # Search for auth decorators, escaping
                recommendations.append("read_file")  # Read to verify controls

        # Deduplicate while preserving order
        seen = set()
        unique_recommendations = []
        for tool in recommendations:
            if tool not in seen:
                seen.add(tool)
                unique_recommendations.append(tool)

        return unique_recommendations

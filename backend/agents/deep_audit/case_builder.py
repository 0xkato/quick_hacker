"""Case file builder for Deep Audit Auditor subagent.

Generates structured markdown case files from signals for the Auditor to verify.
"""

from typing import Any, Dict, List, Optional
from services.prompt_router import PromptRouter


class CaseBuilder:
    """Case builder for Deep Audit signals.

    Generates structured case files and assembles category-specific prompts.
    """

    def _assemble_prompt_for_category(self, category: str, stage: str, task: str) -> str:
        """
        Assemble prompt using PromptRouter for category-specific validity checklist.

        Args:
            category: Vulnerability category (e.g., "SQL_INJECTION", "XSS")
            stage: DeepAudit stage (e.g., "trace_dataflow", "validate_exploitability")
            task: Specific task description

        Returns:
            Assembled prompt with base + validity_checklist + stage + task
        """
        router = PromptRouter()
        modules = router.route(category=category, stage=stage)
        return router.assemble_from_paths(modules, task=task)


def _map_signal_type_to_category(signal_type: Optional[str]) -> Optional[str]:
    """
    Map signal_type to vulnerability category for PromptRouter.

    Args:
        signal_type: Signal type (e.g., "sql_injection_candidate", "ssrf_candidate") or None

    Returns:
        Category string (e.g., "SQL_INJECTION", "SSRF") or None if no mapping
    """
    # Handle None
    if signal_type is None:
        return None

    # Normalize signal_type to uppercase and remove "_candidate" suffix
    normalized = signal_type.upper().replace("_CANDIDATE", "")

    # Map to PromptRouter categories
    category_map = {
        "SQL_INJECTION": "SQL_INJECTION",
        "SSRF": "SSRF",
        "CODE_INJECTION": "CODE_INJECTION",
        "COMMAND_INJECTION": "COMMAND_INJECTION",
        "XSS": "XSS",
        "CROSS_SITE_SCRIPTING": "XSS",
        "DESERIALIZATION": "DESERIALIZATION",
        "PATH_TRAVERSAL": "PATH_TRAVERSAL",
        "AUTH_BYPASS": "AUTH_BYPASS",
        "IDOR": "IDOR",
        "MEMORY_SAFETY": "MEMORY_SAFETY",
    }

    return category_map.get(normalized)


def assemble_auditor_prompt_for_signal(signal: Dict[str, Any], case_file_path: str) -> str:
    """
    Assemble Auditor prompt using PromptRouter for category-specific validity checklist.

    Args:
        signal: Signal dictionary containing signal_type
        case_file_path: Path to the case file for this signal

    Returns:
        Assembled prompt with base + validity_checklist + task
    """
    signal_type = signal.get("signal_type", "unknown")
    category = _map_signal_type_to_category(signal_type)

    # Build task description
    task = f"""You are an Auditor subagent.

Your task: Verify the signal in case file {case_file_path}.

Read the case file to understand the signal. Then:
1. Use targeted code reads to verify the data flow
2. Use analyze_ast and trace_dataflow to confirm vulnerability
3. Check for sanitization/validation controls
4. Assess exploitability

Use the following tools:
- read_file(path): Read file contents
- analyze_ast(file_path): Get AST analysis
- trace_dataflow(file_path, line_number): Trace data flow
- promote_finding(finding): Promote to Finding (if verified)

Decision:
- If vulnerability CONFIRMED: Call promote_finding with complete details
- If MORE INVESTIGATION needed: Write updated signal with refined next_steps

ONLY call promote_finding if you are confident the vulnerability is real and exploitable.

Case file location: {case_file_path}"""

    if category:
        # Use PromptRouter to assemble prompt with validity checklist
        router = PromptRouter()
        modules = router.route(category=category, stage="validate_exploitability")
        return router.assemble_from_paths(modules, task=task)
    else:
        # Fallback: return task without validity checklist
        return task


def build_case_file(signal: Dict[str, Any], code_excerpts: List[Dict[str, Any]]) -> str:
    """Build a structured markdown case file for the Auditor.

    Args:
        signal: Signal dictionary containing detection information
        code_excerpts: List of code excerpt dictionaries (limited to 6 max)

    Returns:
        Markdown-formatted case file string
    """
    # Extract signal fields
    signal_id = signal.get("signal_id", "unknown")
    signal_type = signal.get("signal_type", "unknown")
    file_path = signal.get("file_path", "unknown")
    line_range = signal.get("line_range", [])
    sink_snippet = signal.get("sink_snippet", "")
    suspected_sources = signal.get("suspected_sources", [])
    confidence = signal.get("confidence", "unknown")
    scope_id = signal.get("scope_id", "unknown")
    next_steps = signal.get("next_steps", [])

    # Format line range
    if isinstance(line_range, list) and len(line_range) == 2:
        line_range_str = f"{line_range[0]}-{line_range[1]}"
    else:
        line_range_str = str(line_range)

    # Limit code excerpts to 6
    limited_excerpts = code_excerpts[:6]

    # Build markdown
    lines = []

    # Header
    lines.append(f"# Case: {signal_id}")
    lines.append("")

    # Signal Details
    lines.append("## Signal Details")
    lines.append("")
    lines.append(f"**Type:** {signal_type}")
    lines.append(f"**File:** {file_path}")
    lines.append(f"**Lines:** {line_range_str}")
    lines.append(f"**Confidence:** {confidence}")
    lines.append(f"**Scope:** {scope_id}")
    lines.append("")

    # Sink
    lines.append("## Sink")
    lines.append("")
    lines.append("```")
    lines.append(sink_snippet)
    lines.append("```")
    lines.append("")

    # Suspected Sources
    lines.append("## Suspected Sources")
    lines.append("")
    if suspected_sources:
        for source in suspected_sources:
            lines.append(f"- {source}")
    else:
        lines.append("None identified")
    lines.append("")

    # Code Excerpts
    lines.append("## Code Excerpts")
    lines.append("")
    if limited_excerpts:
        for excerpt in limited_excerpts:
            excerpt_file = excerpt.get("file_path", "unknown")
            excerpt_lines = excerpt.get("line_range", [])
            excerpt_content = excerpt.get("content", "")

            # Format excerpt line range
            if isinstance(excerpt_lines, list) and len(excerpt_lines) == 2:
                excerpt_lines_str = f"{excerpt_lines[0]}-{excerpt_lines[1]}"
            else:
                excerpt_lines_str = str(excerpt_lines)

            lines.append(f"### {excerpt_file}")
            lines.append(f"Lines {excerpt_lines_str}")
            lines.append("")
            lines.append("```")
            lines.append(excerpt_content)
            lines.append("```")
            lines.append("")
    else:
        lines.append("No code excerpts available")
        lines.append("")

    # Next Steps
    lines.append("## Next Steps")
    lines.append("")
    if next_steps:
        for step in next_steps:
            lines.append(f"- {step}")
    else:
        lines.append("None specified")
    lines.append("")

    # Verification Questions
    lines.append("## Verification Questions")
    lines.append("")
    lines.append("1. Does the sink actually execute with untrusted data from the suspected sources?")
    lines.append("2. Are the suspected sources correct, or is the data flow broken?")
    lines.append("3. Are there any sanitization, validation, or encoding steps that neutralize the risk?")
    lines.append("4. What is the actual severity and exploitability of this finding?")
    lines.append("")

    # Decision
    lines.append("## Decision")
    lines.append("")
    lines.append("Based on your verification, provide:")
    lines.append("")
    lines.append("1. **Verdict:** CONFIRMED | FALSE_POSITIVE | NEEDS_MORE_INFO")
    lines.append("2. **Reasoning:** Explain your decision based on the evidence")
    lines.append("3. **Severity:** If confirmed, rate the severity (critical/high/medium/low)")
    lines.append("4. **Recommendations:** If confirmed, provide remediation guidance")
    lines.append("")

    return "\n".join(lines)

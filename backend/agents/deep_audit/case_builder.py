"""Case file builder for Deep Audit Auditor subagent.

Generates structured markdown case files from signals for the Auditor to verify.
"""

from typing import Any, Dict, List


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

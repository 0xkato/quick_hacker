"""Phase 2: Triage - Candidate detection and categorization.

Paired with: security_detectors, graph_tools
Output: CandidatesByType (candidates grouped by vulnerability class)
"""

from typing import Optional, Dict, Any, List
from dataclasses import dataclass


@dataclass
class TriagePrompt:
    """Triage phase prompt components."""

    mission: str = """
<triage_mission>
PHASE 2: TRIAGE - Detect and categorize potential security candidates

YOUR GOAL:
Use security detection tools to find potential vulnerability candidates.
Categorize them by type for specialized analysis in the next phase.
You are NOT validating exploitability - that comes next.

WHAT TO DO:

1. RUN DETECTORS
   Use security_detectors to scan for dangerous sinks:
   - SQL query construction
   - Command/shell execution
   - File path operations
   - Template rendering
   - Deserialization
   - HTTP request making (SSRF)
   - Authentication checks

2. CATEGORIZE FINDINGS
   Group detected items by vulnerability type:
   - sql_injection: DB query sinks
   - command_injection: Shell/exec sinks
   - path_traversal: File operation sinks
   - xss: Template/render sinks
   - ssrf: HTTP client sinks
   - deserialization: Deserialize sinks
   - auth_bypass: Auth check locations

3. COLLECT CONTEXT
   For each candidate, collect:
   - File and line number
   - ~30 lines of surrounding code
   - Nearby function/method name
   - Any visible input sources
</triage_mission>
"""

    tools: str = """
<triage_tools>
USE THESE TOOLS:

security_detectors:
- find_sinks(sink_type) - Find sinks by category
- detect_patterns(pattern_set) - Run pattern matching
- check_dangerous_functions() - Find dangerous function calls

graph_tools:
- map_data_flows(from_entry, to_sink) - Rough flow mapping
- find_callers(function) - Who calls this

DO NOT deeply analyze - just detect and categorize.
Validation happens in Phase 3.
</triage_tools>
"""

    output: str = """
<triage_output>
OUTPUT FORMAT:

```json
{
  "candidates_by_type": {
    "sql_injection": [
      {
        "id": "SQL-001",
        "file": "services/user.py",
        "line": 45,
        "sink": "cursor.execute",
        "code_snippet": "...",
        "nearby_inputs": ["request.args.get('user_id')"],
        "confidence": "medium"
      }
    ],
    "command_injection": [...],
    "path_traversal": [...],
    "xss": [...],
    "ssrf": [...],
    "deserialization": [...],
    "auth_bypass": [...]
  },
  "stats": {
    "total_candidates": 15,
    "by_type": {"sql_injection": 3, "xss": 5, ...}
  }
}
```

Confidence levels:
- high: Clear sink with visible user input nearby
- medium: Sink found, input source unclear
- low: Potential sink, needs investigation

Signal completion with: "TRIAGE_COMPLETE"
</triage_output>
"""

    threat_models: str = """
<threat_models>
THREAT MODEL (consider when categorizing):

A: UNAUTHENTICATED ATTACKER
   - Only public/unauthenticated surfaces
   - Higher priority for triage

B: AUTHENTICATED ATTACKER
   - Normal user account access
   - Includes A plus auth-required routes

C: INSIDER/PRIVILEGED
   - Internal access, admin panels
   - Lowest priority for external threats
</threat_models>
"""

    def get_full_prompt(self, threat_model: Optional[str] = None) -> str:
        parts = [
            self.mission.strip(),
            self.tools.strip(),
        ]

        if threat_model:
            parts.append(self.threat_models.strip())
            parts.append(f"\nACTIVE THREAT MODEL: {threat_model.upper()}")

        parts.append(self.output.strip())
        return "\n\n".join(parts)


def build_triage_prompt(
    tech_stack: Dict[str, Any],
    threat_model: Optional[str] = None,
    entry_points: Optional[List[Dict]] = None,
) -> str:
    """Build complete triage phase prompt.

    Args:
        tech_stack: Tech stack from exploration phase
        threat_model: Threat model (unauthenticated, authenticated, insider)
        entry_points: Entry points from exploration (optional context)

    Returns:
        Complete triage prompt
    """
    base = TriagePrompt()
    parts = [base.get_full_prompt(threat_model)]

    # Add tech stack context
    context_lines = [
        "=== CONTEXT FROM EXPLORATION ===",
        f"Languages: {', '.join(tech_stack.get('languages', []))}",
        f"Frameworks: {', '.join(tech_stack.get('frameworks', []))}",
    ]

    if entry_points:
        context_lines.append(f"Entry points found: {len(entry_points)}")
        # List first few
        for ep in entry_points[:5]:
            context_lines.append(f"  - {ep.get('name', '?')}: {ep.get('route', ep.get('file', '?'))}")

    parts.insert(0, "\n".join(context_lines))

    return "\n\n".join(parts)

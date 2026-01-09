"""Base analysis prompt - shared validation patterns for all vuln types.

Each specialized prompt (sql_injection.py, xss.py, etc.) builds on this.
"""


class BaseAnalysisPrompt:
    """Common analysis components shared by all vulnerability analyzers."""

    @staticmethod
    def get_validation_requirements() -> str:
        """Return validation requirements for source-to-sink analysis."""
        return """
<validation_requirements>
FOR EACH CANDIDATE, YOU MUST:

1. TRACE SOURCE TO SINK
   - Identify exact user input source (request param, header, body, etc.)
   - Follow data through all transformations
   - Document each hop with file:line
   - Reach the dangerous sink

2. CHECK FOR DEFENSES
   - Look for sanitization/validation between source and sink
   - Check framework-level protections
   - Verify defense actually blocks the attack

3. PROVE EXPLOITABILITY
   - Under DEFAULT configuration
   - With REALISTIC attacker input
   - Without UNLIKELY preconditions

4. ASSESS IMPACT
   - What can attacker achieve?
   - What data/systems affected?
   - Severity: Critical/High/Medium/Low

EVIDENCE REQUIRED:
- Exact file paths and line numbers
- Code snippets showing vulnerable flow
- Proof that no defense blocks the attack

REJECT IF:
- Cannot trace user input to sink
- Defense exists that blocks attack
- Requires non-default configuration
- Exploitation is theoretical only
- Impact is negligible
</validation_requirements>
"""

    @staticmethod
    def get_output_format() -> str:
        """Return JSON output format for validated/rejected findings."""
        return """
<analysis_output>
OUTPUT FOR EACH CANDIDATE:

IF VALIDATED:
```json
{
  "status": "validated",
  "candidate_id": "SQL-001",
  "finding": {
    "title": "SQL Injection in User Lookup",
    "severity": "high",
    "cwe": "CWE-89",
    "cvss": "8.6",
    "file": "services/user.py",
    "line": 45,
    "source": {
      "type": "query_param",
      "location": "routes/api.py:23",
      "param": "user_id"
    },
    "sink": {
      "function": "cursor.execute",
      "location": "services/user.py:45"
    },
    "trace": [
      {"step": 1, "location": "routes/api.py:23", "action": "receives user_id from request.args"},
      {"step": 2, "location": "services/user.py:40", "action": "passes to build_query()"},
      {"step": 3, "location": "services/user.py:45", "action": "executes raw SQL"}
    ],
    "defenses_checked": [
      {"type": "input_validation", "present": false},
      {"type": "parameterized_query", "present": false}
    ],
    "poc": "curl 'http://localhost/api/user?user_id=1%27%20OR%20%271%27=%271'",
    "impact": "Full database read access, potential data exfiltration",
    "remediation": "Use parameterized queries"
  }
}
```

IF REJECTED:
```json
{
  "status": "rejected",
  "candidate_id": "SQL-001",
  "reason": "Defense blocks attack",
  "details": "Input is validated with strict integer check at routes/api.py:20"
}
```
</analysis_output>
"""

    @staticmethod
    def get_analysis_mission(vuln_type: str) -> str:
        """Return mission statement for specialized analysis of given vuln_type."""
        return f"""
<analysis_mission>
PHASE 3: SPECIALIZED ANALYSIS - {vuln_type.upper()}

You are analyzing candidates of type: {vuln_type}

YOUR GOAL:
Validate or reject each candidate through rigorous source-to-sink analysis.
Only VALIDATED findings proceed to verification.

APPROACH:
1. Take each candidate from triage
2. Attempt to prove exploitability
3. If proven: document as VALIDATED
4. If disproven: document as REJECTED with reason
</analysis_mission>
"""

    @staticmethod
    def get_verdict_reporting_instruction() -> str:
        """Return instruction for reporting path verdicts."""
        return """
<path_verdict_reporting>
AFTER TRACING EACH PATH:

When you finish investigating a path from entry point to sink, call trace_path_verdict with:
- entry_point_file, entry_point_line: Location of the entry point
- sink_file, sink_line: Location of the dangerous sink
- verdict: One of:
  - "safe" - No vulnerability, data is properly handled
  - "vulnerable" - Exploitable vulnerability (also call report_finding)
  - "blocked" - Path exists but defenses prevent exploitation
  - "inconclusive" - Cannot determine, need more context
- reasoning: 1-2 sentence explanation
- files_examined: Files you read while tracing

This enables coverage tracking. Do NOT skip this step.
</path_verdict_reporting>
"""

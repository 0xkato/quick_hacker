"""SQL Injection classification gate."""
import re
from typing import Optional

from models.schemas import Finding, Evidence, Disposition, ChecklistStatus, ChecklistItem
from .base import BaseGate, GateResult


class SQLiGate(BaseGate):
    """SQL injection classification gate."""

    def get_category_name(self) -> str:
        return "SQL_INJECTION"

    def evaluate(self, finding: Finding, evidence: Evidence) -> GateResult:
        """Evaluate SQL injection finding."""
        # Check for SQL injection-specific patterns in evidence
        dataflow_item = self._check_sql_injection_dataflow(finding, evidence)

        passed = False
        reasoning = []
        proof_items = {}

        if dataflow_item:
            if dataflow_item.status == ChecklistStatus.DISPROVEN:
                # Mitigation detected - mark as safe
                reasoning.append(dataflow_item.reason)
                passed = False
                proof_items["dataflow_evidenced"] = dataflow_item
            elif dataflow_item.status == ChecklistStatus.PROVEN and dataflow_item.value:
                # Vulnerable pattern detected
                reasoning.append(dataflow_item.reason)
                passed = True
                proof_items["dataflow_evidenced"] = dataflow_item

        return GateResult(
            passed=passed,
            reasoning=reasoning,
            proof_items=proof_items
        )

    def _check_sql_injection_dataflow(
        self, finding: Finding, evidence: Evidence
    ) -> Optional[ChecklistItem]:
        """
        Check SQL injection-specific patterns in evidence.

        Returns ChecklistItem if pattern detected, None otherwise.
        Priority: mitigations > vulnerabilities (a mitigation makes it safe)
        """
        snippet = evidence.snippet or evidence.handler_snippet or ""
        snippet_lower = snippet.lower()

        # FIRST: Check for explicit mitigations - these take highest priority
        # Pattern 1: Complete allowlist validation before query
        # Look for: ALLOWED_X = {...} followed by if check before execute
        if 'allowed_' in snippet_lower and ('if' in snippet_lower and 'not in' in snippet_lower):
            # More specific check: allowlist defined and checked
            if re.search(r'ALLOWED_\w+\s*=\s*\{[^}]+\}', snippet, re.IGNORECASE):
                if re.search(r'if\s+\w+\s+not\s+in\s+ALLOWED_\w+', snippet, re.IGNORECASE):
                    return ChecklistItem(
                        value=False,
                        status=ChecklistStatus.DISPROVEN,
                        reason="Complete allowlist validates input before use",
                        reason_code="mitigated_by_allowlist"
                    )

        # Pattern 2: Positional placeholders with parameter list
        # e.g., cursor.execute("SELECT * FROM users WHERE id = ?", [user_id])
        # BUT: Don't match if there's also an unsafe pattern (mixed code)
        positional_param = re.search(r'\.execute\s*\(\s*["\'].*?\?\s*.*?["\']\s*,\s*\[', snippet)
        has_unsafe_fstring = re.search(r'f["\'].*?\{.*?\}.*?["\']', snippet) and '.execute' in snippet_lower
        has_unsafe_concat = (re.search(r'["\'].*?\s*\+\s*\w+', snippet) or re.search(r'\w+\s*\+\s*["\']', snippet)) and ('.execute' in snippet_lower or 'query' in snippet_lower)

        if positional_param and not (has_unsafe_fstring or has_unsafe_concat):
            return ChecklistItem(
                value=False,
                status=ChecklistStatus.DISPROVEN,
                reason="Parameter binding present: query uses placeholder ? with separate parameter list",
                reason_code="mitigated_by_parameterization"
            )

        # Pattern 3: Named placeholders with parameter dict
        # e.g., cursor.execute("SELECT * FROM users WHERE id = :id", {"id": user_id})
        named_param = re.search(r'\.execute\s*\(\s*["\'].*?:\w+\s*.*?["\']\s*,\s*\{', snippet)
        if named_param and not (has_unsafe_fstring or has_unsafe_concat):
            return ChecklistItem(
                value=False,
                status=ChecklistStatus.DISPROVEN,
                reason="Parameter binding with named placeholder",
                reason_code="mitigated_by_parameterization"
            )

        # SECOND: Check for unsafe patterns (vulnerable)
        # Pattern 4: f-string interpolation in SQL query
        # e.g., f"SELECT * FROM users WHERE id = {user_id}"
        if has_unsafe_fstring:
            return ChecklistItem(
                value=True,
                status=ChecklistStatus.PROVEN,
                reason="f-string interpolation in SQL query (structure-taint)",
                reason_code="unsafe_identifier_influence"
            )

        # Pattern 5: String concatenation with + operator
        # e.g., "SELECT * FROM users WHERE id = '" + user_id + "'"
        if has_unsafe_concat:
            return ChecklistItem(
                value=True,
                status=ChecklistStatus.PROVEN,
                reason="String concatenation allows structure-taint",
                reason_code="unsafe_structure_taint"
            )

        # No SQL injection-specific pattern detected
        return None

"""SQL Injection specialized analysis prompt.

Contains SQLi-specific:
- Sink patterns to look for
- Safe patterns that reject candidates
- Framework-specific considerations
- PoC patterns
"""

from typing import List, Dict, Any, Optional
from .base_analysis import BaseAnalysisPrompt


class SQLInjectionAnalyzer:
    """SQL injection validation patterns."""

    dangerous_sinks = """
<sqli_dangerous_sinks>
DANGEROUS PATTERNS (flag these):

Python:
- cursor.execute(f"SELECT ... {var}")
- cursor.execute("SELECT ... " + var)
- cursor.execute("SELECT ... %s" % var)
- cursor.execute("SELECT ... {}".format(var))
- Model.objects.raw(query_with_var)
- Model.objects.extra(where=[f"... {var}"])
- db.engine.execute(text(query_with_var))

JavaScript/Node:
- db.query("SELECT ... " + var)
- db.query(`SELECT ... ${var}`)
- connection.query(query_with_var)
- knex.raw(query_with_var)

Java:
- statement.executeQuery("SELECT ... " + var)
- entityManager.createQuery("SELECT ... " + var)
- jdbcTemplate.query(query_with_var, ...)
</sqli_dangerous_sinks>
"""

    safe_patterns = """
<sqli_safe_patterns>
SAFE PATTERNS (reject candidates using these):

Parameterized queries:
- cursor.execute("SELECT ... WHERE id = ?", (var,))
- cursor.execute("SELECT ... WHERE id = %s", [var])
- cursor.execute("SELECT ... WHERE id = :id", {"id": var})

ORM usage:
- Model.objects.filter(id=var)  # Django ORM
- Model.objects.get(id=var)
- session.query(Model).filter(Model.id == var)  # SQLAlchemy ORM

Prepared statements:
- PreparedStatement with ? placeholders
- Named parameters (:param)

Input validation:
- Strict type casting: int(var), uuid.UUID(var)
- Allowlist validation before query
</sqli_safe_patterns>
"""

    poc_patterns = """
<sqli_poc_patterns>
PROOF OF CONCEPT PATTERNS:

Basic tests:
- ' OR '1'='1
- ' OR '1'='1' --
- 1' OR '1'='1
- admin'--

Union-based:
- ' UNION SELECT NULL--
- ' UNION SELECT username, password FROM users--

Error-based:
- ' AND 1=CONVERT(int, @@version)--
- ' AND extractvalue(1, concat(0x7e, version()))--

Time-based:
- ' OR SLEEP(5)--
- '; WAITFOR DELAY '0:0:5'--

For PoC, use simplest payload that proves injection.
</sqli_poc_patterns>
"""

    @classmethod
    def get_framework_guidance(cls, framework: Optional[str]) -> str:
        """Return framework-specific SQLi guidance."""
        if not framework:
            return ""

        guidance = {
            "django": """
<django_sqli_guidance>
Django-specific:
- ORM queries (filter, get, exclude) are SAFE - reject these
- raw() is DANGEROUS if query is constructed with user input
- extra() is DANGEROUS - check where/select clauses
- RawSQL() is DANGEROUS
- Check for cursor.execute in views/models
</django_sqli_guidance>
""",
            "flask": """
<flask_sqli_guidance>
Flask/SQLAlchemy-specific:
- SQLAlchemy ORM (session.query, Model.query) is SAFE - reject these
- text() with string formatting is DANGEROUS
- execute() with string concatenation is DANGEROUS
- Check db.engine.execute() calls
</flask_sqli_guidance>
""",
            "express": """
<express_sqli_guidance>
Express/Node-specific:
- Sequelize ORM queries are SAFE - reject these
- knex.raw() is DANGEROUS
- mysql.query() with string concat is DANGEROUS
- Check for template literals in SQL strings
</express_sqli_guidance>
""",
        }
        return guidance.get(framework.lower(), "")

    @classmethod
    def get_full_prompt(cls, framework: Optional[str] = None) -> str:
        """Return full SQLi-specific prompt content."""
        parts = [
            cls.dangerous_sinks.strip(),
            cls.safe_patterns.strip(),
            cls.poc_patterns.strip(),
        ]

        fw_guidance = cls.get_framework_guidance(framework)
        if fw_guidance:
            parts.append(fw_guidance.strip())

        return "\n\n".join(parts)


def build_sqli_prompt(
    candidates: List[Dict[str, Any]],
    framework: Optional[str] = None,
    tech_stack: Optional[Dict[str, Any]] = None,
) -> str:
    """Build complete SQL injection analysis prompt.

    Args:
        candidates: SQLi candidates from triage phase
        framework: Detected framework (django, flask, express, etc.)
        tech_stack: Full tech stack context

    Returns:
        Complete SQLi analysis prompt
    """
    parts = [
        BaseAnalysisPrompt.get_analysis_mission("sql_injection"),
        BaseAnalysisPrompt.get_validation_requirements(),
        SQLInjectionAnalyzer.get_full_prompt(framework),
        BaseAnalysisPrompt.get_output_format(),
    ]

    # Add candidates
    if candidates:
        candidates_section = ["\n=== CANDIDATES TO ANALYZE ==="]
        for c in candidates:
            candidates_section.append(f"""
Candidate {c.get('id', '?')}:
  File: {c.get('file', '?')}:{c.get('line', '?')}
  Sink: {c.get('sink', '?')}
  Code: {c.get('code_snippet', 'N/A')[:200]}
""")
        parts.append("\n".join(candidates_section))

    return "\n\n".join(parts)

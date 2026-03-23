# Remediation Analyst

## Purpose
Generate actionable remediation guidance for a confirmed vulnerability. Provides code-level fix suggestions and defensive patterns.

## Input
- Root cause analysis output
- Vulnerable source code context
- Framework and language conventions

## Output (JSON)
```json
{
  "recommendation": "Add authorization middleware to /api/orders/:id route",
  "fix_pattern": "decorator-based access control",
  "code_suggestion": "@require_owner(Order)\ndef get_order(order_id):",
  "references": ["CWE-862", "OWASP AuthZ Cheat Sheet"]
}
```

## Notes
Fix suggestions respect the project's existing patterns (middleware style, decorator conventions, etc.).

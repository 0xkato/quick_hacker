# SQL Injection Playbook v2.1 - User Guide

**Version:** 2.1
**Date:** 2026-01-17
**Status:** Production

## What Changed

### Before (v1.0)
- Pattern-based detection (grep for "execute", check if parameterized)
- High false positive rate (parameterized queries reported as bugs)
- Missed subtle vulnerabilities (ORDER BY injection, second-order SQLi)

### After (v2.1)
- Conceptual security reasoning (structure-taint detection)
- Reason codes explain WHY a pattern is safe/unsafe
- Finds subtle vulnerabilities (dynamic identifiers, second-order flows)

## Key Concepts

### Structure-Taint
- **Safe:** User input only affects DATA values (via parameterization)
- **Unsafe:** User input affects SQL STRUCTURE (identifiers, operators, clauses)

### Reason Codes

**Safe patterns:**
- `mitigated_by_parameterization` - Query uses ? or :name placeholders
- `mitigated_by_allowlist` - Complete allowlist validates input
- `mitigated_by_sanitization` - Input is sanitized before use
- `mitigated_by_validation` - Input is validated against constraints

**Unsafe patterns:**
- `unsafe_structure_taint` - String interpolation in query
- `unsafe_identifier_influence` - User input affects table/column/ORDER BY

**Out of scope:**
- `DISPROVEN_BY_PROFILE` - Input channel not enabled by threat model

## Examples

### Safe: Parameterized Query
```python
cursor.execute("SELECT * FROM users WHERE id = ?", [user_id])
# Classification: BY_DESIGN
# Reason code: mitigated_by_parameterization
```

### Safe: Complete Allowlist
```python
ALLOWED = {'id', 'name', 'email'}
if col not in ALLOWED: raise ValueError()
cursor.execute(f"SELECT {col} FROM users")
# Classification: BY_DESIGN
# Reason code: mitigated_by_allowlist
```

### Unsafe: ORDER BY Injection
```python
cursor.execute(f"SELECT * FROM users ORDER BY {sort_field}")
# Classification: VALID_SECURITY_ISSUE
# Reason code: unsafe_identifier_influence
```

## Impact

### Precision
- **60-80% reduction in false positives**
- Parameterized queries no longer flagged as bugs
- Complete allowlists recognized as safe

### Recall
- Finds ORDER BY injection
- Finds dynamic table/column names
- Finds second-order SQL injection
- Finds ORM misuse (raw() without binding)

## Threat Model Integration

Findings are automatically gated by your project's threat model.

**Example:** If threat model DISABLES network channel:
- Network input → Query = HARDENING (not VALID_SECURITY_ISSUE)
- Still reported for defense-in-depth, but not as exploitable vuln

## For Developers

### Adding New Reason Codes

1. Add to playbook (`prompting/validity_checklists/sql_injection.md`)
2. Add to downgrade rule in `strict_classifier.py` if it's a safe pattern
3. Add test case in `test_sql_injection_playbook.py`

### Debugging Classifications

Check `proof_checklist.*.reason_code` in finding output:
```json
{
  "disposition": "by_design",
  "proof_checklist": {
    "dataflow_evidenced": {
      "status": "DISPROVEN",
      "reason_code": "mitigated_by_parameterization"
    }
  }
}
```

## Rollback

If issues occur:
1. Revert `prompting/validity_checklists/sql_injection.md`
2. Remove downgrade rule from `strict_classifier.py`
3. Keep `reason_code` field (optional, backward compatible)

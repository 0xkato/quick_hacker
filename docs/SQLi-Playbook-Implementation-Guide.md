# SQL Injection Playbook - Implementation Guide

**Version:** 2.1
**Date:** 2026-01-17
**Status:** Ready for Implementation

---

## What Was Created

### 1. Production-Ready SQLi Playbook
- **Location:** See brainstorming session output (to be saved to `prompting/validity_checklists/sql_injection.md`)
- **Features:**
  - Works with current MCP tools (read_file, search_symbol, find_references, get_call_graph)
  - Structure-taint detection framework
  - Reason code conventions for mitigation tracking
  - Threat model integration
  - Second-order SQLi double-proof requirements

### 2. Comprehensive Test Suite
- **Location:** `backend/tests/services/test_sql_injection_playbook.py`
- **Coverage:**
  - 9 test cases covering all major scenarios
  - Parameterized queries → BY_DESIGN
  - Unsafe interpolation → VALID_SECURITY_ISSUE
  - Threat model gating → HARDENING
  - Complete allowlists → BY_DESIGN
  - Second-order SQLi → Requires both proofs
  - Internal-only functions → Proper scoping

---

## Implementation Steps (In Order)

### Step 1: Add `reason_code` Field to ChecklistItem

**File:** `backend/models/schemas.py`

**Current ChecklistItem:**
```python
class ChecklistItem(BaseModel):
    value: bool
    status: ChecklistStatus
    reason: str
    tool_calls: list[str] = Field(default_factory=list)
```

**Modified ChecklistItem:**
```python
class ChecklistItem(BaseModel):
    value: bool
    status: ChecklistStatus
    reason: str
    tool_calls: list[str] = Field(default_factory=list)
    reason_code: str | None = None  # ← ADD THIS FIELD
```

**Why:** The playbook emits structured reason codes like `"mitigated_by_parameterization"` to enable precise classification downgrades.

---

### Step 2: Add Pattern Downgrade Rule for Mitigations

**File:** `backend/services/strict_classifier.py`

**Locate:** The `_apply_pattern_downgrades()` method

**Add this logic at the end of the method (before `return disposition`):**

```python
def _apply_pattern_downgrades(
    self,
    disposition: Disposition,
    checklist: ProofChecklist,
    finding: Finding,
    evidence: Evidence
) -> Disposition:
    """Apply pattern-based downgrades (ONLY downgrades)."""

    # ... EXISTING DOWNGRADE LOGIC ...

    # NEW: Mitigation-based downgrade
    # If dataflow is DISPROVEN due to a proven mitigation, downgrade to BY_DESIGN
    if checklist.dataflow_evidenced.status == ChecklistStatus.DISPROVEN:
        if checklist.dataflow_evidenced.reason_code in [
            "mitigated_by_parameterization",
            "mitigated_by_allowlist",
            "mitigated_by_safe_builder"
        ]:
            return Disposition.BY_DESIGN  # Safe by design, not a bug

    # If security_control_bypassed is DISPROVEN due to mitigation, also downgrade
    if checklist.security_control_bypassed.status == ChecklistStatus.DISPROVEN:
        if checklist.security_control_bypassed.reason_code in [
            "mitigated_by_parameterization",
            "mitigated_by_allowlist",
            "mitigated_by_safe_builder"
        ]:
            return Disposition.BY_DESIGN

    return disposition
```

**Why:** This prevents parameterized queries and complete allowlists from being reported as bugs under the existing Rule 5 (dataflow DISPROVEN → BUG).

---

### Step 3: Update SQL Injection Validity Checklist

**File:** `prompting/validity_checklists/sql_injection.md`

**Action:** Replace the entire file content with the Production-Ready SQLi Playbook (Version 2.1) from the brainstorming session.

**Key sections to include:**
- Part 1: Core Concept (structure-taint)
- Part 2: Investigation Workflow (with current tools)
- Part 3: Evidence Package Requirements
- Part 4: Reason Code Conventions
- Part 5: Common False Positives
- Part 6: Disposition Logic

**Why:** The new playbook teaches conceptual security reasoning instead of pattern matching, improving both recall and precision.

---

### Step 4: Run Tests to Verify

**Command:**
```bash
cd backend
pytest tests/services/test_sql_injection_playbook.py -v
```

**Expected Results:**

✓ `test_parameterized_positional_placeholder` - PASS
✓ `test_parameterized_named_placeholder` - PASS
✓ `test_f_string_interpolation_with_network_input` - PASS
✓ `test_string_concatenation_is_unsafe` - PASS
✓ `test_network_input_without_network_capability_is_hardening` - PASS
✓ `test_complete_allowlist_is_safe` - PASS
✓ `test_second_order_with_both_proofs_is_vulnerable` - PASS
✓ `test_second_order_without_unsafe_use_is_speculative` - PASS
✓ `test_internal_cron_job_without_threat_model_ci_is_not_vulnerable` - PASS

**If tests fail:**
- Check that `reason_code` field was added to `ChecklistItem`
- Check that downgrade rule was added to `_apply_pattern_downgrades()`
- Check that the downgrade rule is placed AFTER existing downgrades (so it can override)

---

### Step 5: Integration Test with Real Agent

**Create a test repository with vulnerable code:**

```python
# test_repo/api/users.py

from flask import Flask, request
import sqlite3

app = Flask(__name__)

# TEST 1: Should be BY_DESIGN (parameterized)
@app.get("/users/safe")
def get_user_safe():
    user_id = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", [user_id])
    return cursor.fetchall()

# TEST 2: Should be VALID_SECURITY_ISSUE (unsafe interpolation)
@app.get("/users/unsafe")
def get_users_sorted():
    sort_field = request.args.get('sort', 'name')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users ORDER BY {sort_field}")
    return cursor.fetchall()

# TEST 3: Should be BY_DESIGN (complete allowlist)
@app.get("/users/allowlist")
def get_user_column():
    ALLOWED_COLUMNS = {'id', 'name', 'email', 'created_at'}
    col = request.args.get('column', 'name')
    if col not in ALLOWED_COLUMNS:
        return {"error": "Invalid column"}, 400
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT {col} FROM users")
    return cursor.fetchall()
```

**Run QuickHack agent on test_repo:**
```bash
# Assuming QuickHack CLI exists
quickhack scan --repo test_repo --agent STRICT_ANALYSIS
```

**Expected agent behavior:**
1. Finds all 3 SQL operations
2. Classifies `/users/safe` as BY_DESIGN (reason_code: mitigated_by_parameterization)
3. Classifies `/users/unsafe` as VALID_SECURITY_ISSUE (reason_code: unsafe_identifier_influence)
4. Classifies `/users/allowlist` as BY_DESIGN (reason_code: mitigated_by_allowlist)

**Verify in findings output:**
```json
{
  "findings": [
    {
      "title": "SQL Injection in user sorting",
      "file_path": "api/users.py",
      "line_number": 18,
      "disposition": "valid_security_issue",
      "proof_checklist": {
        "dataflow_evidenced": {
          "status": "PROVEN",
          "reason_code": "unsafe_identifier_influence"
        }
      }
    }
  ],
  "safe_patterns": [
    {
      "file_path": "api/users.py",
      "line_number": 7,
      "disposition": "by_design",
      "proof_checklist": {
        "dataflow_evidenced": {
          "status": "DISPROVEN",
          "reason_code": "mitigated_by_parameterization"
        }
      }
    }
  ]
}
```

---

## Expected Impact

### Precision Improvements
- **Before:** Parameterized queries reported as bugs (noise)
- **After:** Parameterized queries classified as BY_DESIGN (safe)
- **Estimated reduction in false positives:** 60-80%

### Recall Improvements
- **Before:** Only finds obvious `cursor.execute(f"...")`
- **After:** Finds:
  - Dynamic ORDER BY injection
  - Dynamic table/column names
  - Second-order SQL injection (with double-proof)
  - ORM misuse (raw() without binding)
  - Query builder composition flaws

### Classification Quality
- **Before:** Binary "vulnerable/not vulnerable"
- **After:** Structured reason codes explaining WHY
  - `mitigated_by_parameterization`
  - `mitigated_by_allowlist`
  - `unsafe_identifier_influence`
  - `unsafe_structure_taint`
  - `DISPROVEN_BY_PROFILE`

---

## Troubleshooting

### Test Failure: "disposition is BUG, expected BY_DESIGN"

**Cause:** Pattern downgrade rule not applied.

**Fix:** Check that `_apply_pattern_downgrades()` includes the new mitigation logic and that it runs AFTER the base disposition is set.

### Test Failure: "reason_code is None"

**Cause:** `reason_code` field not added to ChecklistItem model.

**Fix:** Add `reason_code: str | None = None` to `ChecklistItem` in `backend/models/schemas.py`.

### Agent doesn't use new playbook

**Cause:** SQLi validity checklist not updated.

**Fix:** Replace `prompting/validity_checklists/sql_injection.md` with the new playbook content.

### Agent reports everything as SPECULATIVE

**Cause:** Agent can't gather enough evidence with current tools.

**Fix:** This is expected for complex cases. Future MCP tools (search_code, discover_entry_points, trace_data_flow) will improve this. For now, the playbook provides manual workarounds.

---

## Future Enhancements (Phase 2)

### Implement Missing MCP Tools

**Priority 1: search_code**
- Ripgrep-based content search
- Faster than manual file reading
- TOOL_REQUEST spec provided in brainstorming session

**Priority 2: discover_entry_points**
- Framework-aware route extraction
- Auto-detects Flask/FastAPI/Django patterns
- Provides 2-signal evidence for input channel inference

**Priority 3: trace_data_flow**
- Cross-file taint tracking
- Biggest recall improvement
- Most complex to implement

**Implementation guide for these tools provided in APPENDIX of the playbook.**

---

## Rollback Plan

If the new playbook causes issues:

1. Revert `prompting/validity_checklists/sql_injection.md` to previous version
2. Remove pattern downgrade rule from `_apply_pattern_downgrades()`
3. (Optional) Keep `reason_code` field in ChecklistItem for future use

The changes are isolated and can be rolled back independently.

---

## Monitoring and Validation

**After deployment, monitor:**

1. **False positive rate:** Should decrease by 60-80%
   - Metric: `findings with disposition=BUG where category=SQL_INJECTION`
   - Target: <10% of SQLi findings should be bugs

2. **Recall on known test cases:** Should increase
   - Create a test suite of known SQLi patterns
   - Run QuickHack before/after playbook deployment
   - Measure: % of patterns detected

3. **Reason code distribution:**
   - `mitigated_by_parameterization`: Should be most common for safe code
   - `unsafe_identifier_influence`: Should be common for ORDER BY injection
   - `unsafe_structure_taint`: Should be common for f-string injection

4. **Agent tool usage:**
   - Monitor which tools are called most frequently
   - Identifies candidates for future MCP tool implementation

---

## Questions or Issues?

If you encounter problems during implementation:

1. Run the test suite first to isolate the issue
2. Check that all 3 implementation steps were completed
3. Verify the downgrade rule is in the right location (after base disposition logic)
4. Check agent logs for reason_code values in checklist items

**Good luck with the rollout!**

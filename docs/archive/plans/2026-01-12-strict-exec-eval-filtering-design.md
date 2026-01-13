# Strict Exec/Eval Filtering for Triage System - Design Document

**Date:** 2026-01-12
**Status:** Approved for Implementation
**Version:** 1.0.0

## Overview

Enhance the existing `StrictClassifier` with aggressive exec/eval filtering logic to dramatically reduce false positives from code execution findings. The enhancement adds strict validation layers while maintaining the existing tri-state proof checklist architecture.

## Design Philosophy

**"Unknown ≠ Safe, Unknown = Unproven"**

- Don't mislabel unknowns as "expected" (BY_DESIGN)
- If we can't prove it's a product feature AND can't prove exploitation → SPECULATIVE
- SPECULATIVE findings are still filtered (non-reportable), but correctly labeled as "needs more evidence"
- Prefer false negatives over false positives (harsh but honest)

## The Exec/Eval Rule

### Decision Tree

```
if is_code_exec_sink(evidence):
    ↓
    1) Security control bypassed → BUG (via global BUG rule)
    ↓
    2) Feature intent PROVEN → BY_DESIGN
    ↓
    3) Source + Reachable + Dataflow + (Bypass OR Boundary) → VALID_SECURITY_ISSUE
    ↓
    4) Default → SPECULATIVE
```

### Classification Outcomes

| Scenario | Classification | Reportable? | Reasoning |
|----------|---------------|-------------|-----------|
| Security control bypassed + reachable | BUG | ✅ Yes | Explicit contradiction found (global rule) |
| Path + symbol match (2+ signals) | BY_DESIGN | ❌ No | Proven product feature |
| Source + reachable + dataflow + public | VALID_SECURITY_ISSUE | ✅ Yes | Full proof chain |
| Source + reachable + dataflow + auth unknown | SPECULATIVE | ❌ No | High-risk but unproven |
| Only weak hints | SPECULATIVE | ❌ No | Insufficient evidence |

## Implementation Components

### 1. AST-Based Sink Detection

**Function:** `_is_code_exec_sink(finding, evidence) -> (bool, str)`

**Detects:**
- Direct calls: `exec()`, `eval()`, `compile()`
- Attribute calls: `kernel.execute()`
- Obfuscated: `getattr(__builtins__, "exec")`, `__builtins__["exec"]`

**Critical Features:**
- **Scoped to symbol range** - Only checks nodes within `symbol_info.line_start` to `line_end`
- **Avoids comment/string false positives** - Uses AST when available
- **Handles line-number prefixes** - Strips `^\s*\d+\s*:\s*` in regex fallback

**Example AST Detection:**
```python
for node in ast.walk(evidence.ast_tree):
    if not (line_start <= node.lineno <= line_end):
        continue  # CRITICAL: scope check

    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id in ['exec', 'eval', 'compile']:
            return (True, f"Code-exec sink: {node.func.id}() at line {node.lineno}")
```

### 2. Conservative Feature Intent Detection

**Function:** `_feature_intent_proven(finding, evidence) -> (bool, str)`

**Requires TWO+ strong signals:**

**Signal A - Path Match:**
- `/pipelines/`, `/executor/`, `/kernel/`, `/etl/`, `/workflow/`, `/dag/`, `/notebooks/`
- Package structure: `.../data_preparation/.../block/...`

**Signal B - Symbol Match:**
- Class names: `PipelineExecutor`, `KernelRunner`, `BlockExecutor`
- Function names: `execute_pipeline()`, `run_kernel()`, `eval_block()`

**Signal C - Documentation Match:**
- Comments: "block execution", "pipeline runtime", "notebook kernel"
- Docstrings: "Execute user code", "Run pipeline block"

**Logic:**
```python
if (path_match + symbol_match) OR (path_match + doc_match):
    return (True, f"Feature intent PROVEN: {signals}")
else:
    return (False, "Feature intent UNKNOWN: insufficient signals")
```

**Examples:**
- ✅ `/pipelines/executor.py` + class `PipelineExecutor` → PROVEN
- ✅ `/kernel/runner.py` + comment "# Execute notebook cell" → PROVEN
- ❌ `/utils/runner.py` + `exec()` → UNKNOWN (weak hint only)
- ❌ `/pipelines/helper.py` (no symbol/doc) → UNKNOWN (path only)

### 3. Explicit Auth Bypass Detection

**Function:** `_auth_bypass_explicitly_proven(finding, evidence) -> (bool, str)`

**CRITICAL:** Only searches code evidence, NOT `finding.description` (prevents scanner manipulation)

**Code-only search space:**
- Handler snippet
- Route registration snippets
- Auth gate snippets

**Explicit markers:**

**Parameters (auth-specific):**
- `bypass_auth=True`, `require_auth=False`, `public=True`, `skip_auth=True`

**Function calls:**
- `bypass_oauth_check()`, `skip_permission_check()`, `bypass_auth()`

**Decorators:**
- `@public_endpoint`, `@no_auth_required`, `@unauthenticated`, `@allow_anonymous`

**Comments (in code):**
- `# no auth required`, `# public endpoint`, `# bypass authentication`

**Generic skip/bypass (with auth keyword co-occurrence):**
- `skip=True` + "auth"|"oauth"|"rbac" in same snippet
- `bypass=True` + "auth"|"oauth"|"rbac" in same snippet

**NOT considered explicit:**
- "No auth gates found" (absence ≠ bypass)
- Path contains `/public/` (convention, not proof)

### 4. Modified Disposition Rules

**Location in `_apply_rules` method:**

```python
# Rule 4: STRICT EXEC/EVAL FILTERING
is_exec_sink, exec_reason = self._is_code_exec_sink(finding, evidence)
if is_exec_sink:
    # Store reason and force sink_present to PROVEN
    checklist.exec_sink_reason = exec_reason
    checklist.sink_present = ChecklistItem(
        value=True,
        status=ChecklistStatus.PROVEN,
        reason=exec_reason
    )

    # Sub-rule 4b: Feature intent proven → BY_DESIGN
    feature_proven, feature_reason = self._feature_intent_proven(finding, evidence)
    checklist.feature_intent_reason = feature_reason
    if feature_proven:
        return Disposition.BY_DESIGN

    # Sub-rule 4c: Full proof chain → VALID
    if (source.PROVEN_TRUE and reachable.PROVEN_TRUE and
        dataflow.PROVEN_TRUE):  # CRITICAL: dataflow required

        bypass_proven, bypass_reason = self._auth_bypass_explicitly_proven(finding, evidence)
        checklist.auth_bypass_reason = bypass_reason

        boundary_violated = boundary_crossed.PROVEN_TRUE

        if bypass_proven or boundary_violated:
            return Disposition.VALID_SECURITY_ISSUE

        return Disposition.SPECULATIVE  # Auth unknown

    # Sub-rule 4d: Default → SPECULATIVE
    return Disposition.SPECULATIVE
```

**Note:** Sub-rule 4a (security control bypassed → BUG) is **removed** - the global BUG rule at the top of `_apply_rules` already handles this correctly with proper reachability checks.

### 5. Auditable Reasoning

Every exec/eval finding includes these reasoning bullets:

```python
# Always present
"Code-exec sink: exec() at line 42"

# Feature evaluation
"Feature intent PROVEN: path=/pipelines/ + symbol=PipelineExecutor"
# OR
"Feature intent UNKNOWN: only weak signal (path=/utils/)"

# Auth evaluation (if source + reachable)
"Auth bypass PROVEN: decorator '@public_endpoint' in code"
# OR
"Auth bypass not PROVEN: no explicit bypass markers in code"
```

## Edge Cases Handled

### 1. Comment/String False Positives
```python
# This function uses exec() internally  ← NOT detected as sink
"""Call exec(code) to run"""  ← NOT detected as sink
exec(user_code)  ← DETECTED as sink
```
**Solution:** AST-based detection scoped to symbol range, regex ignores comment lines

### 2. Obfuscated Exec
```python
getattr(__builtins__, "exec")(code)  ← DETECTED
__builtins__["exec"](code)  ← DETECTED
```
**Solution:** AST detects getattr/subscript patterns with "exec"/"eval" strings

### 3. RBAC Bypass Without Explicit Markers
```python
@app.post("/admin/execute")  # Admin path
async def run_script(script: str):  # No role check
    exec(script)
```
→ **VALID_SECURITY_ISSUE** (boundary_crossed.PROVEN_TRUE)

**Solution:** Use existing `boundary_crossed` checklist item instead of only explicit markers

### 4. No Dataflow False Positives
```python
def handler(user_code: str):  # Source
    config = load_config()
    exec(config['script'])  # Sink, but different variable
```
→ **SPECULATIVE** (dataflow not proven)

**Solution:** Require `dataflow_evidenced.PROVEN_TRUE` for VALID upgrades

### 5. Whole-File AST Scan False Positives
```python
def other_function():
    exec(internal_code)  # Different function

def vulnerable_handler(user_code: str):  # Finding is here
    process(user_code)
```
→ **NO exec sink detected** (scoped to vulnerable_handler)

**Solution:** Only check AST nodes within `symbol_info.line_start/end` range

## Data Model Changes

### ProofChecklist Extension

**Location:** `backend/models/schemas.py`

```python
class ProofChecklist(BaseModel):
    """Tri-state proof checklist for vulnerability validation."""
    source_controlled_input: ChecklistItem
    sink_present: ChecklistItem
    dataflow_evidenced: ChecklistItem
    reachable: ChecklistItem
    boundary_crossed: ChecklistItem
    not_only_misconfig: ChecklistItem
    security_control_bypassed: Optional[ChecklistItem] = None

    # Exec/eval specific reasoning (for auditable filtering)
    exec_sink_reason: Optional[str] = None
    feature_intent_reason: Optional[str] = None
    auth_bypass_reason: Optional[str] = None
```

## Integration Points

### Pattern Downgrades
Skip `CODE_INJECTION` category in `_apply_pattern_downgrades` - let exec filter own it:

```python
def _apply_pattern_downgrades(...):
    # SKIP CODE_INJECTION - handled by strict exec filter
    if category == VulnerabilityCategory.CODE_INJECTION:
        return disposition

    # ... rest of pattern downgrades ...
```

### Reasoning Generation
Add exec-specific reasoning at start of `_generate_reasoning`:

```python
if checklist.exec_sink_reason:
    bullets.append(checklist.exec_sink_reason)
    bullets.append(checklist.feature_intent_reason)
    bullets.append(checklist.auth_bypass_reason)
    if len(bullets) >= 3:
        return bullets[:4]  # Truncate if exec reasoning is complete
```

## Examples

### Example 1: True Product Feature
```python
# File: /app/pipelines/transformer.py
class PipelineExecutor:
    def run_block(self, code):
        """Execute user-defined transformation block."""
        exec(code)
```
→ **BY_DESIGN**
- Reasoning:
  - "Code-exec sink: exec() at line 4"
  - "Feature intent PROVEN: path=/pipelines/ + symbol=PipelineExecutor + doc='Execute user-defined transformation'"

### Example 2: Public RCE
```python
# File: /app/api/runner.py
@app.post("/execute")
@public_endpoint
async def run_code(code: str):
    exec(code)
```
→ **VALID_SECURITY_ISSUE**
- Reasoning:
  - "Code-exec sink: exec() at line 4"
  - "Feature intent UNKNOWN: no strong signals found"
  - "Auth bypass PROVEN: decorator '@public_endpoint' in code"

### Example 3: Unknown Auth
```python
# File: /app/api/tools.py
@app.post("/transform")
async def transform_data(script: str):
    exec(script)  # No auth markers
```
→ **SPECULATIVE**
- Reasoning:
  - "Code-exec sink: exec() at line 3"
  - "Feature intent UNKNOWN: no strong signals found"
  - "Auth bypass not PROVEN: no explicit bypass markers in code"

### Example 4: Comment False Positive (Avoided)
```python
# File: /app/utils/helper.py
def process_data(data):
    # We could use exec() here but chose subprocess
    result = subprocess.run(data, shell=False)
```
→ **No exec sink detected** (comment ignored by AST)

### Example 5: No Dataflow
```python
@app.post("/process")
@public_endpoint
async def process_data(user_code: str):  # Source
    config = load_config()
    exec(config['script'])  # Sink, different variable
```
→ **SPECULATIVE**
- Reasoning:
  - "Code-exec sink: exec() at line 4"
  - "Dataflow not proven: user_code does not reach exec sink"

## Testing Strategy

### Test Classes
1. `TestStrictExecEvalFiltering` - Core exec/eval logic
2. `TestASTParsing` - AST detection edge cases
3. `TestFeatureIntent` - Multi-signal requirements
4. `TestAuthBypass` - Explicit marker detection
5. `TestDataflowRequirement` - VALID requires dataflow

### Critical Test Cases
- Comment containing "exec" → No sink detected
- Obfuscated `getattr(__builtins__, "exec")` → Detected
- Auth unknown → SPECULATIVE (not BY_DESIGN)
- Admin path without role check → VALID (boundary crossed)
- Weak path hint only → SPECULATIVE (not BY_DESIGN)
- Path + symbol match → BY_DESIGN
- Source + sink but different variables → SPECULATIVE (no dataflow)

## Files Modified

### Primary Implementation
- `backend/services/strict_classifier.py` (3 new methods, 1 modified method)
- `backend/models/schemas.py` (ProofChecklist extension)

### Tests
- `backend/tests/services/test_strict_classifier.py` (new test class with 7+ tests)

## Success Metrics

**Before enhancement:**
- Exec/eval findings: ~40% reportable (high false positive rate)
- BY_DESIGN classification: Often based on weak single signal

**After enhancement:**
- Exec/eval findings: ~5-10% reportable (only proven exploits)
- BY_DESIGN classification: Requires 2+ strong signals
- SPECULATIVE classification: Correctly labels "unproven but suspicious"

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|-----------|
| Miss real RCE in non-standard paths | False negative | SPECULATIVE catches unknowns, not BY_DESIGN |
| AST parsing fails on complex code | Fallback to regex | Regex ignores comments, handles line prefixes |
| Tests break due to evidence field changes | Test failures | Update tests to use correct field names |
| Pydantic extra=forbid errors | Runtime errors | Add explicit fields to ProofChecklist |

## Rollout Plan

1. **Phase 1:** Implement core logic + tests
2. **Phase 2:** Run against historical findings, validate filtering
3. **Phase 3:** Deploy to production
4. **Phase 4:** Monitor SPECULATIVE findings, tune feature intent detection

---

**Design Status:** ✅ Approved
**Next Step:** Implementation via `superpowers:writing-plans`

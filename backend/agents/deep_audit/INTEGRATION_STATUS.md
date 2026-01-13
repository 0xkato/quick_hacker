# DeepAudit PromptRouter Integration Status

**Date:** 2026-01-13
**Task:** Task 2 - Add PromptRouter to DeepAudit Subagents

## Current Status: Architecturally Complete

The PromptRouter integration for DeepAudit subagents is **architecturally complete** and ready for use. All the plumbing is in place, but the actual subagent dispatch in `nodes.py` is still a stub.

## What's Working ✅

### 1. Case Builder Integration (`case_builder.py`)

```python
def assemble_auditor_prompt_for_signal(signal: Dict[str, Any], case_file_path: str) -> str:
    """Assemble Auditor prompt using PromptRouter for category-specific validity checklist."""
    signal_type = signal.get("signal_type", "unknown")
    category = _map_signal_type_to_category(signal_type)

    if category:
        router = PromptRouter()
        modules = router.route(category=category, stage="validate_exploitability")
        return router.assemble_from_paths(modules, task=task)
    else:
        return task  # Fallback without checklist
```

### 2. Signal Type Mapping

```python
def _map_signal_type_to_category(signal_type: Optional[str]) -> Optional[str]:
    """Map signal_type to vulnerability category for PromptRouter."""
    # Handles: sql_injection_candidate → SQL_INJECTION
    #          xss_candidate → XSS
    #          ssrf_candidate → SSRF
    # ... etc
```

Supported mappings:
- `sql_injection_candidate` → `SQL_INJECTION`
- `xss_candidate` → `XSS`
- `cross_site_scripting_candidate` → `XSS`
- `ssrf_candidate` → `SSRF`
- `code_injection_candidate` → `CODE_INJECTION`
- `command_injection_candidate` → `COMMAND_INJECTION`
- `deserialization_candidate` → `DESERIALIZATION`
- `path_traversal_candidate` → `PATH_TRAVERSAL`
- `auth_bypass_candidate` → `AUTH_BYPASS`
- `idor_candidate` → `IDOR`
- `memory_safety_candidate` → `MEMORY_SAFETY`

### 3. Subagent Prompt Function (`subagents.py`)

```python
def get_auditor_prompt(case_file_path: str, signal: Dict[str, Any] = None) -> str:
    """Get Auditor prompt for a specific case file.

    Args:
        case_file_path: Path to the case file
        signal: Optional signal dictionary for category-specific validity checklist

    Returns:
        Assembled prompt with validity checklist if signal is provided
    """
    if signal:
        # Use PromptRouter integration for category-specific validity checklist
        return assemble_auditor_prompt_for_signal(signal, case_file_path)
    else:
        # Fallback to original template for backward compatibility
        return AUDITOR_PROMPT_TEMPLATE.format(case_file_path=case_file_path)
```

### 4. Test Coverage

All 10 tests pass:
- ✅ SQL injection validity checklist loading
- ✅ XSS validity checklist loading (with `security_control_bypassed`)
- ✅ Signal type to category mapping
- ✅ Unknown signal type fallback
- ✅ None signal type handling
- ✅ `get_auditor_prompt()` with signal
- ✅ `get_auditor_prompt()` without signal (backward compatibility)

## What Needs Implementation ⚠️

### `dispatch_auditor()` Node (STUB)

Location: `backend/agents/deep_audit/nodes.py:138-154`

Current status:
```python
def dispatch_auditor(state: SupervisorState) -> SupervisorState:
    """
    Spawn auditor subagent to perform deep analysis of audit case.

    STUB: Currently a no-op. Full implementation will:
    - Select highest priority pending audit case
    - Spawn auditor subagent using Deep Agents task tool
    - Track auditor execution state
    """
    # TODO: Implement auditor spawning with Deep Agents task tool
    return state
```

### How It Should Work When Implemented

```python
def dispatch_auditor(state: SupervisorState) -> SupervisorState:
    """Spawn auditor subagent to perform deep analysis of audit case."""

    # 1. Get next case from signal queue
    if not state.signal_queue:
        return state

    signal_id = state.signal_queue[0]  # Highest priority

    # 2. Load signal data from /memories/scopes/{scope_id}/signals.json
    signal = load_signal_by_id(signal_id)

    # 3. Build case file
    case_file_path = f"/memories/cases/{signal_id}.md"
    case_content = build_case_file(signal, code_excerpts=[])
    write_file(case_file_path, case_content)

    # 4. Get category-aware prompt (THIS IS THE KEY INTEGRATION POINT)
    prompt = get_auditor_prompt(case_file_path, signal=signal)
    # ☝️ This will automatically:
    #    - Extract signal_type from signal
    #    - Map to category (e.g., "sql_injection_candidate" → "SQL_INJECTION")
    #    - Use PromptRouter to load validity_checklists/sql_injection.md
    #    - Assemble: base + validity_checklist + task

    # 5. Spawn auditor subagent with assembled prompt
    auditor = spawn_deep_agent(
        role="auditor",
        prompt=prompt,
        tools=["read_file", "analyze_ast", "trace_dataflow", "promote_finding"]
    )

    # 6. Track auditor
    state.active_case_ids.append(signal_id)

    return state
```

## How to Use (Once dispatch_auditor is Implemented)

### For Developer Implementing dispatch_auditor:

Simply call `get_auditor_prompt()` with the signal:

```python
from agents.deep_audit.subagents import get_auditor_prompt

# Load signal from somewhere (file, state, etc.)
signal = {
    "signal_id": "sig_123",
    "signal_type": "sql_injection_candidate",  # This is the key field!
    "file_path": "/repo/app/routes.py",
    "line_range": [45, 52],
    # ... other signal fields
}

# Get the prompt (automatically includes SQL injection validity checklist)
prompt = get_auditor_prompt(case_file_path, signal=signal)
```

That's it! The PromptRouter integration handles everything else:
1. Maps `"sql_injection_candidate"` → `"SQL_INJECTION"`
2. Routes to `validity_checklists/sql_injection.md`
3. Assembles prompt with checklist items (sink_present, source_controlled_input, etc.)

## Architecture Flow

```
Signal detected by worker
  ↓
signal_type: "sql_injection_candidate"
  ↓
supervisor.dispatch_auditor()
  ↓
get_auditor_prompt(case_file_path, signal=signal)
  ↓
_map_signal_type_to_category("sql_injection_candidate")
  ↓
Returns: "SQL_INJECTION"
  ↓
PromptRouter.route(category="SQL_INJECTION", stage="validate_exploitability")
  ↓
Returns: PromptModules(validity_checklist="validity_checklists/sql_injection.md", ...)
  ↓
PromptRouter.assemble_from_paths(modules, task=...)
  ↓
Assembled prompt includes:
  - Base auditor instructions
  - SQL Injection Proof Checklist (6 items)
  - Task instructions
  - Case file path
  ↓
Auditor receives category-specific prompt
```

## Testing

Run tests:
```bash
cd backend
python -m pytest tests/agents/deep_audit/test_case_builder_prompts.py -v
```

All 10 tests pass (verified 2026-01-13).

## Next Steps

1. **Implement `dispatch_auditor()` in `nodes.py`**
   - Load signal data from storage
   - Call `get_auditor_prompt(case_file_path, signal=signal)`
   - Spawn auditor subagent with the assembled prompt

2. **No changes needed to:**
   - `case_builder.py` (already complete)
   - `subagents.py` (already complete)
   - Signal type mapping (already complete)
   - Test coverage (already complete)

## Verification Checklist

- ✅ PromptRouter integration complete in case_builder.py
- ✅ Signal type to category mapping implemented
- ✅ get_auditor_prompt() accepts signal parameter
- ✅ Backward compatibility maintained (works without signal)
- ✅ All tests pass (10/10)
- ✅ SQL_INJECTION checklist loading verified
- ✅ XSS checklist loading verified (with security_control_bypassed)
- ✅ Unknown signal type fallback works
- ⚠️ dispatch_auditor() stub needs implementation (future work)

## Conclusion

**Task 2 is architecturally complete.** The integration is ready for use as soon as `dispatch_auditor()` is implemented. The developer implementing that function just needs to call `get_auditor_prompt(case_file_path, signal=signal)` and the PromptRouter will automatically inject the category-specific validity checklist.

**No further changes are needed to the prompting system integration for DeepAudit subagents.**

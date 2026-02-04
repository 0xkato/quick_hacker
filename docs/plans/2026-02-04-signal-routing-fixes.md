# Signal Routing Pipeline Fixes

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix critical bugs preventing specialists from being called after signals are found

**Architecture:** Fix file path mismatches, improve JSON parsing consistency, add tool usage instructions to prompts, and improve error visibility

**Tech Stack:** Python, asyncio, Claude CLI

---

## Problem Summary

The signal routing pipeline is broken:
1. SinkHunter finds signals and writes them to files
2. Collection functions look for WRONG file paths
3. `confirmed_findings` stays empty
4. Phase 4 condition fails → Specialists never run

## Tasks

### Task 1: Fix Wave File Path Mismatch

**Files:**
- Modify: `backend/agents/deep_audit/overseer.py:946-988`

**Problem:**
```python
# Deliverable writes to:
f"/memories/waves/wave_{wave_num}/sinks_{focus_name}.json"

# But collection looks for:
f"{wave_dir}/sinks.json"  # WRONG!
```

**Step 1: Update `_collect_wave_findings()` to use glob pattern**

Find and replace in `overseer.py` around line 946-955:

```python
async def _collect_wave_findings(self, wave_num: int):
    """Collect findings from a specific wave's outputs."""
    wave_dir = f"/memories/waves/wave_{wave_num}"

    # Use glob pattern to find all sink files (sinks_*.json)
    try:
        all_files = self.filesystem.list_directory(wave_dir)
    except FileNotFoundError:
        print(f"[Overseer] Wave {wave_num}: Directory not found: {wave_dir}")
        return

    # Match any sinks file (sinks.json, sinks_memory.json, sinks_injection.json, etc.)
    sink_files = [f for f in all_files if f.startswith("sinks") and f.endswith(".json")]
    dataflow_files = [f for f in all_files if "dataflow" in f and f.endswith(".json")]
    auth_files = [f for f in all_files if "auth" in f and f.endswith(".json")]

    files_to_check = [f"{wave_dir}/{f}" for f in sink_files + dataflow_files + auth_files]

    if not files_to_check:
        print(f"[Overseer] Wave {wave_num}: No signal files found in {wave_dir}")
        return
```

**Step 2: Verify the change**

Run: `grep -n "files_to_check\|list_directory" backend/agents/deep_audit/overseer.py`

**Step 3: Commit**

```bash
git add backend/agents/deep_audit/overseer.py
git commit -m "fix(overseer): Use glob pattern to find wave signal files

The collection function was looking for exact filenames like sinks.json
but deliverables write to sinks_{focus_name}.json. Now uses list_directory
to find all matching files.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

### Task 2: Fix EntrypointHunter JSON Parser Inconsistency

**Files:**
- Modify: `backend/agents/deep_audit/overseer.py:931-942`

**Problem:**
```python
# EntrypointHunter uses raw json.loads() - fails on Claude's markdown output:
entrypoints_data = json.loads(entrypoints_content)

# But SinkHunter uses _extract_json_from_output() which handles markdown
```

**Step 1: Update EntrypointHunter parsing**

Find around line 931-942 and replace:

```python
# Read EntrypointHunter output (for context, not findings)
try:
    entrypoints_content = self.filesystem.read_file("/memories/signals/entrypoints.json")
    if entrypoints_content:
        entrypoints_data = self._extract_json_from_output(entrypoints_content)
        if entrypoints_data:
            entrypoints = entrypoints_data.get("entrypoints", [])
            self.campaign_state.entrypoints = entrypoints
            print(f"[Overseer] Found {len(entrypoints)} entrypoints from EntrypointHunter")
        else:
            print(f"[Overseer] Could not parse EntrypointHunter output as JSON")
except Exception as e:
    print(f"[Overseer] Could not read EntrypointHunter output: {e}")
```

**Step 2: Commit**

```bash
git add backend/agents/deep_audit/overseer.py
git commit -m "fix(overseer): Use consistent JSON extraction for EntrypointHunter

EntrypointHunter was using raw json.loads() which fails on Claude's
markdown-wrapped output. Now uses _extract_json_from_output() like
SinkHunter does.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

### Task 3: Add Error Visibility for Signal Collection Failures

**Files:**
- Modify: `backend/agents/deep_audit/overseer.py:894-944`

**Problem:** Errors are printed to console but not visible in UI. Signals can be silently lost.

**Step 1: Add emit_log calls for errors**

Update the exception handlers in `_collect_findings_from_signals()`:

```python
async def _collect_findings_from_signals(self):
    """Read sub-agent outputs and extract findings from signals."""
    collection_errors = []

    # Read SinkHunter output
    try:
        sinks_content = self.filesystem.read_file("/memories/signals/sinks.json")
        if sinks_content:
            sinks_data = self._extract_json_from_output(sinks_content)
            if sinks_data:
                # ... existing signal extraction code ...
                print(f"[Overseer] Collected {len(signals)} signals from SinkHunter")
            else:
                error_msg = "Could not parse SinkHunter output as JSON"
                print(f"[Overseer] {error_msg}")
                collection_errors.append(error_msg)
        else:
            error_msg = "SinkHunter output file is empty"
            print(f"[Overseer] {error_msg}")
            collection_errors.append(error_msg)
    except FileNotFoundError:
        error_msg = "SinkHunter output not found at /memories/signals/sinks.json"
        print(f"[Overseer] {error_msg}")
        collection_errors.append(error_msg)
    except Exception as e:
        error_msg = f"Could not read SinkHunter output: {e}"
        print(f"[Overseer] {error_msg}")
        collection_errors.append(error_msg)

    # ... similar for EntrypointHunter ...

    # Report errors to UI
    if collection_errors:
        await self.emit_log(f"WARNING: {len(collection_errors)} collection errors: {'; '.join(collection_errors)}")

    await self.emit_log(f"Collected {len(self.campaign_state.confirmed_findings)} potential findings from sub-agents")
```

**Step 2: Commit**

```bash
git add backend/agents/deep_audit/overseer.py
git commit -m "fix(overseer): Add error visibility for signal collection failures

Errors during signal collection were only printed to console, making
debugging difficult. Now emits warnings to UI when collection fails.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

### Task 4: Add Tool Usage Instructions to Subagent Prompts

**Files:**
- Modify: `backend/agents/deep_audit/subagents.py`

**Problem:** Subagents have tools available but prompts don't instruct them to USE the tools. They do pure inference instead of actually searching the codebase.

**Step 1: Read current subagent prompts**

```bash
grep -n "SINKHUNTER_PROMPT\|def get_.*_prompt" backend/agents/deep_audit/subagents.py | head -20
```

**Step 2: Add tool usage section to SinkHunter prompt**

Find the SinkHunter prompt and add this section near the top:

```python
## CRITICAL: Tool Usage Requirements

You MUST use your available tools to search the actual codebase. Do NOT rely on training data or assumptions.

**Required workflow:**
1. Use `Grep` to search for dangerous patterns (e.g., `grep -r "exec\|eval\|system\|popen"`)
2. Use `Read` to examine each file containing potential sinks
3. Use `Glob` to find relevant file types (e.g., `**/*.py`, `**/*.go`)

**Tools available to you:**
- Read: Read file contents
- Grep: Search for patterns in code
- Glob: Find files by pattern

**DO NOT skip tool usage.** Every signal you report MUST be based on actual code you read with the Read tool.
```

**Step 3: Add similar sections to other hunter prompts**

Apply the same pattern to:
- EntrypointHunter
- DataFlowTracer
- Specialist prompts

**Step 4: Commit**

```bash
git add backend/agents/deep_audit/subagents.py
git commit -m "feat(subagents): Add explicit tool usage instructions to prompts

Subagents were not using their available tools, doing pure inference
instead of actually searching the codebase. Added CRITICAL sections
requiring tool usage with specific workflow instructions.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

### Task 5: Add Debug Logging for Phase 4 Condition

**Files:**
- Modify: `backend/agents/deep_audit/overseer.py:828-832`

**Problem:** Hard to debug why Phase 4 is skipped. Need visibility into the condition check.

**Step 1: Add logging before Phase 4 condition**

```python
# === PHASE 4: SIGNAL ROUTING ===
# Route each signal through: Decider → FamilyCoordinator → Specialist → Triager
findings_count = len(self.campaign_state.confirmed_findings)
time_remaining = self.campaign_state.time_remaining()
print(f"[Overseer] Phase 4 check: {findings_count} findings, {time_remaining:.0f}s remaining")
await self.emit_log(f"Phase 4 check: {findings_count} findings, {time_remaining:.0f}s remaining")

if findings_count > 0 and time_remaining > 60:
    await self._route_all_signals()
else:
    skip_reason = []
    if findings_count == 0:
        skip_reason.append("no findings collected")
    if time_remaining <= 60:
        skip_reason.append(f"insufficient time ({time_remaining:.0f}s <= 60s)")
    await self.emit_log(f"Skipping Phase 4: {', '.join(skip_reason)}")
    print(f"[Overseer] Skipping Phase 4: {', '.join(skip_reason)}")
```

**Step 2: Commit**

```bash
git add backend/agents/deep_audit/overseer.py
git commit -m "feat(overseer): Add debug logging for Phase 4 condition

Hard to debug why specialists aren't called. Now logs the exact
condition values and reason for skipping Phase 4.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

### Task 6: Verify Fixes with Integration Test

**Files:**
- Create: `backend/tests/test_signal_routing_fixes.py`

**Step 1: Create test file**

```python
"""Test signal routing pipeline fixes."""
import pytest
import json
from pathlib import Path
from agents.deep_audit.overseer import Overseer
from agents.deep_audit.filesystem import MemoriesFilesystem


class TestWaveFileCollection:
    """Test that wave files with focus suffixes are collected."""

    def test_collect_wave_findings_with_focus_suffix(self, tmp_path):
        """Wave files like sinks_memory.json should be collected."""
        # Setup
        fs = MemoriesFilesystem("test", str(tmp_path))
        wave_dir = tmp_path / "memories" / "waves" / "wave_2"
        wave_dir.mkdir(parents=True)

        # Write file with focus suffix (how dispatcher writes it)
        (wave_dir / "sinks_memory.json").write_text(json.dumps({
            "signals": [{"title": "Test", "severity": "HIGH"}]
        }))

        # Verify list_directory finds it
        files = fs.list_directory("/memories/waves/wave_2")
        assert "sinks_memory.json" in files

        # Verify it matches the pattern
        sink_files = [f for f in files if f.startswith("sinks") and f.endswith(".json")]
        assert len(sink_files) == 1


class TestJSONExtraction:
    """Test consistent JSON extraction across all hunters."""

    def test_extract_json_from_markdown_wrapped_output(self):
        """Claude often wraps JSON in markdown code blocks."""
        from agents.deep_audit.utils.json_extractor import extract_json_from_output

        markdown_output = '''Here are the entrypoints I found:

```json
{
  "entrypoints": [
    {"path": "/api/users", "method": "GET"}
  ]
}
```

These are the main entry points.'''

        result = extract_json_from_output(markdown_output)
        assert result is not None
        assert "entrypoints" in result
        assert len(result["entrypoints"]) == 1
```

**Step 2: Run tests**

```bash
cd backend && python -m pytest tests/test_signal_routing_fixes.py -v
```

**Step 3: Commit**

```bash
git add backend/tests/test_signal_routing_fixes.py
git commit -m "test: Add tests for signal routing fixes

Tests verify:
- Wave files with focus suffixes are collected
- JSON extraction handles markdown-wrapped output

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Execution Order

Tasks can be executed in this order (some parallelizable):

1. **Task 1** (path mismatch) - CRITICAL, fixes core bug
2. **Task 2** (JSON parser) - Quick fix, independent
3. **Task 3** (error visibility) - Depends on Task 1/2 context
4. **Task 4** (tool instructions) - Independent, can parallel
5. **Task 5** (debug logging) - Quick, independent
6. **Task 6** (tests) - After all fixes

## Success Criteria

After implementing all tasks:
1. Run a scan and verify in LLM Interactions panel that tools are being used (not "0 tools")
2. Verify signals appear in `confirmed_findings` after hunting phase
3. Verify Phase 4 runs and specialists are called
4. Verify UI shows collection errors if they occur

# Structured Diagram + MCP Stability Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make Structured Trace diagrams easier to read (green/yellow/red) and stop Codex CLI MCP tool calls from failing due to stdout pollution / optional deps.

**Architecture:** Keep Structured Trace as the primary DAG view, but adjust risk coloring to be *node-local* (avoid propagating “finding” to all ancestors). For MCP stability, ensure no imports print to stdout and make `anthropic` an optional dependency via lazy import + graceful fallback.

**Tech Stack:** FastAPI (backend), MCP stdio server (Codex CLI), Next.js + React Flow (frontend), pytest + node:test.

---

### Task 1: Add failing backend tests for MCP/triage safety

**Files:**
- Create: `backend/tests/protocol_config/test_protocol_config_stdio.py`
- Create: `backend/tests/services/tool_core/test_triage_finding_no_anthropic.py`

**Step 1: Write failing test — ProtocolConfig must not write to stdout**

Create `backend/tests/protocol_config/test_protocol_config_stdio.py`:
- Reload `protocol_config.protocol_config` with `ANTHROPIC_API_KEY` unset and `ENABLE_QUESTS_BY_DEFAULT=true`
- Assert `capsys.readouterr().out == ""`

**Step 2: Run test to verify it fails**

Run: `cd backend && pytest -q backend/tests/protocol_config/test_protocol_config_stdio.py`
Expected: FAIL (stdout contains the quests warning).

**Step 3: Write failing test — finding_filters import must not require anthropic**

Create `backend/tests/services/tool_core/test_triage_finding_no_anthropic.py`:
- Monkeypatch `builtins.__import__` to raise for `anthropic`
- `import services.finding_filters` should succeed

**Step 4: Write failing test — ToolCore.triage_finding returns keep without key**

In same test file:
- Ensure `ANTHROPIC_API_KEY` unset
- Create `ToolCore(...)`
- `await tool_core.triage_finding(...)` returns `{decision:"keep", reason:...}` and includes `is_production_code` key.

**Step 5: Run tests to verify they fail**

Run: `cd backend && pytest -q backend/tests/services/tool_core/test_triage_finding_no_anthropic.py`
Expected: FAIL (import error for anthropic and/or missing `is_production_code`).

---

### Task 2: Fix stdout pollution + make anthropic optional

**Files:**
- Modify: `backend/protocol_config/protocol_config.py`
- Modify: `backend/services/finding_filters/filters/production_filter.py`
- Modify: `backend/services/tool_core/finding_management.py`

**Step 1: ProtocolConfig warning must not go to stdout**
- Replace `print(...)` with stderr-safe output (`print(..., file=sys.stderr)`) or `logging.warning`.

**Step 2: Lazy-import anthropic in ProductionRelevanceFilter**
- Move `from anthropic import Anthropic` into `__init__` (or the call site) and raise a clear error only when the filter is actually invoked.

**Step 3: Make triage_finding robust**
- Check for `ANTHROPIC_API_KEY` before importing `ProductionRelevanceFilter`
- Catch `ImportError/ModuleNotFoundError` and return `"keep"` with a reason instead of throwing
- Ensure the return shape always includes `is_production_code` (boolean) for downstream/UI compatibility

**Step 4: Run backend tests**

Run:
- `cd backend && pytest -q backend/tests/protocol_config/test_protocol_config_stdio.py`
- `cd backend && pytest -q backend/tests/services/tool_core/test_triage_finding_no_anthropic.py`
Expected: PASS.

---

### Task 3: Adjust Structured Trace risk coloring (avoid “everything is red”)

**Files:**
- Modify: `frontend/components/FlowVisualization/structuredTraceRisk.js`
- Modify: `frontend/components/FlowVisualization/structuredTraceRisk.test.js`

**Step 1: Update tests (RED)**
- Change tests to expect *no ancestor propagation*: only actual finding nodes are `finding`, only dangerous_sink nodes are `sink`, everything else `none`.

**Step 2: Run tests to verify they fail**

Run: `node --test frontend/components/FlowVisualization/structuredTraceRisk.test.js`
Expected: FAIL (current code propagates risk).

**Step 3: Update implementation (GREEN)**
- Make `computeStructuredTraceRiskLevels` return `baseRisk(node)` per node (no DFS propagation).

**Step 4: Re-run tests**

Run: `node --test frontend/components/FlowVisualization/structuredTraceRisk.test.js`
Expected: PASS.

---

### Task 4: Sanity verification

**Files:**
- None (verification only)

**Step 1: Run backend suite (fast path if needed)**

Run: `cd backend && pytest -q`
Expected: PASS.

**Step 2: Optional UI sanity**
- Start stack and verify:
  - Structured Trace nodes are green by default
  - Dangerous sinks are yellow
  - Findings are red
  - Clicking “Finding” / “Sinks” / “Entrypoints” in the legend opens the navigator and focuses nodes
  - Codex CLI scans no longer show MCP `Result: None` errors for `triage_finding` when no Anthropic key is configured


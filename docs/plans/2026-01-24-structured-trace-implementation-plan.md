# Structured Trace Diagram Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a new “Structured Trace” diagram mode that renders a multi-level, collapsible audit trace organized by `Entrypoint → Folder → File → Function → Steps → Finding`, with all tool calls represented and grouped under collapsed “Steps” nodes.

**Architecture:** Extend the existing flow graph model to support **edge kinds** (legacy vs structured). Emit a parallel “structured” edge set and a small set of structural nodes (root/global/folder/steps/sinks group). The UI adds a new diagram mode that filters nodes/edges to render the structured tree without breaking existing diagrams.

**Tech Stack:** FastAPI + Python (FlowService + agents/orchestrator instrumentation), Next.js + ReactFlow + TypeScript (FlowVisualization), Playwright (frontend smoke tests), pytest (backend tests).

> Note: The superpowers workflow expects a git worktree. In this environment, writing into `.git/refs/*` is blocked (“Operation not permitted”), so `git worktree add`/new branches may not work. Implement and verify normally; commits are optional and can be done manually outside this sandbox if desired.

---

## Task 1: Add Edge “Kind” Support (Legacy vs Structured)

**Files:**
- Modify: `backend/services/flow_service.py`
- Test: `backend/tests/services/test_flow_service.py`

**Step 1: Write a failing test for edge kind default**

Add a test that calls `flow_service.add_node()` twice and asserts the created edge has `kind == "legacy"` (or that missing kind is treated as legacy for backwards compat).

Run: `cd backend && pytest tests/services/test_flow_service.py -k edge_kind -v`  
Expected: FAIL (edge has no `kind` / cannot filter).

**Step 2: Implement `FlowEdge.kind` and defaulting**

- Add `kind: str | None = None` to `FlowEdge`.
- Update `add_node(..., edge_kind: str = "legacy")` to set `edge.kind = edge_kind`.
- Update `add_edge(..., kind: str = "legacy")` similarly.
- Ensure restore logic tolerates missing `kind` (default None).

**Step 3: Re-run the test**

Run: `cd backend && pytest tests/services/test_flow_service.py -k edge_kind -v`  
Expected: PASS.

---

## Task 2: Add Structured Trace Node Types + Index Helpers

**Files:**
- Modify: `backend/services/flow_service.py`
- Test: `backend/tests/services/test_flow_service.py`

**Step 1: Write failing tests for “ensure roots” + dedupe**

Add tests for:
- `ensure_structured_trace(agent_id)` creates exactly one each: `structured_root`, `global_recon`, `sinks_group`.
- Calling it twice does not duplicate nodes.

Run: `cd backend && pytest tests/services/test_flow_service.py -k structured_trace_roots -v`  
Expected: FAIL (helper not implemented).

**Step 2: Implement structured node types + helpers**

In `FlowService`:
- Extend `NodeType` with: `structured_root`, `global_recon`, `folder`, `steps`, `sinks_group`.
- Add an in-memory per-agent index (e.g., `self._structured_index[agent_id][key] = node_id`).
- Add helpers:
  - `ensure_structured_trace(agent_id) -> dict[str, str]` returning node ids for root/global/sinks_group.
  - `_ensure_structured_node(agent_id, *, key, type, label, parent_id, data) -> FlowNode` (edge_kind="structured", set_current=False)

**Step 3: Re-run the tests**

Run: `cd backend && pytest tests/services/test_flow_service.py -k structured_trace_roots -v`  
Expected: PASS.

---

## Task 3: Steps Parent Resolution (Entrypoint/Global → Folder → File → Function → Steps)

**Files:**
- Modify: `backend/services/flow_service.py`
- Test: `backend/tests/services/test_flow_service.py`

**Step 1: Write failing tests for path construction**

Test that `get_or_create_structured_steps_parent(...)`:
- creates folder nodes for `backend/services/foo.py` in order (`backend`, `backend/services`)
- creates a file node under the deepest folder
- optionally creates function node when `function_name` provided
- always creates a `steps` node under the final structural node
- is idempotent (same inputs return the same `steps` id)

Run: `cd backend && pytest tests/services/test_flow_service.py -k structured_steps_parent -v`  
Expected: FAIL.

**Step 2: Implement `get_or_create_structured_steps_parent`**

Inputs:
- `trace_root_key` (e.g. `entry_point:<fingerprint>` or `global_recon`)
- optional `file_path`
- optional `function_name` + `line_number`

Behavior:
- Root is the structured entrypoint node (or global_recon node).
- Create folder chain from `file_path` segments (excluding file).
- Create `file` node with `data.file_path`.
- Create `function` node with `data.function_name`/`line_number` (optional).
- Create `steps` node and return its id.

**Step 3: Re-run tests**

Run: `cd backend && pytest tests/services/test_flow_service.py -k structured_steps_parent -v`  
Expected: PASS.

---

## Task 4: Populate Structured Entrypoints + Global Sinks From Static Scan

**Files:**
- Modify: `backend/agents/react_agent.py` (scanner/triage path)
- Modify: `backend/services/flow_service.py` (helper API)
- Test: `backend/tests/integration/test_agent_flow_integration.py` (or add a focused new test)

**Step 1: Add helper to populate from candidates**

Add `FlowService.populate_structured_from_candidates(agent_id, candidates)`:
- ensure roots
- for each entrypoint candidate: create structured `entry_point` under `structured_root` keyed by candidate fingerprint; set `data.touched=false`
- for each sink candidate: create `dangerous_sink` under `global_recon → sinks_group`

**Step 2: Wire it into ReAct scan phase**

In `ReActSecurityAgent._build_attack_surface_tree()` after `candidates = attack_surface_service.scan_candidates(...)`:
- call `flow_service.populate_structured_from_candidates(self.id, candidates)`

**Step 3: Add/adjust an integration test**

Run: `cd backend && pytest tests/integration/test_agent_flow_integration.py -k structured_entrypoints -v`  
Expected: PASS with at least one structured entrypoint node present for a fixture repo that has routes.

---

## Task 5: Set Active Structured Root When Starting A Queued Investigation

**Files:**
- Modify: `backend/services/flow_service.py` (context field + setter)
- Modify: `backend/agents/react_agent.py`
- Test: `backend/tests/services/test_flow_service.py`

**Step 1: Add `structured_trace_root_key` to `FlowContext`**

Default is `global_recon`. Provide a setter helper:
- `set_structured_trace_root(agent_id, root_key)`
- `mark_structured_entrypoint_touched(agent_id, entrypoint_fingerprint)`

**Step 2: Update `_maybe_start_next_queued_investigation`**

When dequeuing `task.flow_node_id`:
- look up the candidate node in flow
- if it’s an entrypoint candidate, compute `root_key = entry_point:<attack_surface_candidate_id>` and set it
- else set root to `global_recon`

**Step 3: Add a unit test**

Create a fake flow with:
- a structured entrypoint for fingerprint X
- a scan candidate node that references `attack_surface_candidate_id = X`
Assert that calling the root setter + mark touched updates the structured entrypoint node’s `data.touched`.

Run: `cd backend && pytest tests/services/test_flow_service.py -k structured_root_selection -v`  
Expected: PASS.

---

## Task 6: Attach Tool Nodes + Findings Under Structured “Steps”

**Files:**
- Modify: `backend/services/flow_service.py`
- Modify: `backend/agents/react_agent.py`
- Modify: `backend/services/agent_orchestrator.py`
- Test: `backend/tests/services/test_flow_service.py`

**Step 1: Add `attach_node_to_structured_trace(agent_id, node_id, *, tool_name, args, file_path?, function_name?)`**

Rules:
- Resolve `trace_root_key` from context (default `global_recon`).
- Prefer `file_path` from tool args (`read_file.path`, etc); else fall back to `flow.context.current_file`.
- Get steps parent id via `get_or_create_structured_steps_parent`.
- Create a structured edge from steps → node (`add_edge(..., kind="structured")`).

**Step 2: ReAct agent wiring**

In `_process_tool_calls`, immediately after creating `tool_node`:
- call `flow_service.attach_node_to_structured_trace(...)` for the tool call node.

For findings:
- Update `_create_finding` to `return finding` so the caller can get `finding.id`.
- When adding a flow `finding` node, include `data.finding_id = finding.id`.
- Attach the finding node to structured trace the same way (under steps).

**Step 3: Codex CLI / SDK orchestrator wiring**

In `services/agent_orchestrator.py` where tool nodes are created:
- call the same `attach_node_to_structured_trace` for `tool_node.id`.
- When creating finding nodes, include `finding_id` in node data and attach as well.

**Step 4: Tests**

Add a unit test:
- create structured roots + set root key
- create a tool node (legacy add_node)
- attach it to structured trace
- assert there is exactly one structured edge whose `target == tool_node.id` and whose `source` is a `steps` node.

Run: `cd backend && pytest tests/services/test_flow_service.py -k attach_structured -v`  
Expected: PASS.

---

## Task 7: Frontend – Add “Structured Trace” Diagram Mode

**Files:**
- Modify: `frontend/app/page.tsx`
- Modify: `frontend/hooks/useCallTree.ts`

**Step 1: Extend diagram mode type**

Update `diagramMode` state to include `'structured'` and add an option:
- `<option value="structured">Structured Trace</option>`

Ensure:
- agent selector shows for both `investigation` and `structured`
- route selector only for `calltree`

**Step 2: Render the right visualization**

- `investigation`: keep current span-based TreeLayout behavior when enabled
- `structured`: always render `FlowVisualization` with `variant="structured"`

---

## Task 8: Frontend – FlowVisualization “structured” Variant

**Files:**
- Modify: `frontend/components/FlowVisualization/FlowVisualization.tsx`
- Modify: `frontend/components/FlowVisualization/FlowNodePopover.tsx`
- Test: `frontend/playwright.smoke.spec.ts` (optional small addition) or a new small spec

**Step 1: Update types to accept `edge.kind`**

- Extend FlowEdge type with `kind?: string`
- Add `variant?: 'investigation' | 'calltree' | 'structured'`

**Step 2: Filter nodes/edges for structured view**

When `variant === "structured"`:
- only include edges with `kind === "structured"`
- only include nodes reachable from `structured_root` via those edges (or all nodes referenced by those edges)

When `variant === "investigation"`:
- exclude `kind === "structured"` edges (treat missing kind as legacy)

**Step 3: Default collapse rules**

On first render for structured variant:
- auto-collapse all `steps` nodes
- optionally auto-collapse deep folder subtrees (phase 1 can skip depth-based collapse; steps-only is OK)

**Step 4: Styling**

- Entry points with `data.touched === true` get an accent ring/badge.
- Dangerous sinks keep icon/sign + severity color.

**Step 5: “Open in editor” action**

Plumb a callback from `page.tsx` → `FlowVisualization` → `FlowNodePopover`.
If node has `data.file_path` (or `data.file`), show a button:
- on click: switch to non-flow view and open that file (existing `workspace.selectFile` path).

**Step 6 (optional): Finding focus behavior (Choice B)**

If already in structured mode and a finding is clicked:
- expand ancestors and center on the corresponding finding node id (match by `finding_id`)

---

## Task 9: Verification

**Backend**
- Run: `cd backend && pytest -q`
- Expected: PASS

**Frontend**
- Run: `cd frontend && npm test` (or `npx playwright test`)
- Expected: PASS (at least smoke test)

**Manual sanity**
1. Start an audit.
2. Open Flow view → select “Structured Trace”.
3. Confirm: Global Recon + Entrypoints exist; steps are collapsed; tool calls appear under steps as the audit runs.

---

## Execution Choice

Plan saved. Two execution options:

1. **Subagent-Driven (this session)** – would normally dispatch subagents per task; in Codex we’ll execute tasks sequentially with review checkpoints.
2. **Parallel Session (separate)** – open a new session and run @superpowers:executing-plans against this plan.

Which approach do you want?


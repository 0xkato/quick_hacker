# Post-Scan Contextual Chat (Diagram → Chat) Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** After a scan finishes, let users click any node in the Structured Trace diagram and open the Chat panel with a compact “context pack” (path + relevant findings/tool summaries) so follow-up validation is fast and uses the same provider/model as the scan agent.

**Architecture:** Build the context pack client-side from the Structured Trace subgraph already loaded in the UI, and pass it through the existing `/api/chat/stream` endpoint via `context.flow_context_pack`. The backend extends `get_system_prompt()` to render this pack concisely with hard caps.

**Tech Stack:** Next.js (App Router) + ReactFlow (frontend), FastAPI (backend), Node `node:test` for lightweight frontend unit tests, `pytest` for backend unit tests.

---

## Task 1: Add Context Pack Builder (TDD)

**Files:**
- Create: `frontend/components/FlowVisualization/flowContextPack.js`
- Create: `frontend/components/FlowVisualization/flowContextPack.test.js`

**Step 1: Write failing unit tests (RED)**

Cover:
- `getStructuredSubgraph(flow)` returns only edges with `kind === "structured"` and the connected nodes.
- `buildFlowContextPack(...)` includes:
  - `selected_node` summary
  - `path` (ancestors → selected)
  - `finding` details when `finding_id` is present and matches a Finding
  - hard-capped string fields (no unbounded dumps)

Run:
- `cd frontend && node --test components/FlowVisualization/flowContextPack.test.js`

Expected: FAIL (module/functions not implemented).

**Step 2: Implement minimal builder (GREEN)**

Implement:
- `getStructuredSubgraph(flow)`
- `buildFlowContextPack({ flow, nodeId, findings })`

Re-run:
- `cd frontend && node --test components/FlowVisualization/flowContextPack.test.js`

Expected: PASS.

---

## Task 2: Tighten “Finding” Semantics in Structured Trace (TDD)

**Files:**
- Modify: `frontend/components/FlowVisualization/flowNavigator.js`
- Modify: `frontend/components/FlowVisualization/flowNavigator.test.js`
- Modify: `frontend/components/FlowVisualization/structuredTraceRisk.js`
- Modify: `frontend/components/FlowVisualization/structuredTraceRisk.test.js`

**Step 1: Write failing tests (RED)**

Update tests to assert:
- Navigator “finding” list only includes *actual findings* (nodes with `data.severity` or `data.finding_id`), not `report_finding` tool-call nodes.
- Structured Trace risk becomes `finding` only when an *actual finding* exists, not merely when a node has `type === "finding"`.

Run:
- `cd frontend && node --test components/FlowVisualization/flowNavigator.test.js`
- `cd frontend && node --test components/FlowVisualization/structuredTraceRisk.test.js`

Expected: FAIL.

**Step 2: Implement minimal filtering logic (GREEN)**

Re-run the same tests.

Expected: PASS.

---

## Task 3: Wire “Open in Chat” from Diagram Node Popover

**Files:**
- Modify: `frontend/components/FlowVisualization/FlowNodePopover.tsx`
- Modify: `frontend/components/FlowVisualization/FlowVisualization.tsx`
- Modify: `frontend/app/page.tsx`
- Modify: `frontend/components/ChatPanel/ChatPanel.tsx`
- Modify: `frontend/lib/api.ts`

**Step 1: Add a popover action**

In `FlowNodePopover.tsx`, add a button:
- “Open in Chat” (or “Ask about this”) – calls `onOpenChat(node)`

**Step 2: Build + pass a context pack**

In `FlowVisualization.tsx`:
- On “Open in Chat”, compute pack via `buildFlowContextPack({ flow, nodeId, findings })`
- Call `onOpenChat({ pack, filePath })`

In `frontend/app/page.tsx`:
- Keep `chatFlowContextPack` state.
- When called, optionally open the related file, open Chat panel, and seed Chat input.
- Pass `provider/model` to ChatPanel from `selectedAgent.provider_config` (same provider/model as scan).

In `ChatPanel.tsx`:
- Accept `provider`, `model`, `flowContextPack`, and optional `seedInput`.
- Include `flowContextPack` in `buildContext()`.
- Pass provider/model into `chat.stream(...)`.
- Show a small context indicator and a “Clear” action.

In `frontend/lib/api.ts`:
- Extend `ChatContext` to include `flow_context_pack?: unknown`.

**Step 3: Verify build**

Run:
- `cd frontend && npm run build`

Expected: PASS.

---

## Task 4: Backend Prompt Rendering for Flow Context Pack (TDD)

**Files:**
- Modify: `backend/routers/chat.py`
- Create: `backend/tests/routers/test_chat_flow_context_prompt.py`

**Step 1: Write failing tests (RED)**

Add tests that:
- Provide `context={"flow_context_pack": {...}}` and assert `get_system_prompt()` includes a “Flow Context” section.
- Assert prompt output is capped (e.g., long fields get truncated and don’t explode).

Run:
- `cd backend && pytest -q backend/tests/routers/test_chat_flow_context_prompt.py`

Expected: FAIL.

**Step 2: Implement minimal prompt formatting (GREEN)**

In `get_system_prompt()`:
- Detect `flow_context_pack`
- Render compact sections: path, selected node, finding summary, and key node fields
- Hard-cap at safe lengths per section

Re-run the test.

Expected: PASS.

---

## Task 5: Verification

**Frontend**
- `cd frontend && node --test components/FlowVisualization/flowContextPack.test.js`
- `cd frontend && node --test components/FlowVisualization/flowNavigator.test.js`
- `cd frontend && node --test components/FlowVisualization/structuredTraceRisk.test.js`
- `cd frontend && npm run lint`
- `cd frontend && npm run build`

**Backend**
- `cd backend && pytest -q`


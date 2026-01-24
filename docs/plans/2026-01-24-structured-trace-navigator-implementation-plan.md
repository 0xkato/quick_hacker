# Structured Trace Navigator + Mode Simplification Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make Structured Trace the primary/only diagram view and add a small “jump-to” navigator that lets users click a legend item (e.g. Findings) to see a list of nodes and jump/focus to them in the diagram.

**Architecture:** Keep the existing Flow graph as-is, but simplify the UI so Flow view renders the Structured Trace variant by default. Add a lightweight client-side navigator panel inside `FlowVisualization` that indexes currently-rendered nodes by type (Findings/Sinks/Entrypoints), expands ancestors when jumping, and centers the ReactFlow viewport on the selected node.

**Tech Stack:** Next.js (App Router), ReactFlow, TypeScript, Node’s built-in `node:test` runner for lightweight unit tests.

---

## Task 1: Make Structured Trace the Only Flow Diagram Mode

**Files:**
- Modify: `frontend/app/page.tsx`

**Step 1: Write a failing “build” check (manual)**

There is no dedicated frontend unit test runner wired up, so use `next build` as the correctness gate.

Run: `cd frontend && npm run build`  
Expected: PASS before change (baseline).

**Step 2: Implement mode simplification**

In `frontend/app/page.tsx`:
- Remove the diagram-mode `<select>` (Investigation/Calltree/Structured).
- Remove calltree route selector UI.
- Always render `FlowVisualization` with `variant="structured"` using the selected agent’s flow.

**Step 3: Verify build**

Run: `cd frontend && npm run build`  
Expected: PASS.

---

## Task 2: Add “Jump To” Navigator for Findings/Sinks/Entrypoints (TDD)

**Files:**
- Create: `frontend/components/FlowVisualization/flowNavigator.js`
- Create: `frontend/components/FlowVisualization/flowNavigator.test.js`
- Modify: `frontend/components/FlowVisualization/FlowVisualization.tsx`

**Step 1: Write failing unit tests (RED)**

Create `flowNavigator.test.js` to cover:
- `indexNodesByType(...)` returns only nodes of a given type and sorts deterministically.
- `expandAncestors(collapsedNodes, targetId, edges)` un-collapses all ancestors in a parent-pointer tree.

Run: `cd frontend && node --test components/FlowVisualization/flowNavigator.test.js`  
Expected: FAIL (module/functions not implemented).

**Step 2: Implement minimal navigator helpers (GREEN)**

In `flowNavigator.js` implement:
- `indexNodesByType(nodes, type)` → list of `{ id, label, severity?, file_path? }`
- `expandAncestors(collapsed, targetId, edges)` → new collapsed map with ancestors set to `false`

Re-run: `cd frontend && node --test components/FlowVisualization/flowNavigator.test.js`  
Expected: PASS.

**Step 3: Wire navigator UI into FlowVisualization**

In `FlowVisualization.tsx`:
- Capture ReactFlow instance via `onInit`.
- Add `focusNode(nodeId)` that:
  - expands ancestors via `expandAncestors`
  - centers viewport on the node position (`setCenter`), best-effort.
- Make legend items clickable in `variant === "structured"` for:
  - Findings (`type === "finding"`)
  - Dangerous Sinks (`type === "dangerous_sink"`)
  - Entrypoints (`type === "entry_point"`)
- Clicking a legend item opens a small panel listing matching nodes; clicking a list item focuses the node.

**Step 4: Verify build**

Run: `cd frontend && npm run build`  
Expected: PASS.

---

## Task 3: Verification

**Frontend**
- Run: `cd frontend && node --test components/FlowVisualization/structuredTraceRisk.test.js`
- Run: `cd frontend && node --test components/FlowVisualization/flowNavigator.test.js`
- Run: `cd frontend && npm run lint`
- Run: `cd frontend && npm run build`


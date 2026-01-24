# Structured Trace Diagram (Entrypoint → Folder → File → Function → Steps → Finding)

**Date:** 2026-01-24  
**Status:** Design Complete  
**Author:** Codex (via superpowers:brainstorming)

## Problem

The current investigation visualization often degrades into a mostly-linear chain of tool calls with shallow branching. This makes it hard to mentally track:
- which *entrypoint / route* an investigation step belongs to
- which *folders/files/functions* were involved
- the full path leading to a specific finding (and how it was discovered)

We want a multi-level, collapsible, visually “mentally pleasing” diagram that mirrors the LLM’s audit path with explicit structure.

## Goals

1. **Entrypoint-first hierarchy**: show all entrypoints (static + touched) as first-class roots.
2. **Multi-level structure**: `Entrypoint → Folder(s) → File → Function → Steps → Events → Finding`.
3. **Everything is trackable**: tool calls/results are always represented (but collapsed by default).
4. **Shared nodes supported**: same file/function can appear in multiple entrypoint paths.
5. **User-friendly UI**: collapsible tree, readable spacing, color + sign/icon for dangerous sinks.
6. **Finding focusing**: when already in Structured Trace, clicking a finding auto-expands + centers its path.

## Non-Goals (Phase 1)

- Reconstructing Structured Trace for historical runs from legacy linear flow (optional later).
- Replacing the existing Investigation Flow (span-based) view immediately.
- Perfect DAG canonicalization for shared nodes (Phase 1 duplicates nodes by default).

## Approach (Instrumentation-First)

Structured Trace is built by **explicit instrumentation at event creation time** rather than relying on heuristic reconstruction of the legacy flow chain.

### Core Idea

Maintain “structural” nodes (entrypoints, folders, files, functions, steps) and attach each event node to the correct structural parent using trace metadata.

This prevents the “one node → 1M children” problem and produces a consistent hierarchy regardless of tool-call ordering.

## Data Model

### New/Extended Node Types

Structured Trace adds a small set of structural node types:
- `structured_root` (single root for the Structured Trace tree)
- `global_recon` (pseudo-entrypoint for work not tied to a specific entrypoint)
- `folder`
- `steps` (collapsed container for tool calls/results and other step events)
- `sinks_group` (under Global Recon)

Existing node types remain (and are reused under `steps`), e.g.:
`tool_call`, `tool_result`, `search`, `scan`, `code_read`, `analysis`, `finding`, `dangerous_sink`, `entry_point`, etc.

### Trace Metadata (per node)

Each node emits structured-trace metadata in `node.data`, minimally:
- `trace_root_key`: `entrypoint:<id>` or `global_recon`
- `trace_parent_key`: stable structural key for parent (folder/file/function/steps)
- `trace_kind`: `structural` | `step`
- `shared_key` (optional): stable key used to mark shared nodes across roots
- `touched` (boolean): indicates whether an entrypoint/root was actually used in this run

Additionally for sinks:
- `is_dangerous` / `severity` flags to drive styling (color + icon/sign)

## Backend Design

### Root Construction

When an agent run starts:
1. Create `structured_root` under the run start node.
2. Create `global_recon` under `structured_root`.
3. Create `entry_point` nodes for statically discovered entrypoints under `structured_root` (untouched by default).

### Structural Path Construction

When an event occurs (tool call/result, file read, function discovery, finding, etc.), compute the structural parent chain:

`(EntryPoint | Global Recon) → Folder(s) → File → Function → Steps`

Rules:
- Folder nodes are created on-demand from `file_path` segments.
- File/function nodes are on-demand and keyed by `(root, file_path)` and `(root, file_path, function_name[, line])` respectively (Phase 1 duplicates across roots).
- Each `(root, file/function)` has exactly one `steps` container node.
- All tool nodes are attached under `steps` (collapsed by default in UI).

### Global Sinks Group

Dangerous sinks are represented as normal nodes but are grouped under:

`Global Recon → Sinks (sinks_group) → dangerous_sink`

Sinks remain clickable and include file/line/snippet metadata.

### Finding Linking

Findings emitted by tools must carry enough metadata to locate their structural path:
- prefer using `activation_path` (route/cli/etc) when available
- otherwise fall back to current context (current entrypoint, current file/function)

In Structured Trace, findings attach under the relevant `steps` container.

## Frontend Design

### New Diagram Mode

Add a new Flow diagram mode: **Structured Trace**, alongside:
- Investigation Flow
- Call Tree (FastAPI)

Phase 1 is additive; existing modes remain unchanged.

### Default Presentation

- Render all roots at once: `Global Recon` + all `Entry Points`.
- Default-collapsed:
  - all `steps` nodes
  - deep folder/file subtrees beyond an initial depth threshold (tunable)
- Visually distinguish “touched” entrypoints (badge or accent border).

### Node Interactions

- Clicking a node opens details (existing popover/panel pattern).
- File/function nodes include:
  - “Open in editor” action
  - file path + line number + signature/context (when available)

### Shared Nodes (Phase 1)

Default rendering is **tree-first duplication**:
- If the same file/function appears under multiple roots, it appears multiple times (one per root path).
- Duplicates show a “shared” badge and provide jump links to other occurrences.

### Finding Focus Behavior

User choice: **do not auto-switch views**.
- If the user is already in Structured Trace: clicking a finding auto-expands and centers the path.
- Otherwise: show a small “View in Structured Trace” affordance (no forced navigation).

### Sink Styling

Dangerous sinks are rendered as normal nodes but:
- show an icon/sign
- use severity coloring to be easy to spot

## Rollout Plan

1. **Phase 1 (Ship Additive)**: add Structured Trace mode + backend instrumentation for new runs.
2. **Phase 2 (Optional Backfill)**: add reconstruction/backfill for old runs if needed.
3. **Phase 3 (Replace Later)**: consider making Structured Trace the default if it outperforms legacy views.

## Testing

Backend:
- unit tests verifying structural parent assignment and dedupe behavior
- tests ensuring all tool calls/results are attached under a `steps` container

Frontend:
- Playwright smoke test: Structured Trace mode exists and renders
- collapse/expand behavior works for steps and deep subtrees
- finding click focus works only when already in Structured Trace


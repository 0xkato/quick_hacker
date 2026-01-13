# Investigation Trace System Design

**Date:** 2026-01-13
**Status:** Production-Ready Design
**Authors:** Architecture Design Session

## Executive Summary

This document describes a tree/DAG trace model for the AI security auditing tool that transforms the current flat chronological event stream into a structured investigation narrative. The system enables users to:

- Visualize branching investigations and hypothesis exploration
- Nest tool calls under higher-level spans (e.g., "Investigate route X")
- Collapse/expand subtrees for focused exploration
- Deep-link nodes to artifacts (file snippets, search results, call paths)
- Switch between timeline and tree views

**Key Design Principles:**
- Keep raw chronological ledger (append-only, immutable)
- Add span/artifact structure on top (derived, reconstructable)
- Declarative routing via turn plans (no inference heuristics)
- Incremental rollout with dual-write period

---

## Section A: Proposed Schema

### Enhanced Flow Events

Existing FlowNode events extended with span/artifact tracking:

```python
{
  # Existing fields
  event_type: str,
  event_id: str,
  label: str,
  timestamp: datetime,
  data: dict,

  # NEW: Span tracking
  span_id: str | None,              # Authoritative during dual-write
  parent_span_id: str | None,       # For hierarchy preservation
  hypothesis_id: str | None,        # Links to hypothesis being investigated
  turn_id: int,                     # Monotonic counter per agent session
  correlation_id: str,              # Groups events within same turn

  # NEW: Artifact provenance
  input_artifact_ids: list[str],    # Artifacts consumed by this event
  output_artifact_ids: list[str],   # Artifacts produced by this event

  # NEW: Tool pairing
  tool_invocation_id: str | None    # UUID linking tool_call ↔ tool_result
}
```

### Turn Plan Event (NEW)

Emitted at start of each agent turn, provides investigation preview:

```python
{
  event_type: "turn_plan",
  event_id: str,
  turn_id: int,
  timestamp: datetime,
  stage: str | None,                # For LangGraph: "mapping", "scanning", "triage"

  plan: {
    goal: str,                      # "Investigate SQL injection in /login"

    hypotheses: [
      {
        hypothesis_id: str,         # Stable agent-generated ID
        parent_hypothesis_id: str | None,
        label: str,                 # "Check route handler sanitization"
        state: "open" | "completed" | "discarded",
        activity: "new" | "continuing" | "revisiting" | "queued",
        created_turn_id: int,       # Turn when hypothesis was created

        # NEW: Focus gap (safer than free-text reasoning)
        focus_gap: "reachable" | "dataflow_evidenced" |
                   "source_controlled_input" | "sink_present" |
                   "boundary_crossed" | "not_only_misconfig" |
                   "security_control_bypassed" | "other",
        focus_note: str | None,     # Max 120 chars, "why gap matters"

        # NEW: Span routing (dual-write)
        span_id: str | None,        # Backend-assigned or deterministic
        parent_span_id: str | None
      }
    ],

    selected_hypothesis_id: str,    # Which hypothesis agent works on this turn
    selected_span_id: str           # CRITICAL: Authoritative routing
  }
}
```

### Hypothesis Completed Event (NEW)

Updates span lifecycle:

```python
{
  event_type: "hypothesis_completed",
  hypothesis_id: str,
  span_id: str,
  outcome: "confirmed" | "refuted" | "inconclusive",
  timestamp: datetime
}
```

### Span Table

Persistent span metadata (in-memory or DB):

```python
{
  span_id: str,                    # UUID or deterministic hash
  span_type: "hypothesis" | "hypothesis_visit" | "critic_pass" | "placeholder",
  parent_span_id: str | None,      # For tree hierarchy
  hypothesis_id: str,
  label: str,

  # Lifecycle
  state: "open" | "completed" | "discarded",
  outcome: "confirmed" | "refuted" | "inconclusive" | None,
  created_turn_id: int | None,
  completed_at: datetime | None,

  # Context
  focus_gap: str | None,
  stage: str | None,               # Inherited from turn_plan

  # Containment
  event_ids: list[str],            # Events nested under this span
  artifact_ids: list[str],         # Artifacts produced in this span

  # Metadata
  metadata: dict                   # e.g., {"backfilled": true, "missing_parent_hypothesis": "hyp_x"}
}
```

### Artifact Table

Content-hash deduplicated artifacts:

```python
{
  artifact_id: str,                # SHA256(content) for deduplication
  artifact_type: "file_snippet" | "search_result" | "call_graph" | "tool_output",

  # Content
  content: str | dict,             # Redacted content
  summary: str,                    # 200-char human-readable summary

  # References
  references: {
    file_path: str | None,
    line_start: int | None,
    line_end: int | None
  },

  # Provenance (computed during reconstruction)
  producer_spans: set[str],        # Spans that produced this artifact
  consumer_spans: set[str],        # Spans that consumed this artifact

  created_at: datetime,
  size_bytes: int
}
```

---

## Section B: Branch/Span Creation Rules

### Span Creation Triggers

**1. New Hypothesis** (`activity: "new"`):
```python
# Backend creates span when processing turn_plan
span_id = hyp.span_id or deterministic_span_id(agent_exec_id, hyp.hypothesis_id)
hypothesis_to_span_id[hyp.hypothesis_id] = span_id

# Parent resolution
if hyp.parent_span_id:
    parent_span_id = hyp.parent_span_id
elif hyp.parent_hypothesis_id:
    parent_span_id = hypothesis_to_span_id.get(hyp.parent_hypothesis_id)
else:
    parent_span_id = None

create_span(
    span_id=span_id,
    span_type="hypothesis",
    parent_span_id=parent_span_id,
    hypothesis_id=hyp.hypothesis_id,
    label=hyp.label,
    state=hyp.state,
    focus_gap=hyp.focus_gap,
    created_turn_id=hyp.created_turn_id
)
```

**2. Continuing Hypothesis** (`activity: "continuing"`):
```python
# Reuse existing span, append new events
span_id = hypothesis_to_span_id[hyp.hypothesis_id]
# Events route to this span via turn_plan.selected_span_id
```

**3. Revisiting Hypothesis** (`activity: "revisiting"`):
```python
# Backend decides whether to create visit span
# If gap > 5 turns, create hypothesis_visit span
if turn_gap > 5:
    visit_span_id = deterministic_span_id(
        agent_exec_id, hyp.hypothesis_id, f":visit_turn:{turn_id}"
    )
    create_span(
        span_id=visit_span_id,
        span_type="hypothesis_visit",
        parent_span_id=hypothesis_to_span_id[hyp.hypothesis_id],
        label=f"Revisit: {hyp.label} (turn {turn_id})"
    )
    # Update selected_span_id to point to visit span
else:
    # Use base hypothesis span
```

**4. Critic Pass** (Emitted by critic loop):
```python
# Created from critic_started event
critic_span_id = generate_uuid()
create_span(
    span_id=critic_span_id,
    span_type="critic_pass",
    parent_span_id=hypothesis_span_id,
    label=f"Critic Pass {pass_number}"
)
```

### Tool Call Routing

All tool events inherit span context from turn_plan:

```python
tool_call_event = {
    span_id: turn_plan.selected_span_id,  # Authoritative
    primary_hypothesis_id: turn_plan.selected_hypothesis_id,
    related_hypothesis_ids: [],  # Optional: evidence supports multiple
    tool_invocation_id: generate_uuid(),
    input_artifact_ids: [...],
    output_artifact_ids: [...]
}
```

### LangGraph Stage Integration

DeepAudit nodes emit turn_plan at node entry:

```python
# At start of each LangGraph node
def on_node_enter(node_name: str, state: dict):
    emit_turn_plan(
        stage=node_name,  # "mapping", "scanning", "triage"
        plan=state["current_plan"],
        selected_span_id=state["active_span_id"]
    )
```

---

## Section C: Reconstruction Algorithm (Production-Perfect)

### Core Principle

**Declarative Routing:** Trust `turn_plan.selected_span_id` as source of truth. No gap inference heuristics.

### Routing Priority

```python
# CORRECT priority (visit-preserving):
if event.span_id:
    # Authoritative (dual-write)
    span_id = event.span_id
elif event.parent_span_id and event.parent_span_id in spans:
    # Explicit hierarchy
    span_id = event.parent_span_id
elif current_selected_span:
    # From turn_plan.selected_span_id (time-correct)
    span_id = current_selected_span
elif event.hypothesis_id:
    # Fallback to base hypothesis span
    span_id = hypothesis_to_base_span.get(event.hypothesis_id)
else:
    # Never drop events
    span_id = unattributed_span_id
```

### Single-Pass Streaming Reconstruction

```python
def reconstruct_investigation_dag(
    events: List[Event],
    artifacts: Dict[str, Artifact],
    agent_exec_id: str
) -> Tuple[Dict[str, Span], List[Edge], Dict[str, str]]:
    """Production-perfect single-pass reconstruction."""

    # Defensive sort for WebSocket stability
    sorted_events = sort_events(events)

    spans: Dict[str, Span] = {}
    hypothesis_to_base_span: Dict[str, str] = {}
    event_to_span: Dict[str, str] = {}
    tool_invocation_pairs: Dict[str, List[Event]] = {}

    # Provenance indices (for linear-time cross-links)
    artifact_producer_spans: Dict[str, Set[str]] = defaultdict(set)
    artifact_consumer_spans: Dict[str, Set[str]] = defaultdict(set)

    # Create unattributed span
    unattributed_span_id = deterministic_span_id(agent_exec_id, "UNATTRIBUTED")
    spans[unattributed_span_id] = create_placeholder_span(
        span_id=unattributed_span_id,
        label="Unattributed Events"
    )

    # Current span tracking (updated as we stream)
    current_selected_span: str | None = None
    current_selected_hypothesis_id: str | None = None
    current_turn_plan_stage: str | None = None

    # ========== SINGLE PASS ==========
    for event in sorted_events:

        # === Handle turn_plan ===
        if event.type == "turn_plan":
            current_turn_plan_stage = event.stage
            plan = event.plan

            # Create/update hypothesis spans
            for hyp in plan.hypotheses:
                span_id = ensure_span_exists(
                    hyp, spans, hypothesis_to_base_span,
                    agent_exec_id, current_turn_plan_stage
                )

            # Update current routing
            current_selected_span = plan.selected_span_id or \
                                   hypothesis_to_base_span.get(plan.selected_hypothesis_id)
            current_selected_hypothesis_id = plan.selected_hypothesis_id

            # Ensure selected span exists
            if current_selected_span and current_selected_span not in spans:
                spans[current_selected_span] = create_placeholder_span(
                    span_id=current_selected_span,
                    label=f"(Selected span metadata missing)",
                    stage=current_turn_plan_stage
                )

            # Attach turn_plan event
            span_id = current_selected_span or unattributed_span_id
            spans[span_id].event_ids.append(event.id)
            event_to_span[event.id] = span_id
            continue

        # === Handle hypothesis_completed ===
        if event.type == "hypothesis_completed":
            span_id = event.span_id or hypothesis_to_base_span.get(event.hypothesis_id)
            if span_id and span_id in spans:
                spans[span_id].state = "completed"
                spans[span_id].outcome = event.outcome
                spans[span_id].completed_at = event.timestamp
                spans[span_id].event_ids.append(event.id)
                event_to_span[event.id] = span_id
            continue

        # === Handle other events: priority routing ===
        span_id = route_event_to_span(
            event, current_selected_span, current_selected_hypothesis_id,
            hypothesis_to_base_span, spans, unattributed_span_id,
            current_turn_plan_stage
        )

        # Attach event
        spans[span_id].event_ids.append(event.id)
        if hasattr(event, 'output_artifact_ids') and event.output_artifact_ids:
            spans[span_id].artifact_ids.extend(event.output_artifact_ids)
            # Update provenance index
            for aid in event.output_artifact_ids:
                artifact_producer_spans[aid].add(span_id)

        if hasattr(event, 'input_artifact_ids') and event.input_artifact_ids:
            for aid in event.input_artifact_ids:
                artifact_consumer_spans[aid].add(span_id)

        event_to_span[event.id] = span_id

        # Track tool pairs
        if event.type in ["tool_call", "tool_result"]:
            tool_inv_id = getattr(event, 'tool_invocation_id', None)
            if tool_inv_id:
                if tool_inv_id not in tool_invocation_pairs:
                    tool_invocation_pairs[tool_inv_id] = [None, None]
                idx = 0 if event.type == "tool_call" else 1
                tool_invocation_pairs[tool_inv_id][idx] = event

    # Deduplicate artifacts per span
    for span in spans.values():
        span.artifact_ids = list(dict.fromkeys(span.artifact_ids))

    # Build edges (linear-time)
    edges = build_edges_linear(
        spans, sorted_events, tool_invocation_pairs, event_to_span,
        artifact_producer_spans, artifact_consumer_spans, artifacts
    )

    # Enrich with artifacts
    for span in spans.values():
        span.artifacts = [artifacts[aid] for aid in span.artifact_ids if aid in artifacts]

    # Validation
    assert len(sorted_events) == len(event_to_span), \
        f"Events dropped: {len(sorted_events)} events, {len(event_to_span)} mapped"

    return spans, edges, event_to_span
```

### Edge Construction (Linear-Time)

```python
def build_edges_linear(
    spans: Dict[str, Span],
    events: List[Event],
    tool_invocation_pairs: Dict[str, List[Event]],
    event_to_span: Dict[str, str],
    artifact_producer_spans: Dict[str, Set[str]],
    artifact_consumer_spans: Dict[str, Set[str]],
    artifacts: Dict[str, Artifact]
) -> List[Edge]:
    edges = []

    # 1. Span hierarchy (parent → child)
    for span in spans.values():
        if span.parent_span_id:
            edges.append(Edge(
                id=f"hierarchy_{span.parent_span_id}_{span.span_id}",
                source=span.parent_span_id,
                target=span.span_id,
                edge_type="parent_child"
            ))

    # 2. Containment (span → events, hidden in DAG)
    for event_id, span_id in event_to_span.items():
        edges.append(Edge(
            id=f"contains_{span_id}_{event_id}",
            source=span_id,
            target=event_id,
            edge_type="contains",
            hidden=True
        ))

    # 3. Tool invocation pairs
    for tool_inv_id, (call, result) in tool_invocation_pairs.items():
        if call and result:
            tool_name = call.data.get('tool') if hasattr(call, 'data') else None
            edges.append(Edge(
                id=f"tool_{tool_inv_id}",
                source=call.id,
                target=result.id,
                edge_type="tool_invocation",
                label=tool_name
            ))

    # 4. Artifact provenance (aggregated, time-directional)
    span_pair_artifacts: Dict[Tuple[str, str], Set[str]] = defaultdict(set)

    for aid, prod_spans in artifact_producer_spans.items():
        for prod_span in prod_spans:
            for cons_span in artifact_consumer_spans.get(aid, set()):
                if cons_span != prod_span:
                    # Time-directional check
                    prod_latest = max(
                        e.timestamp for e in events
                        if e.id in spans[prod_span].event_ids
                    )
                    cons_earliest = min(
                        e.timestamp for e in events
                        if e.id in spans[cons_span].event_ids
                    )

                    if prod_latest < cons_earliest:
                        span_pair_artifacts[(prod_span, cons_span)].add(aid)

    # Create bundled edges (threshold: >= 3 artifacts)
    for (prod_span, cons_span), artifact_ids in span_pair_artifacts.items():
        count = len(artifact_ids)

        # Build detailed metadata for popover
        bundled_edges = []
        for aid in artifact_ids:
            prod_event = next((e for e in events
                             if aid in getattr(e, 'output_artifact_ids', [])
                             and event_to_span[e.id] == prod_span), None)
            cons_event = next((e for e in events
                             if aid in getattr(e, 'input_artifact_ids', [])
                             and event_to_span[e.id] == cons_span), None)

            bundled_edges.append({
                "artifact_id": aid,
                "artifact_summary": artifacts.get(aid, {}).get("summary", "(missing)"),
                "producer_span_id": prod_span,
                "producer_event_id": prod_event.id if prod_event else None,
                "consumer_span_id": cons_span,
                "consumer_event_id": cons_event.id if cons_event else None,
                "timestamp": cons_event.timestamp if cons_event else None
            })

        samples = [e["artifact_summary"] for e in bundled_edges[:3]]

        if count >= 3:
            # Bundle edge
            edges.append(Edge(
                id=f"evidence_{prod_span}_{cons_span}",
                source=prod_span,
                target=cons_span,
                edge_type="evidence_link",
                label=f"{count} artifacts",
                style="dashed",
                metadata={
                    "artifact_count": count,
                    "sample_summaries": samples,
                    "bundled_edges": bundled_edges
                }
            ))
        else:
            # Individual edges
            for bundle_data in bundled_edges:
                edges.append(Edge(
                    id=f"evidence_{aid}_{prod_span}_{cons_span}",
                    source=prod_span,
                    target=cons_span,
                    edge_type="evidence_link",
                    label=bundle_data["artifact_summary"][:20] + "...",
                    style="dashed",
                    metadata=bundle_data
                ))

    # 5. Sequential within span (hidden in DAG, shown in timeline)
    for span in spans.values():
        for i in range(len(span.event_ids) - 1):
            edges.append(Edge(
                id=f"seq_{span.event_ids[i]}_{span.event_ids[i+1]}",
                source=span.event_ids[i],
                target=span.event_ids[i+1],
                edge_type="sequential",
                hidden=True
            ))

    return edges
```

### Validation Invariants

```python
# Ship-blocker assertions:
assert len(events) == len(event_to_span), "Events dropped"
assert all(span.parent_span_id in spans or span.parent_span_id is None
          for span in spans.values()), "Missing parent spans"
assert all(len(pair) == 2 and all(pair)
          for pair in tool_invocation_pairs.values()), "Incomplete tool pairs"
```

---

## Section D: UI Blueprint

### Node Types

**1. Hypothesis Span Node**:
```typescript
interface HypothesisNode {
  type: "hypothesis" | "hypothesis_visit"
  data: {
    hypothesis_id: string
    label: string
    state: "open" | "completed" | "discarded"
    outcome: "confirmed" | "refuted" | "inconclusive" | null
    focus_gap: string
    focus_note: string | null
    event_count: number
    artifact_count: number
    is_collapsed: boolean
  }
  style: {
    border: outcome-based color
    badge: focus_gap icon
  }
}
```

**2. Critic Pass Node**:

Source-of-truth mapping:
- `critic_started` → creates node (span)
- `critic_output` → populates evidence_gaps, recommended_actions
- `critic_decision` → sets decision + styling
- `critic_completed` → marks finalized

```typescript
interface CriticPassNode {
  type: "critic_pass"
  data: {
    span_id: string
    parent_hypothesis_id: string
    pass_number: 1 | 2 | 3
    decision: "READY_FOR_TRIAGE" | "CONTINUE" | "DISCARD" | "MARK_SPECULATIVE"
    evidence_gaps: Array<{
      checklist_item: string
      blocking: boolean
      criticality: "HIGH" | "MEDIUM" | "LOW"
    }>
    recommended_actions: Array<{
      tool: "ReadFileTool" | "RipgrepTool" | "CallGraphTool" | "GetRoutesTool",
      args: object
    }>
    confidence_delta: number
  }
}
```

Decision label mapping:
```typescript
const DECISION_UI_MAP = {
  "READY_FOR_TRIAGE": { label: "READY_TO_REPORT", color: "green" },
  "CONTINUE": { label: "CONTINUE", color: "yellow" },
  "DISCARD": { label: "STOP (False Positive)", color: "red" },
  "MARK_SPECULATIVE": { label: "SPECULATIVE", color: "gray" }
}
```

### Layout Modes

**1. Hypothesis Tree** (Default):
- Hypothesis spans at L0, L1, L2 (nested by parent_span_id)
- Visit/critic spans indent under parent
- Events collapsed by default
- Vertical tree layout

**2. DAG View with Swimlanes**:
- Stage-based swimlanes (mapping, scanning, triage)
- Evidence edges cross swimlanes horizontally
- Stage derived from `span.stage` (O(S) lookup)

```python
# Stage inheritance during reconstruction
if span_type in ["critic_pass", "hypothesis_visit"]:
    parent_span = spans.get(parent_span_id)
    if parent_span and parent_span.stage:
        spans[span_id].stage = parent_span.stage
    elif current_turn_plan_stage:
        spans[span_id].stage = current_turn_plan_stage
```

**3. Timeline View**:
- Chronological events on X-axis
- Hypothesis spans as horizontal bands
- Sequential edges shown

### Interactions

**Click Interactions**:
- Hypothesis node → Details panel (outcome, gaps, events, artifacts)
- Tool call/result → Popup with args + result
- Artifact → Open in Monaco at line_start
- Evidence edge → Highlight producer/consumer, show artifact list
- Bundled edge (>= 3 artifacts) → Popover with expandable list

**Keyboard Shortcuts** (Scoped):
```typescript
// Only active when Flow panel focused
// Don't override Monaco shortcuts
{
  "Cmd/Ctrl + F": "Focus search",
  "Cmd/Ctrl + G": "Next match",
  "Escape": "Clear search",
  "E": "Expand all",
  "C": "Collapse all",
  "T": "Toggle timeline",
  "Space": "Toggle node collapse"
}
```

**Search/Filter**:
- Syntax: `type:hypothesis`, `gap:dataflow`, `file:auth.py`, `outcome:confirmed`
- Real-time highlighting
- Fit view to matches

### Performance Optimizations

**Virtual Rendering** (>500 nodes):
```typescript
const visibleNodes = nodes.filter(node =>
  isInViewport(node.position, viewport, BUFFER_SIZE)
)
```

**Incremental Updates** (Neighbor-aware):
```typescript
// When new events arrive:
// 1. Identify affected spans (containment + artifact provenance neighbors)
// 2. Reconstruct affected subgraph
// 3. Merge edges, preserving unaffected
// 4. Fallback: full rebuild if update > 200 events
```

**Edge Bundling** (Threshold >= 3):
```typescript
// Bundle evidence edges between same span pair
// Store full metadata for popover expansion
```

### Empty/Error States

- No events: "Agent hasn't started"
- Agent running: "Waiting for first hypothesis"
- WebSocket disconnected: "Reconnecting..." + Retry button
- Partial reconstruction: "Some spans missing metadata" (info banner)
- Missing parent: "Tree structure incomplete" (warning badge)

### Accessibility

- Keyboard navigation (Tab order: search → filters → nodes)
- ARIA labels: `"Hypothesis: X. State: completed. 12 events"`
- Screen reader announcements on search/collapse
- Focus indicators on nodes

---

## Section E: Incremental Rollout Plan + Risks

### Rollout Strategy: Dual-Write Period (2-4 weeks)

**Phase 1: Backend Implementation (Week 1-2)**

Deploy new event types:
- Add `span_id`, `parent_span_id`, `hypothesis_id` to FlowNode
- Add `input_artifact_ids`, `output_artifact_ids` to tool events
- Implement `turn_plan` emission at start of each turn
- Implement `hypothesis_completed` lifecycle events
- Add `selected_span_id` to turn plans

Dual-write mode:
```python
# Emit both old (backward compatible) and new (span-based) formats
def emit_event(event_type, data, span_id=None, artifact_ids=None):
    # Old format
    flow_service.add_node(agent_id, event_type, data)

    # New format (optional fields)
    if span_id or artifact_ids:
        flow_service.add_node(
            agent_id, event_type, data,
            span_id=span_id,
            output_artifact_ids=artifact_ids
        )
```

**Phase 2: UI Feature Flag (Week 2-3)**

Frontend supports both views:
```typescript
const useSpanBasedFlow = useFeatureFlag('span_based_flow_visualization')

return useSpanBasedFlow ?
  <SpanBasedFlowVisualization /> :
  <LegacyFlowVisualization />
```

Users can toggle between legacy (chronological) and beta (tree).

**Phase 3: Default Switchover (Week 3-4)**

- Make span-based view default
- Keep legacy view accessible via toggle
- Monitor rendering bugs, performance

**Phase 4: Deprecation (Week 5+)**

- Remove legacy view after 2 weeks with no critical bugs
- Stop dual-writing old format
- Clean up deprecated fields

### Migration for Existing Sessions

**Best-Effort Backfill**:
```python
def backfill_spans_for_legacy_session(agent_id: str):
    """Reconstruct spans from legacy chronological events."""
    # Heuristic: group by file/function
    # Create one hypothesis per file
    # Mark with metadata.backfilled = true
    # Limitations:
    # - No nested hypotheses
    # - No critic passes
    # - No artifact provenance
```

**Legacy Badge**: Sessions show "(Legacy Data)" banner.

### Risks + Mitigations

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Reconstruction breaks on partial streams | Incomplete trees | Medium | Placeholders for missing spans; validation assertions |
| Out-of-order WebSocket delivery | Misrouted events | Medium | Defensive sort by timestamp; 500ms buffer |
| Performance degradation (>1000 events) | UI freezes | High | Virtual rendering; incremental updates; lazy-load |
| Dual-write memory overhead | OOM on long sessions | Low | TTL on old events (7 days); compression |
| Artifact deduplication creates wrong cross-links | Incorrect evidence edges | Medium | Set-based producers; time-directional validation |
| Missing turn_plans in DeepAudit | UNATTRIBUTED events | High | Emit turn_plan at every LangGraph node |
| Backward compatibility breaks | Crashes on legacy data | Low | Keep legacy viewer; format detection |

### Success Metrics

**Week 2 (Beta)**:
- 90% of sessions emit span_id on all events
- Reconstruction succeeds for 95% of sessions
- <5% "confusing UI" reports

**Week 4 (Default)**:
- P95 reconstruction time <200ms (500 events)
- Zero crashes related to spans
- 90% incremental updates working

**Week 6 (Deprecation)**:
- <1% users using legacy view
- No critical bugs
- Memory usage within 10% baseline

### Rollback Plan

**Triggers**:
- >5% sessions fail reconstruction
- >10% "missing events" reports
- P95 render time >2s
- Memory usage +30%

**Actions**:
1. Immediate: Flip feature flag to legacy default
2. Within 24h: Fix bug
3. Deploy hotfix, test on staging
4. Re-enable gradually (10% → 50% → 100%)

---

## Appendix: Production Requirements Checklist

### Backend
- [ ] Turn plan emission at start of every agent turn
- [ ] Span_id generation (deterministic or UUID)
- [ ] Artifact provenance tracking (input/output IDs)
- [ ] Tool invocation ID pairing
- [ ] Hypothesis lifecycle events
- [ ] Stage tracking for LangGraph nodes

### Reconstruction
- [ ] Single-pass streaming algorithm
- [ ] Declarative routing via selected_span_id
- [ ] Placeholder span creation for missing metadata
- [ ] Linear-time artifact cross-links
- [ ] Time-directional evidence edges
- [ ] Validation assertions (no dropped events)

### UI
- [ ] Hypothesis/critic/visit node types
- [ ] Stage-based swimlanes
- [ ] Collapse/expand subtrees
- [ ] Search/filter with keyboard shortcuts
- [ ] Artifact deep-linking to Monaco
- [ ] Bundled evidence edges (>= 3 threshold)
- [ ] Empty/error states
- [ ] Accessibility (ARIA labels, keyboard nav)

### Rollout
- [ ] Dual-write period (2-4 weeks)
- [ ] Feature flag toggle
- [ ] Legacy session backfill
- [ ] Performance monitoring (P95 <200ms)
- [ ] Memory monitoring (within 10% baseline)
- [ ] Rollback trigger thresholds defined

---

**End of Design Document**

*Generated: 2026-01-13*

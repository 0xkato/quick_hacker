"""
Reconstruction Service - Transforms flat event streams into structured DAGs.

Implements single-pass streaming reconstruction algorithm with declarative routing.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Any, Set
from collections import defaultdict
import logging

from models.investigation_trace import (
    Span,
    SpanType,
    SpanState,
    FocusGap,
    Artifact,
)

logger = logging.getLogger(__name__)


@dataclass
class Edge:
    """
    Investigation DAG edge.

    Represents relationships between spans (hierarchy) or spans and artifacts (provenance).
    """
    id: str
    source: str  # span_id or artifact_id
    target: str  # span_id or artifact_id
    edge_type: str  # "parent_child", "produces", "consumes"

    # Optional fields
    label: Optional[str] = None
    style: Optional[str] = None
    hidden: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


def deterministic_span_id(agent_exec_id: str, suffix: str) -> str:
    """
    Generate deterministic span ID.

    Args:
        agent_exec_id: Agent execution ID
        suffix: Span-specific suffix (e.g., "hyp__hyp-1", "unattributed")

    Returns:
        Deterministic span ID: "{agent_exec_id}__{suffix}"
    """
    return f"{agent_exec_id}__{suffix}"


class ReconstructionService:
    """
    Reconstruction service for investigation traces.

    Transforms flat event streams into structured DAGs using:
    - Single-pass streaming algorithm (O(n))
    - Declarative routing via turn plans
    - Priority-based event attachment
    """

    def reconstruct_investigation_dag(
        self,
        events: List[Dict],
        artifacts: Dict[str, Artifact],
        agent_exec_id: str
    ) -> Tuple[Dict[str, Span], List[Edge], Dict[str, str]]:
        """
        Reconstruct investigation DAG from flat event stream.

        Algorithm:
        1. Sort events defensively by timestamp (WebSocket stability)
        2. Create unattributed span (catch-all for orphan events)
        3. Single pass through events:
           - If type="turn_plan": create hypothesis spans, update routing
           - Else: route event to span via priority rules, attach event
        4. Build edges from span hierarchy
        5. Return (spans, edges, event_to_span)

        Args:
            events: Flat list of events (FlowNode-like dicts)
            artifacts: Artifact registry (for future provenance)
            agent_exec_id: Agent execution ID for deterministic span IDs

        Returns:
            Tuple of (spans_dict, edges_list, event_to_span_mapping)
        """
        # Step 1: Sort events defensively by timestamp
        sorted_events = sorted(events, key=lambda e: e.get("timestamp", ""))

        # Step 2: Create data structures
        spans: Dict[str, Span] = {}
        hypothesis_to_base_span: Dict[str, str] = {}  # hypothesis_id -> base span_id
        event_to_span: Dict[str, str] = {}  # event_id -> span_id

        # Step 3: Create unattributed span (deterministic ID)
        unattributed_span_id = deterministic_span_id(agent_exec_id, "unattributed")
        unattributed_span = Span(
            span_id=unattributed_span_id,
            span_type=SpanType.PLACEHOLDER,
            hypothesis_id="unattributed",
            label="Unattributed Events",
            state=SpanState.OPEN,
            parent_span_id=None,
        )
        spans[unattributed_span_id] = unattributed_span

        # Step 4: Track routing context
        current_selected_span: Optional[str] = None
        current_selected_hypothesis_id: Optional[str] = None
        current_stage: Optional[str] = None

        # Step 4b: Track artifact provenance
        artifact_producer_spans: Dict[str, Set[str]] = defaultdict(set)
        artifact_consumer_spans: Dict[str, Set[str]] = defaultdict(set)

        # Step 5: Single pass through events
        for event in sorted_events:
            event_id = event.get("id")
            event_type = event.get("type")
            event_data = event.get("data", {})

            # CRITICAL: Validate event_id exists
            if not event_id:
                logger.error("Event missing 'id' field, skipping: %s", event)
                continue

            if event_type == "turn_plan":
                # CRITICAL: Validate turn_plan data structure
                if not isinstance(event_data, dict):
                    logger.error("turn_plan event has invalid data structure (not dict), skipping event_id=%s", event_id)
                    continue

                hypotheses_data = event_data.get("hypotheses")
                if not isinstance(hypotheses_data, list):
                    logger.error("turn_plan event has invalid hypotheses (not list), skipping event_id=%s", event_id)
                    continue

                # Create hypothesis spans and update routing
                turn_id = event_data.get("turn_id")
                goal = event_data.get("goal", "")
                stage = event_data.get("stage")
                selected_hypothesis_id = event_data.get("selected_hypothesis_id")
                selected_span_id = event_data.get("selected_span_id")

                current_stage = stage
                current_selected_hypothesis_id = selected_hypothesis_id
                current_selected_span = selected_span_id

                # Create spans for each hypothesis
                for hyp_data in hypotheses_data:
                    hypothesis_id = hyp_data.get("hypothesis_id")
                    parent_hypothesis_id = hyp_data.get("parent_hypothesis_id")

                    # Deterministic span ID
                    span_id = deterministic_span_id(agent_exec_id, f"hyp__{hypothesis_id}")

                    # CRITICAL: Check for duplicate span_id (silent overwrite prevention)
                    if span_id in spans:
                        logger.warning("Span ID already exists, skipping duplicate creation: span_id=%s, hypothesis_id=%s", span_id, hypothesis_id)
                        continue

                    # Track hypothesis -> base span mapping
                    hypothesis_to_base_span[hypothesis_id] = span_id

                    # Determine parent span ID
                    parent_span_id = None
                    if parent_hypothesis_id:
                        parent_span_id = hypothesis_to_base_span.get(parent_hypothesis_id)

                    # Parse state and activity
                    state_str = hyp_data.get("state", "active")
                    activity_str = hyp_data.get("activity", "new")

                    # Map state string to SpanState
                    if state_str == "active":
                        span_state = SpanState.OPEN
                    elif state_str == "completed":
                        span_state = SpanState.COMPLETED
                    elif state_str == "discarded":
                        span_state = SpanState.DISCARDED
                    else:
                        span_state = SpanState.OPEN

                    # Parse focus_gap
                    focus_gap_str = hyp_data.get("focus_gap")
                    focus_gap = None
                    if focus_gap_str:
                        try:
                            focus_gap = FocusGap(focus_gap_str)
                        except ValueError:
                            focus_gap = FocusGap.OTHER

                    # Create span
                    span = Span(
                        span_id=span_id,
                        span_type=SpanType.HYPOTHESIS,
                        hypothesis_id=hypothesis_id,
                        label=hyp_data.get("label", ""),
                        state=span_state,
                        parent_span_id=parent_span_id,
                        created_turn_id=turn_id,
                        focus_gap=focus_gap,
                        focus_note=hyp_data.get("focus_note"),
                        stage=stage,
                        event_ids=[],
                        artifact_ids=[],
                    )
                    spans[span_id] = span

                # Attach turn_plan event to selected span
                if current_selected_span and current_selected_span in spans:
                    spans[current_selected_span].event_ids.append(event_id)
                    event_to_span[event_id] = current_selected_span
                elif unattributed_span_id in spans:
                    # Fallback to unattributed
                    spans[unattributed_span_id].event_ids.append(event_id)
                    event_to_span[event_id] = unattributed_span_id

            else:
                # Route event to span
                target_span_id = self._route_event_to_span(
                    event=event,
                    current_selected_span=current_selected_span,
                    current_selected_hypothesis_id=current_selected_hypothesis_id,
                    hypothesis_to_base_span=hypothesis_to_base_span,
                    unattributed_span_id=unattributed_span_id
                )

                # Attach event to span
                if target_span_id in spans:
                    spans[target_span_id].event_ids.append(event_id)
                    event_to_span[event_id] = target_span_id

                    # Track artifact provenance
                    output_artifact_ids = event.get("output_artifact_ids", [])
                    for aid in output_artifact_ids:
                        spans[target_span_id].artifact_ids.append(aid)
                        artifact_producer_spans[aid].add(target_span_id)

                    input_artifact_ids = event.get("input_artifact_ids", [])
                    for aid in input_artifact_ids:
                        artifact_consumer_spans[aid].add(target_span_id)

        # Step 6: Deduplicate artifact_ids in spans
        for span in spans.values():
            span.artifact_ids = list(dict.fromkeys(span.artifact_ids))

        # Step 6.5: Fallback - if only unattributed span exists, create tool-call-based spans
        if len(spans) == 1 and unattributed_span_id in spans:
            self._create_fallback_tool_spans(
                unattributed_span=spans[unattributed_span_id],
                sorted_events=sorted_events,
                spans=spans,
                event_to_span=event_to_span,
                agent_exec_id=agent_exec_id
            )

        # Step 7: Build edges
        edges = self._build_edges(
            spans=spans,
            artifact_producer_spans=artifact_producer_spans,
            artifact_consumer_spans=artifact_consumer_spans,
            artifacts=artifacts,
            event_to_span=event_to_span,
            sorted_events=sorted_events
        )

        return spans, edges, event_to_span

    def _route_event_to_span(
        self,
        event: Dict,
        current_selected_span: Optional[str],
        current_selected_hypothesis_id: Optional[str],
        hypothesis_to_base_span: Dict[str, str],
        unattributed_span_id: str
    ) -> str:
        """
        Route event to span using priority rules.

        Priority:
        1. Explicit span_id in event
        2. current_selected_span from turn plan
        3. Hypothesis fallback (if event has hypothesis_id)
        4. Unattributed span (catch-all)

        Args:
            event: Event to route
            current_selected_span: Currently selected span from turn plan
            current_selected_hypothesis_id: Currently selected hypothesis
            hypothesis_to_base_span: Mapping from hypothesis_id to base span_id
            unattributed_span_id: Fallback span ID

        Returns:
            Target span ID for event attachment
        """
        # Priority 1: Explicit span_id
        explicit_span_id = event.get("span_id")
        if explicit_span_id:
            return explicit_span_id

        # Priority 2: current_selected_span
        if current_selected_span:
            return current_selected_span

        # Priority 3: Hypothesis fallback
        event_hypothesis_id = event.get("hypothesis_id")
        if event_hypothesis_id and event_hypothesis_id in hypothesis_to_base_span:
            return hypothesis_to_base_span[event_hypothesis_id]

        # Priority 4: Unattributed span
        return unattributed_span_id

    def _build_edges(
        self,
        spans: Dict[str, Span],
        artifact_producer_spans: Dict[str, Set[str]],
        artifact_consumer_spans: Dict[str, Set[str]],
        artifacts: Dict[str, Artifact],
        event_to_span: Dict[str, str],
        sorted_events: List[Dict]
    ) -> List[Edge]:
        """
        Build span hierarchy and artifact provenance edges.

        Creates two types of edges:
        1. parent_child: From span.parent_span_id relationships
        2. evidence_link: From artifact provenance (producer -> consumer)

        Args:
            spans: Spans dict
            artifact_producer_spans: Mapping of artifact_id -> producer span_ids
            artifact_consumer_spans: Mapping of artifact_id -> consumer span_ids
            artifacts: Artifacts dict
            event_to_span: Mapping of event_id -> span_id
            sorted_events: Sorted events list (for timestamp checks)

        Returns:
            List of edges
        """
        edges: List[Edge] = []

        # 1. Span hierarchy edges (parent_child)
        for span_id, span in spans.items():
            if span.parent_span_id:
                # IMPORTANT: Validate parent exists before creating edge
                if span.parent_span_id not in spans:
                    logger.warning("Parent span does not exist, skipping edge creation: parent_span_id=%s, child_span_id=%s", span.parent_span_id, span_id)
                    continue

                edge_id = f"edge_{span.parent_span_id}_to_{span_id}"
                edge = Edge(
                    id=edge_id,
                    source=span.parent_span_id,
                    target=span_id,
                    edge_type="parent_child",
                    label="parent_child",
                )
                edges.append(edge)

        # 2. Artifact provenance edges (evidence_link)
        span_pair_artifacts: Dict[Tuple[str, str], Set[str]] = defaultdict(set)

        for aid, prod_spans in artifact_producer_spans.items():
            for prod_span in prod_spans:
                for cons_span in artifact_consumer_spans.get(aid, set()):
                    if cons_span != prod_span:
                        # Time-directional check
                        prod_events = [e for e in sorted_events if event_to_span.get(e.get("id")) == prod_span]
                        cons_events = [e for e in sorted_events if event_to_span.get(e.get("id")) == cons_span]

                        if prod_events and cons_events:
                            prod_latest = max(e.get("timestamp", "") for e in prod_events)
                            cons_earliest = min(e.get("timestamp", "") for e in cons_events)

                            if prod_latest < cons_earliest:
                                span_pair_artifacts[(prod_span, cons_span)].add(aid)

        # Create evidence edges
        for (prod_span, cons_span), artifact_ids in span_pair_artifacts.items():
            count = len(artifact_ids)

            if count >= 3:
                # Bundle edge
                edges.append(Edge(
                    id=f"evidence_{prod_span}_{cons_span}",
                    source=prod_span,
                    target=cons_span,
                    edge_type="evidence_link",
                    label=f"{count} artifacts",
                    style="dashed"
                ))
            else:
                # Individual edges
                for aid in artifact_ids:
                    artifact = artifacts.get(aid)
                    if artifact and artifact.summary:
                        summary = artifact.summary[:20] + "..." if len(artifact.summary) > 20 else artifact.summary
                    else:
                        summary = "(missing)"

                    edges.append(Edge(
                        id=f"evidence_{aid}_{prod_span}_{cons_span}",
                        source=prod_span,
                        target=cons_span,
                        edge_type="evidence_link",
                        label=summary,
                        style="dashed"
                    ))

        return edges

    def _create_fallback_tool_spans(
        self,
        unattributed_span: Span,
        sorted_events: List[Dict],
        spans: Dict[str, Span],
        event_to_span: Dict[str, str],
        agent_exec_id: str
    ):
        """
        Fallback algorithm: Create spans from tool_call groupings with file-based hierarchy.

        When no turn_plan events exist, creates hierarchy:
        - Root span: "Investigation"
        - File spans: One per unique file being analyzed
        - Tool spans: Grouped under their target file

        Args:
            unattributed_span: The single unattributed span
            sorted_events: All events sorted by timestamp
            spans: Spans dictionary to modify
            event_to_span: Event mapping to update
            agent_exec_id: Agent execution ID
        """
        # Update unattributed span to be the root
        unattributed_span.label = "Investigation Root"
        unattributed_span.span_type = SpanType.HYPOTHESIS
        unattributed_span.event_ids = []  # Clear, will reassign

        # Track file spans for grouping
        file_spans: Dict[str, str] = {}  # file_path -> span_id
        file_span_counter = 0

        # Group tool_call with their results
        tool_span_counter = 0
        pending_tool_call = None
        pending_tool_call_data = None

        for event in sorted_events:
            event_id = event.get("id")
            event_type = event.get("type")
            event_data = event.get("data", {})

            if event_type == "tool_call":
                tool_span_counter += 1
                tool_name = event_data.get("tool_name", "unknown_tool")

                # Extract file path from tool arguments
                file_path = None
                tool_input = event_data.get("tool_input", {})
                if isinstance(tool_input, dict):
                    file_path = tool_input.get("file_path") or tool_input.get("path")

                # Determine parent span (file span or root)
                parent_span_id = unattributed_span.span_id
                if file_path:
                    # Get or create file span
                    if file_path not in file_spans:
                        file_span_counter += 1
                        file_span_id = deterministic_span_id(agent_exec_id, f"file_{file_span_counter}")

                        # Extract just filename for label
                        filename = file_path.split('/')[-1] if '/' in file_path else file_path

                        file_span = Span(
                            span_id=file_span_id,
                            span_type=SpanType.HYPOTHESIS,
                            hypothesis_id=f"file_{file_span_counter}",
                            label=f"📄 {filename}",
                            state=SpanState.OPEN,
                            parent_span_id=unattributed_span.span_id,
                            event_ids=[],
                            artifact_ids=[],
                        )
                        spans[file_span_id] = file_span
                        file_spans[file_path] = file_span_id

                    parent_span_id = file_spans[file_path]

                # Create tool span
                tool_span_id = deterministic_span_id(agent_exec_id, f"tool_{tool_span_counter}")
                tool_span = Span(
                    span_id=tool_span_id,
                    span_type=SpanType.HYPOTHESIS,
                    hypothesis_id=f"tool_{tool_span_counter}",
                    label=f"{tool_name}",
                    state=SpanState.OPEN,
                    parent_span_id=parent_span_id,
                    event_ids=[event_id],
                    artifact_ids=[],
                )
                spans[tool_span_id] = tool_span
                event_to_span[event_id] = tool_span_id

                # Track for result pairing
                pending_tool_call = tool_span_id
                pending_tool_call_data = {"file_path": file_path}

            elif event_type == "tool_result":
                # Attach to pending tool call if exists
                if pending_tool_call and pending_tool_call in spans:
                    spans[pending_tool_call].event_ids.append(event_id)
                    event_to_span[event_id] = pending_tool_call

                    # Mark as completed
                    spans[pending_tool_call].state = SpanState.COMPLETED

                    # Check for success/error
                    if event_data.get("is_error"):
                        spans[pending_tool_call].label += " ❌"
                    else:
                        spans[pending_tool_call].label += " ✓"

                    # Mark parent file span as completed if exists
                    if pending_tool_call_data and pending_tool_call_data.get("file_path"):
                        file_path = pending_tool_call_data["file_path"]
                        if file_path in file_spans:
                            file_span_id = file_spans[file_path]
                            if file_span_id in spans:
                                spans[file_span_id].state = SpanState.COMPLETED

                    pending_tool_call = None
                    pending_tool_call_data = None
                else:
                    # Orphan result - attach to root
                    unattributed_span.event_ids.append(event_id)
                    event_to_span[event_id] = unattributed_span.span_id

            else:
                # Other events (llm_request, finding, etc.) - attach to root
                unattributed_span.event_ids.append(event_id)
                event_to_span[event_id] = unattributed_span.span_id


# Export global instance
reconstruction_service = ReconstructionService()

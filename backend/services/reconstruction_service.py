"""
Reconstruction Service - Transforms flat event streams into structured DAGs.

Implements single-pass streaming reconstruction algorithm with declarative routing.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime

from models.investigation_trace import (
    Span,
    SpanType,
    SpanState,
    SpanOutcome,
    FocusGap,
    HypothesisState,
    HypothesisActivity,
    HypothesisInfo,
    TurnPlan,
    Artifact,
)


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

        # Step 5: Single pass through events
        for event in sorted_events:
            event_id = event.get("id")
            event_type = event.get("type")
            event_data = event.get("data", {})

            if event_type == "turn_plan":
                # Create hypothesis spans and update routing
                turn_id = event_data.get("turn_id")
                goal = event_data.get("goal", "")
                stage = event_data.get("stage")
                hypotheses_data = event_data.get("hypotheses", [])
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

        # Step 6: Build edges
        edges = self._build_edges(spans)

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

    def _build_edges(self, spans: Dict[str, Span]) -> List[Edge]:
        """
        Build span hierarchy edges.

        Creates parent_child edges from span.parent_span_id relationships.

        Args:
            spans: Spans dict

        Returns:
            List of edges
        """
        edges: List[Edge] = []

        for span_id, span in spans.items():
            if span.parent_span_id:
                edge_id = f"edge_{span.parent_span_id}_to_{span_id}"
                edge = Edge(
                    id=edge_id,
                    source=span.parent_span_id,
                    target=span_id,
                    edge_type="parent_child",
                    label="parent_child",
                )
                edges.append(edge)

        return edges


# Export global instance
reconstruction_service = ReconstructionService()

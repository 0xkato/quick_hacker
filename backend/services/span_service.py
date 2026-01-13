"""
Span Service - Manages investigation spans.

Provides CRUD operations for spans and maintains per-agent span stores.
"""

import hashlib
from collections import defaultdict
from datetime import datetime
from typing import Optional
from models.investigation_trace import (
    Span, SpanType, SpanState, SpanOutcome, FocusGap
)


def generate_deterministic_span_id(
    agent_exec_id: str,
    hypothesis_id: str,
    suffix: str = ""
) -> str:
    """
    Generate deterministic span ID.

    Uses SHA1 hash of (agent_exec_id, hypothesis_id, suffix) for stable IDs
    that survive reconstruction.

    Args:
        agent_exec_id: Agent execution identifier
        hypothesis_id: Hypothesis identifier
        suffix: Optional suffix for visit spans (e.g., ":visit_turn:10")

    Returns:
        Deterministic span ID like "span_a1b2c3d4e5f67890"

    Examples:
        >>> generate_deterministic_span_id("agent_1", "hyp_1")
        "span_a1b2c3d4e5f67890"

        >>> generate_deterministic_span_id("agent_1", "hyp_1", ":visit_turn:10")
        "span_f0e1d2c3b4a59687"
    """
    key = f"{agent_exec_id}:{hypothesis_id}{suffix}"
    hash_obj = hashlib.sha1(key.encode('utf-8'))
    hash_hex = hash_obj.hexdigest()[:16]
    return f"span_{hash_hex}"


class SpanService:
    """
    Manages investigation spans for agents.

    Spans are stored in-memory per agent.
    """

    def __init__(self):
        # agent_id -> {span_id -> Span}
        self._spans: dict[str, dict[str, Span]] = defaultdict(dict)

    def create_span(
        self,
        agent_id: str,
        span_id: str,
        span_type: SpanType,
        hypothesis_id: str,
        label: str,
        state: SpanState,
        parent_span_id: Optional[str] = None,
        focus_gap: Optional[FocusGap] = None,
        focus_note: Optional[str] = None,
        stage: Optional[str] = None,
        created_turn_id: Optional[int] = None
    ) -> Span:
        """
        Create a new span.

        Args:
            agent_id: Agent identifier
            span_id: Unique span identifier
            span_type: Type of span (hypothesis, visit, critic, placeholder)
            hypothesis_id: Hypothesis this span investigates
            label: Human-readable label
            state: Initial state (open, completed, discarded)
            parent_span_id: Optional parent for hierarchy
            focus_gap: Evidence gap being investigated
            focus_note: Optional note (max 120 chars)
            stage: Optional LangGraph stage
            created_turn_id: Turn when span was created

        Returns:
            Created Span
        """
        span = Span(
            span_id=span_id,
            span_type=span_type,
            hypothesis_id=hypothesis_id,
            label=label,
            state=state,
            parent_span_id=parent_span_id,
            focus_gap=focus_gap,
            focus_note=focus_note[:120] if focus_note else None,
            stage=stage,
            created_turn_id=created_turn_id
        )

        self._spans[agent_id][span_id] = span
        return span

    def get_span(self, agent_id: str, span_id: str) -> Optional[Span]:
        """Get a specific span"""
        return self._spans.get(agent_id, {}).get(span_id)

    def get_agent_spans(self, agent_id: str) -> dict[str, Span]:
        """Get all spans for an agent"""
        return self._spans.get(agent_id, {})

    def update_span(
        self,
        agent_id: str,
        span_id: str,
        state: Optional[SpanState] = None,
        outcome: Optional[str] = None,
        completed_at: Optional[datetime] = None,
        stage: Optional[str] = None
    ) -> Optional[Span]:
        """
        Update an existing span.

        Returns:
            Updated Span, or None if not found
        """
        span = self.get_span(agent_id, span_id)
        if not span:
            return None

        if state is not None:
            span.state = state
        if outcome is not None:
            span.outcome = SpanOutcome(outcome)
        if completed_at is not None:
            span.completed_at = completed_at
        if stage is not None:
            span.stage = stage

        return span

    def attach_event(self, agent_id: str, span_id: str, event_id: str) -> bool:
        """
        Attach an event to a span.

        Returns:
            True if successful, False if span not found
        """
        span = self.get_span(agent_id, span_id)
        if not span:
            return False

        if event_id not in span.event_ids:
            span.event_ids.append(event_id)

        return True

    def attach_artifact(self, agent_id: str, span_id: str, artifact_id: str) -> bool:
        """
        Attach an artifact to a span.

        Returns:
            True if successful, False if span not found
        """
        span = self.get_span(agent_id, span_id)
        if not span:
            return False

        if artifact_id not in span.artifact_ids:
            span.artifact_ids.append(artifact_id)

        return True

    def clear_agent_spans(self, agent_id: str) -> None:
        """Clear all spans for an agent"""
        if agent_id in self._spans:
            del self._spans[agent_id]


# Global instance
span_service = SpanService()

"""
Investigation Trace Data Models

Span and Artifact models for structured investigation narratives.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class SpanType(str, Enum):
    """Type of investigation span"""
    HYPOTHESIS = "hypothesis"
    HYPOTHESIS_VISIT = "hypothesis_visit"
    CRITIC_PASS = "critic_pass"
    PLACEHOLDER = "placeholder"


class SpanState(str, Enum):
    """Lifecycle state of span"""
    OPEN = "open"
    COMPLETED = "completed"
    DISCARDED = "discarded"


class SpanOutcome(str, Enum):
    """Investigation outcome"""
    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"


class FocusGap(str, Enum):
    """Evidence gap being investigated"""
    REACHABLE = "reachable"
    DATAFLOW_EVIDENCED = "dataflow_evidenced"
    SOURCE_CONTROLLED_INPUT = "source_controlled_input"
    SINK_PRESENT = "sink_present"
    BOUNDARY_CROSSED = "boundary_crossed"
    NOT_ONLY_MISCONFIG = "not_only_misconfig"
    SECURITY_CONTROL_BYPASSED = "security_control_bypassed"
    OTHER = "other"


@dataclass
class Span:
    """
    Investigation span representing a hypothesis or investigation episode.

    Spans form a tree hierarchy and contain chronological events.
    """
    span_id: str
    span_type: SpanType
    hypothesis_id: str
    label: str
    state: SpanState

    # Hierarchy
    parent_span_id: Optional[str] = None

    # Lifecycle
    outcome: Optional[SpanOutcome] = None
    created_turn_id: Optional[int] = None
    completed_at: Optional[datetime] = None

    # Context
    focus_gap: Optional[FocusGap] = None
    focus_note: Optional[str] = None  # Max 120 chars
    stage: Optional[str] = None  # LangGraph stage: "mapping", "scanning", "triage"

    # Containment
    event_ids: list[str] = field(default_factory=list)
    artifact_ids: list[str] = field(default_factory=list)

    # Metadata
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dict for serialization"""
        return {
            "span_id": self.span_id,
            "span_type": self.span_type.value,
            "hypothesis_id": self.hypothesis_id,
            "label": self.label,
            "state": self.state.value,
            "parent_span_id": self.parent_span_id,
            "outcome": self.outcome.value if self.outcome else None,
            "created_turn_id": self.created_turn_id,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "focus_gap": self.focus_gap.value if self.focus_gap else None,
            "focus_note": self.focus_note,
            "stage": self.stage,
            "event_ids": self.event_ids,
            "artifact_ids": self.artifact_ids,
            "metadata": self.metadata
        }

"""
Investigation Trace Data Models

Span and Artifact models for structured investigation narratives.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
import hashlib
import json


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


class HypothesisState(str, Enum):
    """State of hypothesis investigation"""
    OPEN = "open"
    COMPLETED = "completed"
    DISCARDED = "discarded"


class HypothesisActivity(str, Enum):
    """Activity indicator for hypothesis in current turn"""
    NEW = "new"  # First time creating this hypothesis
    CONTINUING = "continuing"  # Actively working on it
    REVISITING = "revisiting"  # Returning after gap >5 turns
    QUEUED = "queued"  # Declared but not active this turn


class ArtifactType(str, Enum):
    """Type of artifact"""
    FILE_SNIPPET = "file_snippet"
    SEARCH_RESULT = "search_result"
    CALL_GRAPH = "call_graph"
    TOOL_OUTPUT = "tool_output"


def generate_artifact_id(content: str | dict) -> str:
    """
    Generate deterministic artifact ID from content hash.

    Uses SHA256 hash for content deduplication.
    """
    if isinstance(content, dict):
        content = json.dumps(content, sort_keys=True)

    hash_obj = hashlib.sha256(content.encode('utf-8'))
    hash_hex = hash_obj.hexdigest()[:16]  # First 16 chars
    return f"art_{hash_hex}"


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

    def __post_init__(self):
        """Validate field constraints."""
        if self.focus_note and len(self.focus_note) > 120:
            raise ValueError(f"focus_note must be ≤120 chars, got {len(self.focus_note)}")

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


@dataclass
class Artifact:
    """
    Investigation artifact (file snippet, search result, etc.)

    Deduplicated by content hash for efficient cross-span evidence tracking.
    """
    artifact_id: str
    artifact_type: ArtifactType
    content: str | dict
    summary: str  # Max 200 chars

    # File references (for FILE_SNIPPET type)
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None

    # Provenance (computed during reconstruction)
    producer_spans: set[str] = field(default_factory=set)
    consumer_spans: set[str] = field(default_factory=set)

    # Metadata
    created_at: Optional[datetime] = None
    size_bytes: int = 0

    def __post_init__(self):
        """Validate field constraints."""
        if self.summary and len(self.summary) > 200:
            raise ValueError(f"summary must be ≤200 chars, got {len(self.summary)}")

    def to_dict(self) -> dict:
        """Convert to dict for serialization"""
        return {
            "artifact_id": self.artifact_id,
            "artifact_type": self.artifact_type.value,
            "content": self.content,
            "summary": self.summary,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "producer_spans": list(self.producer_spans),
            "consumer_spans": list(self.consumer_spans),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "size_bytes": self.size_bytes
        }


@dataclass
class HypothesisInfo:
    """
    Hypothesis metadata for turn plan.

    Emitted by agent to declare investigation structure.
    """
    hypothesis_id: str
    label: str
    state: HypothesisState
    activity: HypothesisActivity
    created_turn_id: int
    focus_gap: FocusGap

    # Optional fields
    parent_hypothesis_id: Optional[str] = None
    focus_note: Optional[str] = None  # Max 120 chars

    # Dual-write: Backend may assign these
    span_id: Optional[str] = None
    parent_span_id: Optional[str] = None

    def __post_init__(self):
        """Validate field constraints."""
        if self.focus_note and len(self.focus_note) > 120:
            raise ValueError(f"focus_note must be ≤120 chars, got {len(self.focus_note)}")

    def to_dict(self) -> dict:
        return {
            "hypothesis_id": self.hypothesis_id,
            "label": self.label,
            "state": self.state.value,
            "activity": self.activity.value,
            "created_turn_id": self.created_turn_id,
            "focus_gap": self.focus_gap.value,
            "parent_hypothesis_id": self.parent_hypothesis_id,
            "focus_note": self.focus_note,
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id
        }


@dataclass
class TurnPlan:
    """
    Investigation plan for current agent turn.

    Provides preview of what agent will investigate and why.
    """
    goal: str
    hypotheses: list[HypothesisInfo]
    selected_hypothesis_id: str
    selected_span_id: str  # CRITICAL: Authoritative routing

    def to_dict(self) -> dict:
        return {
            "goal": self.goal,
            "hypotheses": [h.to_dict() for h in self.hypotheses],
            "selected_hypothesis_id": self.selected_hypothesis_id,
            "selected_span_id": self.selected_span_id
        }

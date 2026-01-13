"""Turn plan models for declarative investigation routing.

This module provides TurnPlan and Hypothesis models for agent turn previews
with hypothesis spans in the investigation trace system.
"""

from dataclasses import dataclass, field
from enum import Enum


class HypothesisActivity(str, Enum):
    """Status of hypothesis in current turn."""

    NEW = "new"
    CONTINUING = "continuing"
    REVISITING = "revisiting"
    QUEUED = "queued"


class FocusGap(str, Enum):
    """Types of security analysis gaps that drive hypothesis focus."""

    REACHABLE = "reachable"
    DATAFLOW_EVIDENCED = "dataflow_evidenced"
    SOURCE_CONTROLLED_INPUT = "source_controlled_input"
    SINK_PRESENT = "sink_present"
    BOUNDARY_CROSSED = "boundary_crossed"
    NOT_ONLY_MISCONFIG = "not_only_misconfig"
    SECURITY_CONTROL_BYPASSED = "security_control_bypassed"
    OTHER = "other"


@dataclass
class Hypothesis:
    """A security hypothesis being investigated.

    Attributes:
        hypothesis_id: Unique identifier for this hypothesis
        label: Human-readable description of the hypothesis
        state: Current state (e.g., "active", "queued", "resolved")
        activity: Activity status in current turn
        created_turn_id: Turn ID when hypothesis was created
        focus_gap: Type of security gap this hypothesis addresses
        parent_hypothesis_id: ID of parent hypothesis (if derived)
        focus_note: Brief note about current focus (max 120 chars)
        span_id: Associated span ID in trace tree
        parent_span_id: Parent span ID in trace tree
    """

    hypothesis_id: str
    label: str
    state: str
    activity: HypothesisActivity
    created_turn_id: str
    focus_gap: FocusGap
    parent_hypothesis_id: str | None = None
    focus_note: str | None = None
    span_id: str | None = None
    parent_span_id: str | None = None

    def __post_init__(self):
        """Truncate focus_note to 120 characters if needed."""
        if self.focus_note and len(self.focus_note) > 120:
            self.focus_note = self.focus_note[:120]


@dataclass
class TurnPlan:
    """A plan for an agent investigation turn.

    Attributes:
        turn_id: Unique identifier for this turn
        goal: High-level goal for this turn
        hypotheses: List of hypotheses being tracked
        selected_hypothesis_id: ID of hypothesis selected for this turn
        selected_span_id: ID of span selected for this turn
        stage: Optional investigation stage (e.g., "exploration", "validation")
    """

    turn_id: str
    goal: str
    hypotheses: list[Hypothesis] = field(default_factory=list)
    selected_hypothesis_id: str | None = None
    selected_span_id: str | None = None
    stage: str | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "turn_id": self.turn_id,
            "goal": self.goal,
            "hypotheses": [
                {
                    "hypothesis_id": h.hypothesis_id,
                    "label": h.label,
                    "state": h.state,
                    "activity": h.activity.value if isinstance(h.activity, HypothesisActivity) else h.activity,
                    "created_turn_id": h.created_turn_id,
                    "focus_gap": h.focus_gap.value if isinstance(h.focus_gap, FocusGap) else h.focus_gap,
                    "parent_hypothesis_id": h.parent_hypothesis_id,
                    "focus_note": h.focus_note,
                    "span_id": h.span_id,
                    "parent_span_id": h.parent_span_id,
                }
                for h in self.hypotheses
            ],
            "selected_hypothesis_id": self.selected_hypothesis_id,
            "selected_span_id": self.selected_span_id,
            "stage": self.stage,
        }

# Investigation Trace System Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement tree/DAG trace model that transforms flat chronological event stream into structured investigation narrative with hypothesis spans, artifact provenance, and declarative routing.

**Architecture:** Dual-write period (2-4 weeks) where events emit both legacy format and new span/artifact fields. Frontend toggles between legacy chronological view and new span-based tree/DAG view. Reconstruction algorithm runs client-side for real-time updates.

**Tech Stack:** Python 3.12, FastAPI, Pydantic, React, TypeScript, ReactFlow

---

## Phase 1: Backend Data Models & Schema

### Task 1: Extend FlowNode with Span Tracking Fields

**Files:**
- Modify: `backend/services/flow_service.py:69-81`
- Test: `backend/tests/services/test_flow_service_spans.py`

**Step 1: Write failing test for FlowNode with span fields**

```python
# backend/tests/services/test_flow_service_spans.py
"""Tests for span-enhanced FlowNode"""
import pytest
from services.flow_service import FlowNode

def test_flow_node_with_span_fields():
    """FlowNode should accept span tracking fields"""
    node = FlowNode(
        id="evt_123",
        type="tool_call",
        label="Read file",
        span_id="span_abc",
        parent_span_id="span_parent",
        hypothesis_id="hyp_1",
        turn_id=5,
        correlation_id="corr_5",
        input_artifact_ids=["art_1"],
        output_artifact_ids=["art_2"],
        tool_invocation_id="tool_inv_1"
    )

    assert node.span_id == "span_abc"
    assert node.parent_span_id == "span_parent"
    assert node.hypothesis_id == "hyp_1"
    assert node.turn_id == 5
    assert node.correlation_id == "corr_5"
    assert node.input_artifact_ids == ["art_1"]
    assert node.output_artifact_ids == ["art_2"]
    assert node.tool_invocation_id == "tool_inv_1"

def test_flow_node_span_fields_optional():
    """Span fields should be optional for backward compatibility"""
    node = FlowNode(
        id="evt_123",
        type="tool_call",
        label="Read file"
    )

    assert node.span_id is None
    assert node.parent_span_id is None
    assert node.hypothesis_id is None
    assert node.turn_id == 0  # default
    assert node.correlation_id is None
    assert node.input_artifact_ids == []
    assert node.output_artifact_ids == []
    assert node.tool_invocation_id is None
```

**Step 2: Run test to verify it fails**

```bash
cd backend
pytest tests/services/test_flow_service_spans.py::test_flow_node_with_span_fields -v
```

Expected: `AttributeError: 'FlowNode' object has no attribute 'span_id'`

**Step 3: Add span fields to FlowNode dataclass**

```python
# backend/services/flow_service.py:69-95
@dataclass
class FlowNode:
    id: str
    type: NodeType
    label: str
    status: NodeStatus = "pending"
    data: dict = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    duration_ms: Optional[int] = None
    llm_reasoning: Optional[str] = None
    code_context: Optional[str] = None
    tool_result_summary: Optional[str] = None
    confidence_score: Optional[float] = None

    # NEW: Span tracking fields (dual-write)
    span_id: Optional[str] = None
    parent_span_id: Optional[str] = None
    hypothesis_id: Optional[str] = None
    turn_id: int = 0
    correlation_id: Optional[str] = None

    # NEW: Artifact provenance
    input_artifact_ids: list[str] = field(default_factory=list)
    output_artifact_ids: list[str] = field(default_factory=list)

    # NEW: Tool pairing
    tool_invocation_id: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/services/test_flow_service_spans.py::test_flow_node_with_span_fields -v
pytest tests/services/test_flow_service_spans.py::test_flow_node_span_fields_optional -v
```

Expected: PASS

**Step 5: Commit**

```bash
git add backend/services/flow_service.py backend/tests/services/test_flow_service_spans.py
git commit -m "feat(flow): add span tracking fields to FlowNode

- Add span_id, parent_span_id, hypothesis_id for span hierarchy
- Add turn_id, correlation_id for turn grouping
- Add input/output_artifact_ids for provenance tracking
- Add tool_invocation_id for call/result pairing
- All fields optional for backward compatibility"
```

---

### Task 2: Create Span Dataclass

**Files:**
- Create: `backend/models/investigation_trace.py`
- Test: `backend/tests/models/test_investigation_trace.py`

**Step 1: Write failing test for Span model**

```python
# backend/tests/models/test_investigation_trace.py
"""Tests for investigation trace data models"""
import pytest
from datetime import datetime
from models.investigation_trace import Span, SpanType, SpanState

def test_span_creation():
    """Span should be created with required fields"""
    span = Span(
        span_id="span_123",
        span_type=SpanType.HYPOTHESIS,
        hypothesis_id="hyp_1",
        label="Investigate SQL injection",
        state=SpanState.OPEN
    )

    assert span.span_id == "span_123"
    assert span.span_type == SpanType.HYPOTHESIS
    assert span.hypothesis_id == "hyp_1"
    assert span.label == "Investigate SQL injection"
    assert span.state == SpanState.OPEN
    assert span.parent_span_id is None
    assert span.outcome is None
    assert span.event_ids == []
    assert span.artifact_ids == []

def test_span_with_parent():
    """Span should support parent_span_id for hierarchy"""
    parent = Span(
        span_id="span_parent",
        span_type=SpanType.HYPOTHESIS,
        hypothesis_id="hyp_parent",
        label="Parent hypothesis",
        state=SpanState.OPEN
    )

    child = Span(
        span_id="span_child",
        span_type=SpanType.HYPOTHESIS,
        hypothesis_id="hyp_child",
        label="Child hypothesis",
        state=SpanState.OPEN,
        parent_span_id=parent.span_id
    )

    assert child.parent_span_id == "span_parent"

def test_span_lifecycle():
    """Span should transition through states"""
    span = Span(
        span_id="span_123",
        span_type=SpanType.HYPOTHESIS,
        hypothesis_id="hyp_1",
        label="Test",
        state=SpanState.OPEN
    )

    # Complete the span
    span.state = SpanState.COMPLETED
    span.outcome = "confirmed"
    span.completed_at = datetime.utcnow()

    assert span.state == SpanState.COMPLETED
    assert span.outcome == "confirmed"
    assert span.completed_at is not None
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/models/test_investigation_trace.py::test_span_creation -v
```

Expected: `ModuleNotFoundError: No module named 'models.investigation_trace'`

**Step 3: Create Span dataclass**

```python
# backend/models/investigation_trace.py
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
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/models/test_investigation_trace.py -v
```

Expected: PASS

**Step 5: Commit**

```bash
git add backend/models/investigation_trace.py backend/tests/models/test_investigation_trace.py
git commit -m "feat(models): add Span dataclass for investigation traces

- Add Span with span_id, hypothesis_id, label, state
- Add SpanType enum (hypothesis, visit, critic, placeholder)
- Add SpanState enum (open, completed, discarded)
- Add SpanOutcome enum (confirmed, refuted, inconclusive)
- Add FocusGap enum for evidence gaps
- Support parent_span_id for tree hierarchy
- Track event_ids and artifact_ids for containment"
```

---

### Task 3: Create Artifact Dataclass

**Files:**
- Modify: `backend/models/investigation_trace.py`
- Modify: `backend/tests/models/test_investigation_trace.py`

**Step 1: Write failing test for Artifact model**

```python
# Add to backend/tests/models/test_investigation_trace.py
from models.investigation_trace import Artifact, ArtifactType

def test_artifact_creation():
    """Artifact should be created with content hash ID"""
    artifact = Artifact(
        artifact_id="sha256_abc123",
        artifact_type=ArtifactType.FILE_SNIPPET,
        content="def vulnerable_function():\n    pass",
        summary="File snippet from auth.py:45-50"
    )

    assert artifact.artifact_id == "sha256_abc123"
    assert artifact.artifact_type == ArtifactType.FILE_SNIPPET
    assert artifact.content == "def vulnerable_function():\n    pass"
    assert artifact.summary == "File snippet from auth.py:45-50"

def test_artifact_with_references():
    """Artifact should support file references"""
    artifact = Artifact(
        artifact_id="sha256_abc123",
        artifact_type=ArtifactType.FILE_SNIPPET,
        content="code here",
        summary="File snippet",
        file_path="app/auth.py",
        line_start=45,
        line_end=50
    )

    assert artifact.file_path == "app/auth.py"
    assert artifact.line_start == 45
    assert artifact.line_end == 50

def test_artifact_content_hash_generation():
    """Artifact ID should be deterministic content hash"""
    from models.investigation_trace import generate_artifact_id

    content = "def test(): pass"
    id1 = generate_artifact_id(content)
    id2 = generate_artifact_id(content)

    assert id1 == id2
    assert id1.startswith("art_")
    assert len(id1) == 20  # "art_" + 16 hex chars
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/models/test_investigation_trace.py::test_artifact_creation -v
```

Expected: `ImportError: cannot import name 'Artifact'`

**Step 3: Add Artifact dataclass**

```python
# Add to backend/models/investigation_trace.py
import hashlib

class ArtifactType(str, Enum):
    """Type of artifact"""
    FILE_SNIPPET = "file_snippet"
    SEARCH_RESULT = "search_result"
    CALL_GRAPH = "call_graph"
    TOOL_OUTPUT = "tool_output"


def generate_artifact_id(content: str) -> str:
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
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/models/test_investigation_trace.py::test_artifact_creation -v
pytest tests/models/test_investigation_trace.py::test_artifact_with_references -v
pytest tests/models/test_investigation_trace.py::test_artifact_content_hash_generation -v
```

Expected: PASS

**Step 5: Add missing import**

```python
# Add to top of backend/models/investigation_trace.py
import json
```

**Step 6: Run all artifact tests again**

```bash
pytest tests/models/test_investigation_trace.py -k artifact -v
```

Expected: PASS

**Step 7: Commit**

```bash
git add backend/models/investigation_trace.py backend/tests/models/test_investigation_trace.py
git commit -m "feat(models): add Artifact dataclass with content-hash deduplication

- Add Artifact with artifact_id, type, content, summary
- Add ArtifactType enum (file_snippet, search_result, call_graph, tool_output)
- Add generate_artifact_id() for deterministic content hashing
- Support file_path, line_start, line_end references
- Track producer_spans and consumer_spans for provenance"
```

---

### Task 4: Create TurnPlan Event Models

**Files:**
- Modify: `backend/models/investigation_trace.py`
- Modify: `backend/tests/models/test_investigation_trace.py`

**Step 1: Write failing test for TurnPlan model**

```python
# Add to backend/tests/models/test_investigation_trace.py
from models.investigation_trace import (
    TurnPlan, HypothesisInfo, HypothesisActivity, HypothesisState
)

def test_turn_plan_creation():
    """TurnPlan should structure investigation preview"""
    hypothesis = HypothesisInfo(
        hypothesis_id="hyp_1",
        label="Check SQL injection",
        state=HypothesisState.OPEN,
        activity=HypothesisActivity.NEW,
        created_turn_id=1,
        focus_gap=FocusGap.DATAFLOW_EVIDENCED,
        focus_note="Need to trace user input to query"
    )

    plan = TurnPlan(
        goal="Investigate /login route",
        hypotheses=[hypothesis],
        selected_hypothesis_id="hyp_1",
        selected_span_id="span_hyp_1"
    )

    assert plan.goal == "Investigate /login route"
    assert len(plan.hypotheses) == 1
    assert plan.hypotheses[0].hypothesis_id == "hyp_1"
    assert plan.selected_hypothesis_id == "hyp_1"
    assert plan.selected_span_id == "span_hyp_1"

def test_hypothesis_activity_states():
    """HypothesisActivity should cover all workflow states"""
    # New hypothesis being created
    hyp_new = HypothesisInfo(
        hypothesis_id="hyp_1",
        label="Test",
        state=HypothesisState.OPEN,
        activity=HypothesisActivity.NEW,
        created_turn_id=1,
        focus_gap=FocusGap.OTHER
    )

    # Continuing existing hypothesis
    hyp_continuing = HypothesisInfo(
        hypothesis_id="hyp_1",
        label="Test",
        state=HypothesisState.OPEN,
        activity=HypothesisActivity.CONTINUING,
        created_turn_id=1,
        focus_gap=FocusGap.OTHER
    )

    # Revisiting after gap
    hyp_revisiting = HypothesisInfo(
        hypothesis_id="hyp_1",
        label="Test",
        state=HypothesisState.OPEN,
        activity=HypothesisActivity.REVISITING,
        created_turn_id=1,
        focus_gap=FocusGap.OTHER
    )

    # Queued for future
    hyp_queued = HypothesisInfo(
        hypothesis_id="hyp_2",
        label="Future work",
        state=HypothesisState.OPEN,
        activity=HypothesisActivity.QUEUED,
        created_turn_id=1,
        focus_gap=FocusGap.OTHER
    )

    assert hyp_new.activity == HypothesisActivity.NEW
    assert hyp_continuing.activity == HypothesisActivity.CONTINUING
    assert hyp_revisiting.activity == HypothesisActivity.REVISITING
    assert hyp_queued.activity == HypothesisActivity.QUEUED
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/models/test_investigation_trace.py::test_turn_plan_creation -v
```

Expected: `ImportError: cannot import name 'TurnPlan'`

**Step 3: Add TurnPlan models**

```python
# Add to backend/models/investigation_trace.py

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
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/models/test_investigation_trace.py::test_turn_plan_creation -v
pytest tests/models/test_investigation_trace.py::test_hypothesis_activity_states -v
```

Expected: PASS

**Step 5: Commit**

```bash
git add backend/models/investigation_trace.py backend/tests/models/test_investigation_trace.py
git commit -m "feat(models): add TurnPlan event models for investigation preview

- Add TurnPlan with goal, hypotheses, selected_hypothesis_id, selected_span_id
- Add HypothesisInfo with hypothesis_id, label, state, activity, focus_gap
- Add HypothesisState enum (open, completed, discarded)
- Add HypothesisActivity enum (new, continuing, revisiting, queued)
- Support parent_hypothesis_id for nested hypotheses
- Add focus_note field (max 120 chars)"
```

---

## Phase 2: Span Management Service

### Task 5: Create SpanService

**Files:**
- Create: `backend/services/span_service.py`
- Test: `backend/tests/services/test_span_service.py`

**Step 1: Write failing test for SpanService**

```python
# backend/tests/services/test_span_service.py
"""Tests for SpanService"""
import pytest
from services.span_service import SpanService
from models.investigation_trace import Span, SpanType, SpanState

def test_span_service_create_span():
    """SpanService should create and store spans"""
    service = SpanService()

    span = service.create_span(
        agent_id="agent_1",
        span_id="span_123",
        span_type=SpanType.HYPOTHESIS,
        hypothesis_id="hyp_1",
        label="Test hypothesis",
        state=SpanState.OPEN
    )

    assert span.span_id == "span_123"
    assert span.hypothesis_id == "hyp_1"

    # Should be retrievable
    retrieved = service.get_span("agent_1", "span_123")
    assert retrieved is not None
    assert retrieved.span_id == "span_123"

def test_span_service_get_agent_spans():
    """SpanService should return all spans for an agent"""
    service = SpanService()

    service.create_span(
        agent_id="agent_1",
        span_id="span_1",
        span_type=SpanType.HYPOTHESIS,
        hypothesis_id="hyp_1",
        label="Hypothesis 1",
        state=SpanState.OPEN
    )

    service.create_span(
        agent_id="agent_1",
        span_id="span_2",
        span_type=SpanType.HYPOTHESIS,
        hypothesis_id="hyp_2",
        label="Hypothesis 2",
        state=SpanState.OPEN
    )

    spans = service.get_agent_spans("agent_1")
    assert len(spans) == 2
    assert spans["span_1"].hypothesis_id == "hyp_1"
    assert spans["span_2"].hypothesis_id == "hyp_2"

def test_span_service_update_span():
    """SpanService should update existing spans"""
    service = SpanService()

    span = service.create_span(
        agent_id="agent_1",
        span_id="span_123",
        span_type=SpanType.HYPOTHESIS,
        hypothesis_id="hyp_1",
        label="Test",
        state=SpanState.OPEN
    )

    # Update state
    updated = service.update_span(
        agent_id="agent_1",
        span_id="span_123",
        state=SpanState.COMPLETED,
        outcome="confirmed"
    )

    assert updated.state == SpanState.COMPLETED
    assert updated.outcome == "confirmed"
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/services/test_span_service.py::test_span_service_create_span -v
```

Expected: `ModuleNotFoundError: No module named 'services.span_service'`

**Step 3: Create SpanService**

```python
# backend/services/span_service.py
"""
Span Service - Manages investigation spans.

Provides CRUD operations for spans and maintains per-agent span stores.
"""

from collections import defaultdict
from datetime import datetime
from typing import Optional
from models.investigation_trace import (
    Span, SpanType, SpanState, SpanOutcome, FocusGap
)


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
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/services/test_span_service.py -v
```

Expected: PASS

**Step 5: Commit**

```bash
git add backend/services/span_service.py backend/tests/services/test_span_service.py
git commit -m "feat(services): add SpanService for span management

- Add create_span() for span creation
- Add get_span() and get_agent_spans() for retrieval
- Add update_span() for state/outcome updates
- Add attach_event() and attach_artifact() for containment
- Store spans in-memory per agent
- Export global span_service instance"
```

---

### Task 6: Add Deterministic Span ID Generation

**Files:**
- Modify: `backend/services/span_service.py`
- Modify: `backend/tests/services/test_span_service.py`

**Step 1: Write failing test for deterministic span IDs**

```python
# Add to backend/tests/services/test_span_service.py
from services.span_service import generate_deterministic_span_id

def test_generate_deterministic_span_id():
    """Span IDs should be deterministic for same inputs"""
    agent_id = "agent_123"
    hypothesis_id = "hyp_abc"

    id1 = generate_deterministic_span_id(agent_id, hypothesis_id)
    id2 = generate_deterministic_span_id(agent_id, hypothesis_id)

    assert id1 == id2
    assert id1.startswith("span_")
    assert len(id1) == 21  # "span_" + 16 hex chars

def test_generate_deterministic_span_id_with_suffix():
    """Span IDs should support suffixes for visit spans"""
    agent_id = "agent_123"
    hypothesis_id = "hyp_abc"

    base_id = generate_deterministic_span_id(agent_id, hypothesis_id)
    visit_id = generate_deterministic_span_id(agent_id, hypothesis_id, ":visit_turn:10")

    assert base_id != visit_id
    assert visit_id.startswith("span_")

def test_generate_deterministic_span_id_stability():
    """Span IDs should be stable across process restarts"""
    # Same inputs should always produce same output
    id1 = generate_deterministic_span_id("agent_1", "hyp_1")
    id2 = generate_deterministic_span_id("agent_1", "hyp_1")

    assert id1 == id2
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/services/test_span_service.py::test_generate_deterministic_span_id -v
```

Expected: `ImportError: cannot import name 'generate_deterministic_span_id'`

**Step 3: Add deterministic ID generation**

```python
# Add to backend/services/span_service.py (top of file)
import hashlib

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
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/services/test_span_service.py -k deterministic -v
```

Expected: PASS

**Step 5: Commit**

```bash
git add backend/services/span_service.py backend/tests/services/test_span_service.py
git commit -m "feat(span-service): add deterministic span ID generation

- Add generate_deterministic_span_id() using SHA1 hash
- Support suffix parameter for visit spans
- Stable IDs survive reconstruction across process restarts
- Return format: span_{16_hex_chars}"
```

---

## Phase 3: Artifact Tracking (Coming Next...)

**Remaining tasks:** 15-28 (from original plan)

This covers:
- ArtifactService creation
- Tool execution integration for artifact tracking
- ReAct agent turn_plan emission
- Reconstruction algorithm
- Frontend visualization
- Feature flag rollout

---

## Execution Options

Plan complete and saved to `docs/plans/2026-01-13-investigation-trace-implementation.md`.

**Two execution options:**

**1. Subagent-Driven (this session)** - I dispatch fresh subagent per task, review between tasks, fast iteration with @superpowers:subagent-driven-development

**2. Parallel Session (separate)** - Open new session with executing-plans, batch execution with checkpoints

**Which approach?**

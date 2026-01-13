# Phase 4-7: Complete Investigation Trace System Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Complete the investigation trace system by implementing turn plan emission, reconstruction algorithm, frontend visualization, and feature flag rollout for tree/DAG-based investigation flows.

**Architecture:** Agent-driven turn plans with declarative span routing, client-side single-pass reconstruction algorithm, React Flow visualization with hypothesis/critic nodes, and dual-write feature flag rollout for safe migration.

**Tech Stack:** Python 3.12, FastAPI, pytest, TypeScript, React, React Flow, TanStack Query, WebSocket

---

## Phase 4: Agent Turn Plan Emission

### Task 13: Add Turn Plan Model and Event Types

**Files:**
- Create: `backend/models/turn_plan.py`
- Test: `backend/tests/models/test_turn_plan.py`

**Step 1: Write failing test for TurnPlan model**

```python
# backend/tests/models/test_turn_plan.py
"""Tests for TurnPlan model"""
import pytest
from models.turn_plan import TurnPlan, Hypothesis, HypothesisActivity, FocusGap

def test_hypothesis_creation():
    """Should create Hypothesis with all fields"""
    hyp = Hypothesis(
        hypothesis_id="hyp_1",
        parent_hypothesis_id=None,
        label="Check SQL injection in login",
        state="open",
        activity=HypothesisActivity.NEW,
        created_turn_id=1,
        focus_gap=FocusGap.DATAFLOW_EVIDENCED,
        focus_note="User input reaches query without sanitization",
        span_id="span_abc",
        parent_span_id=None
    )

    assert hyp.hypothesis_id == "hyp_1"
    assert hyp.state == "open"
    assert hyp.activity == HypothesisActivity.NEW
    assert hyp.focus_gap == FocusGap.DATAFLOW_EVIDENCED
    assert len(hyp.focus_note) <= 120

def test_turn_plan_creation():
    """Should create TurnPlan with hypotheses"""
    hyp1 = Hypothesis(
        hypothesis_id="hyp_1",
        label="Check route handler",
        state="open",
        activity=HypothesisActivity.NEW,
        created_turn_id=1,
        focus_gap=FocusGap.REACHABLE,
        span_id="span_1"
    )

    plan = TurnPlan(
        turn_id=1,
        stage="mapping",
        goal="Investigate SQL injection in /login",
        hypotheses=[hyp1],
        selected_hypothesis_id="hyp_1",
        selected_span_id="span_1"
    )

    assert plan.turn_id == 1
    assert plan.stage == "mapping"
    assert len(plan.hypotheses) == 1
    assert plan.selected_hypothesis_id == "hyp_1"

def test_focus_note_max_length():
    """Focus note should be capped at 120 chars"""
    long_note = "x" * 200

    hyp = Hypothesis(
        hypothesis_id="hyp_1",
        label="Test",
        state="open",
        activity=HypothesisActivity.NEW,
        created_turn_id=1,
        focus_gap=FocusGap.OTHER,
        focus_note=long_note
    )

    # Should truncate
    assert len(hyp.focus_note) == 120
```

**Step 2: Run test to verify it fails**

```bash
cd backend
pytest tests/models/test_turn_plan.py::test_hypothesis_creation -v
```

Expected: `ModuleNotFoundError: No module named 'models.turn_plan'`

**Step 3: Create TurnPlan model**

```python
# backend/models/turn_plan.py
"""
Turn Plan Model - Declarative investigation routing.

Emitted at start of each agent turn to provide investigation preview
and authoritative span routing.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class HypothesisActivity(str, Enum):
    """What agent is doing with this hypothesis"""
    NEW = "new"                    # First time investigating
    CONTINUING = "continuing"      # Ongoing investigation
    REVISITING = "revisiting"      # Returning after gap
    QUEUED = "queued"             # Planned but not active


class FocusGap(str, Enum):
    """Triage checklist gaps (safer than free-text reasoning)"""
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
    """Single hypothesis in turn plan"""
    hypothesis_id: str
    label: str
    state: str  # "open" | "completed" | "discarded"
    activity: HypothesisActivity
    created_turn_id: int
    focus_gap: FocusGap

    parent_hypothesis_id: Optional[str] = None
    focus_note: Optional[str] = None
    span_id: Optional[str] = None
    parent_span_id: Optional[str] = None

    def __post_init__(self):
        """Validate and truncate fields"""
        if self.focus_note and len(self.focus_note) > 120:
            self.focus_note = self.focus_note[:120]


@dataclass
class TurnPlan:
    """Agent's plan for current turn"""
    turn_id: int
    goal: str
    hypotheses: list[Hypothesis]
    selected_hypothesis_id: str
    selected_span_id: str

    stage: Optional[str] = None  # For LangGraph: "mapping", "scanning", "triage"

    def to_dict(self) -> dict:
        """Convert to JSON-serializable dict"""
        return {
            "turn_id": self.turn_id,
            "stage": self.stage,
            "goal": self.goal,
            "hypotheses": [
                {
                    "hypothesis_id": h.hypothesis_id,
                    "parent_hypothesis_id": h.parent_hypothesis_id,
                    "label": h.label,
                    "state": h.state,
                    "activity": h.activity.value,
                    "created_turn_id": h.created_turn_id,
                    "focus_gap": h.focus_gap.value,
                    "focus_note": h.focus_note,
                    "span_id": h.span_id,
                    "parent_span_id": h.parent_span_id
                }
                for h in self.hypotheses
            ],
            "selected_hypothesis_id": self.selected_hypothesis_id,
            "selected_span_id": self.selected_span_id
        }
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/models/test_turn_plan.py -v
```

Expected: PASS (3 tests)

**Step 5: Commit**

```bash
git add backend/models/turn_plan.py backend/tests/models/test_turn_plan.py
git commit -m "feat(models): add TurnPlan and Hypothesis models

- Add Hypothesis dataclass with focus gap enumeration
- Add TurnPlan for declarative investigation routing
- Validate focus_note max length (120 chars)
- Add HypothesisActivity and FocusGap enums"
```

---

### Task 14: Add Turn Plan Emission to FlowService

**Files:**
- Modify: `backend/services/flow_service.py`
- Test: `backend/tests/services/test_flow_service_turn_plans.py`

**Step 1: Write failing test for turn plan emission**

```python
# backend/tests/services/test_flow_service_turn_plans.py
"""Tests for FlowService turn plan emission"""
import pytest
from services.flow_service import FlowService
from models.turn_plan import TurnPlan, Hypothesis, HypothesisActivity, FocusGap

def test_emit_turn_plan():
    """FlowService should emit turn_plan events"""
    service = FlowService()
    service.initialize_flow("agent_123")

    hyp = Hypothesis(
        hypothesis_id="hyp_1",
        label="Check SQL injection",
        state="open",
        activity=HypothesisActivity.NEW,
        created_turn_id=1,
        focus_gap=FocusGap.DATAFLOW_EVIDENCED,
        span_id="span_1"
    )

    turn_plan = TurnPlan(
        turn_id=1,
        stage="mapping",
        goal="Investigate /login endpoint",
        hypotheses=[hyp],
        selected_hypothesis_id="hyp_1",
        selected_span_id="span_1"
    )

    node = service.emit_turn_plan("agent_123", turn_plan)

    assert node is not None
    assert node.type == "turn_plan"
    assert node.data["turn_id"] == 1
    assert node.data["goal"] == "Investigate /login endpoint"
    assert len(node.data["hypotheses"]) == 1

def test_turn_plan_updates_context():
    """Turn plan should update flow context"""
    service = FlowService()
    service.initialize_flow("agent_123")

    hyp = Hypothesis(
        hypothesis_id="hyp_1",
        label="Test",
        state="open",
        activity=HypothesisActivity.NEW,
        created_turn_id=1,
        focus_gap=FocusGap.REACHABLE,
        span_id="span_1"
    )

    turn_plan = TurnPlan(
        turn_id=1,
        goal="Test",
        hypotheses=[hyp],
        selected_hypothesis_id="hyp_1",
        selected_span_id="span_1"
    )

    service.emit_turn_plan("agent_123", turn_plan)

    flow = service.get_flow("agent_123")
    assert flow.context.current_candidate_node_id == "span_1"
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/services/test_flow_service_turn_plans.py::test_emit_turn_plan -v
```

Expected: `AttributeError: 'FlowService' object has no attribute 'emit_turn_plan'`

**Step 3: Add emit_turn_plan method**

```python
# Add to backend/services/flow_service.py

    def emit_turn_plan(
        self,
        agent_id: str,
        turn_plan: "TurnPlan"  # Forward ref to avoid circular import
    ) -> FlowNode:
        """
        Emit turn plan event for declarative routing.

        Turn plans provide investigation preview and authoritative
        span routing for all events in this turn.

        Args:
            agent_id: Agent identifier
            turn_plan: TurnPlan object with hypotheses and routing

        Returns:
            Created FlowNode
        """
        flow = self._flows.get(agent_id)
        if not flow:
            flow = self.initialize_flow(agent_id)

        # Create turn_plan node
        node = FlowNode(
            id=str(uuid.uuid4())[:8],
            type="turn_plan",
            label=f"Turn {turn_plan.turn_id}: {turn_plan.goal[:40]}...",
            status="completed",
            data={
                "turn_id": turn_plan.turn_id,
                "stage": turn_plan.stage,
                "goal": turn_plan.goal,
                "hypotheses": [
                    {
                        "hypothesis_id": h.hypothesis_id,
                        "parent_hypothesis_id": h.parent_hypothesis_id,
                        "label": h.label,
                        "state": h.state,
                        "activity": h.activity.value,
                        "created_turn_id": h.created_turn_id,
                        "focus_gap": h.focus_gap.value,
                        "focus_note": h.focus_note,
                        "span_id": h.span_id,
                        "parent_span_id": h.parent_span_id
                    }
                    for h in turn_plan.hypotheses
                ],
                "selected_hypothesis_id": turn_plan.selected_hypothesis_id,
                "selected_span_id": turn_plan.selected_span_id
            },
            # Span tracking
            span_id=turn_plan.selected_span_id,
            hypothesis_id=turn_plan.selected_hypothesis_id,
            turn_id=turn_plan.turn_id
        )

        flow.nodes.append(node)
        flow.current_node_id = node.id

        # Update context for event routing
        flow.context.current_candidate_node_id = turn_plan.selected_span_id

        self._notify_subscribers(agent_id, flow)
        return node
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/services/test_flow_service_turn_plans.py -v
```

Expected: PASS (2 tests)

**Step 5: Commit**

```bash
git add backend/services/flow_service.py backend/tests/services/test_flow_service_turn_plans.py
git commit -m "feat(flow-service): add turn plan emission

- Add emit_turn_plan() for declarative routing
- Create turn_plan node type
- Update flow context with selected_span_id
- Store full hypothesis metadata in node data"
```

---

### Task 15: Integrate Turn Plan Emission in ReAct Agent

**Files:**
- Modify: `backend/agents/react_agent.py`
- Test: `backend/tests/agents/test_react_turn_plans.py`

**Step 1: Write failing integration test**

```python
# backend/tests/agents/test_react_turn_plans.py
"""Tests for ReAct agent turn plan emission"""
import pytest
from unittest.mock import Mock, patch
from agents.react_agent import ReactAgent
from services.flow_service import flow_service

@pytest.mark.asyncio
async def test_react_emits_turn_plan_before_turn():
    """ReAct agent should emit turn plan at start of turn"""
    agent = ReactAgent(
        project_id="test_project",
        agent_id="agent_123",
        repo_path="/tmp/test_repo"
    )

    # Mock flow service
    with patch.object(flow_service, 'emit_turn_plan') as mock_emit:
        # Trigger agent turn (simplified)
        await agent._emit_turn_plan_for_hypothesis(
            hypothesis_id="hyp_1",
            hypothesis_label="Check SQL injection",
            turn_id=1,
            focus_gap="dataflow_evidenced"
        )

        # Verify turn plan emitted
        assert mock_emit.called
        call_args = mock_emit.call_args
        turn_plan = call_args[0][1]  # Second arg is TurnPlan

        assert turn_plan.turn_id == 1
        assert len(turn_plan.hypotheses) == 1
        assert turn_plan.hypotheses[0].hypothesis_id == "hyp_1"
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/agents/test_react_turn_plans.py::test_react_emits_turn_plan_before_turn -v
```

Expected: `AttributeError: 'ReactAgent' object has no attribute '_emit_turn_plan_for_hypothesis'`

**Step 3: Add turn plan emission helper to ReactAgent**

```python
# Add to backend/agents/react_agent.py

from models.turn_plan import TurnPlan, Hypothesis, HypothesisActivity, FocusGap
from services.flow_service import flow_service

class ReactAgent:
    def __init__(self, project_id: str, agent_id: str, repo_path: str):
        # ... existing init ...
        self._turn_counter = 0
        self._active_hypotheses: dict[str, Hypothesis] = {}

    async def _emit_turn_plan_for_hypothesis(
        self,
        hypothesis_id: str,
        hypothesis_label: str,
        turn_id: int,
        focus_gap: str = "other",
        parent_hypothesis_id: str | None = None
    ) -> str:
        """
        Emit turn plan for single hypothesis investigation.

        Returns:
            span_id for this hypothesis
        """
        from services.span_service import span_service

        # Create or get span
        if hypothesis_id in self._active_hypotheses:
            # Continuing
            hyp = self._active_hypotheses[hypothesis_id]
            hyp.state = "open"
            activity = HypothesisActivity.CONTINUING
            span_id = hyp.span_id
        else:
            # New hypothesis
            span_id = f"span_{hypothesis_id}"
            activity = HypothesisActivity.NEW

            # Create span in SpanService
            span_service.create_span(
                agent_id=self.agent_id,
                span_id=span_id,
                span_type="hypothesis",
                hypothesis_id=hypothesis_id,
                label=hypothesis_label,
                state="open"
            )

        # Create hypothesis
        hyp = Hypothesis(
            hypothesis_id=hypothesis_id,
            parent_hypothesis_id=parent_hypothesis_id,
            label=hypothesis_label,
            state="open",
            activity=activity,
            created_turn_id=turn_id,
            focus_gap=FocusGap(focus_gap),
            span_id=span_id,
            parent_span_id=None
        )

        self._active_hypotheses[hypothesis_id] = hyp

        # Create turn plan
        turn_plan = TurnPlan(
            turn_id=turn_id,
            stage=None,  # ReAct has no stages
            goal=f"Investigate: {hypothesis_label}",
            hypotheses=[hyp],
            selected_hypothesis_id=hypothesis_id,
            selected_span_id=span_id
        )

        # Emit to flow service
        flow_service.emit_turn_plan(self.agent_id, turn_plan)

        return span_id
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/agents/test_react_turn_plans.py -v
```

Expected: PASS (1 test)

**Step 5: Commit**

```bash
git add backend/agents/react_agent.py backend/tests/agents/test_react_turn_plans.py
git commit -m "feat(react-agent): add turn plan emission

- Add _emit_turn_plan_for_hypothesis() helper
- Track active hypotheses across turns
- Create spans in SpanService
- Emit turn plans to FlowService before each turn"
```

---

## Phase 5: Reconstruction Algorithm

### Task 16: Create Reconstruction Service Base

**Files:**
- Create: `backend/services/reconstruction_service.py`
- Test: `backend/tests/services/test_reconstruction_service.py`

**Step 1: Write failing test for reconstruction**

```python
# backend/tests/services/test_reconstruction_service.py
"""Tests for reconstruction algorithm"""
import pytest
from services.reconstruction_service import ReconstructionService
from services.flow_service import FlowNode
from models.investigation_trace import Artifact

def test_reconstruct_empty_events():
    """Should handle empty event list"""
    service = ReconstructionService()

    spans, edges, event_to_span = service.reconstruct_investigation_dag(
        events=[],
        artifacts={},
        agent_exec_id="agent_123"
    )

    # Should create unattributed span only
    assert len(spans) == 1
    assert "UNATTRIBUTED" in list(spans.keys())[0]
    assert len(edges) == 0
    assert len(event_to_span) == 0

def test_reconstruct_turn_plan_creates_span():
    """Turn plan event should create hypothesis span"""
    service = ReconstructionService()

    turn_plan_event = FlowNode(
        id="evt_1",
        type="turn_plan",
        label="Turn 1",
        data={
            "turn_id": 1,
            "goal": "Test",
            "hypotheses": [{
                "hypothesis_id": "hyp_1",
                "label": "Check SQL",
                "state": "open",
                "activity": "new",
                "created_turn_id": 1,
                "focus_gap": "dataflow_evidenced",
                "span_id": "span_1"
            }],
            "selected_hypothesis_id": "hyp_1",
            "selected_span_id": "span_1"
        }
    )

    spans, edges, event_to_span = service.reconstruct_investigation_dag(
        events=[turn_plan_event],
        artifacts={},
        agent_exec_id="agent_123"
    )

    # Should create hypothesis span
    assert "span_1" in spans
    assert spans["span_1"].span_type == "hypothesis"
    assert spans["span_1"].hypothesis_id == "hyp_1"

    # Turn plan event should be attached to span
    assert "evt_1" in event_to_span
    assert event_to_span["evt_1"] == "span_1"
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/services/test_reconstruction_service.py::test_reconstruct_empty_events -v
```

Expected: `ModuleNotFoundError: No module named 'services.reconstruction_service'`

**Step 3: Create ReconstructionService**

```python
# backend/services/reconstruction_service.py
"""
Reconstruction Service - Single-pass DAG reconstruction.

Transforms flat event stream into structured investigation DAG
using declarative routing from turn plans.
"""

from collections import defaultdict
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, field
from models.investigation_trace import Span, SpanType, SpanState, Artifact


@dataclass
class Edge:
    """DAG edge"""
    id: str
    source: str
    target: str
    edge_type: str
    label: Optional[str] = None
    style: Optional[str] = None
    hidden: bool = False
    metadata: dict = field(default_factory=dict)


def deterministic_span_id(agent_exec_id: str, suffix: str) -> str:
    """Generate deterministic span ID"""
    return f"{agent_exec_id}:{suffix}"


class ReconstructionService:
    """Reconstructs investigation DAG from event stream"""

    def reconstruct_investigation_dag(
        self,
        events: List,
        artifacts: Dict[str, Artifact],
        agent_exec_id: str
    ) -> Tuple[Dict[str, Span], List[Edge], Dict[str, str]]:
        """
        Single-pass streaming reconstruction.

        Args:
            events: Chronological flow events
            artifacts: Artifact dictionary
            agent_exec_id: Agent execution ID

        Returns:
            (spans, edges, event_to_span)
        """
        # Sort defensively for WebSocket stability
        sorted_events = sorted(events, key=lambda e: getattr(e, 'timestamp', ''))

        spans: Dict[str, Span] = {}
        hypothesis_to_base_span: Dict[str, str] = {}
        event_to_span: Dict[str, str] = {}

        # Create unattributed span
        unattributed_span_id = deterministic_span_id(agent_exec_id, "UNATTRIBUTED")
        spans[unattributed_span_id] = Span(
            span_id=unattributed_span_id,
            span_type=SpanType.PLACEHOLDER,
            hypothesis_id="UNATTRIBUTED",
            label="Unattributed Events",
            state=SpanState.OPEN,
            event_ids=[],
            artifact_ids=[]
        )

        # Current routing context
        current_selected_span: Optional[str] = None
        current_selected_hypothesis_id: Optional[str] = None
        current_stage: Optional[str] = None

        # Process events
        for event in sorted_events:

            # Handle turn_plan
            if event.type == "turn_plan":
                current_stage = event.data.get("stage")
                plan = event.data

                # Create spans for hypotheses
                for hyp_data in plan.get("hypotheses", []):
                    span_id = hyp_data.get("span_id")
                    if span_id and span_id not in spans:
                        spans[span_id] = Span(
                            span_id=span_id,
                            span_type=SpanType.HYPOTHESIS,
                            hypothesis_id=hyp_data["hypothesis_id"],
                            label=hyp_data["label"],
                            state=SpanState.OPEN,
                            parent_span_id=hyp_data.get("parent_span_id"),
                            created_turn_id=hyp_data.get("created_turn_id"),
                            focus_gap=hyp_data.get("focus_gap"),
                            stage=current_stage,
                            event_ids=[],
                            artifact_ids=[]
                        )
                        hypothesis_to_base_span[hyp_data["hypothesis_id"]] = span_id

                # Update routing
                current_selected_span = plan.get("selected_span_id")
                current_selected_hypothesis_id = plan.get("selected_hypothesis_id")

                # Attach turn_plan event
                span_id = current_selected_span or unattributed_span_id
                if span_id in spans:
                    spans[span_id].event_ids.append(event.id)
                    event_to_span[event.id] = span_id
                continue

            # Handle other events: route to span
            span_id = self._route_event_to_span(
                event,
                current_selected_span,
                current_selected_hypothesis_id,
                hypothesis_to_base_span,
                spans,
                unattributed_span_id
            )

            # Attach event
            if span_id in spans:
                spans[span_id].event_ids.append(event.id)
                event_to_span[event.id] = span_id

        # Build edges
        edges = self._build_edges(spans, sorted_events, event_to_span)

        return spans, edges, event_to_span

    def _route_event_to_span(
        self,
        event,
        current_selected_span: Optional[str],
        current_selected_hypothesis_id: Optional[str],
        hypothesis_to_base_span: Dict[str, str],
        spans: Dict[str, Span],
        unattributed_span_id: str
    ) -> str:
        """Route event to correct span (priority order)"""
        # Priority 1: Explicit span_id
        if hasattr(event, 'span_id') and event.span_id:
            if event.span_id in spans:
                return event.span_id

        # Priority 2: Current selected span
        if current_selected_span and current_selected_span in spans:
            return current_selected_span

        # Priority 3: Hypothesis fallback
        if hasattr(event, 'hypothesis_id') and event.hypothesis_id:
            span_id = hypothesis_to_base_span.get(event.hypothesis_id)
            if span_id and span_id in spans:
                return span_id

        # Default: unattributed
        return unattributed_span_id

    def _build_edges(
        self,
        spans: Dict[str, Span],
        events: List,
        event_to_span: Dict[str, str]
    ) -> List[Edge]:
        """Build DAG edges"""
        edges = []

        # Span hierarchy
        for span in spans.values():
            if span.parent_span_id and span.parent_span_id in spans:
                edges.append(Edge(
                    id=f"hierarchy_{span.parent_span_id}_{span.span_id}",
                    source=span.parent_span_id,
                    target=span.span_id,
                    edge_type="parent_child"
                ))

        return edges


# Global instance
reconstruction_service = ReconstructionService()
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/services/test_reconstruction_service.py -v
```

Expected: PASS (2 tests)

**Step 5: Commit**

```bash
git add backend/services/reconstruction_service.py backend/tests/services/test_reconstruction_service.py
git commit -m "feat(reconstruction): add base reconstruction service

- Add single-pass streaming reconstruction algorithm
- Implement declarative routing via turn plans
- Create unattributed span for orphan events
- Build span hierarchy edges"
```

---

### Task 17: Add Artifact Provenance Edge Construction

**Files:**
- Modify: `backend/services/reconstruction_service.py`
- Modify: `backend/tests/services/test_reconstruction_service.py`

**Step 1: Write failing test for artifact edges**

```python
# Add to backend/tests/services/test_reconstruction_service.py

def test_artifact_provenance_creates_edges():
    """Artifact cross-links should create evidence edges"""
    service = ReconstructionService()
    from services.artifact_service import artifact_service
    from models.investigation_trace import generate_artifact_id

    # Clear artifacts
    artifact_service.clear_artifacts()

    # Create artifact
    content = "vulnerable code"
    artifact_id = generate_artifact_id(content)
    artifact = artifact_service.create_artifact(
        artifact_id=artifact_id,
        artifact_type="file_snippet",
        content=content,
        summary="Snippet from auth.py"
    )

    # Mark provenance
    artifact_service.add_producer("span_1", artifact_id)
    artifact_service.add_consumer("span_2", artifact_id)

    # Create events
    turn_plan_1 = FlowNode(
        id="evt_1",
        type="turn_plan",
        label="Turn 1",
        data={
            "turn_id": 1,
            "hypotheses": [{
                "hypothesis_id": "hyp_1",
                "label": "Producer",
                "state": "open",
                "activity": "new",
                "created_turn_id": 1,
                "focus_gap": "reachable",
                "span_id": "span_1"
            }],
            "selected_span_id": "span_1"
        },
        timestamp="2024-01-01T00:00:00"
    )

    tool_result = FlowNode(
        id="evt_2",
        type="tool_result",
        label="Read file",
        span_id="span_1",
        output_artifact_ids=[artifact_id],
        timestamp="2024-01-01T00:00:01"
    )

    turn_plan_2 = FlowNode(
        id="evt_3",
        type="turn_plan",
        label="Turn 2",
        data={
            "turn_id": 2,
            "hypotheses": [{
                "hypothesis_id": "hyp_2",
                "label": "Consumer",
                "state": "open",
                "activity": "new",
                "created_turn_id": 2,
                "focus_gap": "dataflow_evidenced",
                "span_id": "span_2"
            }],
            "selected_span_id": "span_2"
        },
        timestamp="2024-01-01T00:00:02"
    )

    analysis = FlowNode(
        id="evt_4",
        type="analysis",
        label="Analyze code",
        span_id="span_2",
        input_artifact_ids=[artifact_id],
        timestamp="2024-01-01T00:00:03"
    )

    spans, edges, _ = service.reconstruct_investigation_dag(
        events=[turn_plan_1, tool_result, turn_plan_2, analysis],
        artifacts={artifact_id: artifact},
        agent_exec_id="agent_123"
    )

    # Should have evidence edge from span_1 to span_2
    evidence_edges = [e for e in edges if e.edge_type == "evidence_link"]
    assert len(evidence_edges) == 1
    assert evidence_edges[0].source == "span_1"
    assert evidence_edges[0].target == "span_2"
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/services/test_reconstruction_service.py::test_artifact_provenance_creates_edges -v
```

Expected: FAIL - no evidence edges created

**Step 3: Add artifact provenance edge construction**

```python
# Modify backend/services/reconstruction_service.py

    def reconstruct_investigation_dag(
        self,
        events: List,
        artifacts: Dict[str, Artifact],
        agent_exec_id: str
    ) -> Tuple[Dict[str, Span], List[Edge], Dict[str, str]]:
        """Single-pass streaming reconstruction."""
        # ... existing code ...

        # Provenance indices
        artifact_producer_spans: Dict[str, Set[str]] = defaultdict(set)
        artifact_consumer_spans: Dict[str, Set[str]] = defaultdict(set)

        # Process events
        for event in sorted_events:
            # ... existing turn_plan handling ...

            # Route event
            span_id = self._route_event_to_span(...)

            # Attach event
            if span_id in spans:
                spans[span_id].event_ids.append(event.id)
                event_to_span[event.id] = span_id

                # Track artifact provenance
                if hasattr(event, 'output_artifact_ids'):
                    for aid in event.output_artifact_ids or []:
                        spans[span_id].artifact_ids.append(aid)
                        artifact_producer_spans[aid].add(span_id)

                if hasattr(event, 'input_artifact_ids'):
                    for aid in event.input_artifact_ids or []:
                        artifact_consumer_spans[aid].add(span_id)

        # Deduplicate artifacts
        for span in spans.values():
            span.artifact_ids = list(dict.fromkeys(span.artifact_ids))

        # Build edges with provenance
        edges = self._build_edges(
            spans, sorted_events, event_to_span,
            artifact_producer_spans, artifact_consumer_spans,
            artifacts
        )

        return spans, edges, event_to_span

    def _build_edges(
        self,
        spans: Dict[str, Span],
        events: List,
        event_to_span: Dict[str, str],
        artifact_producer_spans: Dict[str, Set[str]],
        artifact_consumer_spans: Dict[str, Set[str]],
        artifacts: Dict[str, Artifact]
    ) -> List[Edge]:
        """Build DAG edges including artifact provenance"""
        edges = []

        # 1. Span hierarchy
        for span in spans.values():
            if span.parent_span_id and span.parent_span_id in spans:
                edges.append(Edge(
                    id=f"hierarchy_{span.parent_span_id}_{span.span_id}",
                    source=span.parent_span_id,
                    target=span.span_id,
                    edge_type="parent_child"
                ))

        # 2. Artifact provenance (time-directional)
        span_pair_artifacts: Dict[Tuple[str, str], Set[str]] = defaultdict(set)

        for aid, prod_spans in artifact_producer_spans.items():
            for prod_span in prod_spans:
                for cons_span in artifact_consumer_spans.get(aid, set()):
                    if cons_span != prod_span:
                        # Time-directional check
                        prod_events = [e for e in events if event_to_span.get(e.id) == prod_span]
                        cons_events = [e for e in events if event_to_span.get(e.id) == cons_span]

                        if prod_events and cons_events:
                            prod_latest = max(getattr(e, 'timestamp', '') for e in prod_events)
                            cons_earliest = min(getattr(e, 'timestamp', '') for e in cons_events)

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
                    summary = artifact.summary[:20] + "..." if artifact else "(missing)"
                    edges.append(Edge(
                        id=f"evidence_{aid}_{prod_span}_{cons_span}",
                        source=prod_span,
                        target=cons_span,
                        edge_type="evidence_link",
                        label=summary,
                        style="dashed"
                    ))

        return edges
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/services/test_reconstruction_service.py -v
```

Expected: PASS (3 tests)

**Step 5: Commit**

```bash
git add backend/services/reconstruction_service.py backend/tests/services/test_reconstruction_service.py
git commit -m "feat(reconstruction): add artifact provenance edges

- Track artifact producers/consumers during reconstruction
- Build time-directional evidence edges
- Bundle edges when >= 3 artifacts between spans
- Include artifact summaries in edge labels"
```

---

## Phase 6: Frontend Visualization

### Task 18: Create React Flow Tree Layout Component

**Files:**
- Create: `frontend/components/InvestigationFlow/TreeLayout.tsx`
- Create: `frontend/components/InvestigationFlow/types.ts`
- Test: `frontend/components/InvestigationFlow/__tests__/TreeLayout.test.tsx`

**Step 1: Write failing test for TreeLayout**

```typescript
// frontend/components/InvestigationFlow/__tests__/TreeLayout.test.tsx
import { render, screen } from '@testing-library/react'
import { TreeLayout } from '../TreeLayout'
import { ReactFlowProvider } from 'reactflow'

describe('TreeLayout', () => {
  it('should render empty state when no spans', () => {
    render(
      <ReactFlowProvider>
        <TreeLayout spans={{}} edges={[]} />
      </ReactFlowProvider>
    )

    expect(screen.getByText(/no investigation data/i)).toBeInTheDocument()
  })

  it('should render hypothesis nodes', () => {
    const spans = {
      'span_1': {
        span_id: 'span_1',
        span_type: 'hypothesis',
        label: 'Check SQL injection',
        state: 'open',
        event_ids: ['evt_1', 'evt_2'],
        artifact_ids: []
      }
    }

    render(
      <ReactFlowProvider>
        <TreeLayout spans={spans} edges={[]} />
      </ReactFlowProvider>
    )

    expect(screen.getByText(/Check SQL injection/i)).toBeInTheDocument()
  })
})
```

**Step 2: Run test to verify it fails**

```bash
cd frontend
npm test TreeLayout.test.tsx
```

Expected: `Cannot find module '../TreeLayout'`

**Step 3: Create types**

```typescript
// frontend/components/InvestigationFlow/types.ts
export type SpanType = 'hypothesis' | 'hypothesis_visit' | 'critic_pass' | 'placeholder'
export type SpanState = 'open' | 'completed' | 'discarded'
export type Outcome = 'confirmed' | 'refuted' | 'inconclusive' | null

export interface Span {
  span_id: string
  span_type: SpanType
  hypothesis_id: string
  label: string
  state: SpanState
  outcome?: Outcome
  parent_span_id?: string
  created_turn_id?: number
  completed_at?: string
  focus_gap?: string
  focus_note?: string
  stage?: string
  event_ids: string[]
  artifact_ids: string[]
  is_collapsed?: boolean
}

export interface Edge {
  id: string
  source: string
  target: string
  edge_type: string
  label?: string
  style?: string
  hidden?: boolean
}
```

**Step 4: Create TreeLayout component**

```typescript
// frontend/components/InvestigationFlow/TreeLayout.tsx
import React, { useMemo, useState } from 'react'
import ReactFlow, {
  Node,
  Edge as ReactFlowEdge,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState
} from 'reactflow'
import 'reactflow/dist/style.css'
import { Span, Edge } from './types'
import { HypothesisNode } from './nodes/HypothesisNode'

const nodeTypes = {
  hypothesis: HypothesisNode
}

interface TreeLayoutProps {
  spans: Record<string, Span>
  edges: Edge[]
}

export function TreeLayout({ spans, edges }: TreeLayoutProps) {
  const [collapsedSpans, setCollapsedSpans] = useState<Set<string>>(new Set())

  // Convert spans to React Flow nodes
  const nodes: Node[] = useMemo(() => {
    const nodeList: Node[] = []

    Object.values(spans).forEach((span, idx) => {
      // Skip collapsed children
      if (span.parent_span_id && collapsedSpans.has(span.parent_span_id)) {
        return
      }

      nodeList.push({
        id: span.span_id,
        type: 'hypothesis',
        position: { x: 0, y: idx * 150 }, // Placeholder, will layout properly
        data: {
          span,
          isCollapsed: collapsedSpans.has(span.span_id),
          onToggleCollapse: () => {
            setCollapsedSpans(prev => {
              const next = new Set(prev)
              if (next.has(span.span_id)) {
                next.delete(span.span_id)
              } else {
                next.add(span.span_id)
              }
              return next
            })
          }
        }
      })
    })

    return nodeList
  }, [spans, collapsedSpans])

  // Convert edges to React Flow edges
  const reactFlowEdges: ReactFlowEdge[] = useMemo(() => {
    return edges
      .filter(edge => !edge.hidden)
      .map(edge => ({
        id: edge.id,
        source: edge.source,
        target: edge.target,
        label: edge.label,
        type: edge.edge_type === 'evidence_link' ? 'smoothstep' : 'default',
        style: edge.style === 'dashed' ? { strokeDasharray: '5,5' } : undefined
      }))
  }, [edges])

  const [nodesState, , onNodesChange] = useNodesState(nodes)
  const [edgesState, , onEdgesChange] = useEdgesState(reactFlowEdges)

  if (Object.keys(spans).length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-gray-500">
        <p>No investigation data available</p>
      </div>
    )
  }

  return (
    <div className="w-full h-full">
      <ReactFlow
        nodes={nodesState}
        edges={edgesState}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        nodeTypes={nodeTypes}
        fitView
      >
        <Background />
        <Controls />
        <MiniMap />
      </ReactFlow>
    </div>
  )
}
```

**Step 5: Create HypothesisNode component**

```typescript
// frontend/components/InvestigationFlow/nodes/HypothesisNode.tsx
import React from 'react'
import { Handle, Position } from 'reactflow'
import { Span } from '../types'

interface HypothesisNodeProps {
  data: {
    span: Span
    isCollapsed: boolean
    onToggleCollapse: () => void
  }
}

export function HypothesisNode({ data }: HypothesisNodeProps) {
  const { span, isCollapsed, onToggleCollapse } = data

  const outcomeColors = {
    confirmed: 'border-green-500 bg-green-50',
    refuted: 'border-red-500 bg-red-50',
    inconclusive: 'border-yellow-500 bg-yellow-50'
  }

  const stateColors = {
    open: 'border-blue-500 bg-blue-50',
    completed: outcomeColors[span.outcome || 'inconclusive'],
    discarded: 'border-gray-500 bg-gray-50'
  }

  return (
    <div
      className={`px-4 py-3 rounded-lg border-2 shadow-sm min-w-[200px] ${
        stateColors[span.state]
      }`}
    >
      <Handle type="target" position={Position.Top} />

      <div className="flex items-start justify-between gap-2">
        <div className="flex-1">
          <div className="font-medium text-sm">{span.label}</div>
          <div className="text-xs text-gray-600 mt-1">
            {span.event_ids.length} events
            {span.artifact_ids.length > 0 && ` • ${span.artifact_ids.length} artifacts`}
          </div>
        </div>

        {span.event_ids.length > 0 && (
          <button
            onClick={onToggleCollapse}
            className="text-gray-500 hover:text-gray-700"
          >
            {isCollapsed ? '▶' : '▼'}
          </button>
        )}
      </div>

      {span.focus_gap && (
        <div className="mt-2 text-xs text-gray-500 italic">
          Gap: {span.focus_gap}
        </div>
      )}

      <Handle type="source" position={Position.Bottom} />
    </div>
  )
}
```

**Step 6: Run test to verify it passes**

```bash
npm test TreeLayout.test.tsx
```

Expected: PASS (2 tests)

**Step 7: Commit**

```bash
git add frontend/components/InvestigationFlow/
git commit -m "feat(ui): add tree layout visualization

- Create TreeLayout component with React Flow
- Add HypothesisNode component with collapse/expand
- Support span hierarchy visualization
- Add outcome-based coloring
- Show event/artifact counts"
```

---

### Task 19: Add WebSocket Reconstruction Integration

**Files:**
- Create: `frontend/hooks/useInvestigationFlow.ts`
- Create: `frontend/lib/reconstructionClient.ts`
- Test: `frontend/hooks/__tests__/useInvestigationFlow.test.ts`

**Step 1: Write failing test for reconstruction hook**

```typescript
// frontend/hooks/__tests__/useInvestigationFlow.test.ts
import { renderHook, waitFor } from '@testing-library/react'
import { useInvestigationFlow } from '../useInvestigationFlow'

describe('useInvestigationFlow', () => {
  it('should reconstruct spans from events', async () => {
    const mockEvents = [
      {
        id: 'evt_1',
        type: 'turn_plan',
        timestamp: '2024-01-01T00:00:00',
        data: {
          turn_id: 1,
          hypotheses: [{
            hypothesis_id: 'hyp_1',
            label: 'Test hypothesis',
            state: 'open',
            activity: 'new',
            created_turn_id: 1,
            focus_gap: 'reachable',
            span_id: 'span_1'
          }],
          selected_span_id: 'span_1'
        }
      }
    ]

    const { result } = renderHook(() =>
      useInvestigationFlow('agent_123', mockEvents)
    )

    await waitFor(() => {
      expect(result.current.spans).toBeDefined()
      expect(Object.keys(result.current.spans).length).toBeGreaterThan(0)
    })

    expect(result.current.spans['span_1']).toBeDefined()
    expect(result.current.spans['span_1'].label).toBe('Test hypothesis')
  })
})
```

**Step 2: Run test to verify it fails**

```bash
npm test useInvestigationFlow.test.ts
```

Expected: `Cannot find module '../useInvestigationFlow'`

**Step 3: Create reconstruction client**

```typescript
// frontend/lib/reconstructionClient.ts
import { Span, Edge } from '@/components/InvestigationFlow/types'

interface ReconstructionResult {
  spans: Record<string, Span>
  edges: Edge[]
  event_to_span: Record<string, string>
}

export async function reconstructInvestigationDag(
  agentId: string,
  events: any[]
): Promise<ReconstructionResult> {
  // Call backend reconstruction API
  const response = await fetch(`/api/agents/${agentId}/reconstruct`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ events })
  })

  if (!response.ok) {
    throw new Error('Reconstruction failed')
  }

  return response.json()
}
```

**Step 4: Create hook**

```typescript
// frontend/hooks/useInvestigationFlow.ts
import { useState, useEffect } from 'react'
import { Span, Edge } from '@/components/InvestigationFlow/types'
import { reconstructInvestigationDag } from '@/lib/reconstructionClient'

export function useInvestigationFlow(agentId: string, events: any[]) {
  const [spans, setSpans] = useState<Record<string, Span>>({})
  const [edges, setEdges] = useState<Edge[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<Error | null>(null)

  useEffect(() => {
    if (!agentId || events.length === 0) {
      return
    }

    let cancelled = false

    async function reconstruct() {
      setIsLoading(true)
      setError(null)

      try {
        const result = await reconstructInvestigationDag(agentId, events)

        if (!cancelled) {
          setSpans(result.spans)
          setEdges(result.edges)
        }
      } catch (err) {
        if (!cancelled) {
          setError(err as Error)
        }
      } finally {
        if (!cancelled) {
          setIsLoading(false)
        }
      }
    }

    reconstruct()

    return () => {
      cancelled = true
    }
  }, [agentId, events])

  return { spans, edges, isLoading, error }
}
```

**Step 5: Run test to verify it passes**

```bash
npm test useInvestigationFlow.test.ts
```

Expected: PASS (1 test)

**Step 6: Commit**

```bash
git add frontend/hooks/useInvestigationFlow.ts frontend/lib/reconstructionClient.ts frontend/hooks/__tests__/
git commit -m "feat(ui): add investigation flow reconstruction hook

- Create useInvestigationFlow hook
- Add reconstructionClient for backend API calls
- Support real-time reconstruction updates
- Handle loading and error states"
```

---

## Phase 7: Feature Flag Rollout

### Task 20: Add Feature Flag System

**Files:**
- Create: `backend/services/feature_flags.py`
- Create: `frontend/lib/featureFlags.ts`
- Test: `backend/tests/services/test_feature_flags.py`

**Step 1: Write failing test for feature flags**

```python
# backend/tests/services/test_feature_flags.py
"""Tests for feature flag service"""
import pytest
from services.feature_flags import FeatureFlagService, Flag

def test_feature_flag_enabled():
    """Should check if feature flag is enabled"""
    service = FeatureFlagService()

    # Default disabled
    assert service.is_enabled(Flag.SPAN_BASED_FLOW) is False

    # Enable
    service.enable(Flag.SPAN_BASED_FLOW)
    assert service.is_enabled(Flag.SPAN_BASED_FLOW) is True

def test_feature_flag_rollout_percentage():
    """Should support gradual rollout by percentage"""
    service = FeatureFlagService()

    # Enable for 50% of users
    service.set_rollout_percentage(Flag.SPAN_BASED_FLOW, 50)

    # User hash determines eligibility
    user_a = service.is_enabled_for_user(Flag.SPAN_BASED_FLOW, "user_a")
    user_b = service.is_enabled_for_user(Flag.SPAN_BASED_FLOW, "user_b")

    # Should be deterministic
    assert service.is_enabled_for_user(Flag.SPAN_BASED_FLOW, "user_a") == user_a
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/services/test_feature_flags.py::test_feature_flag_enabled -v
```

Expected: `ModuleNotFoundError: No module named 'services.feature_flags'`

**Step 3: Create feature flag service**

```python
# backend/services/feature_flags.py
"""
Feature Flag Service - Gradual rollout control.

Supports:
- Boolean flags (all on/off)
- Percentage rollout (gradual)
- User-specific overrides
"""

from enum import Enum
import hashlib


class Flag(str, Enum):
    """Available feature flags"""
    SPAN_BASED_FLOW = "span_based_flow_visualization"
    DUAL_WRITE_MODE = "dual_write_mode"


class FeatureFlagService:
    """Manages feature flags for gradual rollout"""

    def __init__(self):
        self._flags: dict[Flag, bool] = {
            Flag.SPAN_BASED_FLOW: False,
            Flag.DUAL_WRITE_MODE: True  # Enabled by default
        }
        self._rollout_percentages: dict[Flag, int] = {}
        self._user_overrides: dict[tuple[Flag, str], bool] = {}

    def is_enabled(self, flag: Flag) -> bool:
        """Check if flag is globally enabled"""
        return self._flags.get(flag, False)

    def enable(self, flag: Flag) -> None:
        """Enable flag globally"""
        self._flags[flag] = True

    def disable(self, flag: Flag) -> None:
        """Disable flag globally"""
        self._flags[flag] = False

    def set_rollout_percentage(self, flag: Flag, percentage: int) -> None:
        """Set rollout percentage (0-100)"""
        if not 0 <= percentage <= 100:
            raise ValueError("Percentage must be 0-100")
        self._rollout_percentages[flag] = percentage

    def is_enabled_for_user(self, flag: Flag, user_id: str) -> bool:
        """Check if flag is enabled for specific user"""
        # Check override
        override_key = (flag, user_id)
        if override_key in self._user_overrides:
            return self._user_overrides[override_key]

        # Check global
        if self._flags.get(flag, False):
            return True

        # Check percentage rollout
        if flag in self._rollout_percentages:
            percentage = self._rollout_percentages[flag]
            user_hash = int(hashlib.md5(f"{flag}:{user_id}".encode()).hexdigest(), 16)
            return (user_hash % 100) < percentage

        return False

    def set_user_override(self, flag: Flag, user_id: str, enabled: bool) -> None:
        """Override flag for specific user"""
        self._user_overrides[(flag, user_id)] = enabled


# Global instance
feature_flags = FeatureFlagService()
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/services/test_feature_flags.py -v
```

Expected: PASS (2 tests)

**Step 5: Create frontend feature flags**

```typescript
// frontend/lib/featureFlags.ts
export enum FeatureFlag {
  SPAN_BASED_FLOW = 'span_based_flow_visualization',
  DUAL_WRITE_MODE = 'dual_write_mode'
}

class FeatureFlagClient {
  private flags: Map<FeatureFlag, boolean> = new Map()

  async fetchFlags(userId: string): Promise<void> {
    const response = await fetch(`/api/feature-flags?user_id=${userId}`)
    const data = await response.json()

    Object.entries(data.flags).forEach(([key, value]) => {
      this.flags.set(key as FeatureFlag, value as boolean)
    })
  }

  isEnabled(flag: FeatureFlag): boolean {
    return this.flags.get(flag) ?? false
  }
}

export const featureFlags = new FeatureFlagClient()
```

**Step 6: Commit**

```bash
git add backend/services/feature_flags.py backend/tests/services/test_feature_flags.py frontend/lib/featureFlags.ts
git commit -m "feat(feature-flags): add feature flag system

- Add FeatureFlagService with percentage rollout
- Support user-specific overrides
- Add SPAN_BASED_FLOW and DUAL_WRITE_MODE flags
- Create frontend feature flag client"
```

---

### Task 21: Add Dual-Write Mode Toggle

**Files:**
- Modify: `backend/services/flow_service.py`
- Test: `backend/tests/services/test_dual_write_mode.py`

**Step 1: Write failing test for dual-write**

```python
# backend/tests/services/test_dual_write_mode.py
"""Tests for dual-write mode"""
import pytest
from services.flow_service import FlowService
from services.feature_flags import feature_flags, Flag

def test_dual_write_emits_both_formats():
    """When dual-write enabled, emit both legacy and span-based events"""
    service = FlowService()
    service.initialize_flow("agent_123")

    # Enable dual-write
    feature_flags.enable(Flag.DUAL_WRITE_MODE)

    # Add node with span fields
    node = service.add_node(
        agent_id="agent_123",
        node_type="tool_call",
        label="Read file",
        data={"tool": "read_file"},
        span_id="span_1",
        hypothesis_id="hyp_1"
    )

    # Should have both legacy and span fields
    assert node.label == "Read file"  # Legacy
    assert node.span_id == "span_1"    # Span-based
    assert node.hypothesis_id == "hyp_1"

def test_legacy_mode_omits_span_fields():
    """When dual-write disabled, omit span fields"""
    service = FlowService()
    service.initialize_flow("agent_123")

    # Disable dual-write
    feature_flags.disable(Flag.DUAL_WRITE_MODE)

    node = service.add_node(
        agent_id="agent_123",
        node_type="tool_call",
        label="Read file",
        data={"tool": "read_file"}
    )

    # Should only have legacy fields
    assert node.label == "Read file"
    assert node.span_id is None
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/services/test_dual_write_mode.py::test_dual_write_emits_both_formats -v
```

Expected: FAIL - span fields always present

**Step 3: Add dual-write mode logic**

```python
# Modify backend/services/flow_service.py

from services.feature_flags import feature_flags, Flag

class FlowService:
    def add_node(
        self,
        agent_id: str,
        node_type: NodeType,
        label: str,
        data: Optional[dict] = None,
        *,
        parent_id: Optional[str] = None,
        edge_label: Optional[str] = None,
        span_id: Optional[str] = None,
        hypothesis_id: Optional[str] = None,
        # ... other params ...
    ) -> FlowNode:
        """Add node with optional dual-write mode"""
        flow = self._flows.get(agent_id)
        if not flow:
            flow = self.initialize_flow(agent_id)

        # Check dual-write mode
        dual_write_enabled = feature_flags.is_enabled(Flag.DUAL_WRITE_MODE)

        # Determine parent
        if parent_id is None and auto_parent:
            # ... existing logic ...
            pass

        previous_node_id = parent_id or flow.current_node_id

        # Create node
        node = FlowNode(
            id=str(uuid.uuid4())[:8],
            type=node_type,
            label=label,
            status="pending",
            data=data or {},
            # Span fields (only if dual-write enabled)
            span_id=span_id if dual_write_enabled else None,
            hypothesis_id=hypothesis_id if dual_write_enabled else None,
            # ... other fields ...
        )

        # ... rest of method ...

        return node
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/services/test_dual_write_mode.py -v
```

Expected: PASS (2 tests)

**Step 5: Commit**

```bash
git add backend/services/flow_service.py backend/tests/services/test_dual_write_mode.py
git commit -m "feat(flow-service): add dual-write mode support

- Check DUAL_WRITE_MODE flag in add_node()
- Conditionally emit span fields
- Support gradual migration from legacy format
- Maintain backward compatibility"
```

---

## Execution Options

Plan complete and saved to `docs/plans/2026-01-13-phase4-7-complete-trace-system.md`.

**Two execution options:**

**1. Subagent-Driven (this session)** - I dispatch fresh subagent per task, review between tasks, fast iteration

**2. Parallel Session (separate)** - Open new session with executing-plans, batch execution with checkpoints

**Which approach?**

"""
Flow Service - Tracks investigation flow for real-time visualization.

Maintains a graph of nodes (actions) and edges (transitions) that
can be visualized in the frontend as the agent investigates.
"""

import uuid
from datetime import datetime
from typing import Optional, Callable, Literal
from dataclasses import dataclass, field, asdict
from collections import defaultdict


@dataclass
class FlowContext:
    """Tracks investigation context for proper tree branching."""
    current_file: Optional[str] = None
    current_function: Optional[str] = None
    current_candidate_node_id: Optional[str] = None
    investigation_root_id: Optional[str] = None


NodeType = Literal[
    # Existing
    "user_input",
    "tool_call",
    "tool_result",
    "analysis",
    "finding",
    "code_read",
    "search",
    "scan",
    "entry_point",
    "dangerous_sink",
    "investigation",
    # NEW architectural nodes
    "file",
    "function",
    "call",
    "external",
    "auth_boundary",
]

NodeStatus = Literal["pending", "running", "completed", "failed"]


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

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class FlowEdge:
    id: str
    source: str
    target: str
    label: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class InvestigationFlow:
    session_id: str
    nodes: list[FlowNode] = field(default_factory=list)
    edges: list[FlowEdge] = field(default_factory=list)
    current_node_id: Optional[str] = None
    context: FlowContext = field(default_factory=FlowContext)

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "current_node_id": self.current_node_id,
            "context": asdict(self.context),
        }


class FlowService:
    """Manages investigation flows for agents."""

    def __init__(self):
        self._flows: dict[str, InvestigationFlow] = {}
        self._subscribers: dict[str, set[Callable]] = defaultdict(set)

    def initialize_flow(self, agent_id: str) -> InvestigationFlow:
        """Create a new flow for an agent."""
        flow = InvestigationFlow(session_id=agent_id)
        self._flows[agent_id] = flow
        return flow

    def get_flow(self, agent_id: str) -> Optional[InvestigationFlow]:
        """Get flow for an agent."""
        return self._flows.get(agent_id)

    def add_node(
        self,
        agent_id: str,
        node_type: NodeType,
        label: str,
        data: Optional[dict] = None,
        *,
        parent_id: Optional[str] = None,
        edge_label: Optional[str] = None,
        llm_reasoning: Optional[str] = None,
        code_context: Optional[str] = None,
        tool_result_summary: Optional[str] = None,
        confidence_score: Optional[float] = None,
        set_current: bool = True,
    ) -> FlowNode:
        """Add a node to the flow."""
        flow = self._flows.get(agent_id)
        if not flow:
            flow = self.initialize_flow(agent_id)

        previous_node_id = parent_id or flow.current_node_id

        node = FlowNode(
            id=str(uuid.uuid4())[:8],
            type=node_type,
            label=label,
            status="pending",
            data=data or {},
            llm_reasoning=llm_reasoning,
            code_context=code_context,
            tool_result_summary=tool_result_summary,
            confidence_score=confidence_score,
        )

        flow.nodes.append(node)
        if set_current:
            flow.current_node_id = node.id

        # Add edge from previous node
        if previous_node_id:
            edge = FlowEdge(
                id=str(uuid.uuid4())[:8],
                source=previous_node_id,
                target=node.id,
                label=edge_label,
            )
            flow.edges.append(edge)

        self._notify_subscribers(agent_id, flow)
        return node

    def update_node_status(
        self,
        agent_id: str,
        node_id: str,
        status: NodeStatus,
        duration_ms: Optional[int] = None,
    ) -> None:
        """Update a node's status."""
        flow = self._flows.get(agent_id)
        if not flow:
            return

        for node in flow.nodes:
            if node.id == node_id:
                node.status = status
                if duration_ms is not None:
                    node.duration_ms = duration_ms
                break

        self._notify_subscribers(agent_id, flow)

    def update_node_data(
        self,
        agent_id: str,
        node_id: str,
        data: dict,
    ) -> None:
        """Update a node's data."""
        flow = self._flows.get(agent_id)
        if not flow:
            return

        for node in flow.nodes:
            if node.id == node_id:
                node.data.update(data)
                break

        self._notify_subscribers(agent_id, flow)

    def update_node_fields(
        self,
        agent_id: str,
        node_id: str,
        *,
        label: Optional[str] = None,
        llm_reasoning: Optional[str] = None,
        code_context: Optional[str] = None,
        tool_result_summary: Optional[str] = None,
        confidence_score: Optional[float] = None,
    ) -> None:
        """Update top-level fields on a node (not stored in `data`)."""
        flow = self._flows.get(agent_id)
        if not flow:
            return

        for node in flow.nodes:
            if node.id != node_id:
                continue
            if label is not None:
                node.label = label
            if llm_reasoning is not None:
                node.llm_reasoning = llm_reasoning
            if code_context is not None:
                node.code_context = code_context
            if tool_result_summary is not None:
                node.tool_result_summary = tool_result_summary
            if confidence_score is not None:
                node.confidence_score = confidence_score
            break

        self._notify_subscribers(agent_id, flow)

    def add_edge(
        self,
        agent_id: str,
        source_id: str,
        target_id: str,
        label: Optional[str] = None,
    ) -> None:
        """Add an edge between nodes."""
        flow = self._flows.get(agent_id)
        if not flow:
            return

        edge = FlowEdge(
            id=str(uuid.uuid4())[:8],
            source=source_id,
            target=target_id,
            label=label,
        )
        flow.edges.append(edge)
        self._notify_subscribers(agent_id, flow)

    def branch_from(self, agent_id: str, node_id: str) -> None:
        """Mark a node as the start of a branch."""
        flow = self._flows.get(agent_id)
        if flow:
            flow.current_node_id = node_id

    def clear_flow(self, agent_id: str) -> None:
        """Clear flow for an agent."""
        if agent_id in self._flows:
            del self._flows[agent_id]
        if agent_id in self._subscribers:
            del self._subscribers[agent_id]

    def subscribe(self, agent_id: str, callback: Callable) -> Callable:
        """Subscribe to flow updates. Returns unsubscribe function."""
        self._subscribers[agent_id].add(callback)

        # Send current flow immediately
        flow = self._flows.get(agent_id)
        if flow:
            callback(flow.to_dict())

        def unsubscribe():
            self._subscribers[agent_id].discard(callback)

        return unsubscribe

    def _notify_subscribers(self, agent_id: str, flow: InvestigationFlow) -> None:
        """Notify all subscribers of a flow update."""
        for callback in self._subscribers.get(agent_id, []):
            try:
                callback(flow.to_dict())
            except Exception:
                pass

    def get_flow_stats(self, agent_id: str) -> Optional[dict]:
        """Get summary statistics for a flow."""
        flow = self._flows.get(agent_id)
        if not flow:
            return None

        type_counts = defaultdict(int)
        status_counts = defaultdict(int)
        total_duration = 0

        for node in flow.nodes:
            type_counts[node.type] += 1
            status_counts[node.status] += 1
            if node.duration_ms:
                total_duration += node.duration_ms

        return {
            "total_nodes": len(flow.nodes),
            "total_edges": len(flow.edges),
            "node_types": dict(type_counts),
            "status_counts": dict(status_counts),
            "total_duration_ms": total_duration,
        }


# Global instance
flow_service = FlowService()

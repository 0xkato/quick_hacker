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

from services.feature_flags import feature_flags, FeatureFlag


@dataclass
class FlowContext:
    """Tracks investigation context for proper tree branching.

    Attributes:
        current_file: File currently being read/analyzed
        current_function: Function currently being analyzed
        current_candidate_node_id: Root of current investigation tree
        investigation_root_id: For multi-threaded investigations
        structured_trace_root_key: Current Structured Trace root key ("global_recon" or "entry_point:<fingerprint>")
        call_depth: Current depth in call chain (must be non-negative)
        max_call_depth: Maximum depth for call tracing (must be positive)
    """
    current_file: Optional[str] = None
    current_function: Optional[str] = None
    current_candidate_node_id: Optional[str] = None
    investigation_root_id: Optional[str] = None
    structured_trace_root_key: str = "global_recon"
    call_depth: int = 0              # NEW: Current depth in call chain
    max_call_depth: int = 3          # NEW: Configurable limit

    def __post_init__(self):
        """Validate field values."""
        if not self.structured_trace_root_key:
            self.structured_trace_root_key = "global_recon"
        if self.call_depth < 0:
            raise ValueError(f"call_depth must be non-negative, got {self.call_depth}")
        if self.max_call_depth <= 0:
            raise ValueError(f"max_call_depth must be positive, got {self.max_call_depth}")


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
    # Triage system
    "triage_gateway",
    # Turn planning
    "turn_plan",
    # Structured Trace (hierarchical audit trace)
    "structured_root",
    "global_recon",
    "folder",
    "steps",
    "sinks_group",
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


@dataclass
class FlowEdge:
    id: str
    source: str
    target: str
    label: Optional[str] = None
    kind: Optional[str] = None

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
        self._structured_index: dict[str, dict[str, str]] = defaultdict(dict)

    def initialize_flow(self, agent_id: str) -> InvestigationFlow:
        """Create a new flow for an agent."""
        flow = InvestigationFlow(session_id=agent_id)
        self._flows[agent_id] = flow
        return flow

    def get_flow(self, agent_id: str) -> Optional[InvestigationFlow]:
        """Get flow for an agent."""
        return self._flows.get(agent_id)

    def restore_flow(
        self,
        agent_id: str,
        *,
        nodes: list[dict],
        edges: list[dict],
        current_node_id: Optional[str] = None,
    ) -> InvestigationFlow:
        """Restore a flow from a persisted snapshot payload."""
        flow = InvestigationFlow(session_id=agent_id)

        restored_nodes: list[FlowNode] = []
        for raw in nodes or []:
            if not isinstance(raw, dict):
                continue
            try:
                restored_nodes.append(FlowNode(**raw))
            except Exception:
                continue

        restored_edges: list[FlowEdge] = []
        for raw in edges or []:
            if not isinstance(raw, dict):
                continue
            try:
                restored_edges.append(FlowEdge(**raw))
            except Exception:
                continue

        flow.nodes = restored_nodes
        flow.edges = restored_edges
        flow.current_node_id = current_node_id

        self._flows[agent_id] = flow
        self._notify_subscribers(agent_id, flow)
        return flow

    def update_context(
        self,
        agent_id: str,
        *,
        current_file: Optional[str] = None,
        current_function: Optional[str] = None,
        current_candidate_node_id: Optional[str] = None,
        investigation_root_id: Optional[str] = None,
        structured_trace_root_key: Optional[str] = None,
        call_depth: Optional[int] = None,
        max_call_depth: Optional[int] = None,
    ) -> None:
        """Update investigation context for proper tree branching.

        Args:
            agent_id: Agent identifier
            current_file: File currently being read/analyzed
            current_function: Function currently being analyzed
            current_candidate_node_id: Root of current investigation tree
            investigation_root_id: For multi-threaded investigations
            call_depth: Current depth in call chain (0 = root function)
            max_call_depth: Maximum depth for call tracing (prevents infinite recursion)

        Raises:
            ValueError: If call_depth < 0 or max_call_depth <= 0
        """
        flow = self._flows.get(agent_id)
        if not flow:
            return

        if current_file is not None:
            flow.context.current_file = current_file
        if current_function is not None:
            flow.context.current_function = current_function
        if current_candidate_node_id is not None:
            flow.context.current_candidate_node_id = current_candidate_node_id
        if investigation_root_id is not None:
            flow.context.investigation_root_id = investigation_root_id
        if structured_trace_root_key is not None and str(structured_trace_root_key).strip():
            flow.context.structured_trace_root_key = str(structured_trace_root_key).strip()
        if call_depth is not None:
            if call_depth < 0:
                raise ValueError(f"call_depth must be non-negative, got {call_depth}")
            flow.context.call_depth = call_depth
        if max_call_depth is not None:
            if max_call_depth <= 0:
                raise ValueError(f"max_call_depth must be positive, got {max_call_depth}")
            flow.context.max_call_depth = max_call_depth

    def set_structured_trace_root(self, agent_id: str, root_key: str) -> None:
        """Set the active Structured Trace root key for subsequent step attachments."""
        self.update_context(agent_id, structured_trace_root_key=root_key)

    def mark_structured_entrypoint_touched(self, agent_id: str, entrypoint_fingerprint: str) -> None:
        """Mark a structured entrypoint node as touched (best-effort)."""
        flow = self._flows.get(agent_id)
        if not flow:
            return

        key = f"structured:entry_point:{entrypoint_fingerprint}"
        node = self._get_structured_indexed_node(agent_id, key)
        if not node:
            return
        node.data["touched"] = True
        self._notify_subscribers(agent_id, flow)

    def get_or_create_file_node(
        self,
        agent_id: str,
        file_path: str,
    ) -> Optional[FlowNode]:
        """Get existing file node or return None (let caller create it).

        This prevents duplicate file nodes in the tree. Each file should
        only appear once, with functions as children.

        Args:
            agent_id: Agent identifier
            file_path: Path to the file being investigated

        Returns:
            FlowNode if file already has a node, None otherwise
        """
        flow = self._flows.get(agent_id)
        if not flow:
            return None

        # Check if we already have a node for this file
        for node in flow.nodes:
            if (
                node.type == "file"
                and node.data.get("file_path") == file_path
                and node.data.get("trace_kind") != "structural"
            ):
                return node

        return None

    def add_node(
        self,
        agent_id: str,
        node_type: NodeType,
        label: str,
        data: Optional[dict] = None,
        *,
        parent_id: Optional[str] = None,
        edge_label: Optional[str] = None,
        edge_kind: str = "legacy",
        llm_reasoning: Optional[str] = None,
        code_context: Optional[str] = None,
        tool_result_summary: Optional[str] = None,
        confidence_score: Optional[float] = None,
        set_current: bool = True,
        auto_parent: bool = False,
        span_id: Optional[str] = None,
        hypothesis_id: Optional[str] = None,
    ) -> FlowNode:
        """Add a node to the flow.

        Span fields (span_id, hypothesis_id) are only emitted when the
        DUAL_WRITE_MODE feature flag is enabled, supporting gradual migration
        from legacy format to span-based format.

        Args:
            agent_id: Agent identifier
            node_type: Type of node to create
            label: Human-readable label for the node
            data: Optional data dictionary
            parent_id: Optional parent node ID for explicit parent relationship
            edge_label: Optional label for the edge from parent to this node
            llm_reasoning: Optional LLM reasoning text
            code_context: Optional code context
            tool_result_summary: Optional tool result summary
            confidence_score: Optional confidence score (0.0-1.0)
            set_current: Whether to set this node as current in flow
            auto_parent: Whether to auto-determine parent based on node type
            span_id: Optional span ID (only emitted if DUAL_WRITE_MODE enabled)
            hypothesis_id: Optional hypothesis ID (only emitted if DUAL_WRITE_MODE enabled)

        Returns:
            The created FlowNode
        """
        flow = self._flows.get(agent_id)
        if not flow:
            flow = self.initialize_flow(agent_id)

        # Check dual-write mode flag
        dual_write_enabled = feature_flags.is_enabled(FeatureFlag.DUAL_WRITE_MODE)

        # Determine parent based on context if not explicitly provided
        if parent_id is None and auto_parent:
            if node_type == "file":
                # Files are children of investigation root (candidate)
                parent_id = flow.context.current_candidate_node_id
            elif node_type == "function":
                # Functions are children of current file
                if flow.context.current_file:
                    file_node = self.get_or_create_file_node(agent_id, flow.context.current_file)
                    parent_id = file_node.id if file_node else flow.context.current_candidate_node_id
            elif node_type == "call":
                # Calls are children of current function/node
                parent_id = flow.current_node_id
            # else: keep parent_id as None, will use flow.current_node_id below

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
            span_id=span_id if dual_write_enabled else None,
            hypothesis_id=hypothesis_id if dual_write_enabled else None,
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
                kind=edge_kind,
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
        *,
        kind: str = "legacy",
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
            kind=kind,
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
        if agent_id in self._structured_index:
            del self._structured_index[agent_id]

    def ensure_structured_trace(self, agent_id: str) -> dict[str, str]:
        """Ensure the Structured Trace root nodes exist (idempotent).

        Creates:
        - structured_root (attached under the run start node via legacy edge)
        - global_recon (child of structured_root via structured edge)
        - sinks_group (child of global_recon via structured edge)
        """
        flow = self._flows.get(agent_id)
        if not flow:
            flow = self.initialize_flow(agent_id)

        # Prefer the initial run "start" node if present (first user_input node).
        start_node_id = next((n.id for n in flow.nodes if n.type == "user_input"), None)
        start_node_id = start_node_id or flow.current_node_id

        root_key = "structured:root"
        root_node = self._get_structured_indexed_node(agent_id, root_key)
        if not root_node:
            # Attach root via a legacy edge so structured view can treat it as a root
            # (no structured parent edge into it).
            root_node = self.add_node(
                agent_id,
                node_type="structured_root",
                label="Structured Trace",
                data={"trace_kind": "structural", "trace_key": root_key},
                parent_id=start_node_id,
                edge_kind="legacy",
                set_current=False,
            )
            self._structured_index[agent_id][root_key] = root_node.id

        global_key = "structured:global_recon"
        global_node = self._ensure_structured_node(
            agent_id,
            key=global_key,
            node_type="global_recon",
            label="Global Recon",
            parent_id=root_node.id,
            data={"trace_kind": "structural", "trace_key": global_key},
        )

        sinks_key = "structured:sinks_group"
        sinks_node = self._ensure_structured_node(
            agent_id,
            key=sinks_key,
            node_type="sinks_group",
            label="Sinks",
            parent_id=global_node.id,
            data={"trace_kind": "structural", "trace_key": sinks_key},
        )

        return {"structured_root": root_node.id, "global_recon": global_node.id, "sinks_group": sinks_node.id}

    def _get_structured_indexed_node(self, agent_id: str, key: str) -> Optional[FlowNode]:
        flow = self._flows.get(agent_id)
        if not flow:
            return None
        node_id = self._structured_index.get(agent_id, {}).get(key)
        if not node_id:
            return None
        return next((n for n in flow.nodes if n.id == node_id), None)

    def _ensure_structured_node(
        self,
        agent_id: str,
        *,
        key: str,
        node_type: NodeType,
        label: str,
        parent_id: Optional[str],
        data: Optional[dict] = None,
    ) -> FlowNode:
        """Create or return a structured node keyed by `key` (idempotent)."""
        existing = self._get_structured_indexed_node(agent_id, key)
        if existing:
            return existing

        node = self.add_node(
            agent_id,
            node_type=node_type,
            label=label,
            data=data or {},
            parent_id=parent_id,
            edge_kind="structured",
            set_current=False,
        )
        self._structured_index[agent_id][key] = node.id
        return node

    def get_or_create_structured_steps_parent(
        self,
        agent_id: str,
        *,
        trace_root_key: str,
        file_path: Optional[str] = None,
        function_name: Optional[str] = None,
        line_number: Optional[int] = None,
    ) -> str:
        """Return the id of a structured `steps` node for the given context (idempotent)."""
        roots = self.ensure_structured_trace(agent_id)

        # Resolve root node.
        root_node_id = roots["global_recon"]
        if trace_root_key.startswith("entry_point:"):
            fingerprint = trace_root_key.split(":", 1)[1]
            entry_key = f"structured:entry_point:{fingerprint}"
            entry_node = self._get_structured_indexed_node(agent_id, entry_key)
            if entry_node:
                root_node_id = entry_node.id

        parent_id: str = root_node_id

        # Folder chain (if file_path present).
        folder_paths: list[str] = []
        if file_path:
            parts = [p for p in str(file_path).split("/") if p]
            for i in range(1, max(1, len(parts))):
                folder_paths.append("/".join(parts[:i]))

            # Exclude the filename itself.
            if folder_paths and folder_paths[-1] == "/".join(parts):
                folder_paths = folder_paths[:-1]

        for folder_path in folder_paths:
            folder_key = f"structured:{trace_root_key}:folder:{folder_path}"
            folder_node = self._ensure_structured_node(
                agent_id,
                key=folder_key,
                node_type="folder",
                label=folder_path,
                parent_id=parent_id,
                data={"folder_path": folder_path, "trace_kind": "structural", "trace_key": folder_key},
            )
            parent_id = folder_node.id

        if file_path:
            base = str(file_path).split("/")[-1] if "/" in str(file_path) else str(file_path)
            file_key = f"structured:{trace_root_key}:file:{file_path}"
            file_node = self._ensure_structured_node(
                agent_id,
                key=file_key,
                node_type="file",
                label=f"📄 {base}",
                parent_id=parent_id,
                data={"file_path": file_path, "trace_kind": "structural", "trace_key": file_key},
            )
            parent_id = file_node.id

        if function_name:
            func_key = f"structured:{trace_root_key}:function:{file_path or ''}:{function_name}:{line_number or ''}"
            func_node = self._ensure_structured_node(
                agent_id,
                key=func_key,
                node_type="function",
                label=f"⚡ {function_name}()",
                parent_id=parent_id,
                data={
                    "file_path": file_path,
                    "function_name": function_name,
                    "line_number": line_number,
                    "trace_kind": "structural",
                    "trace_key": func_key,
                },
            )
            parent_id = func_node.id

        steps_key = f"structured:{trace_root_key}:steps:{file_path or ''}:{function_name or ''}:{line_number or ''}"
        steps_node = self._ensure_structured_node(
            agent_id,
            key=steps_key,
            node_type="steps",
            label="Steps",
            parent_id=parent_id,
            data={
                "file_path": file_path,
                "function_name": function_name,
                "line_number": line_number,
                "trace_kind": "structural",
                "trace_key": steps_key,
            },
        )

        return steps_node.id

    def populate_structured_from_candidates(self, agent_id: str, candidates: list) -> None:
        """Populate Structured Trace entrypoints and sinks from static scan candidates.

        This is best-effort and idempotent.
        """
        roots = self.ensure_structured_trace(agent_id)
        structured_root_id = roots["structured_root"]
        sinks_group_id = roots["sinks_group"]

        def _get(obj, key: str, default=None):
            if isinstance(obj, dict):
                return obj.get(key, default)
            return getattr(obj, key, default)

        for c in candidates or []:
            kind = str(_get(c, "kind", "") or "")
            cid = str(_get(c, "id", "") or "")
            label = str(_get(c, "label", "") or "").strip() or cid
            file_path = _get(c, "file_path", None)
            line_number = _get(c, "line_number", None)
            metadata = _get(c, "metadata", None)
            code_context = _get(c, "code_context", None)

            if kind == "entry_point" and cid:
                entry_key = f"structured:entry_point:{cid}"
                if self._get_structured_indexed_node(agent_id, entry_key):
                    continue

                node = self.add_node(
                    agent_id,
                    node_type="entry_point",
                    label=label,
                    data={
                        "trace_kind": "structural",
                        "trace_key": entry_key,
                        "attack_surface_candidate_id": cid,
                        "touched": False,
                        "file_path": file_path,
                        "line_number": line_number,
                        "metadata": metadata or {},
                    },
                    parent_id=structured_root_id,
                    edge_kind="structured",
                    code_context=code_context,
                    set_current=False,
                )
                self._structured_index[agent_id][entry_key] = node.id
                continue

            if kind == "sink" and cid:
                sink_type = ""
                if isinstance(metadata, dict):
                    sink_type = str(metadata.get("sink_type") or "")
                sink_key = f"structured:sink:{cid}"
                if self._get_structured_indexed_node(agent_id, sink_key):
                    continue

                sink_label = f"⚠️ {sink_type.upper()} sink" if sink_type else "⚠️ Sink"
                node = self.add_node(
                    agent_id,
                    node_type="dangerous_sink",
                    label=sink_label,
                    data={
                        "trace_kind": "structural",
                        "trace_key": sink_key,
                        "attack_surface_candidate_id": cid,
                        "sink_type": sink_type,
                        "file_path": file_path,
                        "line_number": line_number,
                        "metadata": metadata or {},
                        "severity": "high",
                    },
                    parent_id=sinks_group_id,
                    edge_kind="structured",
                    code_context=code_context,
                    set_current=False,
                )
                self._structured_index[agent_id][sink_key] = node.id

    def attach_node_to_structured_trace(
        self,
        agent_id: str,
        node_id: str,
        *,
        tool_name: Optional[str] = None,
        args: Optional[dict] = None,
        file_path: Optional[str] = None,
        function_name: Optional[str] = None,
        line_number: Optional[int] = None,
    ) -> None:
        """Attach an existing node under the Structured Trace `steps` container.

        This does not change legacy edges; it adds a parallel structured edge.
        Best-effort and idempotent.
        """
        flow = self._flows.get(agent_id)
        if not flow:
            return

        # Resolve root from context.
        trace_root_key = str(getattr(flow.context, "structured_trace_root_key", "") or "").strip() or "global_recon"

        # Infer file path from args if not provided.
        resolved_file_path = (file_path or "").strip() if isinstance(file_path, str) else ""
        if not resolved_file_path and isinstance(args, dict):
            # Common tool conventions.
            candidate = args.get("path") or args.get("file_path") or args.get("file")
            if isinstance(candidate, str) and candidate.strip():
                resolved_file_path = candidate.strip()

        if not resolved_file_path:
            resolved_file_path = str(flow.context.current_file or "").strip()

        resolved_function_name = (function_name or "").strip() if isinstance(function_name, str) else ""
        if not resolved_function_name:
            resolved_function_name = str(flow.context.current_function or "").strip()

        steps_id = self.get_or_create_structured_steps_parent(
            agent_id,
            trace_root_key=trace_root_key,
            file_path=resolved_file_path or None,
            function_name=resolved_function_name or None,
            line_number=line_number,
        )

        # Idempotency: don't add duplicate structured edges.
        for edge in flow.edges:
            if edge.source == steps_id and edge.target == node_id and (edge.kind or "legacy") == "structured":
                return

        self.add_edge(
            agent_id,
            source_id=steps_id,
            target_id=node_id,
            label=None,
            kind="structured",
        )

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

    def emit_turn_plan(self, agent_id: str, turn_plan: "TurnPlan") -> FlowNode:
        """Emit a turn plan node for declarative routing.

        Creates a turn_plan node with full hypothesis metadata and updates
        flow context to route subsequent actions to the selected span.

        Span fields (span_id, hypothesis_id) are only emitted when the
        DUAL_WRITE_MODE feature flag is enabled, supporting gradual migration
        from legacy format to span-based format.

        Args:
            agent_id: Agent identifier
            turn_plan: TurnPlan instance with hypotheses and selection

        Returns:
            FlowNode representing the turn plan
        """
        flow = self._flows.get(agent_id)
        if not flow:
            flow = self.initialize_flow(agent_id)

        # Check dual-write mode flag
        dual_write_enabled = feature_flags.is_enabled(FeatureFlag.DUAL_WRITE_MODE)

        # Create truncated label from goal (40 chars max)
        goal_preview = turn_plan.goal[:40] + "..." if len(turn_plan.goal) > 40 else turn_plan.goal
        label = f"Turn {turn_plan.turn_id}: {goal_preview}"

        # Serialize turn plan data using the to_dict method
        node_data = turn_plan.to_dict()

        # Create node
        # Note: turn_id field accepts string despite int type hint for compatibility
        node = FlowNode(
            id=str(uuid.uuid4())[:8],
            type="turn_plan",
            label=label,
            status="completed",
            data=node_data,
            span_id=turn_plan.selected_span_id if dual_write_enabled else None,
            hypothesis_id=turn_plan.selected_hypothesis_id if dual_write_enabled else None,
            turn_id=turn_plan.turn_id,  # type: ignore
        )

        flow.nodes.append(node)

        # Update flow context with selected_span_id for authoritative routing
        if turn_plan.selected_span_id:
            flow.context.current_candidate_node_id = turn_plan.selected_span_id

        # Notify subscribers
        self._notify_subscribers(agent_id, flow)

        return node

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

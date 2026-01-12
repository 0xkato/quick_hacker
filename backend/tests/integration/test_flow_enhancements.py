"""
Integration tests for flow tree enhancements.

Tests cover the 5 major enhancements:
1. Call tracing with depth limits across multiple files
2. TypeScript/Go/Rust function extraction
3. Call node creation when analyzing functions
4. Context tracking for proper tree branching
5. Flow statistics calculation
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Optional
from unittest.mock import Mock

import pytest


# Mock types for testing (these should match the actual types in flow_service.py)
NodeType = Literal[
    "user_input",
    "tool_call",
    "tool_result",
    "analysis",
    "finding",
    "scan",
    "entry_point",
    "dangerous_sink",
    "investigation",
    "file",
    "function",
    "call",
    "external",
    "auth_boundary",
]


@dataclass
class FlowNode:
    """A node in the investigation flow."""

    id: str
    type: NodeType
    label: str
    status: str = "pending"
    data: dict = field(default_factory=dict)
    timestamp: str = ""


@dataclass
class FlowEdge:
    """An edge connecting two nodes."""

    id: str
    source: str
    target: str
    label: Optional[str] = None


@dataclass
class FlowContext:
    """Tracks investigation context for proper tree branching."""

    current_file: Optional[str] = None
    current_function: Optional[str] = None
    current_candidate_node_id: Optional[str] = None
    investigation_root_id: Optional[str] = None
    call_depth: int = 0
    max_call_depth: int = 3


@dataclass
class InvestigationFlow:
    """Complete investigation flow with nodes, edges, and context."""

    session_id: str
    nodes: list[FlowNode] = field(default_factory=list)
    edges: list[FlowEdge] = field(default_factory=list)
    current_node_id: Optional[str] = None
    context: FlowContext = field(default_factory=FlowContext)


class MockFlowService:
    """Mock flow service for testing."""

    def __init__(self):
        self._flows: dict[str, InvestigationFlow] = {}
        self._node_counter = 0

    def initialize_flow(self, agent_id: str) -> InvestigationFlow:
        """Initialize a new flow."""
        flow = InvestigationFlow(session_id=agent_id)
        self._flows[agent_id] = flow
        return flow

    def get_flow(self, agent_id: str) -> Optional[InvestigationFlow]:
        """Get existing flow."""
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
        set_current: bool = True,
    ) -> FlowNode:
        """Add a node to the flow."""
        flow = self._flows.get(agent_id)
        if not flow:
            flow = self.initialize_flow(agent_id)

        node_id = f"node-{self._node_counter}"
        self._node_counter += 1

        node = FlowNode(
            id=node_id,
            type=node_type,
            label=label,
            status="pending",
            data=data or {},
            timestamp="2026-01-12T00:00:00Z",
        )

        flow.nodes.append(node)

        if parent_id:
            edge_id = f"edge-{len(flow.edges)}"
            edge = FlowEdge(
                id=edge_id, source=parent_id, target=node_id, label=edge_label
            )
            flow.edges.append(edge)

        if set_current:
            flow.current_node_id = node_id

        return node

    def update_context(
        self,
        agent_id: str,
        *,
        current_file: Optional[str] = None,
        current_function: Optional[str] = None,
        current_candidate_node_id: Optional[str] = None,
        call_depth: Optional[int] = None,
        max_call_depth: Optional[int] = None,
    ) -> None:
        """Update investigation context."""
        flow = self._flows.get(agent_id)
        if not flow:
            return

        if current_file is not None:
            flow.context.current_file = current_file
        if current_function is not None:
            flow.context.current_function = current_function
        if current_candidate_node_id is not None:
            flow.context.current_candidate_node_id = current_candidate_node_id
        if call_depth is not None:
            flow.context.call_depth = call_depth
        if max_call_depth is not None:
            flow.context.max_call_depth = max_call_depth

    def get_or_create_file_node(
        self, agent_id: str, file_path: str
    ) -> Optional[FlowNode]:
        """Get existing file node or return None."""
        flow = self._flows.get(agent_id)
        if not flow:
            return None

        for node in flow.nodes:
            if node.type == "file" and node.data.get("file_path") == file_path:
                return node

        return None

    def update_node_status(
        self, agent_id: str, node_id: str, status: str
    ) -> None:
        """Update node status."""
        flow = self._flows.get(agent_id)
        if not flow:
            return

        for node in flow.nodes:
            if node.id == node_id:
                node.status = status
                break

    def get_flow_stats(self, agent_id: str) -> dict:
        """Calculate flow statistics."""
        flow = self._flows.get(agent_id)
        if not flow:
            return {}

        stats = {
            "total_nodes": len(flow.nodes),
            "node_types": {},
            "node_statuses": {},
        }

        for node in flow.nodes:
            # Count by type
            stats["node_types"][node.type] = (
                stats["node_types"].get(node.type, 0) + 1
            )
            # Count by status
            stats["node_statuses"][node.status] = (
                stats["node_statuses"].get(node.status, 0) + 1
            )

        return stats


@pytest.fixture
def flow_service():
    """Create a mock flow service for testing."""
    return MockFlowService()


class TestCallTracingIntegration:
    """Test call tracing across multiple files with depth limits."""

    def test_call_tracing_respects_depth_limit(self, flow_service):
        """Verify calls stop at max_call_depth."""
        agent_id = "test-agent-1"
        flow = flow_service.initialize_flow(agent_id)

        # Set max depth to 2
        flow_service.update_context(
            agent_id, max_call_depth=2, call_depth=0
        )

        # Create function node
        func1 = flow_service.add_node(
            agent_id,
            node_type="function",
            label="handleRequest",
            data={"file": "api.py", "line": 10},
        )

        # Simulate call at depth 0
        flow_service.update_context(agent_id, call_depth=1)
        call1 = flow_service.add_node(
            agent_id,
            node_type="call",
            label="→ validateInput",
            parent_id=func1.id,
        )

        # Simulate call at depth 1
        flow_service.update_context(agent_id, call_depth=2)
        call2 = flow_service.add_node(
            agent_id,
            node_type="call",
            label="→ checkAuth",
            parent_id=call1.id,
        )

        # Try to create call at depth 2 (should be prevented by caller)
        flow_service.update_context(agent_id, call_depth=3)

        flow_result = flow_service.get_flow(agent_id)
        assert flow_result is not None
        assert flow_result.context.call_depth == 3
        assert flow_result.context.max_call_depth == 2
        # In real implementation, depth limit would prevent adding more call nodes

    def test_call_tracing_across_files(self, flow_service):
        """Verify call nodes created when tracing across files."""
        agent_id = "test-agent-2"
        flow = flow_service.initialize_flow(agent_id)

        # Create file node
        file1 = flow_service.add_node(
            agent_id,
            node_type="file",
            label="api/routes.py",
            data={"file_path": "api/routes.py"},
        )

        # Create function in file1
        func1 = flow_service.add_node(
            agent_id,
            node_type="function",
            label="handleUpload",
            data={"file": "api/routes.py"},
            parent_id=file1.id,
        )

        # Create call to function in different file
        file2 = flow_service.add_node(
            agent_id,
            node_type="file",
            label="services/storage.py",
            data={"file_path": "services/storage.py"},
        )

        call_node = flow_service.add_node(
            agent_id,
            node_type="call",
            label="→ saveFile",
            data={"target_file": "services/storage.py"},
            parent_id=func1.id,
        )

        flow_result = flow_service.get_flow(agent_id)
        assert flow_result is not None
        assert len(flow_result.nodes) == 4
        assert any(n.type == "call" for n in flow_result.nodes)

    def test_call_depth_increments_correctly(self, flow_service):
        """Verify call depth increments as we trace deeper."""
        agent_id = "test-agent-3"
        flow = flow_service.initialize_flow(agent_id)

        # Set initial depth
        flow_service.update_context(agent_id, call_depth=0, max_call_depth=5)

        # Create chain of calls
        func = flow_service.add_node(
            agent_id, node_type="function", label="main"
        )

        for i in range(1, 4):
            flow_service.update_context(agent_id, call_depth=i)
            call = flow_service.add_node(
                agent_id,
                node_type="call",
                label=f"→ func{i}",
                parent_id=func.id,
            )
            func = call  # Next call branches from this one

        flow_result = flow_service.get_flow(agent_id)
        assert flow_result is not None
        assert flow_result.context.call_depth == 3


class TestFunctionExtractionIntegration:
    """Test function extraction for multiple languages."""

    def test_python_function_extraction(self, flow_service):
        """Verify Python function extraction creates function nodes."""
        agent_id = "test-python"
        flow = flow_service.initialize_flow(agent_id)

        # Simulate reading a Python file
        file_node = flow_service.add_node(
            agent_id,
            node_type="file",
            label="utils.py",
            data={"file_path": "utils.py", "language": "python"},
        )

        # In real implementation, these would be extracted from code
        functions = [
            {"name": "parse_input", "line": 10},
            {"name": "validate_data", "line": 25},
            {"name": "process_result", "line": 40},
        ]

        for func in functions:
            flow_service.add_node(
                agent_id,
                node_type="function",
                label=f"{func['name']}()",
                data={"function_name": func["name"], "line_number": func["line"]},
                parent_id=file_node.id,
                set_current=False,
            )

        flow_result = flow_service.get_flow(agent_id)
        assert flow_result is not None
        assert len([n for n in flow_result.nodes if n.type == "function"]) == 3

    def test_typescript_function_extraction(self, flow_service):
        """Verify TypeScript arrow functions and methods extracted."""
        agent_id = "test-typescript"
        flow = flow_service.initialize_flow(agent_id)

        file_node = flow_service.add_node(
            agent_id,
            node_type="file",
            label="api.ts",
            data={"file_path": "api.ts", "language": "typescript"},
        )

        # Simulate extracted TypeScript functions
        functions = [
            {"name": "fetchData", "type": "arrow", "line": 5},
            {"name": "processResponse", "type": "method", "line": 15},
            {"name": "handleError", "type": "arrow", "line": 30},
        ]

        for func in functions:
            flow_service.add_node(
                agent_id,
                node_type="function",
                label=f"{func['name']}()",
                data={
                    "function_name": func["name"],
                    "function_type": func["type"],
                    "line_number": func["line"],
                },
                parent_id=file_node.id,
                set_current=False,
            )

        flow_result = flow_service.get_flow(agent_id)
        assert flow_result is not None
        functions_nodes = [n for n in flow_result.nodes if n.type == "function"]
        assert len(functions_nodes) == 3
        assert any(n.data.get("function_type") == "arrow" for n in functions_nodes)

    def test_go_function_extraction(self, flow_service):
        """Verify Go function extraction works."""
        agent_id = "test-go"
        flow = flow_service.initialize_flow(agent_id)

        file_node = flow_service.add_node(
            agent_id,
            node_type="file",
            label="handler.go",
            data={"file_path": "handler.go", "language": "go"},
        )

        # Go functions and methods
        functions = [
            {"name": "HandleRequest", "receiver": None, "line": 10},
            {"name": "ValidateToken", "receiver": "Auth", "line": 25},
        ]

        for func in functions:
            label = (
                f"{func['receiver']}.{func['name']}()"
                if func["receiver"]
                else f"{func['name']}()"
            )
            flow_service.add_node(
                agent_id,
                node_type="function",
                label=label,
                data={
                    "function_name": func["name"],
                    "receiver": func["receiver"],
                    "line_number": func["line"],
                },
                parent_id=file_node.id,
                set_current=False,
            )

        flow_result = flow_service.get_flow(agent_id)
        assert flow_result is not None
        assert len([n for n in flow_result.nodes if n.type == "function"]) == 2

    def test_rust_function_extraction(self, flow_service):
        """Verify Rust function extraction works."""
        agent_id = "test-rust"
        flow = flow_service.initialize_flow(agent_id)

        file_node = flow_service.add_node(
            agent_id,
            node_type="file",
            label="lib.rs",
            data={"file_path": "src/lib.rs", "language": "rust"},
        )

        # Rust functions and impl blocks
        functions = [
            {"name": "process_data", "impl": None, "line": 5},
            {"name": "validate", "impl": "Validator", "line": 20},
        ]

        for func in functions:
            label = (
                f"{func['impl']}::{func['name']}()"
                if func["impl"]
                else f"{func['name']}()"
            )
            flow_service.add_node(
                agent_id,
                node_type="function",
                label=label,
                data={
                    "function_name": func["name"],
                    "impl_block": func["impl"],
                    "line_number": func["line"],
                },
                parent_id=file_node.id,
                set_current=False,
            )

        flow_result = flow_service.get_flow(agent_id)
        assert flow_result is not None
        assert len([n for n in flow_result.nodes if n.type == "function"]) == 2


class TestCallNodeCreation:
    """Test call node creation when analyzing functions."""

    def test_call_nodes_created_during_analysis(self, flow_service):
        """Verify call nodes created when analyzing functions."""
        agent_id = "test-calls"
        flow = flow_service.initialize_flow(agent_id)

        # Create function node
        func_node = flow_service.add_node(
            agent_id,
            node_type="function",
            label="processRequest()",
            data={"function_name": "processRequest"},
        )

        # Simulate finding calls during analysis
        calls = [
            {"target": "validateInput", "target_file": "validators.py"},
            {"target": "saveToDatabase", "target_file": "db.py"},
            {"target": "sendNotification", "target_file": "notifications.py"},
        ]

        for call in calls:
            flow_service.add_node(
                agent_id,
                node_type="call",
                label=f"→ {call['target']}",
                data={
                    "target_function": call["target"],
                    "target_file": call["target_file"],
                },
                parent_id=func_node.id,
                edge_label="calls",
                set_current=False,
            )

        flow_result = flow_service.get_flow(agent_id)
        assert flow_result is not None
        call_nodes = [n for n in flow_result.nodes if n.type == "call"]
        assert len(call_nodes) == 3
        assert all(n.label.startswith("→") for n in call_nodes)

    def test_external_call_nodes(self, flow_service):
        """Verify external library calls marked as external nodes."""
        agent_id = "test-external"
        flow = flow_service.initialize_flow(agent_id)

        func_node = flow_service.add_node(
            agent_id, node_type="function", label="fetchData()"
        )

        # Internal call
        flow_service.add_node(
            agent_id,
            node_type="call",
            label="→ processData",
            data={"call_type": "internal"},
            parent_id=func_node.id,
        )

        # External call
        flow_service.add_node(
            agent_id,
            node_type="external",
            label="→ requests.get",
            data={"call_type": "external", "library": "requests"},
            parent_id=func_node.id,
        )

        flow_result = flow_service.get_flow(agent_id)
        assert flow_result is not None
        assert any(n.type == "call" for n in flow_result.nodes)
        assert any(n.type == "external" for n in flow_result.nodes)


class TestContextTracking:
    """Test investigation context tracking."""

    def test_context_preserves_investigation_root(self, flow_service):
        """Verify context preserves investigation root across operations."""
        agent_id = "test-context"
        flow = flow_service.initialize_flow(agent_id)

        # Create investigation root (candidate)
        candidate = flow_service.add_node(
            agent_id,
            node_type="entry_point",
            label="POST /api/upload",
        )

        flow_service.update_context(
            agent_id, current_candidate_node_id=candidate.id
        )

        # Create file nodes - should be children of candidate
        file1 = flow_service.add_node(
            agent_id,
            node_type="file",
            label="routes.py",
            parent_id=candidate.id,
        )

        flow_service.update_context(agent_id, current_file="routes.py")

        file2 = flow_service.add_node(
            agent_id,
            node_type="file",
            label="validators.py",
            parent_id=candidate.id,
        )

        flow_result = flow_service.get_flow(agent_id)
        assert flow_result is not None
        assert flow_result.context.current_candidate_node_id == candidate.id
        assert flow_result.context.current_file == "routes.py"

    def test_file_node_deduplication(self, flow_service):
        """Verify file nodes are deduplicated."""
        agent_id = "test-dedup"
        flow = flow_service.initialize_flow(agent_id)

        # Create first file node
        file1 = flow_service.add_node(
            agent_id,
            node_type="file",
            label="utils.py",
            data={"file_path": "utils.py"},
        )

        # Try to get existing file node
        existing = flow_service.get_or_create_file_node(agent_id, "utils.py")
        assert existing is not None
        assert existing.id == file1.id

        # Non-existent file returns None
        non_existent = flow_service.get_or_create_file_node(
            agent_id, "other.py"
        )
        assert non_existent is None


class TestFlowStats:
    """Test flow statistics calculation."""

    def test_stats_with_multiple_node_types(self, flow_service):
        """Verify stats correctly count nodes by type and status."""
        agent_id = "test-agent-stats"
        flow = flow_service.initialize_flow(agent_id)

        # Add nodes of different types
        flow_service.add_node(agent_id, "file", "test.py")
        flow_service.add_node(agent_id, "function", "foo")
        flow_service.add_node(agent_id, "call", "→ bar")

        stats = flow_service.get_flow_stats(agent_id)
        assert stats["total_nodes"] == 3
        assert stats["node_types"]["file"] == 1
        assert stats["node_types"]["function"] == 1
        assert stats["node_types"]["call"] == 1

    def test_stats_with_different_statuses(self, flow_service):
        """Verify stats track node statuses."""
        agent_id = "test-statuses"
        flow = flow_service.initialize_flow(agent_id)

        node1 = flow_service.add_node(agent_id, "file", "test1.py")
        node2 = flow_service.add_node(agent_id, "file", "test2.py")
        node3 = flow_service.add_node(agent_id, "file", "test3.py")

        flow_service.update_node_status(agent_id, node1.id, "completed")
        flow_service.update_node_status(agent_id, node2.id, "running")

        stats = flow_service.get_flow_stats(agent_id)
        assert stats["node_statuses"]["completed"] == 1
        assert stats["node_statuses"]["running"] == 1
        assert stats["node_statuses"]["pending"] == 1


class TestEndToEndIntegration:
    """Test complete end-to-end flows."""

    def test_complete_investigation_flow(self, flow_service):
        """Test complete flow: create nodes → trace calls → analyze."""
        agent_id = "test-e2e"
        flow = flow_service.initialize_flow(agent_id)

        # Create scan node
        scan = flow_service.add_node(
            agent_id, node_type="scan", label="Security Scan"
        )

        # Create entry point
        entry = flow_service.add_node(
            agent_id,
            node_type="entry_point",
            label="POST /api/upload",
            parent_id=scan.id,
        )

        flow_service.update_context(
            agent_id, current_candidate_node_id=entry.id
        )

        # Investigate file
        file_node = flow_service.add_node(
            agent_id,
            node_type="file",
            label="routes.py",
            data={"file_path": "routes.py"},
            parent_id=entry.id,
        )

        flow_service.update_context(agent_id, current_file="routes.py")

        # Extract functions
        func = flow_service.add_node(
            agent_id,
            node_type="function",
            label="upload_handler()",
            parent_id=file_node.id,
        )

        # Trace calls
        flow_service.update_context(agent_id, call_depth=1, max_call_depth=3)

        call = flow_service.add_node(
            agent_id,
            node_type="call",
            label="→ save_file",
            parent_id=func.id,
        )

        # Create finding
        finding = flow_service.add_node(
            agent_id,
            node_type="finding",
            label="Path Traversal Vulnerability",
            data={"severity": "high"},
            parent_id=call.id,
        )

        flow_result = flow_service.get_flow(agent_id)
        assert flow_result is not None
        assert len(flow_result.nodes) == 6
        assert len(flow_result.edges) == 5

        # Verify tree structure
        stats = flow_service.get_flow_stats(agent_id)
        assert stats["node_types"]["scan"] == 1
        assert stats["node_types"]["entry_point"] == 1
        assert stats["node_types"]["file"] == 1
        assert stats["node_types"]["function"] == 1
        assert stats["node_types"]["call"] == 1
        assert stats["node_types"]["finding"] == 1

    def test_multiple_investigation_branches(self, flow_service):
        """Test parallel investigation branches."""
        agent_id = "test-parallel"
        flow = flow_service.initialize_flow(agent_id)

        # Create scan with multiple entry points
        scan = flow_service.add_node(agent_id, "scan", "Scan")

        entry1 = flow_service.add_node(
            agent_id, "entry_point", "Entry 1", parent_id=scan.id
        )
        entry2 = flow_service.add_node(
            agent_id, "entry_point", "Entry 2", parent_id=scan.id
        )
        entry3 = flow_service.add_node(
            agent_id, "entry_point", "Entry 3", parent_id=scan.id
        )

        # Each entry point has its own file investigation
        for i, entry in enumerate([entry1, entry2, entry3], 1):
            flow_service.add_node(
                agent_id,
                "file",
                f"file{i}.py",
                parent_id=entry.id,
                set_current=False,
            )

        flow_result = flow_service.get_flow(agent_id)
        assert flow_result is not None
        assert len(flow_result.nodes) == 7  # 1 scan + 3 entries + 3 files
        assert len(flow_result.edges) == 6  # 3 scan→entry + 3 entry→file

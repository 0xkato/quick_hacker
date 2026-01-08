"""Tests for graph manipulation tools."""

import pytest
from cass.graph import KnowledgeGraph, NodeType
from cass.tools.graph_tools import GraphTools


@pytest.fixture
def graph_tools():
    graph = KnowledgeGraph()
    return GraphTools(graph)


def test_add_entry_point(graph_tools):
    """Can add entry point nodes."""
    node_id = graph_tools.add_entry_point(
        name="POST /login",
        file_path="auth.py",
        line_number=10,
        method="POST",
        framework="flask",
    )
    assert node_id is not None
    node = graph_tools.graph.get_node(node_id)
    assert node.type == NodeType.HTTP_ROUTE


def test_add_input_vector(graph_tools):
    """Can add input vector nodes."""
    entry_id = graph_tools.add_entry_point(name="/login", file_path="auth.py", line_number=1)
    input_id = graph_tools.add_input_vector(
        name="username",
        input_type="request_body",
        file_path="auth.py",
        line_number=5,
        entry_point_id=entry_id,
    )

    # Check relationship was created
    rels = graph_tools.graph.get_relationships(entry_id)
    assert len(rels) == 1
    assert rels[0].target_id == input_id


def test_add_sink(graph_tools):
    """Can add dangerous sink nodes."""
    sink_id = graph_tools.add_sink(
        name="db.execute",
        sink_type="sql",
        file_path="db.py",
        line_number=20,
        code="db.execute(query)",
    )
    node = graph_tools.graph.get_node(sink_id)
    assert node.type == NodeType.SQL_QUERY


def test_connect_flow(graph_tools):
    """Can connect data flow between nodes."""
    source_id = graph_tools.add_input_vector(name="user_input", input_type="query_param", file_path="a.py", line_number=1)
    sink_id = graph_tools.add_sink(name="execute", sink_type="sql", file_path="b.py", line_number=10)

    graph_tools.connect_flow(source_id, sink_id)

    paths = graph_tools.graph.find_paths(source_id, sink_id)
    assert len(paths) == 1

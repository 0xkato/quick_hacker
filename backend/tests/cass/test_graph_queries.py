"""Tests for graph query helpers."""

import pytest
from cass.graph.schema import Node, NodeType, NodeProperties, Relationship, RelationshipType
from cass.graph.store import KnowledgeGraph
from cass.graph.queries import GraphQueries


@pytest.fixture
def populated_graph():
    """Graph with realistic security data."""
    graph = KnowledgeGraph()

    # Entry point
    graph.add_node(Node(
        id="route-login",
        type=NodeType.HTTP_ROUTE,
        properties=NodeProperties(name="POST /login", file_path="auth.py", line_number=10),
    ))

    # Input vectors
    graph.add_node(Node(
        id="param-user",
        type=NodeType.REQUEST_BODY,
        properties=NodeProperties(name="username", file_path="auth.py", line_number=12),
    ))
    graph.add_node(Node(
        id="param-pass",
        type=NodeType.REQUEST_BODY,
        properties=NodeProperties(name="password", file_path="auth.py", line_number=12),
        tags=["pii"],
    ))

    # Validator
    graph.add_node(Node(
        id="validator-1",
        type=NodeType.VALIDATOR,
        properties=NodeProperties(name="validate_input", file_path="auth.py", line_number=15),
    ))

    # Sink
    graph.add_node(Node(
        id="sink-sql",
        type=NodeType.SQL_QUERY,
        properties=NodeProperties(name="db.execute", file_path="auth.py", line_number=25),
    ))

    # Relationships
    graph.add_relationship(Relationship(
        id="r1", type=RelationshipType.RECEIVES_INPUT,
        source_id="route-login", target_id="param-user",
    ))
    graph.add_relationship(Relationship(
        id="r2", type=RelationshipType.RECEIVES_INPUT,
        source_id="route-login", target_id="param-pass",
    ))
    graph.add_relationship(Relationship(
        id="r3", type=RelationshipType.VALIDATES,
        source_id="validator-1", target_id="param-user",
    ))
    graph.add_relationship(Relationship(
        id="r4", type=RelationshipType.FLOWS_TO,
        source_id="param-user", target_id="sink-sql",
    ))
    graph.add_relationship(Relationship(
        id="r5", type=RelationshipType.FLOWS_TO,
        source_id="param-pass", target_id="sink-sql",
    ))

    return graph


def test_find_entry_points(populated_graph):
    """Find all entry points."""
    queries = GraphQueries(populated_graph)
    entries = queries.find_entry_points()
    assert len(entries) == 1
    assert entries[0].id == "route-login"


def test_find_dangerous_sinks(populated_graph):
    """Find all dangerous sinks."""
    queries = GraphQueries(populated_graph)
    sinks = queries.find_dangerous_sinks()
    assert len(sinks) == 1
    assert sinks[0].type == NodeType.SQL_QUERY


def test_find_unvalidated_inputs(populated_graph):
    """Find inputs that flow to sinks without validation."""
    queries = GraphQueries(populated_graph)
    unvalidated = queries.find_unvalidated_inputs()
    # param-pass has no validator
    assert len(unvalidated) == 1
    assert unvalidated[0].id == "param-pass"


def test_find_attack_paths(populated_graph):
    """Find paths from entry points to sinks."""
    queries = GraphQueries(populated_graph)
    paths = queries.find_attack_paths()
    assert len(paths) >= 1
    # Should find route-login -> param-* -> sink-sql


def test_get_risk_summary(populated_graph):
    """Get risk summary for the graph."""
    queries = GraphQueries(populated_graph)
    summary = queries.get_risk_summary()
    assert summary["entry_points"] == 1
    assert summary["dangerous_sinks"] == 1
    assert summary["unvalidated_inputs"] >= 1

"""Tests for knowledge graph store."""

import pytest
from cass.graph.schema import Node, NodeType, NodeProperties, Relationship, RelationshipType
from cass.graph.store import KnowledgeGraph


@pytest.fixture
def graph():
    return KnowledgeGraph()


@pytest.fixture
def sample_nodes():
    return [
        Node(
            id="route-1",
            type=NodeType.HTTP_ROUTE,
            properties=NodeProperties(name="/login", file_path="auth.py", line_number=10),
        ),
        Node(
            id="param-1",
            type=NodeType.QUERY_PARAM,
            properties=NodeProperties(name="username", file_path="auth.py", line_number=10),
        ),
        Node(
            id="sink-1",
            type=NodeType.SQL_QUERY,
            properties=NodeProperties(name="db.execute", file_path="auth.py", line_number=25),
        ),
    ]


def test_add_node(graph, sample_nodes):
    """Can add nodes to graph."""
    graph.add_node(sample_nodes[0])
    assert graph.get_node("route-1") is not None
    assert graph.get_node("route-1").type == NodeType.HTTP_ROUTE


def test_add_relationship(graph, sample_nodes):
    """Can add relationships between nodes."""
    for node in sample_nodes:
        graph.add_node(node)

    rel = Relationship(
        id="rel-1",
        type=RelationshipType.RECEIVES_INPUT,
        source_id="route-1",
        target_id="param-1",
    )
    graph.add_relationship(rel)

    rels = graph.get_relationships("route-1")
    assert len(rels) == 1
    assert rels[0].target_id == "param-1"


def test_query_by_type(graph, sample_nodes):
    """Can query nodes by type."""
    for node in sample_nodes:
        graph.add_node(node)

    routes = graph.query_nodes(type=NodeType.HTTP_ROUTE)
    assert len(routes) == 1
    assert routes[0].id == "route-1"


def test_find_path(graph, sample_nodes):
    """Can find paths between nodes."""
    for node in sample_nodes:
        graph.add_node(node)

    graph.add_relationship(Relationship(
        id="rel-1", type=RelationshipType.RECEIVES_INPUT,
        source_id="route-1", target_id="param-1",
    ))
    graph.add_relationship(Relationship(
        id="rel-2", type=RelationshipType.FLOWS_TO,
        source_id="param-1", target_id="sink-1",
    ))

    paths = graph.find_paths("route-1", "sink-1")
    assert len(paths) == 1
    assert paths[0] == ["route-1", "param-1", "sink-1"]


def test_graph_stats(graph, sample_nodes):
    """Can get graph statistics."""
    for node in sample_nodes:
        graph.add_node(node)

    stats = graph.stats()
    assert stats["total_nodes"] == 3
    assert stats["nodes_by_type"][NodeType.HTTP_ROUTE] == 1

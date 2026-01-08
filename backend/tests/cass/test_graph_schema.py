"""Tests for knowledge graph schema."""

import pytest
from cass.graph.schema import (
    NodeType,
    RelationshipType,
    Node,
    Relationship,
    NodeProperties,
)


def test_node_types_exist():
    """All security-critical node types should be defined."""
    assert NodeType.ENTRY_POINT
    assert NodeType.INPUT_VECTOR
    assert NodeType.DATA_SINK
    assert NodeType.VALIDATOR
    assert NodeType.AUTH_CHECK
    assert NodeType.DATA_CLASSIFICATION
    assert NodeType.SECRET
    assert NodeType.DEPENDENCY


def test_relationship_types_exist():
    """All relationship types should be defined."""
    assert RelationshipType.RECEIVES_INPUT
    assert RelationshipType.FLOWS_TO
    assert RelationshipType.VALIDATES
    assert RelationshipType.AUTHENTICATES
    assert RelationshipType.HANDLES_DATA
    assert RelationshipType.DEPENDS_ON
    assert RelationshipType.CALLS


def test_node_creation():
    """Nodes should be creatable with type and properties."""
    node = Node(
        id="node-1",
        type=NodeType.ENTRY_POINT,
        properties=NodeProperties(
            name="/api/login",
            file_path="src/routes/auth.py",
            line_number=42,
            metadata={"method": "POST"},
        ),
    )
    assert node.id == "node-1"
    assert node.type == NodeType.ENTRY_POINT
    assert node.properties.name == "/api/login"


def test_relationship_creation():
    """Relationships connect two nodes."""
    rel = Relationship(
        id="rel-1",
        type=RelationshipType.RECEIVES_INPUT,
        source_id="node-1",
        target_id="node-2",
        properties={"validated": False},
    )
    assert rel.source_id == "node-1"
    assert rel.target_id == "node-2"

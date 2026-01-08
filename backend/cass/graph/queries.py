"""High-level query helpers for the knowledge graph."""

from typing import Optional
from .schema import Node, NodeType, RelationshipType
from .store import KnowledgeGraph


ENTRY_POINT_TYPES = {
    NodeType.ENTRY_POINT,
    NodeType.HTTP_ROUTE,
    NodeType.GRAPHQL_RESOLVER,
    NodeType.WEBSOCKET_HANDLER,
    NodeType.CLI_COMMAND,
    NodeType.EVENT_LISTENER,
}

INPUT_VECTOR_TYPES = {
    NodeType.INPUT_VECTOR,
    NodeType.QUERY_PARAM,
    NodeType.REQUEST_BODY,
    NodeType.HEADER,
    NodeType.COOKIE,
    NodeType.FILE_UPLOAD,
    NodeType.ENV_VAR,
}

DANGEROUS_SINK_TYPES = {
    NodeType.DATA_SINK,
    NodeType.SQL_QUERY,
    NodeType.COMMAND_EXEC,
    NodeType.FILE_OPERATION,
    NodeType.NETWORK_REQUEST,
    NodeType.MEMORY_OPERATION,
}

VALIDATOR_TYPES = {
    NodeType.VALIDATOR,
    NodeType.SANITIZER,
}


class GraphQueries:
    """High-level queries for security analysis."""

    def __init__(self, graph: KnowledgeGraph):
        self.graph = graph

    def find_entry_points(self) -> list[Node]:
        """Find all entry points in the graph."""
        results = []
        for node_type in ENTRY_POINT_TYPES:
            results.extend(self.graph.query_nodes(type=node_type))
        return results

    def find_input_vectors(self) -> list[Node]:
        """Find all input vectors."""
        results = []
        for node_type in INPUT_VECTOR_TYPES:
            results.extend(self.graph.query_nodes(type=node_type))
        return results

    def find_dangerous_sinks(self) -> list[Node]:
        """Find all dangerous sinks."""
        results = []
        for node_type in DANGEROUS_SINK_TYPES:
            results.extend(self.graph.query_nodes(type=node_type))
        return results

    def find_validators(self) -> list[Node]:
        """Find all validators and sanitizers."""
        results = []
        for node_type in VALIDATOR_TYPES:
            results.extend(self.graph.query_nodes(type=node_type))
        return results

    def find_unvalidated_inputs(self) -> list[Node]:
        """Find inputs that are not validated before reaching sinks."""
        unvalidated = []
        inputs = self.find_input_vectors()
        validators = {v.id for v in self.find_validators()}

        for input_node in inputs:
            # Check if any validator validates this input
            has_validator = False
            incoming = self.graph.get_relationships(input_node.id, direction="incoming")
            for rel in incoming:
                if rel.type == RelationshipType.VALIDATES and rel.source_id in validators:
                    has_validator = True
                    break

            if not has_validator:
                # Check if it flows to a dangerous sink
                sinks = self.find_dangerous_sinks()
                for sink in sinks:
                    paths = self.graph.find_paths(input_node.id, sink.id)
                    if paths:
                        unvalidated.append(input_node)
                        break

        return unvalidated

    def find_attack_paths(
        self,
        entry_point_id: Optional[str] = None,
        sink_id: Optional[str] = None,
    ) -> list[dict]:
        """Find paths from entry points to dangerous sinks."""
        attack_paths = []

        entries = [self.graph.get_node(entry_point_id)] if entry_point_id else self.find_entry_points()
        sinks = [self.graph.get_node(sink_id)] if sink_id else self.find_dangerous_sinks()

        for entry in entries:
            if not entry:
                continue
            for sink in sinks:
                if not sink:
                    continue
                paths = self.graph.find_paths(entry.id, sink.id)
                for path in paths:
                    attack_paths.append({
                        "entry_point": entry,
                        "sink": sink,
                        "path": path,
                        "path_nodes": [self.graph.get_node(nid) for nid in path],
                    })

        return attack_paths

    def find_unauthenticated_routes(self) -> list[Node]:
        """Find entry points without auth checks."""
        unauthenticated = []
        auth_checks = {n.id for n in self.graph.query_nodes(type=NodeType.AUTH_CHECK)}

        for entry in self.find_entry_points():
            has_auth = False
            incoming = self.graph.get_relationships(entry.id, direction="incoming")
            for rel in incoming:
                if rel.type == RelationshipType.AUTHENTICATES:
                    has_auth = True
                    break

            if not has_auth:
                unauthenticated.append(entry)

        return unauthenticated

    def get_risk_summary(self) -> dict:
        """Get a summary of security-relevant statistics."""
        entry_points = self.find_entry_points()
        sinks = self.find_dangerous_sinks()
        unvalidated = self.find_unvalidated_inputs()
        unauthenticated = self.find_unauthenticated_routes()
        attack_paths = self.find_attack_paths()

        return {
            "entry_points": len(entry_points),
            "input_vectors": len(self.find_input_vectors()),
            "dangerous_sinks": len(sinks),
            "validators": len(self.find_validators()),
            "unvalidated_inputs": len(unvalidated),
            "unauthenticated_routes": len(unauthenticated),
            "attack_paths": len(attack_paths),
            "high_risk_paths": len([p for p in attack_paths if any(
                n.id in [u.id for u in unvalidated] for n in p["path_nodes"] if n
            )]),
        }

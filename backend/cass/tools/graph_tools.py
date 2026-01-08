"""Graph manipulation tools for the CASS agent."""

import uuid
from typing import Optional

from cass.graph import (
    KnowledgeGraph,
    Node,
    NodeProperties,
    NodeType,
    Relationship,
    RelationshipType,
)


class GraphTools:
    """Tools for manipulating the knowledge graph."""

    # Type maps for input vectors
    INPUT_TYPE_MAP = {
        "query_param": NodeType.QUERY_PARAM,
        "request_body": NodeType.REQUEST_BODY,
        "header": NodeType.HEADER,
        "cookie": NodeType.COOKIE,
        "file_upload": NodeType.FILE_UPLOAD,
        "env_var": NodeType.ENV_VAR,
    }

    # Type maps for sinks
    SINK_TYPE_MAP = {
        "sql": NodeType.SQL_QUERY,
        "command": NodeType.COMMAND_EXEC,
        "file": NodeType.FILE_OPERATION,
        "network": NodeType.NETWORK_REQUEST,
        "memory": NodeType.MEMORY_OPERATION,
    }

    # Type maps for flow relationships
    FLOW_TYPE_MAP = {
        "flows_to": RelationshipType.FLOWS_TO,
        "calls": RelationshipType.CALLS,
        "imports": RelationshipType.IMPORTS,
        "returns": RelationshipType.RETURNS,
    }

    def __init__(self, graph: KnowledgeGraph):
        """Initialize with a knowledge graph.

        Args:
            graph: The knowledge graph to manipulate.
        """
        self.graph = graph

    def _generate_id(self, prefix: str) -> str:
        """Generate a unique ID with the given prefix.

        Args:
            prefix: The prefix for the ID.

        Returns:
            A unique ID string.
        """
        return f"{prefix}_{uuid.uuid4().hex[:8]}"

    def add_entry_point(
        self,
        name: str,
        file_path: str,
        line_number: int,
        method: Optional[str] = None,
        framework: Optional[str] = None,
        **metadata,
    ) -> str:
        """Add an entry point node (HTTP route, etc).

        Args:
            name: Name of the entry point (e.g., "POST /login").
            file_path: Path to the file containing the entry point.
            line_number: Line number in the file.
            method: HTTP method (GET, POST, etc.) if applicable.
            framework: Framework name (flask, django, etc.) if applicable.
            **metadata: Additional metadata to attach.

        Returns:
            The ID of the created node.
        """
        node_id = self._generate_id("entry")

        # If method is provided, it's an HTTP route
        node_type = NodeType.HTTP_ROUTE if method else NodeType.ENTRY_POINT

        # Merge method into metadata if provided
        if method:
            metadata["method"] = method

        properties = NodeProperties(
            name=name,
            file_path=file_path,
            line_number=line_number,
            framework=framework,
            metadata=metadata,
        )

        node = Node(id=node_id, type=node_type, properties=properties)
        self.graph.add_node(node)
        return node_id

    def add_input_vector(
        self,
        name: str,
        input_type: str,
        file_path: str,
        line_number: int,
        entry_point_id: Optional[str] = None,
        **metadata,
    ) -> str:
        """Add an input vector node (query param, request body, etc).

        Args:
            name: Name of the input vector (e.g., "username").
            input_type: Type of input (query_param, request_body, header, cookie, file_upload, env_var).
            file_path: Path to the file.
            line_number: Line number in the file.
            entry_point_id: Optional ID of the entry point that receives this input.
            **metadata: Additional metadata to attach.

        Returns:
            The ID of the created node.
        """
        node_id = self._generate_id("input")

        # Map input type to NodeType
        node_type = self.INPUT_TYPE_MAP.get(input_type, NodeType.INPUT_VECTOR)

        properties = NodeProperties(
            name=name,
            file_path=file_path,
            line_number=line_number,
            metadata=metadata,
        )

        node = Node(id=node_id, type=node_type, properties=properties)
        self.graph.add_node(node)

        # Create relationship to entry point if provided
        if entry_point_id:
            rel_id = self._generate_id("rel")
            rel = Relationship(
                id=rel_id,
                type=RelationshipType.RECEIVES_INPUT,
                source_id=entry_point_id,
                target_id=node_id,
            )
            self.graph.add_relationship(rel)

        return node_id

    def add_sink(
        self,
        name: str,
        sink_type: str,
        file_path: str,
        line_number: int,
        code: Optional[str] = None,
        **metadata,
    ) -> str:
        """Add a dangerous sink node (SQL query, command exec, etc).

        Args:
            name: Name of the sink (e.g., "db.execute").
            sink_type: Type of sink (sql, command, file, network, memory).
            file_path: Path to the file.
            line_number: Line number in the file.
            code: Code snippet of the sink call.
            **metadata: Additional metadata to attach.

        Returns:
            The ID of the created node.
        """
        node_id = self._generate_id("sink")

        # Map sink type to NodeType
        node_type = self.SINK_TYPE_MAP.get(sink_type, NodeType.DATA_SINK)

        properties = NodeProperties(
            name=name,
            file_path=file_path,
            line_number=line_number,
            code_snippet=code,
            metadata=metadata,
        )

        node = Node(id=node_id, type=node_type, properties=properties)
        self.graph.add_node(node)
        return node_id

    def add_validator(
        self,
        name: str,
        file_path: str,
        line_number: int,
        validates_ids: Optional[list[str]] = None,
        **metadata,
    ) -> str:
        """Add a validator node.

        Args:
            name: Name of the validator.
            file_path: Path to the file.
            line_number: Line number in the file.
            validates_ids: Optional list of node IDs that this validator validates.
            **metadata: Additional metadata to attach.

        Returns:
            The ID of the created node.
        """
        node_id = self._generate_id("validator")

        properties = NodeProperties(
            name=name,
            file_path=file_path,
            line_number=line_number,
            metadata=metadata,
        )

        node = Node(id=node_id, type=NodeType.VALIDATOR, properties=properties)
        self.graph.add_node(node)

        # Create validation relationships
        if validates_ids:
            for target_id in validates_ids:
                rel_id = self._generate_id("rel")
                rel = Relationship(
                    id=rel_id,
                    type=RelationshipType.VALIDATES,
                    source_id=node_id,
                    target_id=target_id,
                )
                self.graph.add_relationship(rel)

        return node_id

    def add_auth_check(
        self,
        name: str,
        file_path: str,
        line_number: int,
        protects_ids: Optional[list[str]] = None,
        **metadata,
    ) -> str:
        """Add an authentication check node.

        Args:
            name: Name of the auth check.
            file_path: Path to the file.
            line_number: Line number in the file.
            protects_ids: Optional list of node IDs that this auth check protects.
            **metadata: Additional metadata to attach.

        Returns:
            The ID of the created node.
        """
        node_id = self._generate_id("auth")

        properties = NodeProperties(
            name=name,
            file_path=file_path,
            line_number=line_number,
            metadata=metadata,
        )

        node = Node(id=node_id, type=NodeType.AUTH_CHECK, properties=properties)
        self.graph.add_node(node)

        # Create authentication relationships
        if protects_ids:
            for target_id in protects_ids:
                rel_id = self._generate_id("rel")
                rel = Relationship(
                    id=rel_id,
                    type=RelationshipType.AUTHENTICATES,
                    source_id=node_id,
                    target_id=target_id,
                )
                self.graph.add_relationship(rel)

        return node_id

    def add_secret(
        self,
        name: str,
        secret_type: str,
        file_path: str,
        line_number: int,
        **metadata,
    ) -> str:
        """Add a secret node (API key, password, etc).

        Args:
            name: Name of the secret.
            secret_type: Type of secret (api_key, password, token, etc.).
            file_path: Path to the file.
            line_number: Line number in the file.
            **metadata: Additional metadata to attach.

        Returns:
            The ID of the created node.
        """
        node_id = self._generate_id("secret")

        # Add secret_type to metadata
        metadata["secret_type"] = secret_type

        properties = NodeProperties(
            name=name,
            file_path=file_path,
            line_number=line_number,
            metadata=metadata,
        )

        node = Node(id=node_id, type=NodeType.SECRET, properties=properties)
        self.graph.add_node(node)
        return node_id

    def add_function(
        self,
        name: str,
        file_path: str,
        line_number: int,
        line_end: Optional[int] = None,
        **metadata,
    ) -> str:
        """Add a function node.

        Args:
            name: Name of the function.
            file_path: Path to the file.
            line_number: Start line number.
            line_end: End line number.
            **metadata: Additional metadata to attach.

        Returns:
            The ID of the created node.
        """
        node_id = self._generate_id("func")

        properties = NodeProperties(
            name=name,
            file_path=file_path,
            line_number=line_number,
            line_end=line_end,
            metadata=metadata,
        )

        node = Node(id=node_id, type=NodeType.FUNCTION, properties=properties)
        self.graph.add_node(node)
        return node_id

    def add_dependency(
        self,
        name: str,
        version: Optional[str] = None,
        **metadata,
    ) -> str:
        """Add a dependency node (npm package, pip package, etc).

        Args:
            name: Name of the dependency.
            version: Version of the dependency.
            **metadata: Additional metadata to attach.

        Returns:
            The ID of the created node.
        """
        node_id = self._generate_id("dep")

        # Add version to metadata if provided
        if version:
            metadata["version"] = version

        properties = NodeProperties(
            name=name,
            metadata=metadata,
        )

        node = Node(id=node_id, type=NodeType.DEPENDENCY, properties=properties)
        self.graph.add_node(node)
        return node_id

    def connect_flow(
        self,
        source_id: str,
        target_id: str,
        flow_type: str = "flows_to",
    ) -> str:
        """Connect two nodes with a data flow relationship.

        Args:
            source_id: ID of the source node.
            target_id: ID of the target node.
            flow_type: Type of flow (flows_to, calls, imports, returns).

        Returns:
            The ID of the created relationship.
        """
        rel_id = self._generate_id("rel")

        # Map flow type to RelationshipType
        rel_type = self.FLOW_TYPE_MAP.get(flow_type, RelationshipType.FLOWS_TO)

        rel = Relationship(
            id=rel_id,
            type=rel_type,
            source_id=source_id,
            target_id=target_id,
        )
        self.graph.add_relationship(rel)
        return rel_id

    def mark_explored(self, node_id: str) -> None:
        """Mark a node as explored.

        Args:
            node_id: ID of the node to mark as explored.
        """
        self.graph.update_node(node_id, explored=True)

    def tag_node(self, node_id: str, tag: str) -> None:
        """Add a tag to a node.

        Args:
            node_id: ID of the node to tag.
            tag: Tag to add.
        """
        node = self.graph.get_node(node_id)
        if node:
            if tag not in node.tags:
                node.tags.append(tag)

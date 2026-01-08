"""Knowledge graph schema definitions."""

from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field


class NodeType(str, Enum):
    """Types of nodes in the knowledge graph."""
    # Entry points
    ENTRY_POINT = "entry_point"
    HTTP_ROUTE = "http_route"
    GRAPHQL_RESOLVER = "graphql_resolver"
    WEBSOCKET_HANDLER = "websocket_handler"
    CLI_COMMAND = "cli_command"
    EVENT_LISTENER = "event_listener"

    # Input vectors
    INPUT_VECTOR = "input_vector"
    QUERY_PARAM = "query_param"
    REQUEST_BODY = "request_body"
    HEADER = "header"
    COOKIE = "cookie"
    FILE_UPLOAD = "file_upload"
    ENV_VAR = "env_var"

    # Data flow
    DATA_SINK = "data_sink"
    SQL_QUERY = "sql_query"
    COMMAND_EXEC = "command_exec"
    FILE_OPERATION = "file_operation"
    NETWORK_REQUEST = "network_request"
    MEMORY_OPERATION = "memory_operation"

    # Security
    VALIDATOR = "validator"
    SANITIZER = "sanitizer"
    AUTH_CHECK = "auth_check"
    AUTHZ_CHECK = "authz_check"

    # Data
    DATA_CLASSIFICATION = "data_classification"
    PII_FIELD = "pii_field"
    SECRET = "secret"
    CRYPTO_OPERATION = "crypto_operation"

    # Code structure
    FUNCTION = "function"
    CLASS = "class"
    MODULE = "module"
    DEPENDENCY = "dependency"


class RelationshipType(str, Enum):
    """Types of relationships between nodes."""
    RECEIVES_INPUT = "receives_input"
    FLOWS_TO = "flows_to"
    VALIDATES = "validates"
    SANITIZES = "sanitizes"
    AUTHENTICATES = "authenticates"
    AUTHORIZES = "authorizes"
    HANDLES_DATA = "handles_data"
    DEPENDS_ON = "depends_on"
    CALLS = "calls"
    IMPORTS = "imports"
    RETURNS = "returns"
    CONTAINS = "contains"


class NodeProperties(BaseModel):
    """Properties attached to a node."""
    name: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    line_end: Optional[int] = None
    code_snippet: Optional[str] = None
    language: Optional[str] = None
    framework: Optional[str] = None
    risk_score: Optional[float] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class Node(BaseModel):
    """A node in the knowledge graph."""
    id: str
    type: NodeType
    properties: NodeProperties
    tags: list[str] = Field(default_factory=list)
    explored: bool = False


class Relationship(BaseModel):
    """A relationship between two nodes."""
    id: str
    type: RelationshipType
    source_id: str
    target_id: str
    properties: dict[str, Any] = Field(default_factory=dict)

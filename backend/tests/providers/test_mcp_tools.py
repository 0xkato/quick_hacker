# backend/tests/providers/test_mcp_tools.py
"""Tests for MCP tool server definitions and creation."""
import pytest
from unittest.mock import MagicMock, AsyncMock

from providers.mcp_tools import (
    MCP_TOOLS,
    MCPTool,
    create_quickhack_mcp_server,
    MAX_OUTPUT_SIZE,
    _truncate_output,
)
from services.tool_core import ToolCore
import json


class TestMCPToolDefinitions:
    """Tests for MCP_TOOLS list structure."""

    def test_all_tools_have_required_fields(self):
        """Each tool should have name, description, input_schema."""
        for tool in MCP_TOOLS:
            assert "name" in tool, f"Tool missing 'name' field"
            assert "description" in tool, f"Tool {tool.get('name', '?')} missing 'description'"
            assert "input_schema" in tool, f"Tool {tool.get('name', '?')} missing 'input_schema'"
            # name and description must be non-empty strings
            assert isinstance(tool["name"], str) and tool["name"], "name must be non-empty string"
            assert isinstance(tool["description"], str) and tool["description"], "description must be non-empty string"

    def test_input_schemas_are_valid_json_schema(self):
        """Each input_schema should have type: object and properties."""
        for tool in MCP_TOOLS:
            schema = tool["input_schema"]
            assert schema.get("type") == "object", f"Tool {tool['name']} schema must have type: object"
            assert "properties" in schema, f"Tool {tool['name']} schema must have properties"
            assert isinstance(schema["properties"], dict), f"Tool {tool['name']} properties must be a dict"

    def test_expected_tools_are_defined(self):
        """Should have all required tools defined."""
        expected_tools = {
            "read_file",
            "search_code",
            "list_directory",
            "list_sink_signals",
            "upsert_sink_signal",
            "report_finding",
            "scan_repo_for_secrets",
            "dependency_audit",
            "grep_semantic",
            "generate_security_report",
        }
        actual_tools = {tool["name"] for tool in MCP_TOOLS}
        assert expected_tools <= actual_tools, f"Missing tools: {expected_tools - actual_tools}"

    def test_required_params_are_arrays(self):
        """Each tool's required field (if present) should be an array."""
        for tool in MCP_TOOLS:
            schema = tool["input_schema"]
            if "required" in schema:
                assert isinstance(schema["required"], list), f"Tool {tool['name']} required must be a list"


class TestMCPToolDataclass:
    """Tests for MCPTool dataclass."""

    def test_mcp_tool_has_required_attributes(self):
        """MCPTool should have name, description, input_schema, handler."""
        async def dummy_handler(**kwargs):
            return {}

        tool = MCPTool(
            name="test_tool",
            description="A test tool",
            input_schema={"type": "object", "properties": {}},
            handler=dummy_handler,
        )

        assert tool.name == "test_tool"
        assert tool.description == "A test tool"
        assert tool.input_schema == {"type": "object", "properties": {}}
        assert tool.handler is dummy_handler


class TestMCPServerCreation:
    """Tests for create_quickhack_mcp_server function."""

    @pytest.fixture
    def mock_tool_core(self, tmp_path):
        """Create a mock ToolCore for testing."""
        repo = tmp_path / "repo"
        repo.mkdir()
        return ToolCore(repo_path=str(repo), project_id="test-project")

    def test_create_server_returns_tools(self, mock_tool_core):
        """Should return server config and tools list."""
        server_config, tools = create_quickhack_mcp_server(mock_tool_core)

        assert server_config is not None
        assert isinstance(tools, list)
        assert len(tools) > 0
        assert all(isinstance(t, MCPTool) for t in tools)

    def test_all_tools_have_handlers(self, mock_tool_core):
        """All returned tools should have callable handlers."""
        _, tools = create_quickhack_mcp_server(mock_tool_core)

        for tool in tools:
            assert callable(tool.handler), f"Tool {tool.name} handler must be callable"

    def test_tools_match_definitions(self, mock_tool_core):
        """Returned tools should match MCP_TOOLS definitions."""
        _, tools = create_quickhack_mcp_server(mock_tool_core)

        tool_names = {t.name for t in tools}
        definition_names = {d["name"] for d in MCP_TOOLS}
        assert tool_names == definition_names, "Returned tools must match definitions"

    def test_allowed_tools_format(self, mock_tool_core):
        """Should generate mcp__quickhack__<name> format."""
        server_config, tools = create_quickhack_mcp_server(mock_tool_core)

        # Server config should contain allowed_tools in mcp__quickhack__<name> format
        assert "allowed_tools" in server_config
        expected_format = [f"mcp__quickhack__{t.name}" for t in tools]
        assert server_config["allowed_tools"] == expected_format


class TestOutputTruncation:
    """Tests for output truncation constant."""

    def test_max_output_size_is_set(self):
        """MAX_OUTPUT_SIZE should be defined as 50000."""
        assert MAX_OUTPUT_SIZE == 50_000

    def test_max_output_size_is_reasonable(self):
        """MAX_OUTPUT_SIZE should be a reasonable value."""
        # At least 10KB but not more than 1MB
        assert 10_000 <= MAX_OUTPUT_SIZE <= 1_000_000


class TestMCPToolHandlers:
    """Tests for MCP tool handler behavior."""

    @pytest.fixture
    def mock_tool_core(self, tmp_path):
        """Create a mock ToolCore for testing."""
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "test.py").write_text("def test(): pass")
        return ToolCore(repo_path=str(repo), project_id="test-project")

    @pytest.mark.asyncio
    async def test_read_file_handler_calls_tool_core(self, mock_tool_core):
        """read_file handler should call ToolCore.read_file."""
        _, tools = create_quickhack_mcp_server(mock_tool_core)

        read_file_tool = next(t for t in tools if t.name == "read_file")
        result = await read_file_tool.handler(path="test.py")

        assert "def test(): pass" in result

    @pytest.mark.asyncio
    async def test_handler_truncates_large_output(self, mock_tool_core, tmp_path):
        """Handler should truncate output larger than MAX_OUTPUT_SIZE."""
        # Create a large file
        large_content = "x" * (MAX_OUTPUT_SIZE + 10_000)
        (tmp_path / "repo" / "large.txt").write_text(large_content)

        _, tools = create_quickhack_mcp_server(mock_tool_core)
        read_file_tool = next(t for t in tools if t.name == "read_file")

        result = await read_file_tool.handler(path="large.txt")

        assert len(result) <= MAX_OUTPUT_SIZE
        assert "[OUTPUT TRUNCATED]" in result

    @pytest.mark.asyncio
    async def test_list_directory_handler(self, mock_tool_core):
        """list_directory handler should return directory listing."""
        _, tools = create_quickhack_mcp_server(mock_tool_core)

        list_dir_tool = next(t for t in tools if t.name == "list_directory")
        result = await list_dir_tool.handler(path=".")

        # Result should be JSON-like string or dict
        assert result is not None

    @pytest.mark.asyncio
    async def test_search_code_handler(self, mock_tool_core):
        """search_code handler should return search results."""
        _, tools = create_quickhack_mcp_server(mock_tool_core)

        search_tool = next(t for t in tools if t.name == "search_code")
        result = await search_tool.handler(pattern="def")

        # Result should be valid JSON
        parsed = json.loads(result)
        assert isinstance(parsed, (list, dict))

    @pytest.mark.asyncio
    async def test_upsert_sink_signal_handler(self, mock_tool_core):
        """upsert_sink_signal handler should create/update signals."""
        _, tools = create_quickhack_mcp_server(mock_tool_core)

        upsert_tool = next(t for t in tools if t.name == "upsert_sink_signal")
        result = await upsert_tool.handler(
            kind="sink",
            label="Test sink signal",
            file_path="test.py",
            line_number=1,
        )

        # Result should be valid JSON
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    @pytest.mark.asyncio
    async def test_report_finding_handler(self, mock_tool_core):
        """report_finding handler should report vulnerabilities."""
        _, tools = create_quickhack_mcp_server(mock_tool_core)

        report_tool = next(t for t in tools if t.name == "report_finding")
        result = await report_tool.handler(
            severity="high",
            title="Test Finding",
            vulnerability_type="SQL Injection",
            file_path="test.py",
            line_start=1,
            vulnerable_code="query = 'SELECT * FROM users WHERE id=' + user_id",
            description="SQL injection vulnerability",
            confidence=0.9,
        )

        # Result should be valid JSON
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    @pytest.mark.asyncio
    async def test_scan_repo_for_secrets_handler(self, mock_tool_core):
        """scan_repo_for_secrets handler should scan for secrets."""
        _, tools = create_quickhack_mcp_server(mock_tool_core)

        scan_tool = next(t for t in tools if t.name == "scan_repo_for_secrets")
        result = await scan_tool.handler()

        # Result should be valid JSON
        parsed = json.loads(result)
        assert isinstance(parsed, (list, dict))

    @pytest.mark.asyncio
    async def test_dependency_audit_handler(self, mock_tool_core):
        """dependency_audit handler should audit dependencies."""
        _, tools = create_quickhack_mcp_server(mock_tool_core)

        audit_tool = next(t for t in tools if t.name == "dependency_audit")
        result = await audit_tool.handler()

        # Result should be valid JSON
        parsed = json.loads(result)
        assert isinstance(parsed, (list, dict))

    @pytest.mark.asyncio
    async def test_grep_semantic_handler(self, mock_tool_core):
        """grep_semantic handler should search with context."""
        _, tools = create_quickhack_mcp_server(mock_tool_core)

        grep_tool = next(t for t in tools if t.name == "grep_semantic")
        result = await grep_tool.handler(pattern="def", context_lines=2)

        # Result should be valid JSON
        parsed = json.loads(result)
        assert isinstance(parsed, (list, dict))

    @pytest.mark.asyncio
    async def test_generate_security_report_handler(self, mock_tool_core):
        """generate_security_report handler should generate reports."""
        _, tools = create_quickhack_mcp_server(mock_tool_core)

        report_tool = next(t for t in tools if t.name == "generate_security_report")
        result = await report_tool.handler(
            findings=[],
            output_format="markdown",
        )

        # Result should be a string (markdown report)
        assert isinstance(result, str)

    @pytest.mark.asyncio
    async def test_generate_security_report_handler_with_invalid_finding(self, mock_tool_core):
        """generate_security_report handler should handle invalid findings."""
        _, tools = create_quickhack_mcp_server(mock_tool_core)

        report_tool = next(t for t in tools if t.name == "generate_security_report")
        # Pass an invalid finding dict (missing required fields)
        result = await report_tool.handler(
            findings=[{"invalid": "finding"}],
            output_format="markdown",
        )

        # Should return error response
        parsed = json.loads(result)
        assert "error" in parsed
        assert parsed["error"] == "ScanFindingConversionError"

    @pytest.mark.asyncio
    async def test_handler_returns_error_response_on_exception(self, mock_tool_core):
        """Handlers should return structured error response on exception."""
        _, tools = create_quickhack_mcp_server(mock_tool_core)

        read_file_tool = next(t for t in tools if t.name == "read_file")
        # Try to read a non-existent file
        result = await read_file_tool.handler(path="nonexistent_file.txt")

        # Should return structured error response
        parsed = json.loads(result)
        assert "error" in parsed
        assert "details" in parsed


class TestTruncateOutput:
    """Tests for _truncate_output function edge cases."""

    def test_truncate_empty_string(self):
        """Empty string should be returned as-is."""
        result = _truncate_output("")
        assert result == ""

    def test_truncate_string_exactly_at_limit(self):
        """String exactly at MAX_OUTPUT_SIZE should not be truncated."""
        exact_string = "x" * MAX_OUTPUT_SIZE
        result = _truncate_output(exact_string)
        assert result == exact_string
        assert len(result) == MAX_OUTPUT_SIZE
        assert "[OUTPUT TRUNCATED]" not in result

    def test_truncate_string_one_byte_over_limit(self):
        """String one byte over MAX_OUTPUT_SIZE should be truncated."""
        over_string = "x" * (MAX_OUTPUT_SIZE + 1)
        result = _truncate_output(over_string)
        assert len(result) <= MAX_OUTPUT_SIZE
        assert "[OUTPUT TRUNCATED]" in result

    def test_truncate_preserves_content_under_limit(self):
        """Content under limit should be preserved exactly."""
        content = "Hello, World!"
        result = _truncate_output(content)
        assert result == content

    def test_truncate_large_content(self):
        """Large content should be properly truncated with notice."""
        large_content = "x" * (MAX_OUTPUT_SIZE + 10_000)
        result = _truncate_output(large_content)
        assert len(result) <= MAX_OUTPUT_SIZE
        assert result.endswith("[OUTPUT TRUNCATED]")

# backend/tests/providers/test_mcp_tools.py
"""Tests for MCP tool server definitions and creation."""
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
import json

from providers.mcp_tools import (
    MCP_TOOLS,
    create_quickhack_mcp_server,
    MAX_OUTPUT_SIZE,
    _truncate_output,
    SDK_AVAILABLE,
)
from services.tool_core import ToolCore


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
            "get_validity_checklist",
            "finalize_finding",
        }
        actual_tools = {tool["name"] for tool in MCP_TOOLS}
        assert expected_tools <= actual_tools, f"Missing tools: {expected_tools - actual_tools}"

    def test_required_params_are_arrays(self):
        """Each tool's required field (if present) should be an array."""
        for tool in MCP_TOOLS:
            schema = tool["input_schema"]
            if "required" in schema:
                assert isinstance(schema["required"], list), f"Tool {tool['name']} required must be a list"


class TestMCPServerCreation:
    """Tests for create_quickhack_mcp_server function."""

    @pytest.fixture
    def mock_tool_core(self, tmp_path):
        """Create a mock ToolCore for testing."""
        repo = tmp_path / "repo"
        repo.mkdir()
        return ToolCore(repo_path=str(repo), project_id="test-project")

    def test_create_server_returns_config_and_server(self, mock_tool_core):
        """Should return server config and server/tools."""
        server_config, server_or_tools = create_quickhack_mcp_server(mock_tool_core)

        assert server_config is not None
        assert "allowed_tools" in server_config
        assert server_or_tools is not None

    def test_allowed_tools_in_config(self, mock_tool_core):
        """Should have allowed_tools in server config."""
        server_config, _ = create_quickhack_mcp_server(mock_tool_core)

        assert "allowed_tools" in server_config
        assert len(server_config["allowed_tools"]) == len(MCP_TOOLS)


class TestFallbackMode:
    """Tests for fallback mode when SDK is not available."""

    @pytest.fixture
    def mock_tool_core(self, tmp_path):
        """Create a mock ToolCore for testing."""
        repo = tmp_path / "repo"
        repo.mkdir()
        return ToolCore(repo_path=str(repo), project_id="test-project")

    def test_fallback_returns_mcp_tools_list(self, mock_tool_core):
        """In fallback mode, should return MCP_TOOLS list."""
        # Import fallback function directly
        from providers.mcp_tools import _create_fallback_server

        server_config, tools = _create_fallback_server(mock_tool_core)

        assert tools == MCP_TOOLS
        assert "allowed_tools" in server_config

    def test_fallback_allowed_tools_format(self, mock_tool_core):
        """Fallback mode should use mcp__quickhack__<name> format."""
        from providers.mcp_tools import _create_fallback_server

        server_config, _ = _create_fallback_server(mock_tool_core)

        for tool in MCP_TOOLS:
            expected = f"mcp__quickhack__{tool['name']}"
            assert expected in server_config["allowed_tools"]


class TestSDKMode:
    """Tests for SDK mode when SDK is available."""

    @pytest.fixture
    def mock_tool_core(self, tmp_path):
        """Create a mock ToolCore for testing."""
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "test.py").write_text("def test(): pass")
        return ToolCore(repo_path=str(repo), project_id="test-project")

    @pytest.mark.skipif(not SDK_AVAILABLE, reason="Claude SDK not installed")
    def test_sdk_server_is_created(self, mock_tool_core):
        """When SDK is available, should create SDK MCP server."""
        server_config, mcp_server = create_quickhack_mcp_server(mock_tool_core)

        # MCP server should be a McpSdkServerConfig, not a list
        assert not isinstance(mcp_server, list)

    @pytest.mark.skipif(not SDK_AVAILABLE, reason="Claude SDK not installed")
    def test_sdk_allowed_tools_are_tool_names(self, mock_tool_core):
        """SDK mode should expose Claude Code-compatible tool names in allowed_tools."""
        server_config, _ = create_quickhack_mcp_server(mock_tool_core)

        # Claude Code expects MCP tools in `mcp__<server>__<tool>` format.
        expected_names = {f"mcp__quickhack__{t['name']}" for t in MCP_TOOLS}
        actual_names = set(server_config["allowed_tools"])
        assert actual_names == expected_names


class TestOutputTruncation:
    """Tests for output truncation constant."""

    def test_max_output_size_is_set(self):
        """MAX_OUTPUT_SIZE should be defined as 50000."""
        assert MAX_OUTPUT_SIZE == 50_000

    def test_max_output_size_is_reasonable(self):
        """MAX_OUTPUT_SIZE should be a reasonable value."""
        # At least 10KB but not more than 1MB
        assert 10_000 <= MAX_OUTPUT_SIZE <= 1_000_000


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


class TestResponseHelpers:
    """Tests for response helper functions."""

    def test_make_response_creates_content_block(self):
        """_make_response should create proper content structure."""
        from providers.mcp_tools import _make_response

        result = _make_response("Hello")
        assert result == {"content": [{"type": "text", "text": "Hello"}]}

    def test_make_response_with_error(self):
        """_make_response with is_error=True should set is_error flag."""
        from providers.mcp_tools import _make_response

        result = _make_response("Error message", is_error=True)
        assert result == {
            "content": [{"type": "text", "text": "Error message"}],
            "is_error": True
        }

    def test_make_error_response_creates_json_error(self):
        """_make_error_response should create structured error."""
        from providers.mcp_tools import _make_error_response

        error = ValueError("test error")
        result = _make_error_response(error)

        assert result["is_error"] is True
        content = result["content"][0]["text"]
        parsed = json.loads(content)
        assert parsed["error"] == "ValueError"
        assert parsed["details"] == "test error"


class TestSDKAvailableFlag:
    """Tests for SDK_AVAILABLE flag."""

    def test_sdk_available_is_boolean(self):
        """SDK_AVAILABLE should be a boolean."""
        assert isinstance(SDK_AVAILABLE, bool)

    def test_mcp_tools_import_works_without_sdk(self):
        """Module should import even without SDK installed."""
        # If we got here, the import worked
        assert MCP_TOOLS is not None
        assert create_quickhack_mcp_server is not None

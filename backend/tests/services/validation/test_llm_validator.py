"""Tests for LLM validator."""
import asyncio
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock
import tempfile
import os

import pytest
from models.schemas import (
    Finding,
    Evidence,
    ProofChecklist,
    ChecklistItem,
    ChecklistStatus,
    Disposition,
    Severity,
    VulnerabilityCategory,
    ValidationResult,
    InputChannel,
)
from services.classification.classifier import ClassificationResult
from services.validation.llm_validator import LLMFindingValidator


@pytest.fixture
def mock_finding():
    """Create a basic finding for testing."""
    return Finding(
        id="test-1",
        agent_id="agent-1",
        repo_id="repo-1",
        severity=Severity.HIGH,
        title="SQL Injection",
        description="SQL injection vulnerability",
        file_path="/src/main.py",
        line_start=10,
        vulnerability_type="sql_injection",
        confidence=0.9,
        created_at=datetime.now(UTC),
        category=VulnerabilityCategory.SQL_INJECTION,
    )


@pytest.fixture
def mock_evidence():
    """Create basic evidence."""
    return Evidence(
        finding_id="test-1",
        snippet="user_input = request.args.get('id')\nquery = f'SELECT * FROM users WHERE id = {user_input}'",
        input_channel=InputChannel.network,
        input_channel_deterministic=True,
    )


@pytest.fixture
def mock_classification():
    """Create a classification result with full proof checklist."""
    return ClassificationResult(
        disposition=Disposition.VALID_SECURITY_ISSUE,
        classification_confidence=95,
        exploit_confidence=90,
        proof_checklist=ProofChecklist(
            source_controlled_input=ChecklistItem(
                value=True,
                status=ChecklistStatus.PROVEN,
                reason="Network input from request.args",
            ),
            sink_present=ChecklistItem(
                value=True,
                status=ChecklistStatus.PROVEN,
                reason="SQL query execution",
            ),
            dataflow_evidenced=ChecklistItem(
                value=True,
                status=ChecklistStatus.PROVEN,
                reason="Direct flow from input to query",
            ),
            reachable=ChecklistItem(
                value=True,
                status=ChecklistStatus.PROVEN,
                reason="Route is publicly accessible",
            ),
            boundary_crossed=ChecklistItem(
                value=True,
                status=ChecklistStatus.PROVEN,
                reason="Trust boundary crossed",
            ),
            not_only_misconfig=ChecklistItem(
                value=True,
                status=ChecklistStatus.PROVEN,
                reason="Code-level vulnerability",
            ),
        ),
        reasoning=["Clear SQL injection pattern", "User input flows directly to query"],
        category=VulnerabilityCategory.SQL_INJECTION,
    )


def test_llm_validator_initialization():
    """Verify initialization with API key, repo_root, and custom model."""
    api_key = "test-api-key"
    repo_root = "/test/repo"
    model = "claude-opus-4-5-20251101"

    validator = LLMFindingValidator(
        anthropic_api_key=api_key,
        repo_root=repo_root,
        model=model,
    )

    # Verify attributes are set correctly
    assert validator.repo_root == Path(repo_root)
    assert validator.model == model
    # Verify Anthropic client was created (we'll check this indirectly)
    assert hasattr(validator, 'client')
    # Verify tools are initialized
    assert hasattr(validator, 'tools')
    assert isinstance(validator.tools, dict)


def test_llm_validator_default_model():
    """Verify default model is claude-sonnet-3-5-20241022."""
    api_key = "test-api-key"
    repo_root = "/test/repo"

    # Initialize without specifying model
    validator = LLMFindingValidator(
        anthropic_api_key=api_key,
        repo_root=repo_root,
    )

    # Verify default model is set
    assert validator.model == "claude-sonnet-3-5-20241022"


@pytest.mark.asyncio
async def test_validate_timeout(mock_finding, mock_evidence, mock_classification):
    """Verify timeout handling returns is_valid=False with timeout category."""
    api_key = "test-api-key"
    repo_root = "/test/repo"

    validator = LLMFindingValidator(
        anthropic_api_key=api_key,
        repo_root=repo_root,
    )

    # Mock _run_validation to sleep longer than timeout
    async def slow_validation(*args, **kwargs):
        await asyncio.sleep(1.0)  # Sleep longer than timeout
        return ValidationResult(
            is_valid=True,
            reasoning=["Should not reach here"],
            categories=["should_not_reach"],
            confidence=95,
            timestamp=datetime.now(UTC),
        )

    validator._run_validation = slow_validation

    # Create a threat model profile mock
    threat_model_profile = Mock()

    # Call validate with very short timeout (0.1 seconds)
    result = await validator.validate(
        finding=mock_finding,
        evidence=mock_evidence,
        classification=mock_classification,
        threat_model_profile=threat_model_profile,
        criticism_level="high",
        timeout_seconds=0.1,
    )

    # Verify timeout handling
    assert isinstance(result, ValidationResult)
    assert result.is_valid is False
    assert "timeout" in result.categories
    assert result.confidence == 0
    assert "Validation timeout" in result.reasoning[0]


@pytest.mark.asyncio
async def test_validate_error_handling(mock_finding, mock_evidence, mock_classification):
    """Verify error handling returns is_valid=False with error category."""
    api_key = "test-api-key"
    repo_root = "/test/repo"

    validator = LLMFindingValidator(
        anthropic_api_key=api_key,
        repo_root=repo_root,
    )

    # Create a threat model profile mock
    threat_model_profile = Mock()

    # Mock _run_validation to raise an exception
    async def mock_run_validation(*args, **kwargs):
        raise RuntimeError("Test error")

    validator._run_validation = mock_run_validation

    # Call validate
    result = await validator.validate(
        finding=mock_finding,
        evidence=mock_evidence,
        classification=mock_classification,
        threat_model_profile=threat_model_profile,
        criticism_level="high",
        timeout_seconds=30,
    )

    # Verify error handling
    assert isinstance(result, ValidationResult)
    assert result.is_valid is False
    assert "error" in result.categories
    assert result.confidence == 0
    assert any("Test error" in reason for reason in result.reasoning)


def test_build_validation_prompt(mock_finding, mock_evidence, mock_classification):
    """Verify prompt contains all required sections."""
    api_key = "test-api-key"
    repo_root = "/test/repo"

    validator = LLMFindingValidator(
        anthropic_api_key=api_key,
        repo_root=repo_root,
    )

    threat_model_profile = Mock()

    # Call _build_validation_prompt
    prompt = validator._build_validation_prompt(
        finding=mock_finding,
        evidence=mock_evidence,
        classification=mock_classification,
        threat_model_profile=threat_model_profile,
        criticism_level="high",
    )

    # Verify prompt is a string
    assert isinstance(prompt, str)

    # Verify required sections are present
    assert "You are a security validation expert" in prompt
    assert "Criticism Level: HIGH" in prompt
    assert mock_finding.title in prompt
    assert mock_finding.file_path in prompt
    assert "Task 1: Validate Attacker Control" in prompt
    assert "Task 2: Validate Reachability" in prompt
    assert "DECISION: VALID | INVALID" in prompt

    # Verify checklist items are present
    assert "Source Controlled Input" in prompt or "source_controlled_input" in prompt
    assert "Sink Present" in prompt or "sink_present" in prompt
    assert "proven" in prompt  # Status from checklist (lowercase)
    assert "Network input from request.args" in prompt  # Reason from checklist


def test_build_validation_prompt_medium_criticism(mock_finding, mock_evidence, mock_classification):
    """Verify criticism level adapts to medium."""
    api_key = "test-api-key"
    repo_root = "/test/repo"

    validator = LLMFindingValidator(
        anthropic_api_key=api_key,
        repo_root=repo_root,
    )

    threat_model_profile = Mock()

    # Call _build_validation_prompt with medium criticism
    prompt = validator._build_validation_prompt(
        finding=mock_finding,
        evidence=mock_evidence,
        classification=mock_classification,
        threat_model_profile=threat_model_profile,
        criticism_level="medium",
    )

    # Verify medium criticism level is present
    assert "Criticism Level: MEDIUM" in prompt
    assert "Criticism Level: HIGH" not in prompt


def test_get_tool_definitions():
    """Verify tool definitions are formatted correctly for Anthropic API."""
    api_key = "test-api-key"
    repo_root = "/test/repo"

    validator = LLMFindingValidator(
        anthropic_api_key=api_key,
        repo_root=repo_root,
    )

    # Call _get_tool_definitions
    tool_defs = validator._get_tool_definitions()

    # Verify we get a list with 3 tools
    assert isinstance(tool_defs, list)
    assert len(tool_defs) == 3

    # Extract tools by name for easier testing
    tools_by_name = {tool["name"]: tool for tool in tool_defs}
    assert "read_file" in tools_by_name
    assert "grep_code" in tools_by_name
    assert "glob_files" in tools_by_name

    # Verify read_file tool
    read_file_tool = tools_by_name["read_file"]
    assert read_file_tool["description"] == "Read source file contents"
    assert "input_schema" in read_file_tool
    assert read_file_tool["input_schema"]["type"] == "object"
    assert "file_path" in read_file_tool["input_schema"]["properties"]
    assert read_file_tool["input_schema"]["properties"]["file_path"]["type"] == "string"
    assert "file_path" in read_file_tool["input_schema"]["required"]

    # Verify grep_code tool
    grep_code_tool = tools_by_name["grep_code"]
    assert grep_code_tool["description"] == "Search codebase for patterns using regex"
    assert "input_schema" in grep_code_tool
    assert grep_code_tool["input_schema"]["type"] == "object"
    assert "pattern" in grep_code_tool["input_schema"]["properties"]
    assert grep_code_tool["input_schema"]["properties"]["pattern"]["type"] == "string"
    assert "glob" in grep_code_tool["input_schema"]["properties"]
    assert grep_code_tool["input_schema"]["properties"]["glob"]["type"] == "string"
    assert "pattern" in grep_code_tool["input_schema"]["required"]
    assert "glob" not in grep_code_tool["input_schema"]["required"]

    # Verify glob_files tool
    glob_files_tool = tools_by_name["glob_files"]
    assert glob_files_tool["description"] == "Find files by name pattern"
    assert "input_schema" in glob_files_tool
    assert glob_files_tool["input_schema"]["type"] == "object"
    assert "pattern" in glob_files_tool["input_schema"]["properties"]
    assert glob_files_tool["input_schema"]["properties"]["pattern"]["type"] == "string"
    assert "pattern" in glob_files_tool["input_schema"]["required"]


# Tool Execution Tests


def test_tool_read_file_success():
    """Test read_file tool reads file successfully."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test file
        test_file = os.path.join(tmpdir, "test.py")
        with open(test_file, "w") as f:
            f.write("def vulnerable_function(user_input):\n    exec(user_input)\n")

        validator = LLMFindingValidator(
            anthropic_api_key="test-key",
            repo_root=tmpdir
        )

        result = validator._tool_read_file("test.py")

        assert "def vulnerable_function" in result
        assert "exec(user_input)" in result


def test_tool_read_file_not_found():
    """Test read_file tool handles missing file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        validator = LLMFindingValidator(
            anthropic_api_key="test-key",
            repo_root=tmpdir
        )

        result = validator._tool_read_file("nonexistent.py")

        assert "Error: File not found" in result


def test_tool_read_file_size_limit():
    """Test read_file tool respects size limit."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create large file
        test_file = os.path.join(tmpdir, "large.py")
        with open(test_file, "w") as f:
            f.write("x" * 200000)  # 200KB

        validator = LLMFindingValidator(
            anthropic_api_key="test-key",
            repo_root=tmpdir
        )

        result = validator._tool_read_file("large.py")

        # Should be truncated to 100KB
        assert len(result) <= 100000


def test_tool_grep_code_basic():
    """Test grep_code tool finds pattern."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test files
        test_file1 = os.path.join(tmpdir, "app.py")
        with open(test_file1, "w") as f:
            f.write("def handler():\n    exec(user_input)\n")

        test_file2 = os.path.join(tmpdir, "utils.py")
        with open(test_file2, "w") as f:
            f.write("def helper():\n    print('safe')\n")

        validator = LLMFindingValidator(
            anthropic_api_key="test-key",
            repo_root=tmpdir
        )

        result = validator._tool_grep_code("exec")

        assert "app.py" in result
        assert "exec(user_input)" in result
        assert "utils.py" not in result


def test_tool_grep_code_with_glob():
    """Test grep_code tool with glob filter."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test files
        test_py = os.path.join(tmpdir, "test.py")
        with open(test_py, "w") as f:
            f.write("exec(cmd)")

        test_js = os.path.join(tmpdir, "test.js")
        with open(test_js, "w") as f:
            f.write("exec(cmd)")

        validator = LLMFindingValidator(
            anthropic_api_key="test-key",
            repo_root=tmpdir
        )

        result = validator._tool_grep_code("exec", glob="*.py")

        assert "test.py" in result
        assert "test.js" not in result


def test_tool_glob_files():
    """Test glob_files tool finds files by pattern."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test files
        os.makedirs(os.path.join(tmpdir, "src"))
        test_file1 = os.path.join(tmpdir, "app.py")
        with open(test_file1, "w") as f:
            f.write("content")

        test_file2 = os.path.join(tmpdir, "src", "utils.py")
        with open(test_file2, "w") as f:
            f.write("content")

        test_file3 = os.path.join(tmpdir, "README.md")
        with open(test_file3, "w") as f:
            f.write("content")

        validator = LLMFindingValidator(
            anthropic_api_key="test-key",
            repo_root=tmpdir
        )

        result = validator._tool_glob_files("**/*.py")

        assert "app.py" in result
        assert "utils.py" in result or "src/utils.py" in result
        assert "README.md" not in result


def test_tool_glob_files_specific_pattern():
    """Test glob_files tool with specific pattern."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test files
        test_file1 = os.path.join(tmpdir, "test_app.py")
        with open(test_file1, "w") as f:
            f.write("content")

        test_file2 = os.path.join(tmpdir, "app.py")
        with open(test_file2, "w") as f:
            f.write("content")

        test_file3 = os.path.join(tmpdir, "test_utils.py")
        with open(test_file3, "w") as f:
            f.write("content")

        validator = LLMFindingValidator(
            anthropic_api_key="test-key",
            repo_root=tmpdir
        )

        result = validator._tool_glob_files("test_*.py")

        # Split result by lines to check exact matches
        result_lines = result.split("\n")
        assert "test_app.py" in result_lines
        assert "test_utils.py" in result_lines
        assert "app.py" not in result_lines


# Security Tests


def test_tool_read_file_blocks_parent_traversal():
    """Test read_file blocks ../ path traversal."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create file outside repo
        parent = Path(tmpdir).parent
        secret = parent / "secret.txt"
        secret.write_text("SECRET_DATA")

        validator = LLMFindingValidator(
            anthropic_api_key="test-key",
            repo_root=tmpdir
        )

        result = validator._tool_read_file("../secret.txt")

        # Should NOT read the secret file
        assert "SECRET_DATA" not in result
        assert "Error: Access denied" in result

        # Cleanup
        secret.unlink()


def test_tool_read_file_blocks_absolute_path():
    """Test read_file blocks absolute path access."""
    validator = LLMFindingValidator(
        anthropic_api_key="test-key",
        repo_root="/tmp"
    )

    result = validator._tool_read_file("/etc/passwd")

    # Should NOT read system files
    assert "root:" not in result
    assert ("Error: Access denied" in result or "Error: File not found" in result)


def test_tool_glob_files_blocks_parent_traversal():
    """Test glob_files blocks ../ patterns."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create file outside repo
        parent = Path(tmpdir).parent
        secret = parent / "secret.py"
        secret.write_text("SECRET_FILE")

        validator = LLMFindingValidator(
            anthropic_api_key="test-key",
            repo_root=tmpdir
        )

        result = validator._tool_glob_files("../*.py")

        # Should NOT list files outside repo
        assert "secret.py" not in result
        assert ("Error:" in result or "No files found" in result or "Pattern must be relative" in result)

        # Cleanup
        secret.unlink()


def test_tool_glob_files_blocks_absolute_pattern():
    """Test glob_files blocks absolute path patterns."""
    validator = LLMFindingValidator(
        anthropic_api_key="test-key",
        repo_root="/tmp"
    )

    result = validator._tool_glob_files("/etc/*.conf")

    # Should reject absolute patterns
    assert "Error:" in result or "Pattern must be relative" in result


# Tool Execution Dispatcher Tests


@pytest.mark.asyncio
async def test_execute_tool_call_read_file():
    """Test _execute_tool_call routes to read_file tool successfully."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test file
        test_file = os.path.join(tmpdir, "test.py")
        with open(test_file, "w") as f:
            f.write("exec(cmd)")

        validator = LLMFindingValidator(
            anthropic_api_key="test-key",
            repo_root=tmpdir
        )

        # Create mock tool_use object
        tool_use = Mock()
        tool_use.name = "read_file"
        tool_use.input = {"file_path": "test.py"}
        tool_use.id = "tool_123"

        # Execute tool call
        result = await validator._execute_tool_call(tool_use)

        # Verify result format
        assert result["type"] == "tool_result"
        assert result["tool_use_id"] == "tool_123"
        assert "exec(cmd)" in result["content"]


@pytest.mark.asyncio
async def test_execute_tool_call_unknown_tool():
    """Test _execute_tool_call handles unknown tool gracefully."""
    with tempfile.TemporaryDirectory() as tmpdir:
        validator = LLMFindingValidator(
            anthropic_api_key="test-key",
            repo_root=tmpdir
        )

        # Create mock tool_use with unknown tool
        tool_use = Mock()
        tool_use.name = "unknown_tool"
        tool_use.input = {}
        tool_use.id = "tool_456"

        # Execute tool call
        result = await validator._execute_tool_call(tool_use)

        # Verify error handling
        assert result["type"] == "tool_result"
        assert result["tool_use_id"] == "tool_456"
        assert "Unknown tool" in result["content"]


@pytest.mark.asyncio
async def test_execute_tool_call_tool_error():
    """Test _execute_tool_call handles tool execution errors gracefully."""
    with tempfile.TemporaryDirectory() as tmpdir:
        validator = LLMFindingValidator(
            anthropic_api_key="test-key",
            repo_root=tmpdir
        )

        # Create mock tool_use with invalid parameters that will cause error
        tool_use = Mock()
        tool_use.name = "read_file"
        tool_use.input = {"file_path": "../../../etc/passwd"}  # Path traversal attempt (blocked by security)
        tool_use.id = "tool_789"

        # Execute tool call
        result = await validator._execute_tool_call(tool_use)

        # Verify error is returned as content (not raised as exception)
        assert result["type"] == "tool_result"
        assert result["tool_use_id"] == "tool_789"
        # Should contain error message from path traversal protection
        assert "Error:" in result["content"] or "denied" in result["content"].lower() or "Access denied" in result["content"]


# Response Parsing Tests


def test_parse_validation_response_valid():
    """Test parsing VALID decision with security_issue category."""
    validator = LLMFindingValidator(
        anthropic_api_key="test-key",
        repo_root="/test/repo"
    )

    response_text = """DECISION: VALID
CATEGORY: security_issue
REASONING:
- exec() is reachable from HTTP endpoint /api/run
- User input flows directly to exec without sanitization
- Clear path from untrusted source to dangerous sink"""

    result = validator._parse_validation_response(response_text)

    # Verify result structure
    assert isinstance(result, ValidationResult)
    assert result.is_valid is True
    assert result.categories == ["security_issue"]
    assert len(result.reasoning) == 3
    assert "exec() is reachable" in result.reasoning[0]


def test_parse_validation_response_invalid():
    """Test parsing INVALID decision with hardening category."""
    validator = LLMFindingValidator(
        anthropic_api_key="test-key",
        repo_root="/test/repo"
    )

    response_text = """DECISION: INVALID
CATEGORY: hardening
REASONING:
- exec() function is defined but never called
- No route registration found for /api/run endpoint
- Code appears to be dead/unreachable"""

    result = validator._parse_validation_response(response_text)

    # Verify result structure
    assert isinstance(result, ValidationResult)
    assert result.is_valid is False
    assert result.categories == ["hardening"]
    assert len(result.reasoning) == 3


def test_parse_validation_response_malformed():
    """Test handling of malformed response without expected format."""
    validator = LLMFindingValidator(
        anthropic_api_key="test-key",
        repo_root="/test/repo"
    )

    response_text = "This is not a valid response format"

    result = validator._parse_validation_response(response_text)

    # Verify conservative error handling
    assert isinstance(result, ValidationResult)
    assert result.is_valid is False
    assert "parse" in result.categories[0].lower()


# Agentic Loop Tests


@pytest.mark.asyncio
async def test_run_validation_with_tool_use(mock_finding, mock_evidence, mock_classification):
    """Test multi-turn conversation with tool use."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test file for tool to read
        test_file = os.path.join(tmpdir, "app.py")
        with open(test_file, "w") as f:
            f.write("def handler():\n    exec(user_input)\n")

        validator = LLMFindingValidator(
            anthropic_api_key="test-key",
            repo_root=tmpdir
        )

        # Mock Anthropic API response structures
        class MockTextBlock:
            def __init__(self, text):
                self.type = "text"
                self.text = text

        class MockToolUse:
            def __init__(self, name, tool_input, tool_id):
                self.type = "tool_use"
                self.name = name
                self.input = tool_input
                self.id = tool_id

        class MockMessage:
            def __init__(self, stop_reason, content):
                self.stop_reason = stop_reason
                self.content = content

        # Track call count
        call_count = 0

        def mock_create(*args, **kwargs):
            nonlocal call_count
            call_count += 1

            # First call: Return tool_use (LLM wants to read file)
            if call_count == 1:
                tool_use = MockToolUse("read_file", {"file_path": "app.py"}, "tool_1")
                return MockMessage("tool_use", [tool_use])

            # Second call: Return end_turn with decision
            elif call_count == 2:
                decision_text = """DECISION: VALID
CATEGORY: security_issue
REASONING:
- exec() is reachable from handler
- User input flows directly to exec
- Clear security vulnerability"""
                text_block = MockTextBlock(decision_text)
                return MockMessage("end_turn", [text_block])

        # Mock the client.messages.create call
        validator.client.messages.create = mock_create

        # Create threat model profile mock
        threat_model_profile = Mock()

        # Call _run_validation
        result = await validator._run_validation(
            finding=mock_finding,
            evidence=mock_evidence,
            classification=mock_classification,
            threat_model_profile=threat_model_profile,
            criticism_level="high"
        )

        # Verify result
        assert isinstance(result, ValidationResult)
        assert call_count == 2  # Should have made 2 API calls
        assert result.is_valid is True
        assert result.categories == ["security_issue"]


@pytest.mark.asyncio
async def test_run_validation_max_turns(mock_finding, mock_evidence, mock_classification):
    """Test max turns limit prevents infinite loops."""
    with tempfile.TemporaryDirectory() as tmpdir:
        validator = LLMFindingValidator(
            anthropic_api_key="test-key",
            repo_root=tmpdir
        )

        # Mock Anthropic API response structures
        class MockToolUse:
            def __init__(self, name, tool_input, tool_id):
                self.type = "tool_use"
                self.name = name
                self.input = tool_input
                self.id = tool_id

        class MockMessage:
            def __init__(self, stop_reason, content):
                self.stop_reason = stop_reason
                self.content = content

        # Track call count
        call_count = 0

        def mock_create(*args, **kwargs):
            nonlocal call_count
            call_count += 1

            # Always return tool_use (never finishes)
            tool_use = MockToolUse("read_file", {"file_path": "app.py"}, f"tool_{call_count}")
            return MockMessage("tool_use", [tool_use])

        # Mock the client.messages.create call
        validator.client.messages.create = mock_create

        # Create threat model profile mock
        threat_model_profile = Mock()

        # Call _run_validation
        result = await validator._run_validation(
            finding=mock_finding,
            evidence=mock_evidence,
            classification=mock_classification,
            threat_model_profile=threat_model_profile,
            criticism_level="high"
        )

        # Verify result
        assert isinstance(result, ValidationResult)
        assert result.is_valid is False
        assert call_count == 10  # Should have hit max turns limit
        assert any("exceeded" in reason.lower() for reason in result.reasoning)
        assert "inconclusive" in result.categories

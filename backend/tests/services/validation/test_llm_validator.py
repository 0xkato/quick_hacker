"""Tests for LLM validator."""
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock

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
    assert grep_code_tool["description"] == "Search codebase for patterns"
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

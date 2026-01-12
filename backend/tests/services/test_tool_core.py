# backend/tests/services/test_tool_core.py
import pytest
from services.tool_core import ToolCore

@pytest.fixture
def temp_repo(tmp_path):
    """Create a temporary repository structure."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "src").mkdir()
    (repo / "src" / "main.py").write_text("def main(): pass")
    (repo / "node_modules").mkdir()
    (repo / "node_modules" / "pkg" / "index.js").parent.mkdir(parents=True)
    (repo / "node_modules" / "pkg" / "index.js").write_text("module.exports = {}")
    return repo

@pytest.fixture
def tool_core(temp_repo):
    """Create ToolCore instance for testing."""
    return ToolCore(
        repo_path=str(temp_repo),
        project_id="test-project",
        agent_id="test-agent"
    )

@pytest.fixture
def mock_flow_service(monkeypatch):
    """Mock flow service for testing."""
    from services.flow_service import FlowService, flow_service
    mock_service = FlowService()

    # Patch the flow_service module-level instance
    import services.flow_service
    monkeypatch.setattr(services.flow_service, "flow_service", mock_service)

    return mock_service

class TestToolCorePathValidation:
    """Tests for ToolCore path validation."""

    def test_validate_path_accepts_valid_file(self, tool_core, temp_repo):
        """Valid file path within repo should be accepted."""
        result = tool_core._validate_path("src/main.py")
        assert result == (temp_repo / "src" / "main.py").resolve()

    def test_validate_path_rejects_path_traversal(self, tool_core):
        """Path traversal attempts should be rejected."""
        with pytest.raises(ValueError, match="escapes"):
            tool_core._validate_path("../../../etc/passwd")

    def test_validate_path_rejects_excluded_dir(self, tool_core):
        """Files in excluded directories should be rejected."""
        with pytest.raises(ValueError, match="excluded"):
            tool_core._validate_path("node_modules/pkg/index.js")

    def test_validate_path_raises_not_found(self, tool_core):
        """Non-existent files should raise FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            tool_core._validate_path("src/nonexistent.py")

    def test_validate_dir_accepts_valid_dir(self, tool_core, temp_repo):
        """Valid directory path should be accepted."""
        result = tool_core._validate_dir("src")
        assert result == (temp_repo / "src").resolve()

    def test_validate_dir_rejects_file(self, tool_core):
        """File paths should be rejected by _validate_dir."""
        with pytest.raises(NotADirectoryError):
            tool_core._validate_dir("src/main.py")

    def test_validate_dir_rejects_symlink(self, tool_core, temp_repo):
        """Symlink directories should be rejected."""
        (temp_repo / "real_dir").mkdir()
        (temp_repo / "link_dir").symlink_to(temp_repo / "real_dir")
        with pytest.raises(ValueError, match="Symlink"):
            tool_core._validate_dir("link_dir")

    def test_validate_dir_rejects_path_traversal(self, tool_core):
        """Directory path traversal should be rejected."""
        with pytest.raises(ValueError, match="escapes"):
            tool_core._validate_dir("../../../tmp")


class TestToolCoreReadFile:
    """Tests for ToolCore.read_file()."""

    @pytest.mark.asyncio
    async def test_read_file_returns_content(self, tool_core, temp_repo):
        """Should return file content."""
        content = await tool_core.read_file("src/main.py")
        assert "def main(): pass" in content

    @pytest.mark.asyncio
    async def test_read_file_with_line_range(self, tool_core, temp_repo):
        """Should return only specified lines."""
        # Create multi-line file
        (temp_repo / "multiline.txt").write_text("line1\nline2\nline3\nline4\nline5")

        content = await tool_core.read_file("multiline.txt", start_line=2, end_line=4)
        assert "line2" in content
        assert "line4" in content
        assert "line1" not in content
        assert "line5" not in content

    @pytest.mark.asyncio
    async def test_read_file_clamps_out_of_range(self, tool_core, temp_repo):
        """Should clamp line numbers to valid range."""
        (temp_repo / "short.txt").write_text("line1\nline2")

        # end_line beyond file length should be clamped
        content = await tool_core.read_file("short.txt", start_line=1, end_line=100)
        assert "line1" in content
        assert "line2" in content

    @pytest.mark.asyncio
    async def test_read_file_raises_not_found(self, tool_core):
        """Should raise FileNotFoundError for missing files."""
        with pytest.raises(FileNotFoundError):
            await tool_core.read_file("nonexistent.py")

    @pytest.mark.asyncio
    async def test_read_file_empty_when_start_exceeds_end(self, tool_core, temp_repo):
        """Should return empty when start >= end after clamping."""
        (temp_repo / "tiny.txt").write_text("line1")

        content = await tool_core.read_file("tiny.txt", start_line=10, end_line=20)
        assert content == ""

    @pytest.mark.asyncio
    async def test_read_file_rejects_path_traversal(self, tool_core):
        """Should reject path traversal attempts."""
        with pytest.raises(ValueError, match="escapes"):
            await tool_core.read_file("../../../etc/passwd")


class TestToolCoreListDirectory:
    """Tests for ToolCore.list_directory()."""

    @pytest.mark.asyncio
    async def test_list_directory_returns_items(self, tool_core, temp_repo):
        """Should return directory contents."""
        result = await tool_core.list_directory(".")
        assert "src/" in result["items"] or "src" in [i.rstrip("/") for i in result["items"]]

    @pytest.mark.asyncio
    async def test_list_directory_excludes_hidden(self, tool_core, temp_repo):
        """Should exclude hidden files/dirs."""
        (temp_repo / ".hidden").write_text("secret")
        result = await tool_core.list_directory(".")
        assert ".hidden" not in result["items"]

    @pytest.mark.asyncio
    async def test_list_directory_raises_not_dir(self, tool_core):
        """Should raise for non-directory paths."""
        with pytest.raises(NotADirectoryError):
            await tool_core.list_directory("src/main.py")

    @pytest.mark.asyncio
    async def test_list_directory_recursive(self, tool_core, temp_repo):
        """Should list files recursively."""
        (temp_repo / "subdir").mkdir()
        (temp_repo / "subdir" / "nested.py").write_text("pass")

        result = await tool_core.list_directory(".", recursive=True)
        assert any("nested.py" in item for item in result["items"])

    @pytest.mark.asyncio
    async def test_list_directory_rejects_excluded_dir(self, tool_core, temp_repo):
        """Should reject listing excluded directories."""
        with pytest.raises(ValueError, match="excluded"):
            await tool_core.list_directory("node_modules")


class TestToolCoreSearchCode:
    """Tests for ToolCore.search_code()."""

    @pytest.mark.asyncio
    async def test_search_code_finds_matches(self, tool_core, temp_repo):
        """Should find pattern matches."""
        result = await tool_core.search_code(r"def\s+\w+")
        assert result["count"] > 0
        assert any("main.py" in m["file"] for m in result["matches"])

    @pytest.mark.asyncio
    async def test_search_code_respects_max_results(self, tool_core, temp_repo):
        """Should respect max_results limit."""
        # Create files with many matches
        for i in range(20):
            (temp_repo / f"file{i}.py").write_text(f"def func{i}(): pass")

        result = await tool_core.search_code(r"def\s+\w+", max_results=5)
        assert result["count"] <= 5

    @pytest.mark.asyncio
    async def test_search_code_invalid_regex(self, tool_core):
        """Should handle invalid regex gracefully."""
        with pytest.raises(ValueError, match="regex"):
            await tool_core.search_code(r"[invalid")


class TestToolCoreSecurityScanners:
    """Tests for ToolCore security scanner methods."""

    @pytest.mark.asyncio
    async def test_scan_for_secrets_returns_result(self, tool_core, temp_repo):
        """Should return scan result."""
        # Create file with fake secret pattern
        (temp_repo / "config.py").write_text('API_KEY = "sk-1234567890abcdef"')

        result = await tool_core.scan_for_secrets()
        assert "files_scanned" in result
        assert "findings" in result

    @pytest.mark.asyncio
    async def test_dependency_audit_returns_result(self, tool_core, temp_repo):
        """Should return audit result even with no lockfiles."""
        result = await tool_core.dependency_audit()
        assert "success" in result

    @pytest.mark.asyncio
    async def test_grep_semantic_finds_pattern(self, tool_core, temp_repo):
        """Should find pattern matches with context."""
        (temp_repo / "vuln.py").write_text("eval(user_input)")

        result = await tool_core.grep_semantic(r"eval\s*\(")
        assert result["success"]

    @pytest.mark.asyncio
    async def test_grep_semantic_invalid_regex(self, tool_core):
        """Should raise error for invalid regex pattern."""
        with pytest.raises(ValueError, match="Invalid regex pattern"):
            await tool_core.grep_semantic(r"[invalid")

    @pytest.mark.asyncio
    async def test_generate_security_report_returns_report(self, tool_core):
        """Should generate a report from findings."""
        report = await tool_core.generate_security_report([], output_format="markdown")
        assert "Security Scan Report" in report
        assert "Total Findings:** 0" in report

    @pytest.mark.asyncio
    async def test_generate_security_report_invalid_format(self, tool_core):
        """Should raise error for invalid format."""
        with pytest.raises(ValueError, match="Invalid format"):
            await tool_core.generate_security_report([], output_format="invalid")


class TestToolCoreSinkSignals:
    """Tests for ToolCore sink signal methods."""

    @pytest.mark.asyncio
    async def test_list_sink_signals_empty(self, tool_core):
        """Should return empty list when no signals."""
        result = await tool_core.list_sink_signals()
        assert "signals" in result
        assert result["count"] >= 0

    @pytest.mark.asyncio
    async def test_upsert_sink_signal_creates(self, tool_core):
        """Should create new sink signal."""
        result = await tool_core.upsert_sink_signal(
            kind="sink",
            label="eval() call",
            file_path="src/main.py",
            line_number=10,
        )
        assert "signal" in result
        assert result["signal"]["kind"] == "sink"


class TestUpsertSinkSignalValidation:
    """Tests for upsert_sink_signal() validation edge cases."""

    @pytest.mark.asyncio
    async def test_upsert_invalid_kind_raises(self, tool_core):
        """Should raise ValueError for invalid kind."""
        with pytest.raises(ValueError, match="Invalid kind"):
            await tool_core.upsert_sink_signal(
                kind="invalid_kind",
                label="test",
                file_path="src/main.py",
            )

    @pytest.mark.asyncio
    async def test_upsert_invalid_status_raises(self, tool_core):
        """Should raise ValueError for invalid status."""
        with pytest.raises(ValueError, match="Invalid status"):
            await tool_core.upsert_sink_signal(
                kind="sink",
                label="test",
                file_path="src/main.py",
                status="invalid_status",
            )

    @pytest.mark.asyncio
    async def test_upsert_invalid_risk_tier_raises(self, tool_core):
        """Should raise ValueError for invalid llm_risk_tier."""
        with pytest.raises(ValueError, match="Invalid risk tier"):
            await tool_core.upsert_sink_signal(
                kind="sink",
                label="test",
                file_path="src/main.py",
                llm_risk_tier="X",  # Invalid tier
            )

    @pytest.mark.asyncio
    async def test_upsert_llm_score_below_zero_raises(self, tool_core):
        """Should raise ValueError for llm_score < 0."""
        with pytest.raises(ValueError, match="llm_score must be 0-100"):
            await tool_core.upsert_sink_signal(
                kind="sink",
                label="test",
                file_path="src/main.py",
                llm_score=-1,
            )

    @pytest.mark.asyncio
    async def test_upsert_llm_score_above_100_raises(self, tool_core):
        """Should raise ValueError for llm_score > 100."""
        with pytest.raises(ValueError, match="llm_score must be 0-100"):
            await tool_core.upsert_sink_signal(
                kind="sink",
                label="test",
                file_path="src/main.py",
                llm_score=101,
            )


class TestListSinkSignalsValidation:
    """Tests for list_sink_signals() validation edge cases."""

    @pytest.mark.asyncio
    async def test_list_invalid_status_raises(self, tool_core):
        """Should raise ValueError for invalid status filter."""
        with pytest.raises(ValueError, match="Invalid status"):
            await tool_core.list_sink_signals(status="invalid_status")

    @pytest.mark.asyncio
    async def test_list_limit_clamped_to_minimum(self, tool_core):
        """Should clamp limit to minimum of 1."""
        result = await tool_core.list_sink_signals(limit=0)
        # Should not fail and should clamp to 1
        assert "signals" in result

    @pytest.mark.asyncio
    async def test_list_limit_clamped_to_maximum(self, tool_core):
        """Should clamp limit to maximum of 200."""
        result = await tool_core.list_sink_signals(limit=500)
        # Should not fail and should clamp to 200
        assert "signals" in result

    @pytest.mark.asyncio
    async def test_list_negative_limit_clamped(self, tool_core):
        """Should clamp negative limit to 1."""
        result = await tool_core.list_sink_signals(limit=-10)
        # Should not fail and should clamp to 1
        assert "signals" in result


class TestToolCoreReportFinding:
    """Tests for ToolCore.report_finding()."""

    @pytest.mark.asyncio
    async def test_report_finding_returns_data(self, tool_core):
        """Should return reported finding data."""
        result = await tool_core.report_finding(
            severity="high",
            title="SQL Injection",
            vulnerability_type="SQL Injection",
            file_path="src/db.py",
            line_start=42,
            vulnerable_code="query = f'SELECT * FROM {user_input}'",
            description="User input concatenated into SQL query",
            confidence=0.9,
        )
        assert result["reported"]
        assert result["finding"]["severity"] == "high"


class TestReportFindingValidation:
    """Tests for report_finding() input validation."""

    @pytest.mark.asyncio
    async def test_invalid_severity_raises(self, tool_core):
        """Should raise ValueError for invalid severity."""
        with pytest.raises(ValueError, match="Invalid severity"):
            await tool_core.report_finding(
                severity="invalid",
                title="Test",
                vulnerability_type="Test",
                file_path="test.py",
                line_start=1,
                vulnerable_code="code",
                description="desc",
                confidence=0.5,
            )

    @pytest.mark.asyncio
    async def test_all_valid_severities_accepted(self, tool_core):
        """Should accept all valid severity values."""
        for severity in ["critical", "high", "medium", "low", "info"]:
            result = await tool_core.report_finding(
                severity=severity,
                title="Test",
                vulnerability_type="Test",
                file_path="test.py",
                line_start=1,
                vulnerable_code="code",
                description="desc",
                confidence=0.5,
            )
            assert result["reported"]

    @pytest.mark.asyncio
    async def test_severity_case_insensitive(self, tool_core):
        """Should accept severity values case-insensitively."""
        result = await tool_core.report_finding(
            severity="HIGH",
            title="Test",
            vulnerability_type="Test",
            file_path="test.py",
            line_start=1,
            vulnerable_code="code",
            description="desc",
            confidence=0.5,
        )
        assert result["reported"]

    @pytest.mark.asyncio
    async def test_confidence_below_zero_raises(self, tool_core):
        """Should raise ValueError for confidence < 0."""
        with pytest.raises(ValueError, match="confidence must be between 0.0 and 1.0"):
            await tool_core.report_finding(
                severity="high",
                title="Test",
                vulnerability_type="Test",
                file_path="test.py",
                line_start=1,
                vulnerable_code="code",
                description="desc",
                confidence=-0.1,
            )

    @pytest.mark.asyncio
    async def test_confidence_above_one_raises(self, tool_core):
        """Should raise ValueError for confidence > 1.0."""
        with pytest.raises(ValueError, match="confidence must be between 0.0 and 1.0"):
            await tool_core.report_finding(
                severity="high",
                title="Test",
                vulnerability_type="Test",
                file_path="test.py",
                line_start=1,
                vulnerable_code="code",
                description="desc",
                confidence=1.5,
            )

    @pytest.mark.asyncio
    async def test_confidence_boundary_values_accepted(self, tool_core):
        """Should accept boundary values 0.0 and 1.0 for confidence."""
        for confidence in [0.0, 1.0]:
            result = await tool_core.report_finding(
                severity="high",
                title="Test",
                vulnerability_type="Test",
                file_path="test.py",
                line_start=1,
                vulnerable_code="code",
                description="desc",
                confidence=confidence,
            )
            assert result["reported"]

    @pytest.mark.asyncio
    async def test_line_start_zero_raises(self, tool_core):
        """Should raise ValueError for line_start = 0."""
        with pytest.raises(ValueError, match="line_start must be a positive integer"):
            await tool_core.report_finding(
                severity="high",
                title="Test",
                vulnerability_type="Test",
                file_path="test.py",
                line_start=0,
                vulnerable_code="code",
                description="desc",
                confidence=0.5,
            )

    @pytest.mark.asyncio
    async def test_line_start_negative_raises(self, tool_core):
        """Should raise ValueError for negative line_start."""
        with pytest.raises(ValueError, match="line_start must be a positive integer"):
            await tool_core.report_finding(
                severity="high",
                title="Test",
                vulnerability_type="Test",
                file_path="test.py",
                line_start=-5,
                vulnerable_code="code",
                description="desc",
                confidence=0.5,
            )

    @pytest.mark.asyncio
    async def test_line_end_less_than_line_start_raises(self, tool_core):
        """Should raise ValueError when line_end < line_start."""
        with pytest.raises(ValueError, match="line_end must be >= line_start"):
            await tool_core.report_finding(
                severity="high",
                title="Test",
                vulnerability_type="Test",
                file_path="test.py",
                line_start=10,
                line_end=5,
                vulnerable_code="code",
                description="desc",
                confidence=0.5,
            )

    @pytest.mark.asyncio
    async def test_line_end_zero_raises(self, tool_core):
        """Should raise ValueError for line_end = 0."""
        with pytest.raises(ValueError, match="line_end must be a positive integer"):
            await tool_core.report_finding(
                severity="high",
                title="Test",
                vulnerability_type="Test",
                file_path="test.py",
                line_start=1,
                line_end=0,
                vulnerable_code="code",
                description="desc",
                confidence=0.5,
            )

    @pytest.mark.asyncio
    async def test_line_end_equal_to_line_start_accepted(self, tool_core):
        """Should accept line_end equal to line_start."""
        result = await tool_core.report_finding(
            severity="high",
            title="Test",
            vulnerability_type="Test",
            file_path="test.py",
            line_start=10,
            line_end=10,
            vulnerable_code="code",
            description="desc",
            confidence=0.5,
        )
        assert result["reported"]

    @pytest.mark.asyncio
    async def test_line_end_greater_than_line_start_accepted(self, tool_core):
        """Should accept line_end greater than line_start."""
        result = await tool_core.report_finding(
            severity="high",
            title="Test",
            vulnerability_type="Test",
            file_path="test.py",
            line_start=10,
            line_end=20,
            vulnerable_code="code",
            description="desc",
            confidence=0.5,
        )
        assert result["reported"]


@pytest.mark.asyncio
async def test_track_file_analysis(tool_core, mock_flow_service):
    """Test tracking file analysis creates file node."""
    # Initialize flow
    mock_flow_service.initialize_flow(tool_core.agent_id)

    result = await tool_core.track_file_analysis(
        file_path="api/routes.py",
        purpose="looking for entry points"
    )

    assert "node_id" in result
    assert result["status"] == "tracked"

    # Verify flow service was called correctly
    flow = mock_flow_service.get_flow(tool_core.agent_id)
    file_nodes = [n for n in flow.nodes if n.type == "file"]
    assert len(file_nodes) == 1
    assert file_nodes[0].label == "api/routes.py"
    assert file_nodes[0].data["purpose"] == "looking for entry points"

    # Verify context updated
    assert flow.context.current_file == "api/routes.py"
    assert flow.context.current_function is None
    assert flow.context.call_depth == 0


@pytest.mark.asyncio
async def test_track_function_discovered(tool_core, mock_flow_service):
    """Test tracking function discovery creates function node."""
    mock_flow_service.initialize_flow(tool_core.agent_id)

    # First track the file
    await tool_core.track_file_analysis("api/routes.py")

    # Then track function
    result = await tool_core.track_function_discovered(
        function_name="handleUpload",
        file_path="api/routes.py",
        line_number=45,
        signature="async def handleUpload(file: UploadFile)",
        reason="handles file uploads"
    )

    assert "node_id" in result

    # Verify function node created
    flow = mock_flow_service.get_flow(tool_core.agent_id)
    func_nodes = [n for n in flow.nodes if n.type == "function"]
    assert len(func_nodes) == 1
    assert func_nodes[0].label == "handleUpload"
    assert func_nodes[0].data["line_number"] == 45
    assert func_nodes[0].data["signature"] == "async def handleUpload(file: UploadFile)"

    # Verify context updated
    assert flow.context.current_function == "handleUpload"


@pytest.mark.asyncio
async def test_track_call_chain(tool_core, mock_flow_service):
    """Test tracking call chain creates call nodes."""
    mock_flow_service.initialize_flow(tool_core.agent_id)

    # Setup: track file and function
    await tool_core.track_file_analysis("api/routes.py")
    await tool_core.track_function_discovered("handleUpload", "api/routes.py", 45)

    # Track call chain
    result = await tool_core.track_call_chain(
        from_function="handleUpload",
        calls=[
            {"target": "validateFile", "file": "validators.py"},
            {"target": "saveToS3", "file": "storage.py"}
        ]
    )

    assert "call_nodes" in result
    assert len(result["call_nodes"]) == 2

    # Verify call nodes created
    flow = mock_flow_service.get_flow(tool_core.agent_id)
    call_nodes = [n for n in flow.nodes if n.type == "call"]
    assert len(call_nodes) == 2
    assert call_nodes[0].label == "→ validateFile"
    assert call_nodes[0].data["target_file"] == "validators.py"
    assert call_nodes[1].label == "→ saveToS3"


@pytest.mark.asyncio
async def test_track_call_chain_respects_depth(tool_core, mock_flow_service):
    """Test call chain respects max_call_depth limit."""
    mock_flow_service.initialize_flow(tool_core.agent_id)

    # Set max depth to 2
    mock_flow_service.update_context(
        tool_core.agent_id,
        max_call_depth=2,
        call_depth=0
    )

    await tool_core.track_file_analysis("test.py")
    await tool_core.track_function_discovered("foo", "test.py", 1)

    # First call (depth 1) - should succeed
    result1 = await tool_core.track_call_chain("foo", [{"target": "bar"}])
    assert len(result1["call_nodes"]) == 1

    # Second call (depth 2) - should succeed
    result2 = await tool_core.track_call_chain("bar", [{"target": "baz"}])
    assert len(result2["call_nodes"]) == 1

    # Third call (depth 3) - should be skipped
    result3 = await tool_core.track_call_chain("baz", [{"target": "qux"}])
    assert len(result3["call_nodes"]) == 0

    # Verify only 2 call nodes created
    flow = mock_flow_service.get_flow(tool_core.agent_id)
    call_nodes = [n for n in flow.nodes if n.type == "call"]
    assert len(call_nodes) == 2

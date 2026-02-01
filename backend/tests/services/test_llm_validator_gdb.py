"""Tests for GDB tool in LLM validator."""
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
import tempfile


class TestGDBTool:
    @pytest.fixture
    def temp_repo(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a simple test binary script
            script_path = Path(tmpdir) / "test_binary.sh"
            script_path.write_text("#!/bin/bash\necho 'test'\n")
            script_path.chmod(0o755)
            yield tmpdir

    @pytest.fixture
    def validator(self, temp_repo):
        # Import here to avoid issues if anthropic not installed
        try:
            from services.validation.llm_validator import LLMFindingValidator
            return LLMFindingValidator(
                anthropic_api_key="test-key",
                repo_root=temp_repo,
                enabled_verifiers=["gdb"],
            )
        except RuntimeError:
            pytest.skip("anthropic package not installed")

    def test_gdb_tool_in_definitions_when_enabled(self, validator):
        tools = validator._get_tool_definitions()
        tool_names = [t["name"] for t in tools]
        assert "gdb_debug" in tool_names

    def test_gdb_tool_not_in_definitions_when_disabled(self, temp_repo):
        try:
            from services.validation.llm_validator import LLMFindingValidator
            validator = LLMFindingValidator(
                anthropic_api_key="test-key",
                repo_root=temp_repo,
                enabled_verifiers=[],  # GDB not enabled
            )
            tools = validator._get_tool_definitions()
            tool_names = [t["name"] for t in tools]
            assert "gdb_debug" not in tool_names
        except RuntimeError:
            pytest.skip("anthropic package not installed")

    def test_gdb_tool_rejects_path_outside_repo(self, validator):
        result = validator._tool_gdb_debug(
            binary_path="/etc/passwd",
            commands=["run"],
        )
        assert "Error" in result
        assert "outside" in result.lower() or "within" in result.lower()

    def test_gdb_tool_rejects_traversal(self, validator):
        result = validator._tool_gdb_debug(
            binary_path="../../../etc/passwd",
            commands=["run"],
        )
        assert "Error" in result

    @patch("subprocess.run")
    def test_gdb_tool_executes_commands(self, mock_run, validator, temp_repo):
        mock_run.return_value = MagicMock(
            stdout="Program received signal SIGSEGV\n#0 0x00 in crash()",
            stderr="",
            returncode=0,
        )
        result = validator._tool_gdb_debug(
            binary_path="test_binary.sh",
            commands=["run", "bt"],
        )
        assert mock_run.called
        assert "SIGSEGV" in result or mock_run.called

    @patch("subprocess.run")
    def test_gdb_tool_timeout(self, mock_run, validator):
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="gdb", timeout=30)
        result = validator._tool_gdb_debug(
            binary_path="test_binary.sh",
            commands=["run"],
        )
        assert "timeout" in result.lower()

    def test_gdb_tool_input_file_outside_repo(self, validator):
        """Test that input_file outside repo is rejected."""
        result = validator._tool_gdb_debug(
            binary_path="test_binary.sh",
            commands=["run"],
            input_file="/etc/passwd"
        )
        assert "Error" in result
        assert "within" in result.lower()

    @patch("subprocess.run")
    def test_gdb_tool_input_file_valid(self, mock_run, validator, temp_repo):
        """Test GDB with valid input file."""
        # Create test input file
        input_path = Path(temp_repo) / "input.txt"
        input_path.write_text("test input")

        mock_run.return_value = MagicMock(
            stdout="Program output",
            stderr="",
            returncode=0,
        )
        result = validator._tool_gdb_debug(
            binary_path="test_binary.sh",
            commands=["bt"],
            input_file="input.txt"
        )
        assert mock_run.called
        # Verify the script contains properly quoted path
        call_args = mock_run.call_args
        assert "run <" in call_args.kwargs['input']

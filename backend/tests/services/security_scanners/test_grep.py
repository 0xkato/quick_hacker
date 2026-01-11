"""Tests for semantic grep scanner."""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from services.security_scanners.base import WorkspacePolicy, ScanLimits
from services.security_scanners.grep import (
    semantic_grep,
    validate_pattern,
)


class TestValidatePattern:
    def test_accepts_valid_pattern(self):
        valid, err = validate_pattern(r"eval\(")
        assert valid is True
        assert err is None

    def test_rejects_too_long_pattern(self):
        valid, err = validate_pattern("x" * 600)
        assert valid is False
        assert "too long" in err.lower()

    def test_rejects_invalid_regex(self):
        valid, err = validate_pattern("[unclosed")
        assert valid is False
        assert "invalid regex" in err.lower()


class TestSemanticGrep:
    @pytest.fixture
    def code_repo(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "src").mkdir()
            (root / "src" / "dangerous.py").write_text(
                "def run_command(cmd):\n"
                "    result = eval(cmd)  # Dangerous!\n"
                "    return result\n"
            )
            (root / "src" / "safe.py").write_text(
                "def add(a, b):\n"
                "    return a + b\n"
            )
            (root / "src" / "sql.py").write_text(
                "def get_user(user_id):\n"
                '    query = f"SELECT * FROM users WHERE id = {user_id}"\n'
                "    return db.execute(query)\n"
            )
            yield root

    @pytest.mark.asyncio
    async def test_finds_pattern_matches(self, code_repo):
        policy = WorkspacePolicy(
            workspace_root=str(code_repo),
            max_file_size=10 * 1024 * 1024,
        )
        result = await semantic_grep(policy, pattern=r"eval\(")

        assert result.success is True
        assert len(result.findings) >= 1
        assert any("dangerous.py" in f.file_path for f in result.findings)

    @pytest.mark.asyncio
    async def test_includes_context_lines(self, code_repo):
        policy = WorkspacePolicy(
            workspace_root=str(code_repo),
            max_file_size=10 * 1024 * 1024,
        )
        result = await semantic_grep(policy, pattern=r"eval\(", context_lines=2)

        assert result.success is True
        for finding in result.findings:
            # snippet should contain the match with context
            assert finding.snippet is not None

    @pytest.mark.asyncio
    async def test_respects_file_glob(self, code_repo):
        policy = WorkspacePolicy(
            workspace_root=str(code_repo),
            max_file_size=10 * 1024 * 1024,
        )
        result = await semantic_grep(policy, pattern=r"return", file_glob="**/*.py")

        assert result.success is True
        # Should find matches in multiple files
        assert len(result.findings) >= 2

    @pytest.mark.asyncio
    async def test_returns_error_for_invalid_pattern(self, code_repo):
        policy = WorkspacePolicy(
            workspace_root=str(code_repo),
            max_file_size=10 * 1024 * 1024,
        )
        result = await semantic_grep(policy, pattern="[unclosed")

        assert result.success is False
        assert "invalid regex" in result.error.lower()

    @pytest.mark.asyncio
    async def test_finds_sql_injection_pattern(self, code_repo):
        policy = WorkspacePolicy(
            workspace_root=str(code_repo),
            max_file_size=10 * 1024 * 1024,
        )
        # Pattern for string formatting in SQL
        result = await semantic_grep(policy, pattern=r'f".*\{.*\}.*"')

        assert result.success is True
        sql_findings = [f for f in result.findings if "sql" in f.file_path]
        assert len(sql_findings) >= 1

    @pytest.mark.asyncio
    async def test_respects_match_limits(self, code_repo):
        policy = WorkspacePolicy(
            workspace_root=str(code_repo),
            max_file_size=10 * 1024 * 1024,
        )
        result = await semantic_grep(policy, pattern=r"return", max_matches=1)

        assert result.success is True
        assert len(result.findings) == 1

    @pytest.mark.asyncio
    async def test_includes_match_in_details(self, code_repo):
        policy = WorkspacePolicy(
            workspace_root=str(code_repo),
            max_file_size=10 * 1024 * 1024,
        )
        result = await semantic_grep(policy, pattern=r"eval\([^)]+\)")

        for finding in result.findings:
            assert finding.details is not None
            assert "match" in finding.details
            assert "pattern" in finding.details

    @pytest.mark.asyncio
    async def test_cancellation_support(self, code_repo):
        policy = WorkspacePolicy(
            workspace_root=str(code_repo),
            max_file_size=10 * 1024 * 1024,
        )
        limits = ScanLimits(cancelled=lambda: True)
        result = await semantic_grep(policy, pattern=r"return", limits=limits)

        # Should return early due to cancellation
        assert result.cancelled is True

    @pytest.mark.asyncio
    async def test_handles_nested_quantifier_patterns(self, code_repo):
        policy = WorkspacePolicy(
            workspace_root=str(code_repo),
            max_file_size=10 * 1024 * 1024,
        )
        # Pattern with nested quantifiers (backtracking risk)
        result = await semantic_grep(policy, pattern=r"(a+)+")

        assert result.success is False
        assert "backtracking" in result.error.lower()

    @pytest.mark.asyncio
    async def test_empty_result_for_no_matches(self, code_repo):
        policy = WorkspacePolicy(
            workspace_root=str(code_repo),
            max_file_size=10 * 1024 * 1024,
        )
        result = await semantic_grep(policy, pattern=r"nonexistent_pattern_xyz123")

        assert result.success is True
        assert len(result.findings) == 0
        assert result.files_scanned > 0

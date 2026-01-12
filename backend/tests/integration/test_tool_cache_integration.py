# backend/tests/integration/test_tool_cache_integration.py
import pytest
import asyncio
import subprocess
from pathlib import Path
from services.tool_core import ToolCore
from services.tool_cache import ToolCache
from services.git_head_tracker import GitHeadTracker


class TestToolCacheIntegration:
    @pytest.mark.asyncio
    async def test_read_file_caches_result(self, tmp_path):
        # Initialize git repo in tmp_path
        subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=tmp_path, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=tmp_path, check=True, capture_output=True)

        # Create test file
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")

        # Commit the file so we have a HEAD
        subprocess.run(["git", "add", "test.txt"], cwd=tmp_path, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=tmp_path, check=True, capture_output=True)

        # Initialize ToolCore with cache
        cache = ToolCache(max_size=100, ttl_seconds=3600)
        tool_core = ToolCore(
            repo_path=str(tmp_path),
            project_id="test_project",
            cache=cache,
        )

        # First read - cache miss
        result1 = await tool_core.read_file(path="test.txt")
        metrics1 = cache.get_metrics()
        assert metrics1["misses"] == 1
        assert metrics1["hits"] == 0

        # Second read - cache hit
        result2 = await tool_core.read_file(path="test.txt")
        metrics2 = cache.get_metrics()
        assert metrics2["misses"] == 1
        assert metrics2["hits"] == 1

        # Results should be identical
        assert result1 == result2

    @pytest.mark.asyncio
    async def test_cache_disabled_when_none(self, tmp_path):
        # Create test file
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")

        # Initialize ToolCore without cache
        tool_core = ToolCore(
            repo_path=str(tmp_path),
            project_id="test_project",
            cache=None,  # Caching disabled
        )

        # Should work without caching
        result = await tool_core.read_file(path="test.txt")
        assert "test content" in result

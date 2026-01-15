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
        assert "test content" in result["content"]

    @pytest.mark.asyncio
    async def test_cache_skipped_when_git_head_unavailable(self, tmp_path):
        """Verify caching is safely skipped when git HEAD cannot be determined."""
        # Create file WITHOUT initializing git repo (git_head will be None)
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")

        cache = ToolCache(max_size=100, ttl_seconds=3600)
        tool_core = ToolCore(repo_path=str(tmp_path), project_id="test", cache=cache)

        # Should work but not cache anything
        result1 = await tool_core.read_file(path="test.txt")
        result2 = await tool_core.read_file(path="test.txt")

        assert "test content" in result1["content"]
        assert result1 == result2

        # Verify cache was never used (all reads are neither hits nor misses)
        metrics = cache.get_metrics()
        assert metrics["hits"] == 0
        assert metrics["misses"] == 0  # Never tried to use cache

    @pytest.mark.asyncio
    async def test_line_range_caching(self, tmp_path):
        """Verify line ranges create separate cache entries."""
        # Setup git repo
        subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=tmp_path, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=tmp_path, check=True, capture_output=True)

        # Create file with multiple lines
        test_file = tmp_path / "test.txt"
        test_file.write_text("line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\nline10\n")

        subprocess.run(["git", "add", "test.txt"], cwd=tmp_path, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Initial"], cwd=tmp_path, check=True, capture_output=True)

        cache = ToolCache(max_size=100, ttl_seconds=3600)
        tool_core = ToolCore(repo_path=str(tmp_path), project_id="test", cache=cache)

        # Read different line ranges - should be separate cache entries
        result1 = await tool_core.read_file(path="test.txt", start_line=1, end_line=5)
        result2 = await tool_core.read_file(path="test.txt", start_line=5, end_line=10)
        result3 = await tool_core.read_file(path="test.txt", start_line=1, end_line=5)

        metrics = cache.get_metrics()
        assert metrics["misses"] == 2  # result1 and result2
        assert metrics["hits"] == 1    # result3 matches result1
        assert result1 == result3
        assert result1 != result2

    @pytest.mark.asyncio
    async def test_cache_invalidated_on_git_commit(self, tmp_path):
        """Verify cache invalidates when git HEAD changes."""
        # Setup git repo
        subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=tmp_path, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=tmp_path, check=True, capture_output=True)

        test_file = tmp_path / "test.txt"
        test_file.write_text("original content")

        subprocess.run(["git", "add", "test.txt"], cwd=tmp_path, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Initial"], cwd=tmp_path, check=True, capture_output=True)

        cache = ToolCache(max_size=100, ttl_seconds=3600)
        tool_core = ToolCore(repo_path=str(tmp_path), project_id="test", cache=cache)

        # First read - cache miss
        result1 = await tool_core.read_file(path="test.txt")
        assert "original content" in result1["content"]

        # Modify file and create new commit
        test_file.write_text("updated content")
        subprocess.run(["git", "add", "test.txt"], cwd=tmp_path, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Update"], cwd=tmp_path, check=True, capture_output=True)

        # Second read - should be cache miss due to HEAD change
        result2 = await tool_core.read_file(path="test.txt")
        assert "updated content" in result2["content"]

        metrics = cache.get_metrics()
        assert metrics["misses"] == 2  # Both reads are misses
        assert metrics["hits"] == 0
        assert result1 != result2

    @pytest.mark.asyncio
    async def test_cache_ttl_expiration(self, tmp_path):
        """Verify cached entries expire after TTL."""
        # Setup git repo
        subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=tmp_path, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=tmp_path, check=True, capture_output=True)

        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")

        subprocess.run(["git", "add", "test.txt"], cwd=tmp_path, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Initial"], cwd=tmp_path, check=True, capture_output=True)

        # Use very short TTL (1 second)
        cache = ToolCache(max_size=100, ttl_seconds=1)
        tool_core = ToolCore(repo_path=str(tmp_path), project_id="test", cache=cache)

        # First read - cache miss
        result1 = await tool_core.read_file(path="test.txt")
        metrics1 = cache.get_metrics()
        assert metrics1["misses"] == 1
        assert metrics1["hits"] == 0

        # Second read immediately - cache hit
        result2 = await tool_core.read_file(path="test.txt")
        metrics2 = cache.get_metrics()
        assert metrics2["misses"] == 1
        assert metrics2["hits"] == 1

        # Wait for TTL expiration (1.1 seconds)
        await asyncio.sleep(1.1)

        # Third read - cache miss due to expiration
        result3 = await tool_core.read_file(path="test.txt")
        metrics3 = cache.get_metrics()
        assert metrics3["misses"] == 2  # Expired entry counts as miss
        assert metrics3["hits"] == 1

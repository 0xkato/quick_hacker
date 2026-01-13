# backend/tests/integration/test_tool_cache_coverage.py
import pytest
import subprocess
import asyncio
from pathlib import Path
from services.tool_core import ToolCore
from services.tool_cache import ToolCache


@pytest.fixture
def git_repo(tmp_path):
    """Initialize a git repository with basic config."""
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=tmp_path, check=True, capture_output=True)
    return tmp_path


class TestToolCacheCoverage:
    @pytest.mark.asyncio
    async def test_search_code_caches_results(self, git_repo):
        # Create test files
        (git_repo / "file1.py").write_text("password = 'secret'")
        (git_repo / "file2.py").write_text("username = 'admin'")

        subprocess.run(["git", "add", "."], cwd=git_repo, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Initial"], cwd=git_repo, check=True, capture_output=True)

        cache = ToolCache(max_size=100, ttl_seconds=3600)
        tool_core = ToolCore(
            repo_path=str(git_repo),
            project_id="test",
            cache=cache,
        )

        # First search - cache miss
        result1 = await tool_core.search_code(pattern="password")
        metrics1 = cache.get_metrics()
        assert metrics1["misses"] == 1
        assert metrics1["hits"] == 0

        # Second identical search - cache hit
        result2 = await tool_core.search_code(pattern="password")
        metrics2 = cache.get_metrics()
        assert metrics2["misses"] == 1
        assert metrics2["hits"] == 1

        assert result1 == result2

    @pytest.mark.asyncio
    async def test_list_directory_caches_results(self, git_repo):
        # Create test structure
        (git_repo / "dir1").mkdir()
        (git_repo / "dir1" / "file.txt").write_text("content")

        subprocess.run(["git", "add", "."], cwd=git_repo, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Initial"], cwd=git_repo, check=True, capture_output=True)

        cache = ToolCache(max_size=100, ttl_seconds=3600)
        tool_core = ToolCore(
            repo_path=str(git_repo),
            project_id="test",
            cache=cache,
        )

        # First listing - cache miss
        result1 = await tool_core.list_directory(path="dir1")
        metrics1 = cache.get_metrics()
        assert metrics1["misses"] == 1
        assert metrics1["hits"] == 0

        # Second listing - cache hit
        result2 = await tool_core.list_directory(path="dir1")
        metrics2 = cache.get_metrics()
        assert metrics2["misses"] == 1
        assert metrics2["hits"] == 1

        assert result1 == result2

    @pytest.mark.asyncio
    async def test_search_code_without_git_repo(self, tmp_path):
        """Verify search_code works without caching when git is unavailable."""
        (tmp_path / "file.py").write_text("password = 'secret'")

        cache = ToolCache(max_size=100, ttl_seconds=3600)
        tool_core = ToolCore(repo_path=str(tmp_path), project_id="test", cache=cache)

        result1 = await tool_core.search_code(pattern="password")
        result2 = await tool_core.search_code(pattern="password")

        assert result1 == result2
        metrics = cache.get_metrics()
        assert metrics["hits"] == 0
        assert metrics["misses"] == 0  # Cache never attempted

    @pytest.mark.asyncio
    async def test_list_directory_without_git_repo(self, tmp_path):
        """Verify list_directory works without caching when git is unavailable."""
        (tmp_path / "dir1").mkdir()
        (tmp_path / "dir1" / "file.txt").write_text("content")

        cache = ToolCache(max_size=100, ttl_seconds=3600)
        tool_core = ToolCore(repo_path=str(tmp_path), project_id="test", cache=cache)

        result1 = await tool_core.list_directory(path="dir1")
        result2 = await tool_core.list_directory(path="dir1")

        assert result1 == result2
        metrics = cache.get_metrics()
        assert metrics["hits"] == 0
        assert metrics["misses"] == 0

    @pytest.mark.asyncio
    async def test_search_code_cache_disabled(self, tmp_path):
        """Verify search_code works when cache is None."""
        (tmp_path / "file.py").write_text("password = 'secret'")

        tool_core = ToolCore(repo_path=str(tmp_path), project_id="test", cache=None)
        result = await tool_core.search_code(pattern="password")

        assert "matches" in result
        assert len(result["matches"]) > 0

    @pytest.mark.asyncio
    async def test_list_directory_cache_disabled(self, tmp_path):
        """Verify list_directory works when cache is None."""
        (tmp_path / "dir1").mkdir()
        (tmp_path / "dir1" / "file.txt").write_text("content")

        tool_core = ToolCore(repo_path=str(tmp_path), project_id="test", cache=None)
        result = await tool_core.list_directory(path="dir1")

        assert "items" in result
        assert "dir1/file.txt" in result["items"]

    @pytest.mark.asyncio
    async def test_search_code_invalidated_on_commit(self, git_repo):
        """Verify cache invalidates when repository changes."""
        (git_repo / "file.py").write_text("password = 'secret'")
        subprocess.run(["git", "add", "."], cwd=git_repo, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Initial"], cwd=git_repo, check=True, capture_output=True)

        cache = ToolCache(max_size=100, ttl_seconds=3600)
        tool_core = ToolCore(repo_path=str(git_repo), project_id="test", cache=cache)

        # First search
        result1 = await tool_core.search_code(pattern="password")

        # Modify and commit
        (git_repo / "file.py").write_text("password = 'changed'")
        subprocess.run(["git", "add", "."], cwd=git_repo, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Update"], cwd=git_repo, check=True, capture_output=True)

        # Second search should be cache miss
        result2 = await tool_core.search_code(pattern="password")

        metrics = cache.get_metrics()
        assert metrics["misses"] == 2  # Both are misses
        assert metrics["hits"] == 0
        assert result1 != result2  # Content changed

    @pytest.mark.asyncio
    async def test_search_code_ttl_expiration(self, git_repo):
        """Verify cached search results expire after TTL."""
        (git_repo / "file.py").write_text("password = 'secret'")
        subprocess.run(["git", "add", "."], cwd=git_repo, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Initial"], cwd=git_repo, check=True, capture_output=True)

        cache = ToolCache(max_size=100, ttl_seconds=1)  # 1 second TTL
        tool_core = ToolCore(repo_path=str(git_repo), project_id="test", cache=cache)

        # First search - cache miss
        await tool_core.search_code(pattern="password")

        # Second search immediately - cache hit
        await tool_core.search_code(pattern="password")

        # Wait for TTL expiration
        await asyncio.sleep(1.1)

        # Third search - cache miss due to expiration
        await tool_core.search_code(pattern="password")

        metrics = cache.get_metrics()
        assert metrics["misses"] == 2  # First and third
        assert metrics["hits"] == 1  # Second

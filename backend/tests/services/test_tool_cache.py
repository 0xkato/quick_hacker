# backend/tests/services/test_tool_cache.py
import pytest
from services.tool_cache import ToolCache


class TestCacheKeyGeneration:
    def test_cache_key_includes_tool_name(self):
        cache = ToolCache(max_size=100, ttl_seconds=3600)
        key1 = cache.generate_key("read_file", {"path": "auth.py"}, "abc123")
        key2 = cache.generate_key("ripgrep", {"path": "auth.py"}, "abc123")
        assert key1 != key2  # Different tool names = different keys

    def test_cache_key_includes_args(self):
        cache = ToolCache(max_size=100, ttl_seconds=3600)
        key1 = cache.generate_key("read_file", {"path": "auth.py"}, "abc123")
        key2 = cache.generate_key("read_file", {"path": "config.py"}, "abc123")
        assert key1 != key2  # Different args = different keys

    def test_cache_key_includes_git_head(self):
        cache = ToolCache(max_size=100, ttl_seconds=3600)
        key1 = cache.generate_key("read_file", {"path": "auth.py"}, "abc123")
        key2 = cache.generate_key("read_file", {"path": "auth.py"}, "def456")
        assert key1 != key2  # Different git HEAD = different keys

    def test_cache_key_is_deterministic(self):
        cache = ToolCache(max_size=100, ttl_seconds=3600)
        key1 = cache.generate_key("read_file", {"path": "auth.py"}, "abc123")
        key2 = cache.generate_key("read_file", {"path": "auth.py"}, "abc123")
        assert key1 == key2  # Same inputs = same key

    def test_cache_key_is_sha256_hex(self):
        cache = ToolCache(max_size=100, ttl_seconds=3600)
        key = cache.generate_key("read_file", {"path": "auth.py"}, "abc123")
        assert len(key) == 64  # SHA-256 hex is 64 characters
        assert all(c in "0123456789abcdef" for c in key)

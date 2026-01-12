# backend/tests/services/test_tool_cache.py
import pytest
import time
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

    def test_cache_key_ignores_arg_order(self):
        cache = ToolCache(max_size=100, ttl_seconds=3600)
        key1 = cache.generate_key("read_file", {"path": "auth.py", "offset": 10}, "abc123")
        key2 = cache.generate_key("read_file", {"offset": 10, "path": "auth.py"}, "abc123")
        assert key1 == key2  # Same args in different order = same key


class TestCacheOperations:
    def test_get_nonexistent_key_returns_none(self):
        cache = ToolCache(max_size=100, ttl_seconds=3600)
        result = cache.get("nonexistent_key")
        assert result is None

    def test_set_and_get_value(self):
        cache = ToolCache(max_size=100, ttl_seconds=3600)
        cache.set("key1", {"result": "data"})
        result = cache.get("key1")
        assert result == {"result": "data"}

    def test_set_overwrites_existing_key(self):
        cache = ToolCache(max_size=100, ttl_seconds=3600)
        cache.set("key1", {"result": "old"})
        cache.set("key1", {"result": "new"})
        result = cache.get("key1")
        assert result == {"result": "new"}

    def test_expired_entry_returns_none(self):
        cache = ToolCache(max_size=100, ttl_seconds=1)  # 1 second TTL
        cache.set("key1", {"result": "data"})
        time.sleep(1.1)  # Wait for expiration
        result = cache.get("key1")
        assert result is None

    def test_expired_entry_is_removed(self):
        cache = ToolCache(max_size=100, ttl_seconds=1)
        cache.set("key1", {"result": "data"})
        time.sleep(1.1)
        cache.get("key1")  # Trigger cleanup
        assert "key1" not in cache._cache

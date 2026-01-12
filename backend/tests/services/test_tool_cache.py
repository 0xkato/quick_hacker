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

    def test_cache_key_rejects_non_serializable_args(self):
        cache = ToolCache(max_size=100, ttl_seconds=3600)
        with pytest.raises(ValueError, match="must be JSON-serializable"):
            cache.generate_key("read_file", {"callback": lambda x: x}, "abc123")


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

    def test_multiple_keys_coexist(self):
        cache = ToolCache(max_size=100, ttl_seconds=3600)
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        assert cache.get("key1") == "value1"
        assert cache.get("key2") == "value2"

    def test_invalid_max_size_raises_error(self):
        with pytest.raises(ValueError, match="max_size must be positive"):
            ToolCache(max_size=0, ttl_seconds=3600)

    def test_invalid_ttl_raises_error(self):
        with pytest.raises(ValueError, match="ttl_seconds must be positive"):
            ToolCache(max_size=100, ttl_seconds=-1)


class TestLRUEviction:
    def test_exceeding_max_size_evicts_oldest(self):
        cache = ToolCache(max_size=3, ttl_seconds=3600)
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.set("key3", "value3")
        cache.set("key4", "value4")  # Should evict key1

        assert cache.get("key1") is None  # Evicted
        assert cache.get("key2") == "value2"
        assert cache.get("key3") == "value3"
        assert cache.get("key4") == "value4"

    def test_get_updates_lru_order(self):
        cache = ToolCache(max_size=3, ttl_seconds=3600)
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.set("key3", "value3")

        # Access key1 (should mark as recently used)
        cache.get("key1")

        # Add key4 (should evict key2, not key1)
        cache.set("key4", "value4")

        assert cache.get("key1") == "value1"  # Not evicted (was accessed)
        assert cache.get("key2") is None  # Evicted (oldest unused)
        assert cache.get("key3") == "value3"
        assert cache.get("key4") == "value4"

    def test_set_updates_lru_order(self):
        cache = ToolCache(max_size=3, ttl_seconds=3600)
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.set("key3", "value3")

        # Update key1 (should mark as recently used)
        cache.set("key1", "value1_updated")

        # Add key4 (should evict key2, not key1)
        cache.set("key4", "value4")

        assert cache.get("key1") == "value1_updated"  # Not evicted
        assert cache.get("key2") is None  # Evicted


class TestCacheMetrics:
    def test_initial_metrics_are_zero(self):
        cache = ToolCache(max_size=100, ttl_seconds=3600)
        metrics = cache.get_metrics()
        assert metrics["hits"] == 0
        assert metrics["misses"] == 0
        assert metrics["hit_rate"] == 0.0
        assert metrics["size"] == 0

    def test_get_miss_increments_misses(self):
        cache = ToolCache(max_size=100, ttl_seconds=3600)
        cache.get("nonexistent")
        metrics = cache.get_metrics()
        assert metrics["misses"] == 1
        assert metrics["hits"] == 0

    def test_expired_entry_increments_misses(self):
        cache = ToolCache(max_size=100, ttl_seconds=1)  # 1 second TTL
        cache.set("key1", "value1")
        time.sleep(1.1)  # Wait for expiration
        result = cache.get("key1")
        assert result is None
        metrics = cache.get_metrics()
        assert metrics["misses"] == 1
        assert metrics["hits"] == 0

    def test_get_hit_increments_hits(self):
        cache = ToolCache(max_size=100, ttl_seconds=3600)
        cache.set("key1", "value1")
        cache.get("key1")
        metrics = cache.get_metrics()
        assert metrics["hits"] == 1
        assert metrics["misses"] == 0

    def test_hit_rate_calculation(self):
        cache = ToolCache(max_size=100, ttl_seconds=3600)
        cache.set("key1", "value1")
        cache.get("key1")  # hit
        cache.get("key2")  # miss
        cache.get("key1")  # hit
        metrics = cache.get_metrics()
        assert metrics["hits"] == 2
        assert metrics["misses"] == 1
        assert metrics["hit_rate"] == 2 / 3  # 66.67%

    def test_size_reflects_cache_entries(self):
        cache = ToolCache(max_size=100, ttl_seconds=3600)
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        metrics = cache.get_metrics()
        assert metrics["size"] == 2

    def test_eviction_updates_size(self):
        cache = ToolCache(max_size=2, ttl_seconds=3600)
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.set("key3", "value3")  # Evicts key1
        metrics = cache.get_metrics()
        assert metrics["size"] == 2

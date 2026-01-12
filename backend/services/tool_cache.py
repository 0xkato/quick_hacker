# backend/services/tool_cache.py
"""Tool output caching for performance optimization."""
from collections import OrderedDict
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class CacheEntry:
    """Cache entry with value and expiration timestamp."""
    value: Any
    expires_at: float


class ToolCache:
    """Hash-based cache for tool outputs with LRU eviction and TTL.

    Cache keys are SHA-256 hashes of:
    - Tool name
    - Tool arguments (canonicalized JSON)
    - Git HEAD (repo state)

    This ensures cache invalidation when repo changes.

    Note: This implementation is thread-safe for single-threaded use.
    For concurrent async operations, consider adding asyncio.Lock protection
    (see Task 6: Async Cache Wrapper).
    """

    def __init__(self, max_size: int = 1000, ttl_seconds: int = 3600):
        """Initialize the tool cache.

        Args:
            max_size: Maximum number of cached entries (LRU eviction)
            ttl_seconds: Time-to-live for cached entries (default 1 hour)
        """
        if max_size <= 0:
            raise ValueError("max_size must be positive")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")

        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        # OrderedDict maintains insertion order for LRU
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        # Metrics
        self._hits: int = 0
        self._misses: int = 0

    def generate_key(
        self,
        tool_name: str,
        args: Dict[str, Any],
        git_head: str
    ) -> str:
        """Generate SHA-256 cache key from tool call parameters.

        Args:
            tool_name: Name of the tool (e.g., "read_file")
            args: Tool arguments as dictionary
            git_head: Current git HEAD hash

        Returns:
            64-character SHA-256 hex string
        """
        # Canonicalize args to ensure deterministic key generation
        # sort_keys=True ensures {"a": 1, "b": 2} == {"b": 2, "a": 1}
        try:
            canonical_args = json.dumps(args, sort_keys=True)
        except (TypeError, ValueError) as e:
            raise ValueError(f"Tool arguments must be JSON-serializable: {e}") from e

        # Combine all components
        key_components = {
            "tool": tool_name,
            "args": canonical_args,
            "git_head": git_head,
        }

        # Generate SHA-256 hash
        key_str = json.dumps(key_components, sort_keys=True)
        return hashlib.sha256(key_str.encode()).hexdigest()

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache if present and not expired.

        Args:
            key: Cache key (SHA-256 hex string)

        Returns:
            Cached value if present and not expired, None otherwise
        """
        if key not in self._cache:
            self._misses += 1
            return None

        entry = self._cache[key]

        # Check expiration
        if time.time() >= entry.expires_at:
            # Remove expired entry
            del self._cache[key]
            self._misses += 1
            return None

        # Move to end (mark as recently used)
        self._cache.move_to_end(key)
        self._hits += 1

        return entry.value

    def set(self, key: str, value: Any) -> None:
        """Store value in cache with TTL and LRU eviction.

        Args:
            key: Cache key (SHA-256 hex string)
            value: Value to cache (any JSON-serializable object)
        """
        expires_at = time.time() + self.ttl_seconds

        # If key exists, remove it first (will re-add at end)
        if key in self._cache:
            del self._cache[key]

        # Add new entry at end (most recently used)
        self._cache[key] = CacheEntry(value=value, expires_at=expires_at)

        # Evict oldest entry if over max_size
        if len(self._cache) > self.max_size:
            # popitem(last=False) removes oldest (FIFO)
            self._cache.popitem(last=False)

    def get_metrics(self) -> Dict[str, Any]:
        """Get cache performance metrics.

        Returns:
            Dictionary with:
            - hits: Number of cache hits
            - misses: Number of cache misses
            - hit_rate: Ratio of hits to total requests (0.0-1.0)
            - size: Current number of cached entries
        """
        total_requests = self._hits + self._misses
        hit_rate = self._hits / total_requests if total_requests > 0 else 0.0

        return {
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": hit_rate,
            "size": len(self._cache),
        }

# backend/services/tool_cache.py
"""Tool output caching for performance optimization."""
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
    """

    def __init__(self, max_size: int = 1000, ttl_seconds: int = 3600):
        """Initialize the tool cache.

        Args:
            max_size: Maximum number of cached entries (LRU eviction)
            ttl_seconds: Time-to-live for cached entries (default 1 hour)
        """
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self._cache: Dict[str, CacheEntry] = {}  # Storage implementation in future tasks

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
            return None

        entry = self._cache[key]

        # Check expiration
        if time.time() > entry.expires_at:
            # Remove expired entry
            del self._cache[key]
            return None

        return entry.value

    def set(self, key: str, value: Any) -> None:
        """Store value in cache with TTL.

        Args:
            key: Cache key (SHA-256 hex string)
            value: Value to cache (any JSON-serializable object)
        """
        expires_at = time.time() + self.ttl_seconds
        self._cache[key] = CacheEntry(value=value, expires_at=expires_at)

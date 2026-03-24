"""Redis cache for build artifacts and intermediate results.

Uses the existing Redis connection for caching compiled harnesses,
coverage rollups, and other expensive-to-recompute data.
"""
from __future__ import annotations

import json
import os
from typing import Any, Optional


class RedisCache:
    """Simple Redis cache wrapper."""

    def __init__(self, redis_url: str | None = None, prefix: str = "qh_cache"):
        self._redis_url = redis_url or os.environ.get("REDIS_URL", "redis://localhost:6380")
        self._prefix = prefix
        self._client = None

    def _get_client(self):
        if self._client is None:
            import redis
            self._client = redis.from_url(self._redis_url)
        return self._client

    def get(self, key: str) -> Optional[Any]:
        try:
            data = self._get_client().get(f"{self._prefix}:{key}")
            if data:
                return json.loads(data)
        except Exception:
            pass
        return None

    def set(self, key: str, value: Any, ttl_seconds: int = 3600) -> None:
        try:
            self._get_client().setex(
                f"{self._prefix}:{key}",
                ttl_seconds,
                json.dumps(value, default=str),
            )
        except Exception:
            pass  # Cache is best-effort

    def delete(self, key: str) -> None:
        try:
            self._get_client().delete(f"{self._prefix}:{key}")
        except Exception:
            pass

    def clear_prefix(self, prefix: str) -> int:
        """Delete all keys matching a prefix."""
        try:
            client = self._get_client()
            pattern = f"{self._prefix}:{prefix}:*"
            keys = client.keys(pattern)
            if keys:
                return client.delete(*keys)
        except Exception:
            pass
        return 0


build_cache = RedisCache(prefix="qh_build")

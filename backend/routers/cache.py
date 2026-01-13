# backend/routers/cache.py
"""Cache metrics API endpoints."""
from fastapi import APIRouter, Depends
from typing import Dict, Any

from config import settings
from middleware.auth import require_auth
from services.agent_orchestrator import orchestrator

router = APIRouter()


@router.get("/cache/metrics")
async def get_cache_metrics(_: str = Depends(require_auth)) -> Dict[str, Any]:
    """Get tool cache performance metrics.

    Returns:
        Cache statistics including hits, misses, hit rate, and size
    """
    # Check if caching is enabled
    if not settings.tool_cache_enabled:
        return {
            "enabled": False,
            "hits": 0,
            "misses": 0,
            "hit_rate": 0.0,
            "size": 0,
        }

    # Aggregate metrics from all active agents
    # NOTE: This is a simplified approach. In production, you might want
    # a global cache or cache manager that tracks all caches.
    total_hits = 0
    total_misses = 0
    total_size = 0
    cache_count = 0

    async with orchestrator._lock:
        for agent in orchestrator._agents.values():
            if hasattr(agent, 'tool_core') and hasattr(agent.tool_core, 'cache'):
                cache = agent.tool_core.cache
                if cache is not None:
                    metrics = cache.get_metrics()
                    total_hits += metrics["hits"]
                    total_misses += metrics["misses"]
                    total_size += metrics["size"]
                    cache_count += 1

    # Calculate aggregate hit rate
    total_requests = total_hits + total_misses
    hit_rate = total_hits / total_requests if total_requests > 0 else 0.0

    return {
        "enabled": True,
        "hits": total_hits,
        "misses": total_misses,
        "hit_rate": hit_rate,
        "size": total_size,
        "cache_count": cache_count,
    }

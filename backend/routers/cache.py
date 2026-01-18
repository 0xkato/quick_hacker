# backend/routers/cache.py
"""Cache metrics API endpoints."""
from fastapi import APIRouter, Depends
from typing import Dict, Any

from config import settings
from middleware.auth import require_auth
from services.agents import orchestrator as agent_orchestrator

router = APIRouter()


@router.get("/cache/metrics")
async def get_cache_metrics(_auth: Depends = Depends(require_auth)) -> Dict[str, Any]:
    """Get tool cache performance metrics.

    Returns:
        Dictionary with:
        - enabled: Whether caching is configured
        - hits: Total cache hits across all agents
        - misses: Total cache misses across all agents
        - hit_rate: Overall hit rate (0.0-1.0)
        - size: Total number of cached entries
        - cache_count: Number of agent caches aggregated
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

    # Get aggregated metrics from orchestrator
    metrics = await agent_orchestrator.get_cache_metrics()

    # Calculate aggregate hit rate
    total_requests = metrics["total_hits"] + metrics["total_misses"]
    hit_rate = metrics["total_hits"] / total_requests if total_requests > 0 else 0.0

    return {
        "enabled": True,
        "hits": metrics["total_hits"],
        "misses": metrics["total_misses"],
        "hit_rate": hit_rate,
        "size": metrics["total_size"],
        "cache_count": metrics["cache_count"],
    }

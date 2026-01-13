import { useState, useEffect, useCallback } from 'react';
import { cache, type CacheMetrics } from '@/lib/api';

export function useCacheMetrics(
  refreshInterval: number = 5000, // Refresh every 5 seconds
  enabled: boolean = true
) {
  const [metrics, setMetrics] = useState<CacheMetrics | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchMetrics = useCallback(async () => {
    if (!enabled) {
      setIsLoading(false);
      return;
    }

    try {
      const data = await cache.getMetrics();
      setMetrics(data);
      setError(null);
    } catch (err) {
      console.error('Failed to fetch cache metrics:', err);
      setError(err instanceof Error ? err.message : 'Failed to fetch metrics');
    } finally {
      setIsLoading(false);
    }
  }, [enabled]);

  useEffect(() => {
    fetchMetrics();

    if (!enabled) return;

    const interval = setInterval(fetchMetrics, refreshInterval);
    return () => clearInterval(interval);
  }, [fetchMetrics, refreshInterval, enabled]);

  return { metrics, isLoading, error, refresh: fetchMetrics };
}

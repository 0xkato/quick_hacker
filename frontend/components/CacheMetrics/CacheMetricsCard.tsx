'use client';

import { useCacheMetrics } from '@/hooks/useCacheMetrics';
import { Database, TrendingUp, AlertCircle } from 'lucide-react';
import clsx from 'clsx';

interface CacheMetricsCardProps {
  className?: string;
  refreshInterval?: number;
}

export function CacheMetricsCard({ className, refreshInterval = 5000 }: CacheMetricsCardProps) {
  const { metrics, isLoading, error } = useCacheMetrics(refreshInterval);

  if (isLoading && !metrics) {
    return (
      <div className={clsx('soft-card', className)}>
        <div className="flex items-center gap-2 mb-2">
          <Database className="w-4 h-4 text-vsc-accent" />
          <span className="text-vsc-sm font-medium text-vsc-text">Cache Metrics</span>
        </div>
        <div className="text-vsc-xs text-vsc-text-muted">Loading...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className={clsx('soft-card', className)}>
        <div className="flex items-center gap-2 mb-2">
          <AlertCircle className="w-4 h-4 text-vsc-error" />
          <span className="text-vsc-sm font-medium text-vsc-text">Cache Metrics</span>
        </div>
        <div className="text-vsc-xs text-vsc-error">{error}</div>
      </div>
    );
  }

  if (!metrics || !metrics.enabled) {
    return (
      <div className={clsx('soft-card', className)}>
        <div className="flex items-center gap-2 mb-2">
          <Database className="w-4 h-4 text-vsc-text-muted" />
          <span className="text-vsc-sm font-medium text-vsc-text">Cache Metrics</span>
        </div>
        <div className="text-vsc-xs text-vsc-text-muted">Caching disabled</div>
      </div>
    );
  }

  const hitRatePercent = (metrics.hit_rate * 100).toFixed(1);
  const totalRequests = metrics.hits + metrics.misses;

  return (
    <div className={clsx('soft-card', className)}>
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <Database className="w-4 h-4 text-vsc-accent" />
          <span className="text-vsc-sm font-medium text-vsc-text">Cache Metrics</span>
        </div>
        <span className="text-vsc-xs px-2 py-0.5 rounded bg-vsc-success/30 text-vsc-success">
          Enabled
        </span>
      </div>

      {/* Hit Rate */}
      <div className="mb-3">
        <div className="flex items-center justify-between mb-1">
          <span className="text-vsc-xs text-vsc-text-muted">Hit Rate</span>
          <span className="text-vsc-sm font-medium text-vsc-text flex items-center gap-1">
            <TrendingUp className="w-3 h-3 text-vsc-success" />
            {hitRatePercent}%
          </span>
        </div>
        <div className="progress-bar">
          <div
            className={clsx('progress-bar-fill', {
              'bg-vsc-success': metrics.hit_rate >= 0.7,
              'bg-vsc-warning': metrics.hit_rate >= 0.4 && metrics.hit_rate < 0.7,
              'bg-vsc-error': metrics.hit_rate < 0.4,
            })}
            style={{ width: `${metrics.hit_rate * 100}%` }}
          />
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-2 gap-3">
        <div>
          <div className="text-vsc-xs text-vsc-text-muted mb-0.5">Hits</div>
          <div className="text-vsc-sm font-medium text-vsc-success">{metrics.hits.toLocaleString()}</div>
        </div>
        <div>
          <div className="text-vsc-xs text-vsc-text-muted mb-0.5">Misses</div>
          <div className="text-vsc-sm font-medium text-vsc-text">{metrics.misses.toLocaleString()}</div>
        </div>
        <div>
          <div className="text-vsc-xs text-vsc-text-muted mb-0.5">Total Requests</div>
          <div className="text-vsc-sm font-medium text-vsc-text">{totalRequests.toLocaleString()}</div>
        </div>
        <div>
          <div className="text-vsc-xs text-vsc-text-muted mb-0.5">Cache Size</div>
          <div className="text-vsc-sm font-medium text-vsc-text">{metrics.size.toLocaleString()}</div>
        </div>
      </div>

      {/* Agent Count */}
      {metrics.cache_count !== undefined && metrics.cache_count > 0 && (
        <div className="mt-3 pt-3 border-t border-vsc-border-subtle">
          <div className="text-vsc-xs text-vsc-text-muted">
            Aggregated from <span className="text-vsc-text font-medium">{metrics.cache_count}</span> agent{metrics.cache_count !== 1 ? 's' : ''}
          </div>
        </div>
      )}
    </div>
  );
}

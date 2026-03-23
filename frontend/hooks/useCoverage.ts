import { useState, useEffect, useCallback } from 'react';
import { campaigns as campaignsApi } from '@/lib/api';
import type { CoverageSummary } from '@/types';

export function useCoverage(campaignId: string | null) {
  const [coverage, setCoverage] = useState<CoverageSummary | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const refresh = useCallback(async () => {
    if (!campaignId) { setCoverage(null); return; }
    setIsLoading(true);
    try {
      const data = await campaignsApi.getCoverage(campaignId) as CoverageSummary;
      setCoverage(data);
    } catch (e) {
      console.error('Failed to load coverage:', e);
    } finally {
      setIsLoading(false);
    }
  }, [campaignId]);

  useEffect(() => {
    refresh();
    if (!campaignId) return;
    const interval = setInterval(refresh, 10000);
    return () => clearInterval(interval);
  }, [refresh, campaignId]);

  return { coverage, isLoading, refresh };
}

import { useState, useEffect, useCallback } from 'react';
import { campaigns as campaignsApi } from '@/lib/api';
import type { LaneSpec } from '@/types';

export function useLanes(campaignId: string | null) {
  const [lanes, setLanes] = useState<LaneSpec[]>([]);
  const [isLoading, setIsLoading] = useState(false);

  const refresh = useCallback(async () => {
    if (!campaignId) { setLanes([]); return; }
    setIsLoading(true);
    try {
      const data = await campaignsApi.getLanes(campaignId);
      setLanes(Array.isArray(data) ? data : []);
    } catch (e) {
      console.error('Failed to load lanes:', e);
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

  return { lanes, isLoading, refresh };
}

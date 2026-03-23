import { useState, useEffect, useCallback } from 'react';
import { campaigns as campaignsApi } from '@/lib/api';
import type { Target } from '@/types';

export function useTargets(campaignId: string | null) {
  const [targets, setTargets] = useState<Target[]>([]);
  const [isLoading, setIsLoading] = useState(false);

  const refresh = useCallback(async () => {
    if (!campaignId) { setTargets([]); return; }
    setIsLoading(true);
    try {
      const data = await campaignsApi.getTargets(campaignId);
      setTargets(Array.isArray(data) ? data : []);
    } catch (e) {
      console.error('Failed to load targets:', e);
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

  return { targets, isLoading, refresh };
}

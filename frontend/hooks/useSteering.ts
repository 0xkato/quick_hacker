import { useState, useEffect, useCallback } from 'react';
import { campaigns as campaignsApi } from '@/lib/api';
import type { SteeringDecision } from '@/types';

export function useSteering(campaignId: string | null) {
  const [decisions, setDecisions] = useState<SteeringDecision[]>([]);
  const [isLoading, setIsLoading] = useState(false);

  const refresh = useCallback(async () => {
    if (!campaignId) { setDecisions([]); return; }
    setIsLoading(true);
    try {
      const data = await campaignsApi.getSteering(campaignId);
      setDecisions(Array.isArray(data) ? data : []);
    } catch (e) {
      console.error('Failed to load steering:', e);
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

  return { decisions, isLoading, refresh };
}

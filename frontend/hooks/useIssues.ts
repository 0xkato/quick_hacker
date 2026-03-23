import { useState, useEffect, useCallback } from 'react';
import { campaigns as campaignsApi } from '@/lib/api';
import type { Issue } from '@/types';

export function useIssues(campaignId: string | null) {
  const [issues, setIssues] = useState<Issue[]>([]);
  const [isLoading, setIsLoading] = useState(false);

  const refresh = useCallback(async () => {
    if (!campaignId) { setIssues([]); return; }
    setIsLoading(true);
    try {
      const data = await campaignsApi.getIssues(campaignId);
      setIssues(Array.isArray(data) ? data : []);
    } catch (e) {
      console.error('Failed to load issues:', e);
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

  return { issues, isLoading, refresh, setIssues };
}

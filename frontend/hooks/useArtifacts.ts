import { useState, useEffect, useCallback } from 'react';
import { campaigns as campaignsApi } from '@/lib/api';
import type { Artifact, ArtifactBucket } from '@/types';

export function useArtifacts(campaignId: string | null) {
  const [artifacts, setArtifacts] = useState<Artifact[]>([]);
  const [buckets, setBuckets] = useState<ArtifactBucket[]>([]);
  const [isLoading, setIsLoading] = useState(false);

  const refresh = useCallback(async () => {
    if (!campaignId) { setArtifacts([]); setBuckets([]); return; }
    setIsLoading(true);
    try {
      const [arts, bkts] = await Promise.all([
        campaignsApi.getArtifacts(campaignId),
        campaignsApi.getArtifactBuckets(campaignId),
      ]);
      setArtifacts(Array.isArray(arts) ? arts : []);
      setBuckets(Array.isArray(bkts) ? bkts : []);
    } catch (e) {
      console.error('Failed to load artifacts:', e);
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

  return { artifacts, buckets, isLoading, refresh };
}

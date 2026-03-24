import { useState, useEffect, useCallback } from 'react';
import { campaigns as campaignsApi } from '@/lib/api';
import type { Campaign } from '@/types';

interface UseCampaignManagementProps {
  projectId: string | null;
  isAuthenticated: boolean;
}

export function useCampaignManagement({ projectId, isAuthenticated }: UseCampaignManagementProps) {
  const [campaignList, setCampaignList] = useState<Campaign[]>([]);
  const [selectedCampaignId, setSelectedCampaignId] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const selectedCampaign = campaignList.find(c => c.id === selectedCampaignId) || null;

  const refreshCampaigns = useCallback(async () => {
    if (!projectId || !isAuthenticated) return;
    setIsLoading(true);
    try {
      const data = await campaignsApi.list(projectId);
      setCampaignList(Array.isArray(data) ? data : []);
    } catch (e) {
      console.error('Failed to load campaigns:', e);
    } finally {
      setIsLoading(false);
    }
  }, [projectId, isAuthenticated]);

  useEffect(() => {
    refreshCampaigns();
    if (!projectId || !isAuthenticated) return;
    const interval = setInterval(refreshCampaigns, 5000);
    return () => clearInterval(interval);
  }, [refreshCampaigns, projectId, isAuthenticated]);

  const createCampaign = useCallback(async (request: any) => {
    const campaign = await campaignsApi.create(request) as Campaign;
    setCampaignList(prev => [campaign, ...prev]);
    setSelectedCampaignId(campaign.id);
    return campaign;
  }, []);

  const startCampaign = useCallback(async (id: string) => {
    const result = await campaignsApi.start(id) as Partial<Campaign>;
    setCampaignList(prev => prev.map(c => c.id === id ? { ...c, ...result } : c));
    return result;
  }, []);

  const pauseCampaign = useCallback(async (id: string) => {
    const result = await campaignsApi.pause(id) as Partial<Campaign>;
    setCampaignList(prev => prev.map(c => c.id === id ? { ...c, ...result } : c));
    return result;
  }, []);

  const resumeCampaign = useCallback(async (id: string) => {
    const result = await campaignsApi.resume(id) as Partial<Campaign>;
    setCampaignList(prev => prev.map(c => c.id === id ? { ...c, ...result } : c));
    return result;
  }, []);

  const cancelCampaign = useCallback(async (id: string) => {
    const result = await campaignsApi.cancel(id) as Partial<Campaign>;
    setCampaignList(prev => prev.map(c => c.id === id ? { ...c, ...result } : c));
    return result;
  }, []);

  const deleteCampaign = useCallback(async (id: string) => {
    // No dedicated delete endpoint yet, but we can cancel + remove from list
    try {
      await campaignsApi.cancel(id);
    } catch {
      // May already be cancelled/completed
    }
    setCampaignList(prev => prev.filter(c => c.id !== id));
    if (selectedCampaignId === id) {
      setSelectedCampaignId(null);
    }
  }, [selectedCampaignId]);

  return {
    campaigns: campaignList,
    selectedCampaign,
    selectedCampaignId,
    isLoading,
    setSelectedCampaignId,
    setCampaignList,
    refreshCampaigns,
    createCampaign,
    startCampaign,
    pauseCampaign,
    resumeCampaign,
    cancelCampaign,
    deleteCampaign,
  };
}

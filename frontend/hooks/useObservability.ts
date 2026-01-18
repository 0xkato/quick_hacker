'use client';

import { useState, useEffect, useCallback } from 'react';
import type { LLMInteraction, ToolDetail } from '@/types';
import { agents as agentsApi } from '@/lib/api';

export interface UseObservabilityOptions {
  selectedAgentId: string | null;
  isAuthenticated: boolean;
}

export interface UseObservabilityResult {
  llmInteractions: LLMInteraction[];
  toolDetails: ToolDetail[];
  setLlmInteractions: React.Dispatch<React.SetStateAction<LLMInteraction[]>>;
  setToolDetails: React.Dispatch<React.SetStateAction<ToolDetail[]>>;
  refreshObservability: () => Promise<void>;
}

export function useObservability({
  selectedAgentId,
  isAuthenticated,
}: UseObservabilityOptions): UseObservabilityResult {
  const [llmInteractions, setLlmInteractions] = useState<LLMInteraction[]>([]);
  const [toolDetails, setToolDetails] = useState<ToolDetail[]>([]);

  const refreshObservability = useCallback(async () => {
    if (!isAuthenticated || !selectedAgentId) {
      setLlmInteractions([]);
      setToolDetails([]);
      return;
    }

    try {
      const [interactions, details] = await Promise.all([
        agentsApi.getLLMInteractions(selectedAgentId),
        agentsApi.getToolDetails(selectedAgentId),
      ]);
      setLlmInteractions(interactions);
      setToolDetails(details);
    } catch (err) {
      console.error('Failed to load observability data:', err);
    }
  }, [selectedAgentId, isAuthenticated]);

  useEffect(() => {
    refreshObservability();
  }, [refreshObservability]);

  return {
    llmInteractions,
    toolDetails,
    setLlmInteractions,
    setToolDetails,
    refreshObservability,
  };
}

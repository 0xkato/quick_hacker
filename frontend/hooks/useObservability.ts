'use client';

import { useState } from 'react';
import type { LLMInteraction, ToolDetail } from '@/types';

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

/**
 * Stubbed observability hook.
 * The old agents router that served LLM interactions / tool details has been removed.
 * This hook returns empty arrays so existing consumers keep working.
 */
export function useObservability({
  selectedAgentId: _selectedAgentId,
  isAuthenticated: _isAuthenticated,
}: UseObservabilityOptions): UseObservabilityResult {
  const [llmInteractions, setLlmInteractions] = useState<LLMInteraction[]>([]);
  const [toolDetails, setToolDetails] = useState<ToolDetail[]>([]);

  return {
    llmInteractions,
    toolDetails,
    setLlmInteractions,
    setToolDetails,
    refreshObservability: async () => {},
  };
}

'use client';

import { useState, useEffect, useCallback } from 'react';
import type { Finding, Agent } from '@/types';
import { agents as agentsApi } from '@/lib/api';
import { autoSelectFindingsAgentId } from '@/lib/findingsSelection';

export interface UseFindingsManagementOptions {
  projectId: string | null;
  agents: Agent[];
  selectedAgentId: string | null;
  activeView: string;
}

export interface UseFindingsManagementResult {
  findings: Finding[];
  selectedFindingForDrawer: Finding | null;
  selectedFindingsAgentId: string | null;
  userSelectedFindingsAgentId: boolean;
  setFindings: React.Dispatch<React.SetStateAction<Finding[]>>;
  setSelectedFindingForDrawer: React.Dispatch<React.SetStateAction<Finding | null>>;
  setSelectedFindingsAgentId: (agentId: string | null) => void;
  setUserSelectedFindingsAgentId: (value: boolean) => void;
  refreshFindings: () => Promise<void>;
}

export function useFindingsManagement({
  projectId,
  agents,
  selectedAgentId,
  activeView,
}: UseFindingsManagementOptions): UseFindingsManagementResult {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedFindingForDrawer, setSelectedFindingForDrawer] = useState<Finding | null>(null);
  const [selectedFindingsAgentId, setSelectedFindingsAgentId] = useState<string | null>(null);
  const [userSelectedFindingsAgentId, setUserSelectedFindingsAgentId] = useState(false);

  // Auto-select agent for findings view
  useEffect(() => {
    if (activeView !== 'findings') return;
    if (agents.length === 0) return;

    const nextSelection = autoSelectFindingsAgentId({
      agents,
      findings,
      selectedAgentId,
      selectedFindingsAgentId,
      userSelectedFindingsAgentId,
    });

    if (nextSelection !== selectedFindingsAgentId) {
      setSelectedFindingsAgentId(nextSelection);
    }
  }, [activeView, agents, findings, selectedAgentId, selectedFindingsAgentId, userSelectedFindingsAgentId]);

  const refreshFindings = useCallback(async () => {
    if (!projectId) return;

    try {
      const allFindings = await agentsApi.getAllFindings(projectId);
      setFindings(allFindings);
    } catch (err) {
      console.error('Failed to load findings:', err);
    }
  }, [projectId]);

  const handleSetSelectedFindingsAgentId = useCallback((agentId: string | null) => {
    setSelectedFindingsAgentId(agentId);
  }, []);

  return {
    findings,
    selectedFindingForDrawer,
    selectedFindingsAgentId,
    userSelectedFindingsAgentId,
    setFindings,
    setSelectedFindingForDrawer,
    setSelectedFindingsAgentId: handleSetSelectedFindingsAgentId,
    setUserSelectedFindingsAgentId,
    refreshFindings,
  };
}

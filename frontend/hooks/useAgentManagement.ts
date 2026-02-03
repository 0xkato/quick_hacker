'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import type { Agent, AgentProgress, Finding, InvestigationFlow, InvestigationReport } from '@/types';
import { agents as agentsApi } from '@/lib/api';

export interface UseAgentManagementOptions {
  projectId: string | null;
  isAuthenticated: boolean;
}

export interface UseAgentManagementResult {
  agents: Agent[];
  selectedAgentId: string | null;
  agentProgress: Record<string, AgentProgress>;
  agentFlow: InvestigationFlow | null;
  isLoadingFlow: boolean;
  selectAgent: (agentId: string | null) => void;
  setAgents: React.Dispatch<React.SetStateAction<Agent[]>>;
  setAgentProgress: React.Dispatch<React.SetStateAction<Record<string, AgentProgress>>>;
  setAgentFlow: React.Dispatch<React.SetStateAction<InvestigationFlow | null>>;
  refreshAgents: () => Promise<void>;
  loadReport: (agentId: string, reportId?: string) => Promise<InvestigationReport | null>;
}

export function useAgentManagement({
  projectId,
  isAuthenticated,
}: UseAgentManagementOptions): UseAgentManagementResult {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [selectedAgentId, setSelectedAgentId] = useState<string | null>(null);
  const [agentProgress, setAgentProgress] = useState<Record<string, AgentProgress>>({});
  const [agentFlow, setAgentFlow] = useState<InvestigationFlow | null>(null);
  const [isLoadingFlow, setIsLoadingFlow] = useState(false);

  // Persist selected agent across refreshes (scoped per project so it doesn't leak across projects).
  const skipPersistRef = useRef(false);

  useEffect(() => {
    if (!projectId) {
      setSelectedAgentId(null);
      return;
    }

    // Prevent persisting a stale agent selection on the first render after project switches.
    skipPersistRef.current = true;

    const stored = localStorage.getItem(`quickhack.selectedAgentId:${projectId}`);
    setSelectedAgentId(stored || null);
  }, [projectId]);

  useEffect(() => {
    if (!projectId) return;

    if (skipPersistRef.current) {
      skipPersistRef.current = false;
      return;
    }

    const key = `quickhack.selectedAgentId:${projectId}`;
    if (selectedAgentId) localStorage.setItem(key, selectedAgentId);
    else localStorage.removeItem(key);
  }, [projectId, selectedAgentId]);

  // Load flow when agent is selected
  useEffect(() => {
    if (!isAuthenticated || !selectedAgentId) {
      setAgentFlow(null);
      return;
    }

    let errorCount = 0;
    const maxErrors = 3;
    let intervalId: NodeJS.Timeout | null = null;

    let isFirstLoad = true;

    const loadFlow = async () => {
      try {
        // Only show loading indicator on first load to avoid UI flicker during polling
        if (isFirstLoad) {
          setIsLoadingFlow(true);
        }
        const flow = await agentsApi.getFlow(selectedAgentId);
        setAgentFlow(flow);
        if (isFirstLoad) {
          setIsLoadingFlow(false);
          isFirstLoad = false;
        }
        errorCount = 0;
      } catch (err) {
        console.error('Failed to load flow:', err);
        if (isFirstLoad) {
          setIsLoadingFlow(false);
          isFirstLoad = false;
        }
        errorCount++;
        if (errorCount >= maxErrors && intervalId) {
          console.log('Stopping flow polling due to repeated errors');
          clearInterval(intervalId);
          intervalId = null;
        }
      }
    };

    loadFlow();

    // Check if selected agent exists and get its status
    const selectedAgent = agents.find(a => a.id === selectedAgentId);

    // If agents are loaded but selected agent doesn't exist, clear selection
    if (agents.length > 0 && !selectedAgent) {
      console.log('Selected agent not found, clearing selection');
      setSelectedAgentId(null);
      return;
    }

    // Only poll if the selected agent is running (10 second interval to reduce load on long scans)
    const isRunning = selectedAgent?.status === 'running' || selectedAgent?.status === 'pending';

    if (isRunning) {
      intervalId = setInterval(loadFlow, 10000);
    }

    return () => {
      if (intervalId) {
        clearInterval(intervalId);
      }
    };
  }, [selectedAgentId, agents, isAuthenticated]);

  const selectAgent = useCallback((agentId: string | null) => {
    setSelectedAgentId(agentId);
  }, []);

  const refreshAgents = useCallback(async () => {
    if (!projectId) return;

    try {
      const projectAgents = await agentsApi.list(projectId);
      setAgents(projectAgents);
    } catch (err) {
      console.error('Failed to load agents:', err);
    }
  }, [projectId]);

  const loadReport = useCallback(async (agentId: string, reportId?: string): Promise<InvestigationReport | null> => {
    try {
      const report = await agentsApi.getReport(agentId, reportId);
      return report;
    } catch (err) {
      console.error('Failed to load report:', err);
      return null;
    }
  }, []);

  return {
    agents,
    selectedAgentId,
    agentProgress,
    agentFlow,
    isLoadingFlow,
    selectAgent,
    setAgents,
    setAgentProgress,
    setAgentFlow,
    refreshAgents,
    loadReport,
  };
}

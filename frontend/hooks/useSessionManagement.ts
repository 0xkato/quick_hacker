'use client';

import { useState, useCallback, useEffect } from 'react';
import type { SessionStatus, SnapshotInfo, Finding } from '@/types';
import { session as sessionApi } from '@/lib/api';
import { ActivityView } from './usePanelLayout';

export interface UseSessionManagementOptions {
  currentProjectId: string | null;
  isAuthenticated: boolean;
  agents: Array<{ id: string; status: string }>;
}

export interface UseSessionManagementResult {
  sessionStatus: SessionStatus;
  snapshotInfo: SnapshotInfo | null;
  showResumeDialog: boolean;
  setSessionStatus: React.Dispatch<React.SetStateAction<SessionStatus>>;
  setSnapshotInfo: React.Dispatch<React.SetStateAction<SnapshotInfo | null>>;
  setShowResumeDialog: React.Dispatch<React.SetStateAction<boolean>>;
  restoreSession: (callbacks: {
    onFindingsRestore: (findings: Finding[]) => void;
    onActiveViewRestore: (view: ActivityView) => void;
    onSelectedFileRestore: (path: string) => void;
    onSelectedAgentRestore: (agentId: string) => void;
  }) => Promise<void>;
  keepCurrentSession: () => Promise<void>;
  checkForSnapshot: () => Promise<void>;
}

export function useSessionManagement({
  currentProjectId,
  isAuthenticated,
  agents,
}: UseSessionManagementOptions): UseSessionManagementResult {
  const [sessionStatus, setSessionStatus] = useState<SessionStatus>('active');
  const [snapshotInfo, setSnapshotInfo] = useState<SnapshotInfo | null>(null);
  const [showResumeDialog, setShowResumeDialog] = useState(false);

  // Check for existing snapshot on project load
  const checkForSnapshot = useCallback(async () => {
    if (!isAuthenticated || !currentProjectId) return;

    try {
      const info = await sessionApi.getSnapshotInfo();
      setSnapshotInfo(info);
    } catch (err) {
      console.error('Failed to check snapshot:', err);
    }
  }, [currentProjectId, isAuthenticated]);

  useEffect(() => {
    checkForSnapshot();
  }, [checkForSnapshot]);

  const restoreSession = useCallback(async (callbacks: {
    onFindingsRestore: (findings: Finding[]) => void;
    onActiveViewRestore: (view: ActivityView) => void;
    onSelectedFileRestore: (path: string) => void;
    onSelectedAgentRestore: (agentId: string) => void;
  }) => {
    try {
      setSessionStatus('resuming');
      const result = await sessionApi.resume();

      // Restore findings from snapshot
      if (result.snapshot.findings) {
        callbacks.onFindingsRestore(result.snapshot.findings as unknown as Finding[]);
      }

      // Restore UI state
      const ui = result.snapshot.ui_state;
      if (ui.active_view) {
        callbacks.onActiveViewRestore(ui.active_view as ActivityView);
      }
      if (ui.selected_file) {
        callbacks.onSelectedFileRestore(ui.selected_file);
      }
      if (ui.selected_agent_id) {
        callbacks.onSelectedAgentRestore(ui.selected_agent_id);
      }

      setSessionStatus('active');
      setShowResumeDialog(false);
      setSnapshotInfo(null);

      // Delete snapshot after restore
      await sessionApi.deleteSnapshot();
    } catch (err) {
      console.error('Failed to restore session:', err);
      setSessionStatus('active');
    }
  }, []);

  const keepCurrentSession = useCallback(async () => {
    setShowResumeDialog(false);
    try {
      await sessionApi.deleteSnapshot();
      setSnapshotInfo(null);
    } catch (err) {
      console.error('Failed to delete snapshot:', err);
    }
  }, []);

  // Handle showing dialog or auto-restore when snapshotInfo changes
  useEffect(() => {
    if (!snapshotInfo) return;

    // Check if we have running agents (conflict)
    const hasRunning = agents.some(a => a.status === 'running');

    if (hasRunning) {
      // Show conflict dialog
      setShowResumeDialog(true);
    } else {
      // Auto-restore if no conflict - but we can't call restoreSession here
      // without the callbacks, so we just show the dialog
      setShowResumeDialog(true);
    }
  }, [snapshotInfo, agents]);

  return {
    sessionStatus,
    snapshotInfo,
    showResumeDialog,
    setSessionStatus,
    setSnapshotInfo,
    setShowResumeDialog,
    restoreSession,
    keepCurrentSession,
    checkForSnapshot,
  };
}

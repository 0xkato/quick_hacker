'use client';

import { useState, useCallback } from 'react';
import { Pause, Play, Loader2 } from 'lucide-react';
import { session as sessionApi } from '@/lib/api';
import type { SessionStatus } from '@/types';

interface SessionControlsProps {
  sessionStatus: SessionStatus;
  onStatusChange: (status: SessionStatus) => void;
  hasRunningAgents: boolean;
  activeView: string;
  selectedFile: string | null;
  openPanels: string[];
  selectedAgentId: string | null;
  onPaused: () => void;
  onError: (error: string) => void;
}

export function SessionControls({
  sessionStatus,
  onStatusChange,
  hasRunningAgents,
  activeView,
  selectedFile,
  openPanels,
  selectedAgentId,
  onPaused,
  onError,
}: SessionControlsProps) {
  const [isLoading, setIsLoading] = useState(false);

  const handlePause = useCallback(async () => {
    setIsLoading(true);
    onStatusChange('pausing');

    try {
      await sessionApi.pause({
        active_view: activeView,
        selected_file: selectedFile,
        open_panels: openPanels,
        selected_agent_id: selectedAgentId,
      });

      onStatusChange('paused');
      onPaused();
    } catch (err) {
      onStatusChange('active');
      onError(err instanceof Error ? err.message : 'Failed to pause session');
    } finally {
      setIsLoading(false);
    }
  }, [
    activeView,
    selectedFile,
    openPanels,
    selectedAgentId,
    onStatusChange,
    onPaused,
    onError,
  ]);

  const handleResume = useCallback(async () => {
    setIsLoading(true);
    onStatusChange('resuming');

    try {
      await sessionApi.resume();
      onStatusChange('active');
    } catch (err) {
      onStatusChange('paused');
      onError(err instanceof Error ? err.message : 'Failed to resume session');
    } finally {
      setIsLoading(false);
    }
  }, [onStatusChange, onError]);

  // Determine button state
  const isPausing = sessionStatus === 'pausing';
  const isPaused = sessionStatus === 'paused';
  const isResuming = sessionStatus === 'resuming';

  if (isPaused) {
    return (
      <button
        onClick={handleResume}
        disabled={isLoading}
        className="flex items-center gap-2 px-3 py-1.5 text-sm font-medium rounded-md bg-green-600 hover:bg-green-700 text-white disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        title="Resume Session"
      >
        {isResuming ? (
          <>
            <Loader2 className="w-4 h-4 animate-spin" />
            Resuming...
          </>
        ) : (
          <>
            <Play className="w-4 h-4" />
            Resume Session
          </>
        )}
      </button>
    );
  }

  return (
    <button
      onClick={handlePause}
      disabled={isLoading || isPausing}
      className={`flex items-center gap-2 px-3 py-1.5 text-sm font-medium rounded-md transition-colors ${
        hasRunningAgents
          ? 'bg-amber-600 hover:bg-amber-700 text-white'
          : 'bg-zinc-700 hover:bg-zinc-600 text-zinc-300'
      } disabled:opacity-50 disabled:cursor-not-allowed`}
      title={hasRunningAgents ? 'Pause running agents and save session' : 'Save session state'}
    >
      {isPausing ? (
        <>
          <Loader2 className="w-4 h-4 animate-spin" />
          Stopping...
        </>
      ) : (
        <>
          <Pause className="w-4 h-4" />
          Pause Session
        </>
      )}
    </button>
  );
}

// frontend/components/UltrathinkPanel/ThinkingTrace.tsx
import React, { useState } from 'react';

interface ThinkingTraceProps {
  gate: string;
  status: 'pending' | 'running' | 'passed' | 'failed';
  confidence?: number;
  reasoning?: string;
  thinkingPreview?: string;
  durationMs?: number;
}

const GATE_DESCRIPTIONS: Record<string, string> = {
  triage: 'Quick filter for obvious non-issues',
  deep_analysis: 'Thorough source-to-sink verification',
  devils_advocate: 'Actively arguing against the finding',
  proof_generator: 'Generating concrete exploit proof',
  final_gate: 'Final reputation-stake decision',
};

export const ThinkingTrace: React.FC<ThinkingTraceProps> = ({
  gate,
  status,
  confidence,
  reasoning,
  thinkingPreview,
  durationMs,
}) => {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="thinking-trace bg-gray-800 rounded-lg p-4">
      <div className="header flex justify-between items-start mb-3">
        <div>
          <h4 className="font-semibold text-white capitalize">
            {gate.replace(/_/g, ' ')}
          </h4>
          <p className="text-gray-500 text-sm">{GATE_DESCRIPTIONS[gate]}</p>
        </div>
        <div className="text-right">
          {confidence !== undefined && (
            <div className="text-lg font-mono">
              <span className={confidence >= 0.8 ? 'text-green-400' : 'text-yellow-400'}>
                {(confidence * 100).toFixed(0)}%
              </span>
            </div>
          )}
          {durationMs !== undefined && (
            <div className="text-xs text-gray-500">
              {(durationMs / 1000).toFixed(1)}s
            </div>
          )}
        </div>
      </div>

      {/* Status indicator */}
      {status === 'running' && (
        <div className="mb-3 p-3 bg-yellow-900/30 rounded border border-yellow-700">
          <div className="flex items-center gap-2">
            <span className="animate-spin">~</span>
            <span className="text-yellow-400">Thinking deeply...</span>
          </div>
        </div>
      )}

      {/* Reasoning */}
      {reasoning && (
        <div className="mb-3">
          <h5 className="text-sm font-medium text-gray-400 mb-1">Reasoning:</h5>
          <p className="text-gray-300 text-sm">{reasoning}</p>
        </div>
      )}

      {/* Thinking preview (collapsible) */}
      {thinkingPreview && (
        <div className="thinking-preview">
          <button
            onClick={() => setExpanded(!expanded)}
            className="flex items-center gap-2 text-sm text-purple-400 hover:text-purple-300"
          >
            <span>{expanded ? 'v' : '>'}</span>
            <span>View Thinking Trace</span>
          </button>

          {expanded && (
            <pre className="mt-2 p-3 bg-gray-900 rounded text-xs text-gray-400 overflow-x-auto max-h-64 overflow-y-auto">
              {thinkingPreview}
            </pre>
          )}
        </div>
      )}
    </div>
  );
};

export default ThinkingTrace;

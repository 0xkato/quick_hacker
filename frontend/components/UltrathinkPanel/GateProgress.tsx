// frontend/components/UltrathinkPanel/GateProgress.tsx
import React from 'react';

interface GateStatus {
  name: string;
  status: 'pending' | 'running' | 'passed' | 'failed';
  confidence?: number;
}

interface GateProgressProps {
  gates: string[];
  statuses: Record<string, GateStatus>;
  selectedGate: string | null;
  onSelectGate: (gate: string) => void;
}

const GATE_LABELS: Record<string, string> = {
  triage: 'Triage',
  deep_analysis: 'Deep Analysis',
  devils_advocate: "Devil's Advocate",
  proof_generator: 'Proof Gen',
  final_gate: 'Final Gate',
};

const STATUS_COLORS = {
  pending: 'bg-gray-600',
  running: 'bg-yellow-500 animate-pulse',
  passed: 'bg-green-500',
  failed: 'bg-red-500',
};

export const GateProgress: React.FC<GateProgressProps> = ({
  gates,
  statuses,
  selectedGate,
  onSelectGate,
}) => {
  return (
    <div className="gate-progress">
      <div className="flex items-center justify-between gap-1">
        {gates.map((gate, index) => {
          const status = statuses[gate];
          const isSelected = selectedGate === gate;

          return (
            <React.Fragment key={gate}>
              {/* Gate node */}
              <button
                onClick={() => onSelectGate(gate)}
                className={`
                  flex flex-col items-center gap-1 p-2 rounded-lg transition-all
                  ${isSelected ? 'ring-2 ring-purple-400' : ''}
                  hover:bg-gray-800
                `}
              >
                <div className={`
                  w-8 h-8 rounded-full flex items-center justify-center text-white
                  ${STATUS_COLORS[status.status]}
                `}>
                  {status.status === 'passed' && <span>&#10003;</span>}
                  {status.status === 'failed' && <span>&#10007;</span>}
                  {status.status === 'running' && <span>~</span>}
                  {status.status === 'pending' && <span>o</span>}
                </div>
                <span className="text-xs text-gray-400 whitespace-nowrap">
                  {GATE_LABELS[gate]}
                </span>
                {status.confidence !== undefined && (
                  <span className="text-xs text-gray-500">
                    {(status.confidence * 100).toFixed(0)}%
                  </span>
                )}
              </button>

              {/* Connector line */}
              {index < gates.length - 1 && (
                <div className={`
                  flex-1 h-0.5
                  ${statuses[gates[index + 1]].status !== 'pending' ? 'bg-gray-500' : 'bg-gray-700'}
                `} />
              )}
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
};

export default GateProgress;

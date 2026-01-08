// frontend/components/UltrathinkPanel/UltrathinkPanel.tsx
import React, { useState, useEffect } from 'react';
import { GateProgress } from './GateProgress';
import { ThinkingTrace } from './ThinkingTrace';

interface UltrathinkPanelProps {
  findingId: string;
  findingTitle: string;
  cascadeEvents: CascadeEvent[];
  isActive: boolean;
}

interface CascadeEvent {
  type: string;
  data: any;
  timestamp: string;
}

interface GateStatus {
  name: string;
  status: 'pending' | 'running' | 'passed' | 'failed';
  confidence?: number;
  reasoning?: string;
  thinkingPreview?: string;
  durationMs?: number;
}

const GATES = ['triage', 'deep_analysis', 'devils_advocate', 'proof_generator', 'final_gate'];

export const UltrathinkPanel: React.FC<UltrathinkPanelProps> = ({
  findingId,
  findingTitle,
  cascadeEvents,
  isActive,
}) => {
  const [gateStatuses, setGateStatuses] = useState<Record<string, GateStatus>>(
    Object.fromEntries(GATES.map(g => [g, { name: g, status: 'pending' }]))
  );
  const [selectedGate, setSelectedGate] = useState<string | null>(null);
  const [finalVerdict, setFinalVerdict] = useState<boolean | null>(null);

  useEffect(() => {
    // Process cascade events
    for (const event of cascadeEvents) {
      if (event.data.finding_id !== findingId) continue;

      switch (event.type) {
        case 'ultrathink_gate_start':
          setGateStatuses(prev => ({
            ...prev,
            [event.data.gate]: { ...prev[event.data.gate], status: 'running' },
          }));
          setSelectedGate(event.data.gate);
          break;

        case 'ultrathink_gate_complete':
          setGateStatuses(prev => ({
            ...prev,
            [event.data.gate]: {
              ...prev[event.data.gate],
              status: event.data.passed ? 'passed' : 'failed',
              confidence: event.data.confidence,
              reasoning: event.data.reasoning,
              thinkingPreview: event.data.thinking_preview,
              durationMs: event.data.duration_ms,
            },
          }));
          break;

        case 'ultrathink_cascade_complete':
          setFinalVerdict(event.data.final_verdict);
          break;
      }
    }
  }, [cascadeEvents, findingId]);

  const selectedGateStatus = selectedGate ? gateStatuses[selectedGate] : null;

  return (
    <div className="ultrathink-panel bg-gray-900 rounded-lg p-4 border border-gray-700">
      <div className="header mb-4">
        <h3 className="text-lg font-bold text-white flex items-center gap-2">
          <span className="text-purple-400">*</span>
          Ultrathink Cascade
          {isActive && (
            <span className="animate-pulse text-yellow-400 text-sm">(Running)</span>
          )}
        </h3>
        <p className="text-gray-400 text-sm mt-1">{findingTitle}</p>
      </div>

      {/* Gate Progress */}
      <div className="gates-progress mb-4">
        <GateProgress
          gates={GATES}
          statuses={gateStatuses}
          selectedGate={selectedGate}
          onSelectGate={setSelectedGate}
        />
      </div>

      {/* Final Verdict */}
      {finalVerdict !== null && (
        <div className={`verdict p-3 rounded-lg mb-4 ${
          finalVerdict ? 'bg-green-900/50 border border-green-600' : 'bg-red-900/50 border border-red-600'
        }`}>
          <span className="font-bold text-lg">
            {finalVerdict ? 'VERIFIED - Will Report' : 'REJECTED - Will Not Report'}
          </span>
        </div>
      )}

      {/* Thinking Trace */}
      {selectedGateStatus && (
        <ThinkingTrace
          gate={selectedGate!}
          status={selectedGateStatus.status}
          confidence={selectedGateStatus.confidence}
          reasoning={selectedGateStatus.reasoning}
          thinkingPreview={selectedGateStatus.thinkingPreview}
          durationMs={selectedGateStatus.durationMs}
        />
      )}
    </div>
  );
};

export default UltrathinkPanel;

'use client';
import type { SteeringDecision } from '@/types';

interface SteeringPanelProps {
  decisions: SteeringDecision[];
  isLoading?: boolean;
}

const decisionIcon = (type: string) => {
  switch (type) {
    case 'plateau_recovery': return '\u{1F4C8}';
    case 'validity_fix': return '\u{1F527}';
    case 'target_rebalance': return '\u{2696}\u{FE0F}';
    default: return '\u{1F3AF}';
  }
};

export function SteeringPanel({ decisions, isLoading }: SteeringPanelProps) {
  if (isLoading) {
    return <div className="p-4 text-xs text-[var(--text-muted)] text-center animate-pulse">Loading...</div>;
  }

  if (decisions.length === 0) {
    return <div className="p-4 text-xs text-[var(--text-muted)] text-center">No steering decisions yet. Steering activates when lanes stall or underperform.</div>;
  }

  return (
    <div className="flex flex-col h-full overflow-y-auto">
      <div className="p-2 border-b border-[var(--border-primary)]">
        <span className="text-xs text-[var(--text-muted)]">{decisions.length} decisions</span>
      </div>
      {decisions.map(d => (
        <div key={d.id} className="p-3 border-b border-[var(--border-primary)]">
          <div className="flex items-center gap-2 mb-1">
            <span>{decisionIcon(d.decision_type)}</span>
            <span className="text-xs font-medium text-[var(--text-primary)]">{d.decision_type.replace(/_/g, ' ')}</span>
          </div>
          <div className="text-[10px] text-[var(--text-muted)] mb-1">{d.recommendation}</div>
          {d.affected_lane_ids?.length > 0 && (
            <div className="text-[10px] text-[var(--text-muted)]">Affected lanes: {d.affected_lane_ids.join(', ')}</div>
          )}
          <div className="text-[10px] text-[var(--text-muted)] mt-1">{new Date(d.created_at).toLocaleString()}</div>
        </div>
      ))}
    </div>
  );
}

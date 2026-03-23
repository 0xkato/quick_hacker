'use client';
import type { CoverageSummary } from '@/types';

interface CoveragePanelProps {
  coverage: CoverageSummary | null;
  isLoading?: boolean;
}

export function CoveragePanel({ coverage, isLoading }: CoveragePanelProps) {
  if (isLoading) {
    return <div className="p-4 text-xs text-[var(--text-muted)] text-center animate-pulse">Loading...</div>;
  }

  if (!coverage) {
    return <div className="p-4 text-xs text-[var(--text-muted)] text-center">No coverage data yet. Start a campaign to collect coverage.</div>;
  }

  const metrics = [
    { label: 'Operations Hit', value: coverage.operations_hit ?? 0 },
    { label: 'Parameters Exercised', value: coverage.parameters_exercised ?? 0 },
    { label: 'Status Classes', value: coverage.status_classes_seen?.join(', ') || 'none' },
    { label: 'Sequence Depth', value: coverage.sequence_depth ?? 0 },
    { label: 'Validity Ratio', value: `${((coverage.validity_ratio ?? 0) * 100).toFixed(1)}%` },
    { label: 'Requests/sec', value: (coverage.requests_per_sec ?? 0).toFixed(1) },
  ];

  return (
    <div className="p-4">
      <h3 className="text-sm font-medium text-[var(--text-primary)] mb-3">API Surface Coverage</h3>
      <div className="grid grid-cols-2 gap-3">
        {metrics.map(m => (
          <div key={m.label} className="bg-[var(--bg-tertiary)] rounded p-3">
            <div className="text-[10px] text-[var(--text-muted)] mb-1">{m.label}</div>
            <div className="text-sm font-medium text-[var(--text-primary)]">{m.value}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

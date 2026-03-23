'use client';
import { useState } from 'react';
import type { Artifact, ArtifactBucket } from '@/types';

interface FailuresPanelProps {
  artifacts: Artifact[];
  buckets: ArtifactBucket[];
  isLoading?: boolean;
}

const typeColor = (type: string) => {
  switch (type) {
    case 'crash': return 'text-red-400';
    case 'hang': return 'text-orange-400';
    case 'oracle_hit': return 'text-yellow-400';
    case 'differential_failure': return 'text-purple-400';
    default: return 'text-gray-400';
  }
};

export function FailuresPanel({ artifacts, buckets, isLoading }: FailuresPanelProps) {
  const [selectedArtifact, setSelectedArtifact] = useState<Artifact | null>(null);

  if (isLoading) {
    return <div className="p-4 text-xs text-[var(--text-muted)] text-center animate-pulse">Loading...</div>;
  }

  if (buckets.length === 0 && artifacts.length === 0) {
    return <div className="p-4 text-xs text-[var(--text-muted)] text-center">No failures detected yet.</div>;
  }

  return (
    <div className="flex flex-col h-full overflow-y-auto">
      <div className="p-2 border-b border-[var(--border-primary)]">
        <span className="text-xs text-[var(--text-muted)]">{buckets.length} buckets &middot; {artifacts.length} artifacts</span>
      </div>
      {buckets.map(b => (
        <div key={b.id} className="p-3 border-b border-[var(--border-primary)]">
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs font-mono text-[var(--text-primary)]">{b.bucket_key.slice(0, 12)}...</span>
            <span className="text-xs text-[var(--text-muted)]">{b.artifact_count} artifacts</span>
          </div>
          <div className="text-[10px] text-[var(--text-muted)]">First: {new Date(b.first_seen_at).toLocaleString()}</div>
        </div>
      ))}
      {artifacts.length > 0 && (
        <>
          <div className="p-2 border-b border-[var(--border-primary)] bg-[var(--bg-tertiary)]">
            <span className="text-xs text-[var(--text-muted)]">Recent Artifacts</span>
          </div>
          {artifacts.slice(0, 20).map(a => (
            <div key={a.id} onClick={() => setSelectedArtifact(a)} className="p-3 border-b border-[var(--border-primary)] cursor-pointer hover:bg-[var(--bg-secondary)]">
              <div className="flex items-center justify-between">
                <span className={`text-xs font-medium ${typeColor(a.type)}`}>{a.type}</span>
                <span className="text-[10px] text-[var(--text-muted)]">{a.artifact_classification}</span>
              </div>
              {a.stability_score != null && (
                <div className="text-[10px] text-[var(--text-muted)]">stability: {(a.stability_score * 100).toFixed(0)}%</div>
              )}
            </div>
          ))}
        </>
      )}
      {selectedArtifact && (
        <div className="border-t border-[var(--border-primary)] bg-[var(--bg-tertiary)] p-3">
          <div className="flex justify-between mb-2">
            <span className="text-xs font-medium text-[var(--text-primary)]">Artifact Detail</span>
            <button onClick={() => setSelectedArtifact(null)} className="text-[10px] text-[var(--text-muted)] hover:text-[var(--text-primary)]">&times;</button>
          </div>
          <div className="space-y-1 text-[10px]">
            <div><span className="text-[var(--text-muted)]">ID:</span> <span className="text-[var(--text-primary)]">{selectedArtifact.id}</span></div>
            <div><span className="text-[var(--text-muted)]">Type:</span> <span className={typeColor(selectedArtifact.type)}>{selectedArtifact.type}</span></div>
            <div><span className="text-[var(--text-muted)]">Classification:</span> <span className="text-[var(--text-primary)]">{selectedArtifact.artifact_classification}</span></div>
            <div><span className="text-[var(--text-muted)]">Reproducible:</span> <span className="text-[var(--text-primary)]">{selectedArtifact.reproducible ? 'Yes' : 'No'}</span></div>
            {selectedArtifact.stability_score != null && (
              <div><span className="text-[var(--text-muted)]">Stability:</span> <span className="text-[var(--text-primary)]">{(selectedArtifact.stability_score * 100).toFixed(0)}%</span></div>
            )}
            <div><span className="text-[var(--text-muted)]">Minimized:</span> <span className="text-[var(--text-primary)]">{selectedArtifact.minimized ? 'Yes' : 'No'}</span></div>
            {selectedArtifact.bucket_key && (
              <div><span className="text-[var(--text-muted)]">Bucket:</span> <span className="text-[var(--text-primary)] font-mono">{selectedArtifact.bucket_key}</span></div>
            )}
            {selectedArtifact.evidence_refs && selectedArtifact.evidence_refs.length > 0 && (
              <div>
                <span className="text-[var(--text-muted)]">Evidence:</span>
                {selectedArtifact.evidence_refs.map((ref, i) => (
                  <div key={i} className="text-[var(--text-primary)] font-mono ml-2">{ref}</div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

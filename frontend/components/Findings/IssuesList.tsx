'use client';
import { useState } from 'react';
import type { Issue } from '@/types';

interface IssuesListProps {
  issues: Issue[];
  isLoading?: boolean;
}

const severityColor = (s: string) => {
  switch (s) {
    case 'critical': return 'border-[var(--sev-critical)] text-[var(--sev-critical)] bg-[var(--sev-critical)]/10';
    case 'high': return 'border-[var(--sev-high)] text-[var(--sev-high)] bg-[var(--sev-high)]/10';
    case 'medium': return 'border-[var(--sev-medium)] text-[var(--sev-medium)] bg-[var(--sev-medium)]/10';
    case 'low': return 'border-[var(--sev-low)] text-[var(--sev-low)] bg-[var(--sev-low)]/10';
    default: return 'border-[var(--sev-info)] text-[var(--sev-info)] bg-[var(--sev-info)]/10';
  }
};

const dispositionLabel = (d: string) => {
  switch (d) {
    case 'confirmed_security_issue': return 'Security Issue';
    case 'confirmed_non_security_bug': return 'Bug';
    case 'hardening_observation': return 'Hardening';
    default: return d;
  }
};

export function IssuesList({ issues, isLoading }: IssuesListProps) {
  const [selectedIssue, setSelectedIssue] = useState<Issue | null>(null);

  if (isLoading) {
    return <div className="p-4 text-xs text-[var(--text-muted)] text-center animate-pulse">Loading...</div>;
  }

  if (issues.length === 0) {
    return <div className="p-4 text-xs text-[var(--text-muted)] text-center">No validated issues yet. Issues appear here only after passing all evidence gates.</div>;
  }

  return (
    <div className="flex flex-col h-full overflow-y-auto">
      <div className="p-2 border-b border-[var(--border-primary)]">
        <span className="text-xs text-[var(--text-muted)]">{issues.length} validated issues</span>
      </div>
      {issues.map(issue => (
        <div key={issue.id} onClick={() => setSelectedIssue(issue)} className="p-3 border-b border-[var(--border-primary)] hover:bg-[var(--bg-secondary)] cursor-pointer">
          <div className="flex items-center gap-2 mb-1">
            <span className={`text-[10px] px-1.5 py-0.5 rounded border ${severityColor(issue.severity)}`}>
              {issue.severity.toUpperCase()}
            </span>
            <span className="text-[10px] text-[var(--text-muted)]">{dispositionLabel(issue.disposition)}</span>
          </div>
          <div className="text-xs font-medium text-[var(--text-primary)] mb-1">{issue.title}</div>
          <div className="text-[10px] text-[var(--text-muted)] line-clamp-2">{issue.description}</div>
          {issue.cwe_id && <div className="text-[10px] text-[var(--text-muted)] mt-1">{issue.cwe_id} &middot; {issue.category}</div>}
        </div>
      ))}
      {selectedIssue && (
        <div className="border-t border-[var(--border-primary)] bg-[var(--bg-tertiary)] p-3 max-h-[50%] overflow-y-auto">
          <div className="flex justify-between mb-2">
            <span className="text-xs font-medium text-[var(--text-primary)]">Issue Detail</span>
            <button onClick={() => setSelectedIssue(null)} className="text-[10px] text-[var(--text-muted)]">&times;</button>
          </div>
          <div className="space-y-2 text-[10px]">
            <div className="text-xs font-medium text-[var(--text-primary)]">{selectedIssue.title}</div>
            <div className="text-[var(--text-muted)]">{selectedIssue.description}</div>

            {selectedIssue.root_cause && (
              <div>
                <div className="text-[var(--text-muted)] font-medium mt-2">Root Cause</div>
                <div className="text-[var(--text-primary)]">{selectedIssue.root_cause}</div>
              </div>
            )}

            {selectedIssue.recommended_fix && (
              <div>
                <div className="text-[var(--text-muted)] font-medium mt-2">Recommended Fix</div>
                <div className="text-[var(--text-primary)]">{selectedIssue.recommended_fix}</div>
              </div>
            )}

            {selectedIssue.proof && (
              <div>
                <div className="text-[var(--text-muted)] font-medium mt-2">Proof Checklist</div>
                <div className="grid grid-cols-2 gap-1 mt-1">
                  {Object.entries(selectedIssue.proof).map(([key, value]) => (
                    <div key={key} className="flex items-center gap-1">
                      <span className={value ? 'text-green-400' : 'text-red-400'}>{value ? '\u2713' : '\u2717'}</span>
                      <span className="text-[var(--text-muted)]">{key.replace(/_/g, ' ')}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {selectedIssue.cwe_id && <div className="text-[var(--text-muted)]">{selectedIssue.cwe_id} &middot; {selectedIssue.category}</div>}
          </div>
        </div>
      )}
    </div>
  );
}

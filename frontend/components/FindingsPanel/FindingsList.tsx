'use client';

import { useState } from 'react';
import {
  AlertTriangle,
  AlertCircle,
  Info,
  ChevronRight,
  FileCode,
  ExternalLink,
  Shield,
} from 'lucide-react';
import clsx from 'clsx';
import type { Finding, Severity } from '@/types';

interface FindingsListProps {
  findings: Finding[];
  onFindingClick?: (finding: Finding) => void;
}

const SEVERITY_ICONS: Record<Severity, React.ReactNode> = {
  critical: <AlertTriangle className="w-4 h-4 text-sev-critical" />,
  high: <AlertTriangle className="w-4 h-4 text-sev-high" />,
  medium: <AlertCircle className="w-4 h-4 text-sev-medium" />,
  low: <Info className="w-4 h-4 text-sev-low" />,
  info: <Info className="w-4 h-4 text-sev-info" />,
};

interface FindingCardProps {
  finding: Finding;
  isExpanded: boolean;
  onToggle: () => void;
  onClick: () => void;
}

function FindingCard({ finding, isExpanded, onToggle, onClick }: FindingCardProps) {
  return (
    <div className="soft-card" style={{ padding: 0, overflow: 'hidden' }}>
      {/* Header */}
      <div
        className="flex items-start gap-2 p-3 cursor-pointer hover:bg-vsc-hover"
        onClick={onToggle}
        style={{ transition: 'var(--transition-default)' }}
      >
        <button
          className="mt-0.5 text-vsc-text-muted hover:text-vsc-text"
          style={{ transition: 'transform 150ms ease-out', transform: isExpanded ? 'rotate(90deg)' : 'rotate(0deg)' }}
        >
          <ChevronRight className="w-4 h-4" />
        </button>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span
              className="text-vsc-xs px-2 py-0.5 font-medium"
              style={{
                borderRadius: 'var(--radius-sm)',
                background: finding.severity === 'critical' ? 'rgba(241, 76, 76, 0.25)'
                  : finding.severity === 'high' ? 'rgba(204, 167, 0, 0.25)'
                  : finding.severity === 'medium' ? 'rgba(233, 167, 0, 0.25)'
                  : finding.severity === 'low' ? 'rgba(55, 148, 255, 0.25)'
                  : 'rgba(117, 190, 255, 0.25)',
                color: finding.severity === 'critical' ? 'var(--sev-critical)'
                  : finding.severity === 'high' ? 'var(--sev-high)'
                  : finding.severity === 'medium' ? 'var(--sev-medium)'
                  : finding.severity === 'low' ? 'var(--sev-low)'
                  : 'var(--sev-info)',
              }}
            >
              {finding.severity.toUpperCase()}
            </span>
            <span className="text-vsc-sm truncate text-vsc-text">{finding.title}</span>
          </div>
          <div className="flex items-center gap-2 text-vsc-xs text-vsc-text-muted">
            <FileCode className="w-3 h-3" />
            <span className="truncate">{finding.file_path}</span>
            <span className="text-vsc-text-link">L{finding.line_start}</span>
          </div>
        </div>

        <button
          onClick={(e) => {
            e.stopPropagation();
            onClick();
          }}
          className="btn-icon"
          title="Go to file"
        >
          <ExternalLink className="w-4 h-4" />
        </button>
      </div>

      {/* Expanded content */}
      {isExpanded && (
        <div className="border-t border-vsc-border-subtle p-3 space-y-3 text-vsc-sm bg-vsc-sidebar">
          {/* Type */}
          <div className="flex items-center gap-2">
            <span className="text-vsc-text-muted text-vsc-xs uppercase tracking-wider">Type</span>
            <span className="text-vsc-text">{finding.vulnerability_type}</span>
          </div>

          {/* Description */}
          <div>
            <h4 className="text-vsc-text-muted text-vsc-xs uppercase tracking-wider mb-1">
              Description
            </h4>
            <p className="text-vsc-text leading-relaxed">{finding.description}</p>
          </div>

          {/* Code snippet */}
          {finding.code_snippet && (
            <div>
              <h4 className="text-vsc-text-muted text-vsc-xs uppercase tracking-wider mb-1">
                Code
              </h4>
              <pre
                className="code-snippet whitespace-pre-wrap"
                style={{ borderRadius: 'var(--radius-md)' }}
              >
                {finding.code_snippet}
              </pre>
            </div>
          )}

          {/* Attack scenario */}
          {finding.attack_scenario && (
            <div>
              <h4 className="text-vsc-text-muted text-vsc-xs uppercase tracking-wider mb-1">
                Attack Scenario
              </h4>
              <p className="text-vsc-text leading-relaxed">{finding.attack_scenario}</p>
            </div>
          )}

          {/* Recommended fix */}
          {finding.recommended_fix && (
            <div>
              <h4 className="text-vsc-text-muted text-vsc-xs uppercase tracking-wider mb-1">
                Recommended Fix
              </h4>
              <p className="text-vsc-text leading-relaxed">{finding.recommended_fix}</p>
            </div>
          )}

          {/* Confidence */}
          <div className="flex items-center gap-2">
            <span className="text-vsc-text-muted text-vsc-xs uppercase tracking-wider">
              Confidence
            </span>
            <div className="flex-1 max-w-24">
              <div className="progress-bar">
                <div
                  className="progress-bar-fill"
                  style={{ width: `${finding.confidence * 100}%` }}
                />
              </div>
            </div>
            <span className="text-vsc-xs text-vsc-text">{Math.round(finding.confidence * 100)}%</span>
          </div>
        </div>
      )}
    </div>
  );
}

export function FindingsList({ findings, onFindingClick }: FindingsListProps) {
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());
  const [filterSeverity, setFilterSeverity] = useState<Severity | 'all'>('all');

  const toggleExpanded = (id: string) => {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const filteredFindings =
    filterSeverity === 'all'
      ? findings
      : findings.filter((f) => f.severity === filterSeverity);

  // Count by severity
  const counts: Record<Severity | 'all', number> = {
    all: findings.length,
    critical: findings.filter((f) => f.severity === 'critical').length,
    high: findings.filter((f) => f.severity === 'high').length,
    medium: findings.filter((f) => f.severity === 'medium').length,
    low: findings.filter((f) => f.severity === 'low').length,
    info: findings.filter((f) => f.severity === 'info').length,
  };

  return (
    <div className="h-full flex flex-col">
      {/* Header with filters */}
      <div className="px-3 py-2 border-b border-vsc-border-subtle">
        <div className="flex items-center justify-between mb-2">
          <span className="text-vsc-xs text-vsc-text-muted">
            {filteredFindings.length} of {findings.length}
          </span>
        </div>

        {/* Severity filter */}
        <div className="flex flex-wrap gap-1">
          {(['all', 'critical', 'high', 'medium', 'low', 'info'] as const).map((sev) => (
            <button
              key={sev}
              onClick={() => setFilterSeverity(sev)}
              disabled={counts[sev] === 0}
              className={clsx(
                'px-3 py-1.5 text-vsc-xs transition-all',
                counts[sev] === 0 && 'opacity-50 cursor-not-allowed'
              )}
              style={{
                borderRadius: 'var(--radius-full)',
                border: filterSeverity === sev
                  ? `1px solid ${sev === 'all' ? 'var(--vsc-accent)' : sev === 'critical' ? 'var(--sev-critical)' : sev === 'high' ? 'var(--sev-high)' : sev === 'medium' ? 'var(--sev-medium)' : sev === 'low' ? 'var(--sev-low)' : 'var(--sev-info)'}`
                  : '1px solid #3c3c3c',
                background: filterSeverity === sev
                  ? sev === 'all'
                    ? 'rgba(0, 120, 212, 0.2)'
                    : sev === 'critical' ? 'rgba(241, 76, 76, 0.2)'
                    : sev === 'high' ? 'rgba(204, 167, 0, 0.2)'
                    : sev === 'medium' ? 'rgba(233, 167, 0, 0.2)'
                    : sev === 'low' ? 'rgba(55, 148, 255, 0.2)'
                    : 'rgba(117, 190, 255, 0.2)'
                  : 'transparent',
                color: filterSeverity === sev
                  ? sev === 'all' ? 'var(--vsc-accent)' : `var(--sev-${sev})`
                  : 'var(--vsc-text-muted)',
                transition: 'var(--transition-default)',
              }}
            >
              {sev === 'all' ? 'All' : sev.charAt(0).toUpperCase() + sev.slice(1)}{' '}
              <span style={{ opacity: 0.7 }}>({counts[sev]})</span>
            </button>
          ))}
        </div>
      </div>

      {/* Findings list */}
      <div className="flex-1 overflow-auto p-2 space-y-2">
        {filteredFindings.length === 0 ? (
          <div className="empty-state">
            <Shield className="empty-state-icon" />
            <p className="empty-state-text">
              {findings.length === 0 ? 'No findings yet' : 'No findings match filter'}
            </p>
            {findings.length === 0 && (
              <p className="text-vsc-xs mt-1">Run an agent to scan for vulnerabilities</p>
            )}
          </div>
        ) : (
          filteredFindings.map((finding) => (
            <FindingCard
              key={finding.id}
              finding={finding}
              isExpanded={expandedIds.has(finding.id)}
              onToggle={() => toggleExpanded(finding.id)}
              onClick={() => onFindingClick?.(finding)}
            />
          ))
        )}
      </div>
    </div>
  );
}

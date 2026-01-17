'use client';

import { AlertTriangle, AlertCircle, Info, FileCode } from 'lucide-react';
import type { Finding, Severity } from '@/types';

interface FindingsReportViewProps {
  findings: Finding[];
  onNavigateToFile?: (finding: Finding) => void;
}

const SEVERITY_ICONS: Record<Severity, React.ReactNode> = {
  critical: <AlertTriangle className="w-5 h-5 text-sev-critical" />,
  high: <AlertTriangle className="w-5 h-5 text-sev-high" />,
  medium: <AlertCircle className="w-5 h-5 text-sev-medium" />,
  low: <Info className="w-5 h-5 text-sev-low" />,
  info: <Info className="w-5 h-5 text-sev-info" />,
};

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: 'border-sev-critical bg-sev-critical/10',
  high: 'border-sev-high bg-sev-high/10',
  medium: 'border-sev-medium bg-sev-medium/10',
  low: 'border-sev-low bg-sev-low/10',
  info: 'border-vsc-border bg-vsc-sidebar',
};

export function FindingsReportView({ findings, onNavigateToFile }: FindingsReportViewProps) {
  // Sort by severity
  const sortedFindings = [...findings].sort((a, b) => {
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return severityOrder[a.severity] - severityOrder[b.severity];
  });

  // Count by severity
  const severityCounts = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  return (
    <div className="h-full overflow-auto bg-vsc-bg">
      {/* Header */}
      <div className="sticky top-0 bg-vsc-sidebar border-b border-vsc-border-subtle p-4 z-10">
        <h2 className="text-lg font-semibold text-vsc-text mb-2">Security Findings Report</h2>
        <div className="flex items-center gap-4 text-sm text-vsc-text-muted">
          <span>Total: {findings.length}</span>
          {severityCounts.critical > 0 && (
            <span className="text-sev-critical">Critical: {severityCounts.critical}</span>
          )}
          {severityCounts.high > 0 && (
            <span className="text-sev-high">High: {severityCounts.high}</span>
          )}
          {severityCounts.medium > 0 && (
            <span className="text-sev-medium">Medium: {severityCounts.medium}</span>
          )}
          {severityCounts.low > 0 && (
            <span className="text-sev-low">Low: {severityCounts.low}</span>
          )}
        </div>
      </div>

      {/* Findings */}
      <div className="p-4 space-y-6">
        {sortedFindings.length === 0 ? (
          <div className="text-center py-12 text-vsc-text-muted">
            No findings to display
          </div>
        ) : (
          sortedFindings.map((finding, index) => (
            <div
              key={finding.id}
              className={`border-l-4 rounded-r-lg p-4 ${SEVERITY_COLORS[finding.severity]}`}
            >
              {/* Finding header */}
              <div className="flex items-start gap-3 mb-3">
                <div className="mt-0.5">{SEVERITY_ICONS[finding.severity]}</div>
                <div className="flex-1">
                  <h3 className="text-base font-semibold text-vsc-text mb-1">
                    {index + 1}. {finding.title}
                  </h3>
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="px-2 py-0.5 text-xs font-medium uppercase bg-vsc-bg border border-vsc-border rounded">
                      {finding.severity}
                    </span>
                    {finding.vulnerability_type && (
                      <span className="px-2 py-0.5 text-xs bg-vsc-bg border border-vsc-border rounded">
                        {finding.vulnerability_type}
                      </span>
                    )}
                    {finding.cwe_id && (
                      <span className="px-2 py-0.5 text-xs bg-vsc-bg border border-vsc-border rounded">
                        CWE-{finding.cwe_id}
                      </span>
                    )}
                    {finding.disposition && (
                      <span className="px-2 py-0.5 text-xs bg-vsc-bg border border-vsc-border rounded">
                        {finding.disposition}
                      </span>
                    )}
                  </div>
                </div>
              </div>

              {/* Location */}
              {finding.file_path && (
                <div className="mb-3">
                  <div className="flex items-center gap-2 text-sm">
                    <FileCode className="w-4 h-4 text-vsc-text-muted" />
                    <button
                      onClick={() => onNavigateToFile?.(finding)}
                      className="text-vsc-textLink hover:underline font-mono"
                    >
                      {finding.file_path}
                      {finding.line_start && `:${finding.line_start}`}
                      {finding.line_end && finding.line_end !== finding.line_start && `-${finding.line_end}`}
                    </button>
                  </div>
                </div>
              )}

              {/* Description */}
              {finding.description && (
                <div className="mb-3">
                  <h4 className="text-sm font-semibold text-vsc-text mb-1">Description</h4>
                  <p className="text-sm text-vsc-text-muted leading-relaxed whitespace-pre-wrap">
                    {finding.description}
                  </p>
                </div>
              )}

              {/* Vulnerable Code */}
              {(finding.vulnerable_code || finding.code_snippet) && (
                <div className="mb-3">
                  <h4 className="text-sm font-semibold text-vsc-text mb-1">Vulnerable Code</h4>
                  <pre className="bg-vsc-bg border border-vsc-border rounded p-3 overflow-x-auto text-xs">
                    <code>{finding.vulnerable_code || finding.code_snippet}</code>
                  </pre>
                </div>
              )}

              {/* Attack Scenario */}
              {finding.attack_scenario && (
                <div className="mb-3">
                  <h4 className="text-sm font-semibold text-vsc-text mb-1">Attack Scenario</h4>
                  <p className="text-sm text-vsc-text-muted leading-relaxed whitespace-pre-wrap">
                    {finding.attack_scenario}
                  </p>
                </div>
              )}

              {/* Proof of Concept */}
              {finding.proof_of_concept && (
                <div className="mb-3">
                  <h4 className="text-sm font-semibold text-vsc-text mb-1">Proof of Concept</h4>
                  <pre className="bg-vsc-bg border border-vsc-border rounded p-3 overflow-x-auto text-xs">
                    <code>{finding.proof_of_concept}</code>
                  </pre>
                </div>
              )}

              {/* Recommended Fix */}
              {finding.recommended_fix && (
                <div className="mb-3">
                  <h4 className="text-sm font-semibold text-vsc-text mb-1">Recommended Fix</h4>
                  <p className="text-sm text-vsc-text-muted leading-relaxed whitespace-pre-wrap">
                    {finding.recommended_fix}
                  </p>
                </div>
              )}

              {/* Additional metadata */}
              <div className="flex items-center gap-4 text-xs text-vsc-text-muted pt-2 border-t border-vsc-border-subtle">
                {finding.confidence !== undefined && (
                  <span>Confidence: {(finding.confidence * 100).toFixed(0)}%</span>
                )}
                {finding.classification_confidence !== undefined && (
                  <span>Classification: {finding.classification_confidence}/100</span>
                )}
                {finding.created_at && (
                  <span>Found: {new Date(finding.created_at).toLocaleString()}</span>
                )}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

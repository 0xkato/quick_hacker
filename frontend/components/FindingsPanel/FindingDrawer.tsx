'use client';

import { useEffect } from 'react';
import { X, FileCode, ExternalLink } from 'lucide-react';
import type { Finding } from '@/types';
import ProofChecklistView from './ProofChecklistView';

// Import constants from FindingsList
const DISPOSITION_COLORS: Record<string, string> = {
  valid_security_issue: 'rgba(220, 38, 38, 0.85)',
  bug: 'rgba(234, 88, 12, 0.85)',
  misconfiguration: 'rgba(234, 179, 8, 0.85)',
  hardening: 'rgba(59, 130, 246, 0.85)',
  by_design: 'rgba(107, 114, 128, 0.85)',
  speculative: 'rgba(156, 163, 175, 0.85)',
};

const DISPOSITION_LABELS: Record<string, string> = {
  valid_security_issue: 'Valid Issue',
  bug: 'Bug',
  misconfiguration: 'Misconfiguration',
  hardening: 'Hardening',
  by_design: 'By Design',
  speculative: 'Speculative',
};

const CLASSIFICATION_COLORS: Record<string, string> = {
  security_issue: 'rgba(220, 38, 38, 0.85)',
  bug: 'rgba(202, 138, 4, 0.85)',
  misconfiguration: 'rgba(234, 88, 12, 0.85)',
  hardening: 'rgba(59, 130, 246, 0.85)',
};

const CLASSIFICATION_LABELS: Record<string, string> = {
  security_issue: 'Security Issue',
  bug: 'Bug',
  misconfiguration: 'Misconfiguration',
  hardening: 'Hardening',
};

const REPORTABLE_DISPOSITIONS = new Set(['valid_security_issue', 'bug']);

interface FindingDrawerProps {
  finding: Finding;
  onClose: () => void;
  onNavigateToFile?: (filePath: string) => void;
}

export function FindingDrawer({ finding, onClose, onNavigateToFile }: FindingDrawerProps) {
  // ESC key handler
  useEffect(() => {
    const handleEsc = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };
    window.addEventListener('keydown', handleEsc);
    return () => window.removeEventListener('keydown', handleEsc);
  }, [onClose]);

  // Body scroll lock
  useEffect(() => {
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = '';
    };
  }, []);

  const handleGoToFile = () => {
    if (onNavigateToFile) {
      onNavigateToFile(finding.file_path);
      onClose();
    }
  };

  return (
    <>
      {/* Overlay backdrop */}
      <div
        className="fixed inset-0 bg-black/60 z-40"
        onClick={onClose}
        style={{ backdropFilter: 'blur(2px)' }}
      />

      {/* Drawer panel */}
      <div
        className="fixed top-0 right-0 bottom-0 z-50 bg-vsc-sidebar border-l border-vsc-border flex flex-col"
        style={{
          width: '700px',
          boxShadow: '-4px 0 16px rgba(0, 0, 0, 0.3)',
        }}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-vsc-border-subtle">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-2 flex-wrap">
              {/* Disposition badge (always shown if present) */}
              {finding.disposition && (
                <span
                  className="text-vsc-xs px-2 py-0.5 font-medium text-white"
                  style={{
                    borderRadius: 'var(--radius-sm)',
                    background: DISPOSITION_COLORS[finding.disposition],
                  }}
                  title={`Triage disposition: ${DISPOSITION_LABELS[finding.disposition]}`}
                >
                  {DISPOSITION_LABELS[finding.disposition]}
                </span>
              )}
              {/* Severity badge (only for reportable findings) */}
              {finding.severity && finding.disposition && REPORTABLE_DISPOSITIONS.has(finding.disposition) && (
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
              )}
              {/* Legacy: Show severity if no disposition (backward compatibility) */}
              {finding.severity && !finding.disposition && (
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
              )}
              {/* Legacy classification badge */}
              {finding.classification && (
                <span
                  className="text-vsc-xs px-2 py-0.5 font-medium text-white"
                  style={{
                    borderRadius: 'var(--radius-sm)',
                    background: CLASSIFICATION_COLORS[finding.classification],
                  }}
                >
                  {CLASSIFICATION_LABELS[finding.classification]}
                </span>
              )}
              {/* Non-reportable notice */}
              {finding.disposition && !REPORTABLE_DISPOSITIONS.has(finding.disposition) && (
                <span
                  className="text-vsc-xs px-2 py-0.5 font-medium text-vsc-text-muted"
                  style={{
                    borderRadius: 'var(--radius-sm)',
                    background: 'rgba(107, 114, 128, 0.2)',
                  }}
                  title="This finding was filtered by triage"
                >
                  Filtered by triage
                </span>
              )}
            </div>
            <h2 className="text-vsc-base text-vsc-text font-medium">{finding.title}</h2>
          </div>
          <button
            onClick={onClose}
            className="btn-icon ml-4"
            title="Close (Esc)"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* File path with Go to File button */}
        <div className="flex items-center justify-between px-6 py-3 bg-vsc-bg border-b border-vsc-border-subtle">
          <div className="flex items-center gap-2 text-vsc-sm text-vsc-text-muted min-w-0">
            <FileCode className="w-4 h-4 flex-shrink-0" />
            <span className="truncate">{finding.file_path}</span>
            <span className="text-vsc-text-link flex-shrink-0">L{finding.line_start}</span>
          </div>
          {onNavigateToFile && (
            <button
              onClick={handleGoToFile}
              className="btn-primary ml-4 flex-shrink-0 flex items-center gap-2"
              title="Go to file"
            >
              <ExternalLink className="w-4 h-4" />
              <span>Go to File</span>
            </button>
          )}
        </div>

        {/* Content - scrollable */}
        <div className="flex-1 overflow-y-auto px-6 py-4 space-y-6 text-vsc-sm">
          {/* Type */}
          <div className="flex items-center gap-2">
            <span className="text-vsc-text-muted text-vsc-xs uppercase tracking-wider">Type</span>
            <span className="text-vsc-text">{finding.vulnerability_type}</span>
          </div>

          {/* Description */}
          <div>
            <h4 className="text-vsc-text-muted text-vsc-xs uppercase tracking-wider mb-2">
              Description
            </h4>
            <p className="text-vsc-text leading-relaxed">{finding.description}</p>
          </div>

          {/* Code snippet */}
          {finding.code_snippet && (
            <div>
              <h4 className="text-vsc-text-muted text-vsc-xs uppercase tracking-wider mb-2">
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
              <h4 className="text-vsc-text-muted text-vsc-xs uppercase tracking-wider mb-2">
                Attack Scenario
              </h4>
              <p className="text-vsc-text leading-relaxed">{finding.attack_scenario}</p>
            </div>
          )}

          {/* Recommended fix */}
          {finding.recommended_fix && (
            <div>
              <h4 className="text-vsc-text-muted text-vsc-xs uppercase tracking-wider mb-2">
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
            <div className="flex-1 max-w-48">
              <div className="progress-bar">
                <div
                  className="progress-bar-fill"
                  style={{ width: `${finding.confidence * 100}%` }}
                />
              </div>
            </div>
            <span className="text-vsc-xs text-vsc-text">{Math.round(finding.confidence * 100)}%</span>
          </div>

          {/* Triage reasoning */}
          {finding.reasoning && finding.reasoning.length > 0 && (
            <div>
              <h4 className="text-vsc-text-muted text-vsc-xs uppercase tracking-wider mb-2">
                Triage Reasoning
              </h4>
              <ul className="text-vsc-text leading-relaxed space-y-1 list-disc list-inside">
                {finding.reasoning.map((reason, idx) => (
                  <li key={idx}>{reason}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Proof checklist */}
          {finding.proof_checklist && (
            <div>
              <ProofChecklistView checklist={finding.proof_checklist} />
            </div>
          )}

          {/* Triage confidence scores */}
          {(finding.classification_confidence !== undefined || finding.exploit_confidence !== undefined) && (
            <div className="space-y-3">
              {finding.classification_confidence !== undefined && (
                <div className="flex items-center gap-2">
                  <span className="text-vsc-text-muted text-vsc-xs uppercase tracking-wider">
                    Classification Confidence
                  </span>
                  <div className="flex-1 max-w-48">
                    <div className="progress-bar">
                      <div
                        className="progress-bar-fill"
                        style={{ width: `${finding.classification_confidence}%` }}
                      />
                    </div>
                  </div>
                  <span className="text-vsc-xs text-vsc-text">{finding.classification_confidence}%</span>
                </div>
              )}
              {finding.exploit_confidence !== undefined && (
                <div className="flex items-center gap-2">
                  <span className="text-vsc-text-muted text-vsc-xs uppercase tracking-wider">
                    Exploit Confidence
                  </span>
                  <div className="flex-1 max-w-48">
                    <div className="progress-bar">
                      <div
                        className="progress-bar-fill"
                        style={{ width: `${finding.exploit_confidence}%` }}
                      />
                    </div>
                  </div>
                  <span className="text-vsc-xs text-vsc-text">{finding.exploit_confidence}%</span>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </>
  );
}

'use client';

import { FileCode, ExternalLink } from 'lucide-react';
import type { Finding } from '@/types';
import ProofChecklistView from './ProofChecklistView';
import { SubmissionBadge } from '@/components/FindingsList/SubmissionBadge';
import { SubmissionPanel } from '@/components/FindingDrawer/SubmissionPanel';
import { ValidationBadge } from '@/components/ValidationBadge';

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

interface FindingFullViewProps {
  finding: Finding;
  onNavigateToFile?: (filePath: string) => void;
}

export function FindingFullView({ finding, onNavigateToFile }: FindingFullViewProps) {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2 mb-3 flex-wrap">
          {/* Disposition badge */}
          {finding.disposition && (
            <span
              className="text-xs px-3 py-1 font-medium text-white rounded-full"
              style={{ background: DISPOSITION_COLORS[finding.disposition] }}
            >
              {DISPOSITION_LABELS[finding.disposition]}
            </span>
          )}
          {/* Severity badge */}
          {finding.severity && (
            <span
              className="text-xs px-3 py-1 font-medium rounded-full"
              style={{
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
          {/* Submission badge */}
          {finding.submission_result && (
            <SubmissionBadge submissionResult={finding.submission_result} />
          )}
        </div>
        <h1 className="text-xl font-semibold text-text-primary mb-2">{finding.title}</h1>
        {/* Validation badge */}
        {finding.validation_result && (
          <div className="mt-2">
            <ValidationBadge validationResult={finding.validation_result} />
          </div>
        )}
      </div>

      {/* File path with Go to File button */}
      <div className="flex items-center justify-between p-4 bg-bg-secondary rounded-lg">
        <div className="flex items-center gap-2 text-sm text-text-muted min-w-0">
          <FileCode className="w-5 h-5 flex-shrink-0" />
          <span className="truncate font-mono">{finding.file_path}</span>
          <span className="text-accent font-mono">L{finding.line_start}</span>
        </div>
        {onNavigateToFile && (
          <button
            onClick={() => onNavigateToFile(finding.file_path)}
            className="btn-primary flex items-center gap-2"
          >
            <ExternalLink className="w-4 h-4" />
            Go to File
          </button>
        )}
      </div>

      {/* Type */}
      <div className="p-4 bg-bg-secondary rounded-lg">
        <span className="text-xs text-text-muted uppercase tracking-wider">Vulnerability Type</span>
        <p className="text-text-primary mt-1 font-medium">{finding.vulnerability_type}</p>
      </div>

      {/* Description */}
      <div>
        <h3 className="text-sm font-medium text-text-muted uppercase tracking-wider mb-3">Description</h3>
        <p className="text-text-primary leading-relaxed">{finding.description}</p>
      </div>

      {/* Code snippet */}
      {finding.code_snippet && (
        <div>
          <h3 className="text-sm font-medium text-text-muted uppercase tracking-wider mb-3">Vulnerable Code</h3>
          <pre className="p-4 bg-bg-tertiary rounded-lg overflow-x-auto font-mono text-sm">
            {finding.code_snippet}
          </pre>
        </div>
      )}

      {/* Attack scenario */}
      {finding.attack_scenario && (
        <div>
          <h3 className="text-sm font-medium text-text-muted uppercase tracking-wider mb-3">Attack Scenario</h3>
          <p className="text-text-primary leading-relaxed">{finding.attack_scenario}</p>
        </div>
      )}

      {/* Recommended fix */}
      {finding.recommended_fix && (
        <div>
          <h3 className="text-sm font-medium text-text-muted uppercase tracking-wider mb-3">Recommended Fix</h3>
          <p className="text-text-primary leading-relaxed">{finding.recommended_fix}</p>
        </div>
      )}

      {/* Confidence */}
      <div className="p-4 bg-bg-secondary rounded-lg">
        <span className="text-xs text-text-muted uppercase tracking-wider">Confidence</span>
        <div className="flex items-center gap-3 mt-2">
          <div className="flex-1 max-w-xs">
            <div className="h-2 bg-bg-tertiary rounded-full overflow-hidden">
              <div
                className="h-full bg-accent rounded-full"
                style={{ width: `${finding.confidence * 100}%` }}
              />
            </div>
          </div>
          <span className="text-sm font-medium text-text-primary">{Math.round(finding.confidence * 100)}%</span>
        </div>
      </div>

      {/* Triage reasoning */}
      {finding.reasoning && finding.reasoning.length > 0 && (
        <div>
          <h3 className="text-sm font-medium text-text-muted uppercase tracking-wider mb-3">Triage Reasoning</h3>
          <ul className="space-y-2">
            {finding.reasoning.map((reason, idx) => (
              <li key={idx} className="flex items-start gap-2 text-text-primary">
                <span className="text-accent mt-1">•</span>
                <span>{reason}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Proof checklist */}
      {finding.proof_checklist && (
        <div>
          <h3 className="text-sm font-medium text-text-muted uppercase tracking-wider mb-3">Proof Checklist</h3>
          <ProofChecklistView checklist={finding.proof_checklist} />
        </div>
      )}

      {/* Classification confidence */}
      {finding.classification_confidence !== undefined && (
        <div className="p-4 bg-bg-secondary rounded-lg">
          <span className="text-xs text-text-muted uppercase tracking-wider">Classification Confidence</span>
          <div className="flex items-center gap-3 mt-2">
            <div className="flex-1 max-w-xs">
              <div className="h-2 bg-bg-tertiary rounded-full overflow-hidden">
                <div
                  className="h-full bg-accent rounded-full"
                  style={{ width: `${finding.classification_confidence}%` }}
                />
              </div>
            </div>
            <span className="text-sm font-medium text-text-primary">{finding.classification_confidence}%</span>
          </div>
        </div>
      )}

      {/* Submission Panel */}
      {finding.submission_result && (
        <div>
          <h3 className="text-sm font-medium text-text-muted uppercase tracking-wider mb-3">Submission Evaluation</h3>
          <SubmissionPanel
            submissionResult={finding.submission_result}
            findingId={finding.id}
            onRetriggerQuest={() => console.log('Quest retriggered for finding:', finding.id)}
          />
        </div>
      )}
    </div>
  );
}

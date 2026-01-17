'use client';

import { useState } from 'react';
import { SubmissionResult, SubmissionDecision } from '@/types/protocol';
import { evidenceQuests } from '@/lib/api';

interface SubmissionPanelProps {
  submissionResult: SubmissionResult;
  findingId: string;
  onRetriggerQuest?: () => void;
}

export const SubmissionPanel: React.FC<SubmissionPanelProps> = ({
  submissionResult,
  findingId,
  onRetriggerQuest
}) => {
  const [showDetails, setShowDetails] = useState(true);
  const [isRetriggering, setIsRetriggering] = useState(false);

  const getDecisionIcon = (decision: SubmissionDecision) => {
    switch (decision) {
      case SubmissionDecision.SUBMIT: return '✅';
      case SubmissionDecision.DONT_SUBMIT: return '❌';
      case SubmissionDecision.NEEDS_MORE_INFO: return '❓';
    }
  };

  const getDecisionTitle = (decision: SubmissionDecision) => {
    switch (decision) {
      case SubmissionDecision.SUBMIT: return 'Ready for Submission';
      case SubmissionDecision.DONT_SUBMIT: return 'Not Submittable';
      case SubmissionDecision.NEEDS_MORE_INFO: return 'Needs More Information';
    }
  };

  const getColorClasses = (decision: SubmissionDecision) => {
    switch (decision) {
      case SubmissionDecision.SUBMIT:
        return {
          bg: 'rgba(34, 197, 94, 0.1)',
          border: 'rgba(34, 197, 94, 0.3)',
          text: 'rgb(22, 163, 74)',
        };
      case SubmissionDecision.DONT_SUBMIT:
        return {
          bg: 'rgba(107, 114, 128, 0.1)',
          border: 'rgba(107, 114, 128, 0.3)',
          text: 'rgb(107, 114, 128)',
        };
      case SubmissionDecision.NEEDS_MORE_INFO:
        return {
          bg: 'rgba(245, 158, 11, 0.1)',
          border: 'rgba(245, 158, 11, 0.3)',
          text: 'rgb(217, 119, 6)',
        };
    }
  };

  const handleRetriggerQuest = async () => {
    try {
      setIsRetriggering(true);
      await evidenceQuests.trigger(findingId);
      if (onRetriggerQuest) onRetriggerQuest();
    } catch (err) {
      console.error('Failed to trigger quest:', err);
    } finally {
      setIsRetriggering(false);
    }
  };

  const colors = getColorClasses(submissionResult.decision);

  return (
    <div className="p-4 space-y-4 border border-vsc-border-subtle rounded-lg">
      {/* Header */}
      <div
        className="flex items-start gap-3 p-3 rounded-lg border"
        style={{
          background: colors.bg,
          borderColor: colors.border,
        }}
      >
        <div className="text-2xl">{getDecisionIcon(submissionResult.decision)}</div>
        <div className="flex-1">
          <h3
            className="font-semibold text-vsc-sm mb-1"
            style={{ color: colors.text }}
          >
            {getDecisionTitle(submissionResult.decision)}
          </h3>
          <div className="text-vsc-xs text-vsc-text-muted">
            Protocol: <span className="font-medium">{submissionResult.protocol_id}</span>
          </div>
        </div>
        <button
          onClick={() => setShowDetails(!showDetails)}
          className="text-vsc-sm px-2 py-1 text-vsc-text-muted hover:text-vsc-text"
        >
          {showDetails ? '▼' : '▶'}
        </button>
      </div>

      {showDetails && (
        <>
          {/* Reasons */}
          <div>
            <h4 className="text-vsc-xs font-semibold text-vsc-text-muted uppercase tracking-wider mb-2">
              Reasoning
            </h4>
            <ul className="space-y-1.5">
              {submissionResult.reasons.map((reason, idx) => (
                <li key={idx} className="text-vsc-sm text-vsc-text flex items-start gap-2">
                  <span className="text-vsc-text-muted">•</span>
                  <span>{reason}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Disposition Modified Warning */}
          {submissionResult.disposition_modified && (
            <div
              className="border rounded-lg p-3"
              style={{
                background: 'rgba(249, 115, 22, 0.1)',
                borderColor: 'rgba(249, 115, 22, 0.3)',
              }}
            >
              <div className="flex items-start gap-2">
                <span style={{ color: 'rgb(234, 88, 12)' }}>⚠️</span>
                <div>
                  <div className="text-vsc-sm font-medium" style={{ color: 'rgb(234, 88, 12)' }}>
                    Disposition Modified by Protocol
                  </div>
                  {submissionResult.disposition_reason && (
                    <div className="text-vsc-xs mt-1" style={{ color: 'rgb(217, 119, 6)' }}>
                      {submissionResult.disposition_reason}
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Missing Evidence */}
          {submissionResult.decision === SubmissionDecision.NEEDS_MORE_INFO &&
           submissionResult.missing_evidence.length > 0 && (
            <div>
              <h4 className="text-vsc-xs font-semibold text-vsc-text-muted uppercase tracking-wider mb-2">
                Missing Evidence
              </h4>
              <ul className="space-y-1.5">
                {submissionResult.missing_evidence.map((item, idx) => (
                  <li key={idx} className="text-vsc-sm flex items-start gap-2" style={{ color: 'rgb(217, 119, 6)' }}>
                    <span style={{ color: 'rgb(245, 158, 11)' }}>⚠</span>
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Suggested Next Steps */}
          {submissionResult.suggested_next_steps && submissionResult.suggested_next_steps.length > 0 && (
            <div>
              <h4 className="text-vsc-xs font-semibold text-vsc-text-muted uppercase tracking-wider mb-2">
                Suggested Next Steps
              </h4>
              <ul className="space-y-1.5">
                {submissionResult.suggested_next_steps.map((step, idx) => (
                  <li key={idx} className="text-vsc-sm text-vsc-text flex items-start gap-2">
                    <span className="text-vsc-text-muted">{idx + 1}.</span>
                    <span>{step}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Quest Status */}
          {submissionResult.quest_run && (
            <div
              className="border rounded-lg p-3"
              style={{
                background: 'rgba(59, 130, 246, 0.1)',
                borderColor: 'rgba(59, 130, 246, 0.3)',
              }}
            >
              <div className="flex items-start gap-2">
                <span style={{ color: 'rgb(37, 99, 235)' }}>🔍</span>
                <div className="flex-1">
                  <div className="text-vsc-sm font-medium" style={{ color: 'rgb(37, 99, 235)' }}>
                    Evidence Quest Executed
                  </div>
                  <div className="text-vsc-xs mt-1" style={{ color: 'rgb(59, 130, 246)' }}>
                    Autonomous agent gathered additional evidence for this finding.
                  </div>
                  {submissionResult.quest_id && (
                    <div className="text-vsc-xs font-mono mt-2" style={{ color: 'rgb(59, 130, 246)' }}>
                      Quest ID: {submissionResult.quest_id}
                    </div>
                  )}
                  {submissionResult.quest_findings && Object.keys(submissionResult.quest_findings).length > 0 && (
                    <div className="mt-2">
                      <div className="text-vsc-xs font-semibold mb-1" style={{ color: 'rgb(37, 99, 235)' }}>
                        Quest Findings:
                      </div>
                      <pre
                        className="text-vsc-xs p-2 rounded overflow-x-auto"
                        style={{
                          background: 'rgba(59, 130, 246, 0.05)',
                          color: 'rgb(59, 130, 246)',
                        }}
                      >
                        {JSON.stringify(submissionResult.quest_findings, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Actions */}
          <div className="flex gap-2">
            {submissionResult.decision === SubmissionDecision.SUBMIT && (
              <button
                className="flex-1 py-2 rounded font-medium text-vsc-sm text-white"
                style={{ background: 'rgb(22, 163, 74)' }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.background = 'rgb(21, 128, 61)';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.background = 'rgb(22, 163, 74)';
                }}
              >
                Generate Report →
              </button>
            )}

            {submissionResult.decision === SubmissionDecision.NEEDS_MORE_INFO && onRetriggerQuest && (
              <button
                onClick={handleRetriggerQuest}
                disabled={isRetriggering}
                className="flex-1 py-2 rounded font-medium text-vsc-sm border"
                style={{
                  borderColor: 'rgb(37, 99, 235)',
                  color: 'rgb(37, 99, 235)',
                  background: isRetriggering ? 'rgba(59, 130, 246, 0.1)' : 'transparent',
                }}
                onMouseEnter={(e) => {
                  if (!isRetriggering) {
                    e.currentTarget.style.background = 'rgba(59, 130, 246, 0.1)';
                  }
                }}
                onMouseLeave={(e) => {
                  if (!isRetriggering) {
                    e.currentTarget.style.background = 'transparent';
                  }
                }}
              >
                {isRetriggering ? 'Triggering...' : '🔍 Retry Evidence Quest'}
              </button>
            )}
          </div>
        </>
      )}
    </div>
  );
};

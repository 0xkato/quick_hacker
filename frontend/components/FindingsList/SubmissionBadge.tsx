'use client';

import { SubmissionResult, SubmissionDecision } from '@/types/protocol';

interface SubmissionBadgeProps {
  submissionResult?: SubmissionResult;
  compact?: boolean;
}

export const SubmissionBadge: React.FC<SubmissionBadgeProps> = ({
  submissionResult,
  compact = false
}) => {
  if (!submissionResult) return null;

  const getConfig = (decision: SubmissionDecision) => {
    switch (decision) {
      case SubmissionDecision.SUBMIT:
        return {
          icon: '✓',
          text: 'Submittable',
          bgColor: 'rgba(34, 197, 94, 0.15)',
          textColor: 'rgb(22, 163, 74)',
          borderColor: 'rgba(34, 197, 94, 0.3)',
        };
      case SubmissionDecision.DONT_SUBMIT:
        return {
          icon: '✗',
          text: 'Not Submittable',
          bgColor: 'rgba(107, 114, 128, 0.15)',
          textColor: 'rgb(107, 114, 128)',
          borderColor: 'rgba(107, 114, 128, 0.3)',
        };
      case SubmissionDecision.NEEDS_MORE_INFO:
        return {
          icon: '?',
          text: 'Needs Info',
          bgColor: 'rgba(245, 158, 11, 0.15)',
          textColor: 'rgb(217, 119, 6)',
          borderColor: 'rgba(245, 158, 11, 0.3)',
        };
    }
  };

  const config = getConfig(submissionResult.decision);

  if (compact) {
    return (
      <span
        className="text-vsc-xs px-2 py-0.5 rounded font-medium"
        style={{
          background: config.bgColor,
          color: config.textColor,
        }}
        title={config.text}
      >
        {config.icon}
      </span>
    );
  }

  return (
    <div className="flex items-center gap-2 flex-wrap">
      <span
        className="text-vsc-xs px-2 py-1 border rounded font-medium"
        style={{
          background: config.bgColor,
          color: config.textColor,
          borderColor: config.borderColor,
        }}
      >
        <span className="mr-1">{config.icon}</span>
        {config.text}
      </span>
      {submissionResult.quest_run && (
        <span
          className="text-vsc-xs px-2 py-1 border rounded font-medium"
          style={{
            background: 'rgba(59, 130, 246, 0.15)',
            color: 'rgb(37, 99, 235)',
            borderColor: 'rgba(59, 130, 246, 0.3)',
          }}
          title="Evidence quest was executed"
        >
          🔍 Quest
        </span>
      )}
      {submissionResult.disposition_modified && (
        <span
          className="text-vsc-xs px-2 py-1 border rounded font-medium"
          style={{
            background: 'rgba(249, 115, 22, 0.15)',
            color: 'rgb(234, 88, 12)',
            borderColor: 'rgba(249, 115, 22, 0.3)',
          }}
          title="Disposition was modified by protocol"
        >
          Modified
        </span>
      )}
    </div>
  );
};

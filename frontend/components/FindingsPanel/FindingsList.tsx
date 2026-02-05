'use client';

import { useCallback, useEffect, useState } from 'react';
import {
  AlertTriangle,
  AlertCircle,
  Info,
  FileCode,
  ExternalLink,
  Shield,
  Eye,
  EyeOff,
  FileText,
  Filter,
  Loader2,
} from 'lucide-react';
import { agents } from '@/lib/api';
import clsx from 'clsx';
import type { Finding, Severity, FindingClassification, Disposition } from '@/types';
import ProofChecklistView from './ProofChecklistView';
import { FindingsReportView } from './FindingsReportView';
import { TriageConfigModal, type TriageConfig } from './TriageConfigModal';

// Classification badge colors and labels
const CLASSIFICATION_COLORS: Record<FindingClassification, string> = {
  security_issue: 'rgba(220, 38, 38, 0.85)',  // red-600
  bug: 'rgba(202, 138, 4, 0.85)',             // yellow-600
  misconfiguration: 'rgba(234, 88, 12, 0.85)', // orange-500
  hardening: 'rgba(59, 130, 246, 0.85)',      // blue-500
};

const CLASSIFICATION_LABELS: Record<FindingClassification, string> = {
  security_issue: 'Security Issue',
  bug: 'Bug',
  misconfiguration: 'Misconfiguration',
  hardening: 'Hardening',
};

// Disposition badge colors and labels
const DISPOSITION_COLORS: Record<Disposition, string> = {
  valid_security_issue: 'rgba(220, 38, 38, 0.85)',  // red-600
  bug: 'rgba(234, 88, 12, 0.85)',                   // orange-600
  misconfiguration: 'rgba(234, 179, 8, 0.85)',      // yellow-500
  hardening: 'rgba(59, 130, 246, 0.85)',            // blue-500
  by_design: 'rgba(107, 114, 128, 0.85)',           // gray-500
  speculative: 'rgba(156, 163, 175, 0.85)',         // gray-400
};

const DISPOSITION_LABELS: Record<Disposition, string> = {
  valid_security_issue: 'Valid Issue',
  bug: 'Bug',
  misconfiguration: 'Misconfiguration',
  hardening: 'Hardening',
  by_design: 'By Design',
  speculative: 'Speculative',
};

// Reportable dispositions
const REPORTABLE_DISPOSITIONS = new Set<Disposition>(['valid_security_issue', 'bug']);

interface FindingsListProps {
  findings: Finding[];
  agentId?: string | null;
  repoId?: string | null;  // For triaging all findings when no agent selected
  allAgents?: Array<{ id: string; status: string; agent_type: string }>;  // To check triage agent status
  onFindingClick?: (finding: Finding) => void;
  onNavigateToFile?: (finding: Finding) => void;
  onFindingsUpdated?: (findings: Finding[]) => void;
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
  onClick: () => void;
  onNavigateToFile: () => void;
}

// Helper function to get validation status
function getValidationStatus(finding: Finding): {
  label: string;
  className: string;
  icon: string;
} {
  if (finding.validation_result?.is_valid === true) {
    return { label: 'CONFIRMED', className: 'confirmed', icon: '●' };
  }
  if (finding.validation_result?.is_valid === false) {
    return { label: 'REJECTED', className: 'rejected', icon: '●' };
  }
  if (finding.disposition && !REPORTABLE_DISPOSITIONS.has(finding.disposition)) {
    return { label: 'NEEDS REVIEW', className: 'needs-review', icon: '●' };
  }
  return { label: 'UNPROCESSED', className: 'unprocessed', icon: '○' };
}

function FindingCard({ finding, onClick, onNavigateToFile }: FindingCardProps) {
  const validationStatus = getValidationStatus(finding);

  return (
    <div
      className={clsx('soft-card', finding.severity && `severity-${finding.severity}`)}
      style={{ padding: 0, overflow: 'hidden' }}
    >
      {/* Header */}
      <div
        className="flex items-start gap-2 p-3 cursor-pointer hover:bg-bg-tertiary"
        onClick={onClick}
        style={{ transition: 'var(--transition-default)' }}
      >
        <div className="flex-1 min-w-0">
          {/* Title first (primary text, font-medium) */}
          <div className="text-sm font-medium text-text-primary mb-1.5 truncate">
            {finding.title}
          </div>

          {/* Badges row: severity badge + validation status + disposition */}
          <div className="flex items-center gap-2 mb-1.5 flex-wrap">
            {/* Severity badge using new design system classes */}
            {finding.severity && (
              <span className={clsx('severity-badge', finding.severity)}>
                {finding.severity.toUpperCase()}
              </span>
            )}

            {/* Validation status indicator */}
            <span className={clsx('validation-status', validationStatus.className)}>
              <span>{validationStatus.icon}</span>
              <span>{validationStatus.label}</span>
            </span>

            {/* Disposition badge */}
            {finding.disposition && (
              <span
                className="text-xs px-2 py-0.5 font-medium text-white rounded"
                style={{
                  background: DISPOSITION_COLORS[finding.disposition],
                }}
                title={`Triage disposition: ${DISPOSITION_LABELS[finding.disposition]}`}
              >
                {DISPOSITION_LABELS[finding.disposition]}
              </span>
            )}

            {/* Legacy classification badge */}
            {finding.classification && !finding.disposition && (
              <span
                className="text-xs px-2 py-0.5 font-medium text-white rounded"
                style={{
                  background: CLASSIFICATION_COLORS[finding.classification],
                }}
              >
                {CLASSIFICATION_LABELS[finding.classification]}
              </span>
            )}
          </div>

          {/* Location (file:line) */}
          <div className="flex items-center gap-2 text-xs text-text-muted mb-1">
            <FileCode className="w-3 h-3" />
            <span className="truncate">{finding.file_path}</span>
            <span className="text-accent">L{finding.line_start}</span>
          </div>

          {/* Description (truncated, if exists) */}
          {finding.description && (
            <p className="text-xs text-text-secondary line-clamp-2 mt-1">
              {finding.description}
            </p>
          )}
        </div>

        <button
          onClick={(e) => {
            e.stopPropagation();
            onNavigateToFile();
          }}
          className="btn-icon"
          title="Go to file"
        >
          <ExternalLink className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
}

// localStorage key for tracking pending triage
const TRIAGE_STORAGE_KEY = 'pendingTriage';
const TRIAGE_TIMEOUT_MS = 60 * 60 * 1000; // 1 hour max triage time

interface StoredTriageState {
  agentId: string;
  startedAt: number;
  triageAgentId?: string;
}

function getStoredTriageState(): StoredTriageState | null {
  if (typeof window === 'undefined') return null;
  try {
    const stored = localStorage.getItem(TRIAGE_STORAGE_KEY);
    if (!stored) return null;
    const state = JSON.parse(stored) as StoredTriageState;
    // Expire if older than timeout
    if (Date.now() - state.startedAt > TRIAGE_TIMEOUT_MS) {
      localStorage.removeItem(TRIAGE_STORAGE_KEY);
      return null;
    }
    return state;
  } catch {
    return null;
  }
}

function setStoredTriageState(agentId: string, triageAgentId?: string): void {
  if (typeof window === 'undefined') return;
  const state: StoredTriageState = { agentId, startedAt: Date.now(), triageAgentId };
  localStorage.setItem(TRIAGE_STORAGE_KEY, JSON.stringify(state));
}

function clearStoredTriageState(): void {
  if (typeof window === 'undefined') return;
  localStorage.removeItem(TRIAGE_STORAGE_KEY);
}

// Disposition priority for sorting (lower = higher priority)
const DISPOSITION_PRIORITY: Record<Disposition | 'none', number> = {
  valid_security_issue: 0,
  bug: 1,
  misconfiguration: 2,
  hardening: 3,
  by_design: 4,
  speculative: 5,
  none: 6,
};

export function FindingsList({ findings, agentId, repoId, allAgents, onFindingClick, onNavigateToFile, onFindingsUpdated }: FindingsListProps) {
  const [filterSeverity, setFilterSeverity] = useState<Severity | 'all'>('all');
  const [filterDisposition, setFilterDisposition] = useState<Disposition | 'all'>('all');
  const [showReportView, setShowReportView] = useState(false);
  const [isTriaging, setIsTriaging] = useState(false);
  const [triageMessage, setTriageMessage] = useState<string | null>(null);
  const [showTriageModal, setShowTriageModal] = useState(false);
  const [triageAgentId, setTriageAgentId] = useState<string | null>(null);

  // Check for pending triage on mount and when agents change
  useEffect(() => {
    const stored = getStoredTriageState();
    if (!stored || stored.agentId !== agentId) {
      // No pending triage for this agent
      return;
    }

    // If we have a triage agent ID, check its status
    if (stored.triageAgentId) {
      const triageAgent = allAgents?.find(a => a.id === stored.triageAgentId);
      if (triageAgent) {
        if (triageAgent.status === 'running' || triageAgent.status === 'pending') {
          setIsTriaging(true);
          setTriageAgentId(stored.triageAgentId);
        } else if (triageAgent.status === 'completed' || triageAgent.status === 'failed') {
          // Triage finished while we were away
          clearStoredTriageState();
          setIsTriaging(false);
          setTriageAgentId(null);
          if (triageAgent.status === 'completed') {
            setTriageMessage('Triage completed');
          } else {
            setTriageMessage('Triage failed');
          }
        }
      } else {
        // Triage agent not in list - might be loading, keep showing spinner
        setIsTriaging(true);
      }
    } else {
      // No triage agent ID yet - triage was started but hasn't returned
      // Check if any triage agent is running for this repo
      const runningTriageAgent = allAgents?.find(
        a => a.agent_type === 'triage' && (a.status === 'running' || a.status === 'pending')
      );
      if (runningTriageAgent) {
        setIsTriaging(true);
        setTriageAgentId(runningTriageAgent.id);
        // Update stored state with the triage agent ID
        setStoredTriageState(agentId, runningTriageAgent.id);
      } else {
        // No running triage found - still waiting for API response, keep spinner
        setIsTriaging(true);
      }
    }
  }, [agentId, allAgents]);

  const handleStartTriage = async (config: TriageConfig) => {
    // Need either agentId or repoId to triage
    if (!agentId && !repoId) return;

    setShowTriageModal(false);
    setIsTriaging(true);
    setTriageMessage(null);

    // Store triage state so we can recover if user navigates away
    setStoredTriageState(agentId || repoId || 'all');

    try {
      // Use repo-level triage when no specific agent, otherwise use agent-level
      const result = agentId
        ? await agents.llmTriage(agentId, undefined, config)
        : await agents.llmTriageByRepo(repoId!, undefined, config);

      // Update stored state with triage agent ID if provided
      if (result.triage_agent_id) {
        setTriageAgentId(result.triage_agent_id);
      }

      // Count decisions
      const validCount = result.results.filter(r => r.decision === 'valid_security_issue').length;
      const filteredCount = result.results.filter(r =>
        ['hardening', 'by_design', 'bug', 'misconfiguration'].includes(r.decision)
      ).length;

      setTriageMessage(
        `Analyzed ${result.triaged_count} findings: ${validCount} confirmed, ${filteredCount} filtered`
      );

      // Update findings in parent
      if (onFindingsUpdated) {
        onFindingsUpdated(result.findings);
      }

      // Clear stored state on success
      clearStoredTriageState();
    } catch (error: unknown) {
      console.error('LLM Triage failed:', error);
      let errorMsg = 'Triage failed. ';
      if (error instanceof Error) {
        errorMsg += error.message;
      } else {
        errorMsg += 'Check console for details.';
      }
      setTriageMessage(errorMsg);

      // Clear stored state on failure
      clearStoredTriageState();
    } finally {
      setIsTriaging(false);
      setTriageAgentId(null);
    }
  };

  const isTriageFiltered = useCallback(
    (finding: Finding) => Boolean(finding.disposition && !REPORTABLE_DISPOSITIONS.has(finding.disposition)),
    []
  );
  const isReportable = useCallback((finding: Finding) => !isTriageFiltered(finding), [isTriageFiltered]);
  const triageFilteredCount = findings.filter(isTriageFiltered).length;

  // If triage filtered everything, default to showing filtered findings so the panel
  // doesn't look empty even though findings exist.
  const defaultShowFiltered = findings.length > 0 && findings.every((f) => !isReportable(f));
  const [showFiltered, setShowFiltered] = useState(defaultShowFiltered);
  const [userToggledShowFiltered, setUserToggledShowFiltered] = useState(false);

  useEffect(() => {
    if (userToggledShowFiltered) return;
    if (!showFiltered && findings.length > 0 && findings.every((f) => !isReportable(f))) {
      setShowFiltered(true);
    }
  }, [findings, isReportable, showFiltered, userToggledShowFiltered]);

  // Filter by reportability (if triage system is enabled)
  const visibleFindings = showFiltered ? findings : findings.filter(isReportable);

  // Filter by severity
  const severityFiltered =
    filterSeverity === 'all'
      ? visibleFindings
      : visibleFindings.filter((f) => f.severity === filterSeverity);

  // Filter by disposition
  const dispositionFiltered =
    filterDisposition === 'all'
      ? severityFiltered
      : severityFiltered.filter((f) => f.disposition === filterDisposition);

  // Sort by disposition priority (valid issues first), then by severity
  const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const filteredFindings = [...dispositionFiltered].sort((a, b) => {
    const dispA = DISPOSITION_PRIORITY[a.disposition || 'none'];
    const dispB = DISPOSITION_PRIORITY[b.disposition || 'none'];
    if (dispA !== dispB) return dispA - dispB;
    return SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
  });

  // Count by severity (from visible findings)
  const counts: Record<Severity | 'all', number> = {
    all: visibleFindings.length,
    critical: visibleFindings.filter((f) => f.severity === 'critical').length,
    high: visibleFindings.filter((f) => f.severity === 'high').length,
    medium: visibleFindings.filter((f) => f.severity === 'medium').length,
    low: visibleFindings.filter((f) => f.severity === 'low').length,
    info: visibleFindings.filter((f) => f.severity === 'info').length,
  };

  // Count by disposition
  const dispCounts: Record<Disposition | 'all', number> = {
    all: visibleFindings.length,
    valid_security_issue: visibleFindings.filter((f) => f.disposition === 'valid_security_issue').length,
    bug: visibleFindings.filter((f) => f.disposition === 'bug').length,
    misconfiguration: visibleFindings.filter((f) => f.disposition === 'misconfiguration').length,
    hardening: visibleFindings.filter((f) => f.disposition === 'hardening').length,
    by_design: visibleFindings.filter((f) => f.disposition === 'by_design').length,
    speculative: visibleFindings.filter((f) => f.disposition === 'speculative').length,
  };

  return (
    <div className="h-full flex flex-col">
      {/* Header with filters */}
      <div className="px-3 py-2 border-b border-vsc-border-subtle">
        <div className="flex items-center justify-between mb-2">
          <span className="text-vsc-xs text-vsc-text-muted">
            {filteredFindings.length} of {findings.length}
            {triageFilteredCount > 0 && !showFiltered && (
              <span className="ml-1 text-vsc-text-muted">
                ({triageFilteredCount} filtered)
              </span>
            )}
          </span>
          {/* Right side controls */}
          <div className="flex items-center gap-2">
            {/* LLM Triage Button - works with agent or repo */}
            {(agentId || repoId) && findings.length > 0 && (
              <button
                onClick={() => setShowTriageModal(true)}
                disabled={isTriaging}
                className="flex items-center gap-1.5 px-2 py-1 text-vsc-xs transition-all hover:bg-vsc-hover disabled:opacity-50"
                style={{
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid var(--vsc-border)',
                  color: isTriaging ? 'var(--vsc-accent)' : 'var(--vsc-text-muted)',
                }}
                title="Run LLM-based triage to analyze and confirm/reject findings"
              >
                {isTriaging ? (
                  <Loader2 className="w-3 h-3 animate-spin" />
                ) : (
                  <Filter className="w-3 h-3" />
                )}
                <span>{isTriaging ? 'Analyzing...' : 'Triage'}</span>
              </button>
            )}

            {/* Report View Button */}
            <button
              onClick={() => setShowReportView(true)}
              className="flex items-center gap-1.5 px-2 py-1 text-vsc-xs transition-all hover:bg-vsc-hover"
              style={{
                borderRadius: 'var(--radius-sm)',
                border: '1px solid var(--vsc-border)',
                color: 'var(--vsc-text-muted)',
              }}
              title="Show all findings in report view"
            >
              <FileText className="w-3 h-3" />
              <span>Report</span>
            </button>

            {/* Show Filtered toggle */}
            {triageFilteredCount > 0 && (
              <button
                onClick={() => {
                  setUserToggledShowFiltered(true);
                  setShowFiltered(!showFiltered);
                }}
                className="flex items-center gap-1.5 px-2 py-1 text-vsc-xs transition-all hover:bg-vsc-hover"
                style={{
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid var(--vsc-border)',
                  color: showFiltered ? 'var(--vsc-accent)' : 'var(--vsc-text-muted)',
                }}
                title={showFiltered ? 'Hide filtered findings' : 'Show filtered findings'}
              >
                {showFiltered ? <Eye className="w-3 h-3" /> : <EyeOff className="w-3 h-3" />}
                <span>{showFiltered ? 'Hide Filtered' : 'Show Filtered'}</span>
              </button>
            )}
          </div>
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

        {/* Disposition filter */}
        <div className="flex flex-wrap gap-1 mt-2">
          {(['all', 'valid_security_issue', 'bug', 'misconfiguration', 'hardening', 'by_design', 'speculative'] as const).map((disp) => (
            <button
              key={disp}
              onClick={() => setFilterDisposition(disp)}
              disabled={dispCounts[disp] === 0}
              className={clsx(
                'px-2 py-1 text-vsc-xs transition-all',
                dispCounts[disp] === 0 && 'opacity-50 cursor-not-allowed'
              )}
              style={{
                borderRadius: 'var(--radius-full)',
                border: filterDisposition === disp
                  ? `1px solid ${disp === 'all' ? 'var(--vsc-accent)' : DISPOSITION_COLORS[disp]}`
                  : '1px solid #3c3c3c',
                background: filterDisposition === disp
                  ? disp === 'all'
                    ? 'rgba(0, 120, 212, 0.2)'
                    : `${DISPOSITION_COLORS[disp].replace('0.85', '0.2')}`
                  : 'transparent',
                color: filterDisposition === disp
                  ? disp === 'all' ? 'var(--vsc-accent)' : DISPOSITION_COLORS[disp]
                  : 'var(--vsc-text-muted)',
                transition: 'var(--transition-default)',
              }}
            >
              {disp === 'all' ? 'All' : DISPOSITION_LABELS[disp]}{' '}
              <span style={{ opacity: 0.7 }}>({dispCounts[disp]})</span>
            </button>
          ))}
        </div>

        {/* Triage result message */}
        {triageMessage && (
          <div
            className="mt-2 px-2 py-1 text-vsc-xs rounded"
            style={{
              background: triageMessage.includes('failed')
                ? 'rgba(220, 38, 38, 0.1)'
                : 'rgba(34, 197, 94, 0.1)',
              color: triageMessage.includes('failed')
                ? 'var(--sev-high)'
                : 'var(--vsc-success, #22c55e)',
            }}
          >
            {triageMessage}
          </div>
        )}
      </div>

      {/* List View */}
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
              onClick={() => onFindingClick?.(finding)}
              onNavigateToFile={() => onNavigateToFile?.(finding)}
            />
          ))
        )}
      </div>

      {/* Report View Drawer */}
      {showReportView && (
        <FindingsReportView
          findings={filteredFindings}
          onClose={() => setShowReportView(false)}
          onNavigateToFile={onNavigateToFile}
        />
      )}

      {/* Triage Config Modal */}
      {showTriageModal && (
        <TriageConfigModal
          findingsCount={findings.length}
          onClose={() => setShowTriageModal(false)}
          onStartTriage={handleStartTriage}
        />
      )}
    </div>
  );
}

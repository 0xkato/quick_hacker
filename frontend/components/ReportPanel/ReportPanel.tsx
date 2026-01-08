'use client';

import { useState } from 'react';
import {
  FileText,
  Clock,
  AlertTriangle,
  Download,
  ChevronDown,
  ChevronRight,
  DollarSign,
  FileCode,
  BarChart3,
  CheckCircle,
} from 'lucide-react';
import clsx from 'clsx';
import { InvestigationReport, FindingSummary, TimelineEvent, Severity } from '@/types';

interface ReportPanelProps {
  report: InvestigationReport;
  onDownload: (format: 'md' | 'json' | 'svg') => void;
}

const severityColors: Record<Severity, string> = {
  critical: 'bg-sev-critical/30 text-sev-critical border-sev-critical',
  high: 'bg-sev-high/30 text-sev-high border-sev-high',
  medium: 'bg-sev-medium/30 text-sev-medium border-sev-medium',
  low: 'bg-sev-low/30 text-sev-low border-sev-low',
  info: 'bg-vsc-border/30 text-vsc-text-muted border-vsc-border',
};

const severityBadgeColors: Record<Severity, string> = {
  critical: 'bg-sev-critical text-white',
  high: 'bg-sev-high text-black',
  medium: 'bg-sev-medium text-black',
  low: 'bg-sev-low text-white',
  info: 'bg-vsc-border text-vsc-text',
};

export function ReportPanel({ report, onDownload }: ReportPanelProps) {
  const [expandedSections, setExpandedSections] = useState<Set<string>>(
    new Set(['findings', 'stats'])
  );
  const [expandedFindings, setExpandedFindings] = useState<Set<string>>(new Set());

  const toggleSection = (section: string) => {
    const newSet = new Set(expandedSections);
    if (newSet.has(section)) {
      newSet.delete(section);
    } else {
      newSet.add(section);
    }
    setExpandedSections(newSet);
  };

  const toggleFinding = (findingId: string) => {
    const newSet = new Set(expandedFindings);
    if (newSet.has(findingId)) {
      newSet.delete(findingId);
    } else {
      newSet.add(findingId);
    }
    setExpandedFindings(newSet);
  };

  const formatDuration = (seconds?: number) => {
    if (!seconds) return 'N/A';
    if (seconds < 60) return `${seconds}s`;
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}m ${secs}s`;
  };

  const formatDate = (dateStr?: string) => {
    if (!dateStr) return 'N/A';
    return new Date(dateStr).toLocaleString();
  };

  const totalFindings =
    (report.findings_by_severity.critical || 0) +
    (report.findings_by_severity.high || 0) +
    (report.findings_by_severity.medium || 0) +
    (report.findings_by_severity.low || 0);

  return (
    <div className="h-full flex flex-col bg-vsc-bg text-vsc-text overflow-hidden">
      {/* Header */}
      <div className="p-4 border-b border-vsc-border">
        <div className="flex items-center justify-between mb-2">
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <FileText className="w-5 h-5 text-vsc-accent" />
            Security Audit Report
          </h2>
          <div className="flex items-center gap-2">
            <button
              onClick={() => onDownload('md')}
              className="flex items-center gap-1 px-2 py-1 text-xs bg-vsc-sidebar border border-vsc-border rounded hover:bg-vsc-hover"
              title="Download Markdown"
            >
              <Download className="w-3 h-3" />
              MD
            </button>
            <button
              onClick={() => onDownload('json')}
              className="flex items-center gap-1 px-2 py-1 text-xs bg-vsc-sidebar border border-vsc-border rounded hover:bg-vsc-hover"
              title="Download JSON"
            >
              <Download className="w-3 h-3" />
              JSON
            </button>
            <button
              onClick={() => onDownload('svg')}
              className="flex items-center gap-1 px-2 py-1 text-xs bg-vsc-sidebar border border-vsc-border rounded hover:bg-vsc-hover"
              title="Download Flow SVG"
            >
              <Download className="w-3 h-3" />
              SVG
            </button>
          </div>
        </div>
        <div className="text-sm text-vsc-text-muted">
          <span className="font-medium">{report.repo_name}</span> &bull; {report.agent_name} ({report.agent_type})
        </div>
        <div className="text-xs text-vsc-text-muted mt-1">
          Generated: {formatDate(report.generated_at)}
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto p-4 space-y-4">
        {/* Executive Summary */}
        <div className="bg-vsc-sidebar border border-vsc-border rounded-lg p-4">
          <h3 className="font-medium mb-2 flex items-center gap-2">
            <CheckCircle className="w-4 h-4 text-vsc-success" />
            Executive Summary
          </h3>
          <p className="text-sm text-vsc-text-muted leading-relaxed">
            {report.executive_summary}
          </p>
        </div>

        {/* Findings Overview */}
        <div className="bg-vsc-sidebar border border-vsc-border rounded-lg overflow-hidden">
          <button
            onClick={() => toggleSection('findings')}
            className="w-full p-4 flex items-center justify-between hover:bg-vsc-hover"
          >
            <h3 className="font-medium flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-sev-high" />
              Findings ({totalFindings})
            </h3>
            {expandedSections.has('findings') ? (
              <ChevronDown className="w-4 h-4" />
            ) : (
              <ChevronRight className="w-4 h-4" />
            )}
          </button>

          {expandedSections.has('findings') && (
            <div className="border-t border-vsc-border">
              {/* Severity breakdown */}
              <div className="p-4 grid grid-cols-4 gap-2 border-b border-vsc-border">
                {(['critical', 'high', 'medium', 'low'] as Severity[]).map((severity) => (
                  <div
                    key={severity}
                    className={clsx(
                      'text-center p-2 rounded border',
                      severityColors[severity]
                    )}
                  >
                    <div className="text-2xl font-bold">
                      {report.findings_by_severity[severity] || 0}
                    </div>
                    <div className="text-xs uppercase">{severity}</div>
                  </div>
                ))}
              </div>

              {/* Finding list */}
              <div className="divide-y divide-vsc-border">
                {report.findings_summary.length === 0 ? (
                  <div className="p-4 text-center text-vsc-text-muted text-sm">
                    No vulnerabilities found
                  </div>
                ) : (
                  report.findings_summary.map((finding) => (
                    <FindingEntry
                      key={finding.id}
                      finding={finding}
                      isExpanded={expandedFindings.has(finding.id)}
                      onToggle={() => toggleFinding(finding.id)}
                    />
                  ))
                )}
              </div>
            </div>
          )}
        </div>

        {/* Statistics */}
        <div className="bg-vsc-sidebar border border-vsc-border rounded-lg overflow-hidden">
          <button
            onClick={() => toggleSection('stats')}
            className="w-full p-4 flex items-center justify-between hover:bg-vsc-hover"
          >
            <h3 className="font-medium flex items-center gap-2">
              <BarChart3 className="w-4 h-4 text-vsc-accent" />
              Statistics
            </h3>
            {expandedSections.has('stats') ? (
              <ChevronDown className="w-4 h-4" />
            ) : (
              <ChevronRight className="w-4 h-4" />
            )}
          </button>

          {expandedSections.has('stats') && (
            <div className="border-t border-vsc-border p-4">
              <div className="grid grid-cols-2 gap-4">
                <StatItem
                  icon={<Clock className="w-4 h-4" />}
                  label="Duration"
                  value={formatDuration(report.duration_seconds)}
                />
                <StatItem
                  icon={<FileCode className="w-4 h-4" />}
                  label="Files Analyzed"
                  value={report.total_files.toString()}
                />
                <StatItem
                  icon={<FileText className="w-4 h-4" />}
                  label="API Calls"
                  value={report.total_api_calls.toString()}
                />
                <StatItem
                  icon={<BarChart3 className="w-4 h-4" />}
                  label="Tokens Used"
                  value={(report.total_prompt_tokens + report.total_completion_tokens).toLocaleString()}
                />
                {report.estimated_cost !== undefined && (
                  <StatItem
                    icon={<DollarSign className="w-4 h-4" />}
                    label="Estimated Cost"
                    value={`$${report.estimated_cost.toFixed(4)}`}
                  />
                )}
              </div>
            </div>
          )}
        </div>

        {/* Timeline */}
        <div className="bg-vsc-sidebar border border-vsc-border rounded-lg overflow-hidden">
          <button
            onClick={() => toggleSection('timeline')}
            className="w-full p-4 flex items-center justify-between hover:bg-vsc-hover"
          >
            <h3 className="font-medium flex items-center gap-2">
              <Clock className="w-4 h-4 text-vsc-accent" />
              Timeline ({report.timeline.length} events)
            </h3>
            {expandedSections.has('timeline') ? (
              <ChevronDown className="w-4 h-4" />
            ) : (
              <ChevronRight className="w-4 h-4" />
            )}
          </button>

          {expandedSections.has('timeline') && (
            <div className="border-t border-vsc-border max-h-64 overflow-auto">
              {report.timeline.map((event, idx) => (
                <TimelineItem key={idx} event={event} />
              ))}
            </div>
          )}
        </div>

        {/* Files with Findings */}
        {report.files_with_findings.length > 0 && (
          <div className="bg-vsc-sidebar border border-vsc-border rounded-lg overflow-hidden">
            <button
              onClick={() => toggleSection('files')}
              className="w-full p-4 flex items-center justify-between hover:bg-vsc-hover"
            >
              <h3 className="font-medium flex items-center gap-2">
                <FileCode className="w-4 h-4 text-sev-high" />
                Affected Files ({report.files_with_findings.length})
              </h3>
              {expandedSections.has('files') ? (
                <ChevronDown className="w-4 h-4" />
              ) : (
                <ChevronRight className="w-4 h-4" />
              )}
            </button>

            {expandedSections.has('files') && (
              <div className="border-t border-vsc-border p-4 max-h-48 overflow-auto">
                <div className="space-y-1">
                  {report.files_with_findings.map((file, idx) => (
                    <div
                      key={idx}
                      className="text-sm font-mono text-vsc-text-muted hover:text-vsc-text"
                    >
                      {file}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// Sub-components

function FindingEntry({
  finding,
  isExpanded,
  onToggle,
}: {
  finding: FindingSummary;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  return (
    <div className="hover:bg-vsc-hover">
      <button
        onClick={onToggle}
        className="w-full p-3 flex items-start gap-3 text-left"
      >
        <span
          className={clsx(
            'px-1.5 py-0.5 rounded text-xs font-medium uppercase',
            severityBadgeColors[finding.severity as Severity]
          )}
        >
          {finding.severity}
        </span>
        <div className="flex-1 min-w-0">
          <div className="text-sm font-medium truncate">{finding.title}</div>
          <div className="text-xs text-vsc-text-muted truncate">
            {finding.file_path}:{finding.line_start}
          </div>
        </div>
        <div className="text-xs text-vsc-text-muted">
          {(finding.confidence * 100).toFixed(0)}%
        </div>
        {isExpanded ? (
          <ChevronDown className="w-4 h-4 flex-shrink-0" />
        ) : (
          <ChevronRight className="w-4 h-4 flex-shrink-0" />
        )}
      </button>

      {isExpanded && (
        <div className="px-3 pb-3 pl-12 space-y-2">
          <div className="text-xs">
            <span className="text-vsc-text-muted">Type: </span>
            <span className="text-vsc-text">{finding.vulnerability_type}</span>
          </div>
          <div className="text-xs">
            <span className="text-vsc-text-muted">File: </span>
            <span className="font-mono text-vsc-text">{finding.file_path}</span>
          </div>
          <div className="text-xs">
            <span className="text-vsc-text-muted">Line: </span>
            <span className="text-vsc-text">{finding.line_start}</span>
          </div>
        </div>
      )}
    </div>
  );
}

function StatItem({
  icon,
  label,
  value,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
}) {
  return (
    <div className="flex items-center gap-3">
      <span className="text-vsc-text-muted">{icon}</span>
      <div>
        <div className="text-xs text-vsc-text-muted">{label}</div>
        <div className="text-sm font-medium">{value}</div>
      </div>
    </div>
  );
}

function TimelineItem({ event }: { event: TimelineEvent }) {
  const eventTypeColors: Record<string, string> = {
    started: 'bg-vsc-accent',
    completed: 'bg-vsc-success',
    finding_reported: 'bg-sev-high',
    tool_called: 'bg-vsc-text-muted',
  };

  return (
    <div className="flex items-start gap-3 px-4 py-2 hover:bg-vsc-hover">
      <div
        className={clsx(
          'w-2 h-2 rounded-full mt-1.5 flex-shrink-0',
          eventTypeColors[event.event_type] || 'bg-vsc-border'
        )}
      />
      <div className="flex-1 min-w-0">
        <div className="text-xs text-vsc-text-muted">
          {new Date(event.timestamp).toLocaleTimeString()}
        </div>
        <div className="text-sm truncate">{event.description}</div>
      </div>
    </div>
  );
}

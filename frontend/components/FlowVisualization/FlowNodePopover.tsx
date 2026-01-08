// @ts-nocheck
// TODO: Fix type inference issue with unknown in Record<string, unknown>
'use client';

import { ReactNode } from 'react';
import { X, Clock, FileText, Code, Brain, AlertTriangle, CheckCircle, XCircle } from 'lucide-react';
import clsx from 'clsx';

interface FlowNode {
  id: string;
  type: string;
  label: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  data?: Record<string, unknown>;
  timestamp: string;
  duration_ms?: number;
  llm_reasoning?: string;
  code_context?: string;
  tool_result_summary?: string;
  confidence_score?: number;
}

interface FlowNodePopoverProps {
  node: FlowNode;
  position: { x: number; y: number };
  onClose: () => void;
}

export function FlowNodePopover({ node, position, onClose }: FlowNodePopoverProps): JSX.Element {
  const typeLabels: Record<string, string> = {
    user_input: 'User Input',
    tool_call: 'Tool Call',
    tool_result: 'Tool Result',
    analysis: 'Analysis',
    finding: 'Security Finding',
    code_read: 'Code Read',
    search: 'Search',
    scan: 'Scan',
    entry_point: 'Entry Point',
    function: 'Function',
    external: 'External Call',
    cycle: 'Cycle',
  };

  const statusColors: Record<FlowNode['status'], string> = {
    pending: 'text-vsc-text-muted',
    running: 'text-vsc-accent',
    completed: 'text-vsc-success',
    failed: 'text-sev-critical',
  };

  const statusIcons: Record<FlowNode['status'], ReactNode> = {
    pending: <Clock className="w-4 h-4" />,
    running: <Code className="w-4 h-4 animate-pulse" />,
    completed: <CheckCircle className="w-4 h-4" />,
    failed: <XCircle className="w-4 h-4" />,
  };

  const getConfidenceColor = (confidence?: number) => {
    if (confidence === undefined) return 'bg-vsc-border';
    if (confidence >= 0.8) return 'bg-vsc-success';
    if (confidence >= 0.6) return 'bg-sev-medium';
    if (confidence >= 0.4) return 'bg-sev-high';
    return 'bg-sev-critical';
  };

  return (
    <div
      className="fixed z-50 bg-vsc-sidebar border border-vsc-border rounded-lg shadow-xl max-w-md"
      style={{
        left: `${position.x}px`,
        top: `${position.y}px`,
        transform: 'translate(-50%, -100%) translateY(-10px)',
      }}
    >
      {/* Header */}
      <div className="flex items-center justify-between p-3 border-b border-vsc-border">
        <div className="flex items-center gap-2">
          {node.type === 'finding' ? (
            <AlertTriangle className="w-4 h-4 text-sev-high" />
          ) : node.type === 'analysis' ? (
            <Brain className="w-4 h-4 text-vsc-accent" />
          ) : (
            <FileText className="w-4 h-4 text-vsc-text-muted" />
          )}
          <span className="font-medium text-vsc-text">
            {typeLabels[node.type] || node.type}
          </span>
          <span className={clsx('flex items-center gap-1 text-sm', statusColors[node.status])}>
            {statusIcons[node.status]}
            {node.status}
          </span>
        </div>
        <button
          onClick={onClose}
          className="p-1 hover:bg-vsc-bg rounded text-vsc-text-muted hover:text-vsc-text"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Content */}
      <div className="p-3 space-y-3 max-h-96 overflow-auto">
        {/* Label */}
        <div>
          <div className="text-xs text-vsc-text-muted mb-1">Label</div>
          <div className="text-sm text-vsc-text">{node.label}</div>
        </div>

        {/* Timestamp & Duration */}
        <div className="flex gap-4">
          <div>
            <div className="text-xs text-vsc-text-muted mb-1">Time</div>
            <div className="text-sm text-vsc-text">
              {new Date(node.timestamp).toLocaleTimeString()}
            </div>
          </div>
          {node.duration_ms !== undefined && (
            <div>
              <div className="text-xs text-vsc-text-muted mb-1">Duration</div>
              <div className="text-sm text-vsc-text">{node.duration_ms}ms</div>
            </div>
          )}
        </div>

        {/* Confidence Score */}
        {node.confidence_score !== undefined && (
          <div>
            <div className="text-xs text-vsc-text-muted mb-1">Confidence</div>
            <div className="flex items-center gap-2">
              <div className="flex-1 h-2 bg-vsc-bg rounded-full overflow-hidden">
                <div
                  className={clsx('h-full rounded-full', getConfidenceColor(node.confidence_score))}
                  style={{ width: `${node.confidence_score * 100}%` }}
                />
              </div>
              <span className="text-sm text-vsc-text">
                {(node.confidence_score * 100).toFixed(0)}%
              </span>
            </div>
          </div>
        )}

        {/* Finding Severity */}
        {node.type === 'finding' && node.data?.severity && (() => {
          const severity = node.data.severity as string;
          return (
            <div>
              <div className="text-xs text-vsc-text-muted mb-1">Severity</div>
              <span
                className={clsx(
                  'inline-block px-2 py-0.5 rounded text-xs font-medium uppercase',
                  severity === 'critical' && 'bg-sev-critical/30 text-sev-critical',
                  severity === 'high' && 'bg-sev-high/30 text-sev-high',
                  severity === 'medium' && 'bg-sev-medium/30 text-sev-medium',
                  severity === 'low' && 'bg-sev-low/30 text-sev-low'
                )}
              >
                {severity}
              </span>
            </div>
          );
        })()}

        {/* LLM Reasoning */}
        {node.llm_reasoning && (
          <div>
            <div className="text-xs text-vsc-text-muted mb-1 flex items-center gap-1">
              <Brain className="w-3 h-3" />
              LLM Reasoning
            </div>
            <div className="text-sm text-vsc-text bg-vsc-bg p-2 rounded font-mono whitespace-pre-wrap max-h-32 overflow-auto">
              {node.llm_reasoning}
            </div>
          </div>
        )}

        {/* Tool Result Summary */}
        {node.tool_result_summary && (
          <div>
            <div className="text-xs text-vsc-text-muted mb-1 flex items-center gap-1">
              <Code className="w-3 h-3" />
              Tool Result
            </div>
            <div className="text-sm text-vsc-text bg-vsc-bg p-2 rounded font-mono whitespace-pre-wrap max-h-32 overflow-auto">
              {node.tool_result_summary}
            </div>
          </div>
        )}

        {/* Code Context */}
        {node.code_context && (
          <div>
            <div className="text-xs text-vsc-text-muted mb-1 flex items-center gap-1">
              <FileText className="w-3 h-3" />
              Code Context
            </div>
            <pre className="text-xs text-vsc-text bg-vsc-bg p-2 rounded overflow-auto max-h-40 font-mono">
              {node.code_context}
            </pre>
          </div>
        )}

        {/* Additional Data */}
        {node.data && Object.keys(node.data).length > 0 && !['severity'].some(k => k in node.data!) && (
          <div>
            <div className="text-xs text-vsc-text-muted mb-1">Additional Data</div>
            <pre className="text-xs text-vsc-text bg-vsc-bg p-2 rounded overflow-auto max-h-32 font-mono">
              {JSON.stringify(node.data, null, 2)}
            </pre>
          </div>
        )}
      </div>

      {/* Arrow pointer */}
      <div
        className="absolute left-1/2 bottom-0 transform -translate-x-1/2 translate-y-full"
        style={{
          width: 0,
          height: 0,
          borderLeft: '8px solid transparent',
          borderRight: '8px solid transparent',
          borderTop: '8px solid var(--vsc-border)',
        }}
      />
    </div>
  );
}

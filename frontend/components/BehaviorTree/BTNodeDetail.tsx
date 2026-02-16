'use client';

import React from 'react';
import {
  Send,
  MessageSquare,
  Wrench,
  ArrowLeftRight,
  AlertTriangle,
  XCircle,
  Layers,
  Radio,
  Signal,
  Bot,
  RotateCw,
  Brain,
  Clock,
  DollarSign,
  Hash,
  X,
} from 'lucide-react';
import type { BTNode } from '@/types';

interface BTNodeDetailProps {
  node: BTNode;
  onClose: () => void;
}

export function BTNodeDetail({ node, onClose }: BTNodeDetailProps) {
  const renderContent = () => {
    switch (node.node_type) {
      case 'session':
        return (
          <div className="space-y-3">
            <DetailField label="Session" value={node.id} />
            <DetailField label="Status" value={node.status} />
            {'total_cost' in node.data && (
              <DetailField label="Total Cost" value={`$${(node.data.total_cost as number).toFixed(4)}`} />
            )}
          </div>
        );

      case 'phase':
        return (
          <div className="space-y-3">
            <DetailField label="Phase" value={node.label} />
            <DetailField label="Status" value={node.status} />
          </div>
        );

      case 'wave':
        return (
          <div className="space-y-3">
            <DetailField label="Wave" value={node.label} />
            {!!node.data.focus && <DetailField label="Focus" value={node.data.focus as string} />}
            <DetailField label="Status" value={node.status} />
          </div>
        );

      case 'signal':
        return (
          <div className="space-y-3">
            <DetailField label="Signal" value={node.label} />
            {!!node.data.severity && (
              <div className="flex items-center gap-2">
                <span className="text-xs text-text-muted">Severity:</span>
                <SeverityBadge severity={node.data.severity as string} />
              </div>
            )}
          </div>
        );

      case 'agent':
        return (
          <div className="space-y-3">
            <DetailField label="Agent" value={node.label} />
            {!!node.data.model && <DetailField label="Model" value={node.data.model as string} />}
            {!!node.data.objective && (
              <DetailBlock label="Objective" value={node.data.objective as string} />
            )}
            {'cost_usd' in node.data && (
              <DetailField label="Cost" value={`$${(node.data.cost_usd as number).toFixed(4)}`} />
            )}
            {'duration_ms' in node.data && (
              <DetailField label="Duration" value={formatDuration(node.data.duration_ms as number)} />
            )}
          </div>
        );

      case 'turn':
        return (
          <div className="space-y-3">
            <DetailField label="Turn" value={node.label} />
            <DetailField label="Status" value={node.status} />
          </div>
        );

      case 'llm_request':
        return (
          <div className="space-y-3">
            <DetailField label="Direction" value="Request (prompt)" />
            {!!node.data.model && <DetailField label="Model" value={node.data.model as string} />}
            {!!node.data.prompt && (
              <DetailBlock label="Prompt" value={node.data.prompt as string} />
            )}
          </div>
        );

      case 'llm_response':
        return (
          <div className="space-y-3">
            <DetailField label="Direction" value="Response" />
            {'tokens' in node.data && (
              <DetailField label="Tokens" value={`${node.data.tokens}`} />
            )}
            {!!node.data.text && (
              <DetailBlock label="Response" value={node.data.text as string} />
            )}
          </div>
        );

      case 'llm_thinking':
        return (
          <div className="space-y-3">
            <DetailField label="Type" value="Extended Thinking" />
            {!!node.data.text && (
              <DetailBlock label="Thinking" value={node.data.text as string} />
            )}
          </div>
        );

      case 'tool_call':
        return (
          <div className="space-y-3">
            <DetailField label="Tool" value={node.data.tool_name as string || node.label} />
            {!!node.data.args && (
              <DetailBlock
                label="Arguments"
                value={
                  typeof node.data.args === 'string'
                    ? node.data.args
                    : JSON.stringify(node.data.args, null, 2)
                }
                mono
              />
            )}
          </div>
        );

      case 'tool_result':
        return (
          <div className="space-y-3">
            <DetailField label="Tool Result" value={node.data.is_error ? 'Error' : 'Success'} />
            {!!node.data.result && (
              <DetailBlock label="Result" value={node.data.result as string} mono />
            )}
          </div>
        );

      case 'finding':
        return (
          <div className="space-y-3">
            <DetailField label="Finding" value={node.label} />
            {!!node.data.severity && (
              <div className="flex items-center gap-2">
                <span className="text-xs text-text-muted">Severity:</span>
                <SeverityBadge severity={node.data.severity as string} />
              </div>
            )}
            {!!node.data.file_path && (
              <DetailField label="File" value={node.data.file_path as string} />
            )}
            {!!node.data.description && (
              <DetailBlock label="Description" value={node.data.description as string} />
            )}
          </div>
        );

      case 'error':
        return (
          <div className="space-y-3">
            <DetailField label="Error" value={node.label} />
            {!!node.data.message && (
              <DetailBlock label="Message" value={node.data.message as string} mono />
            )}
          </div>
        );

      default:
        return (
          <div className="space-y-3">
            <DetailField label="Type" value={node.node_type} />
            <DetailField label="Label" value={node.label} />
            {Object.keys(node.data).length > 0 && (
              <DetailBlock label="Data" value={JSON.stringify(node.data, null, 2)} mono />
            )}
          </div>
        );
    }
  };

  return (
    <div className="w-80 border-l border-border-subtle bg-bg-secondary flex flex-col overflow-hidden">
      {/* Header */}
      <div className="h-10 flex items-center px-3 gap-2 border-b border-border-subtle flex-shrink-0">
        <span className="text-xs font-medium text-text-muted uppercase tracking-wider">
          {node.node_type.replace('_', ' ')}
        </span>
        <span className="ml-auto flex items-center gap-1.5 text-[10px] text-text-muted">
          <Clock className="w-3 h-3" />
          {new Date(node.timestamp).toLocaleTimeString()}
        </span>
        <button onClick={onClose} className="btn-icon ml-1">
          <X className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto p-3">
        {renderContent()}
      </div>
    </div>
  );
}

function DetailField({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-baseline gap-2">
      <span className="text-xs text-text-muted flex-shrink-0">{label}:</span>
      <span className="text-sm text-text-primary truncate">{value}</span>
    </div>
  );
}

function DetailBlock({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="space-y-1">
      <span className="text-xs text-text-muted">{label}:</span>
      <div
        className={`p-2 rounded bg-bg-tertiary border border-border-subtle text-xs leading-relaxed max-h-64 overflow-auto whitespace-pre-wrap break-words ${
          mono ? 'font-mono text-[11px]' : 'text-text-secondary'
        }`}
      >
        {value}
      </div>
    </div>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: 'bg-red-500/20 text-red-400 border-red-500/30',
    high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
    medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    info: 'bg-text-muted/20 text-text-muted border-text-muted/30',
  };
  return (
    <span className={`text-[10px] px-1.5 py-0.5 rounded border ${colors[severity] || colors.info}`}>
      {severity.toUpperCase()}
    </span>
  );
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60000).toFixed(1)}m`;
}

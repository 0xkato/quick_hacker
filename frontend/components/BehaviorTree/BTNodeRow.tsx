'use client';

import React from 'react';
import {
  ChevronRight,
  ChevronDown,
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
  Lightbulb,
  Brain,
} from 'lucide-react';
import type { BTNode, BTNodeType } from '@/types';

interface BTNodeRowProps {
  node: BTNode;
  depth: number;
  isExpanded: boolean;
  hasChildren: boolean;
  isSelected: boolean;
  onToggleExpand: () => void;
  onSelect: () => void;
}

const NODE_ICONS: Record<BTNodeType, React.ElementType> = {
  session: Layers,
  phase: Radio,
  wave: RotateCw,
  signal: Signal,
  agent: Bot,
  turn: ArrowLeftRight,
  llm_request: Send,
  llm_response: MessageSquare,
  llm_thinking: Brain,
  tool_call: Wrench,
  tool_result: ArrowLeftRight,
  finding: AlertTriangle,
  error: XCircle,
};

const NODE_COLORS: Record<BTNodeType, string> = {
  session: 'text-text-secondary',
  phase: 'text-purple-400',
  wave: 'text-cyan-400',
  signal: 'text-yellow-400',
  agent: 'text-blue-400',
  turn: 'text-text-muted',
  llm_request: 'text-indigo-400',
  llm_response: 'text-green-400',
  llm_thinking: 'text-purple-300',
  tool_call: 'text-amber-400',
  tool_result: 'text-text-muted',
  finding: 'text-red-400',
  error: 'text-red-500',
};

const STATUS_DOTS: Record<string, string> = {
  pending: 'bg-text-muted',
  active: 'bg-accent animate-pulse',
  completed: 'bg-green-500',
  failed: 'bg-red-500',
};

const TYPE_PREFIXES: Record<BTNodeType, string> = {
  session: '',
  phase: '',
  wave: '',
  signal: '',
  agent: '',
  turn: '',
  llm_request: '> ',
  llm_response: '< ',
  llm_thinking: '~ ',
  tool_call: '\u25B6 ',
  tool_result: '\u25C0 ',
  finding: '! ',
  error: '\u2718 ',
};

export function BTNodeRow({
  node,
  depth,
  isExpanded,
  hasChildren,
  isSelected,
  onToggleExpand,
  onSelect,
}: BTNodeRowProps) {
  const Icon = NODE_ICONS[node.node_type] || Lightbulb;
  const colorClass = NODE_COLORS[node.node_type] || 'text-text-muted';
  const statusDot = STATUS_DOTS[node.status] || STATUS_DOTS.pending;
  const prefix = TYPE_PREFIXES[node.node_type] || '';

  const indent = depth * 20;

  const truncatedLabel = node.label.length > 120
    ? node.label.slice(0, 117) + '...'
    : node.label;

  const tokens = node.data?.tokens as number | undefined;
  const model = node.data?.model as string | undefined;
  const cost = node.data?.cost_usd as number | undefined;
  const duration = node.data?.duration_ms as number | undefined;

  return (
    <div
      className={`flex items-center h-7 cursor-pointer hover:bg-bg-tertiary group text-sm
        ${isSelected ? 'bg-bg-tertiary ring-1 ring-accent/30' : ''}`}
      style={{ paddingLeft: `${indent + 8}px` }}
      onClick={onSelect}
      onDoubleClick={hasChildren ? onToggleExpand : undefined}
    >
      {/* Expand/collapse chevron */}
      <div className="w-4 h-4 flex items-center justify-center flex-shrink-0 mr-0.5">
        {hasChildren ? (
          <button
            onClick={(e) => {
              e.stopPropagation();
              onToggleExpand();
            }}
            className="p-0 hover:text-text-primary text-text-muted"
          >
            {isExpanded ? (
              <ChevronDown className="w-3.5 h-3.5" />
            ) : (
              <ChevronRight className="w-3.5 h-3.5" />
            )}
          </button>
        ) : null}
      </div>

      {/* Status dot */}
      <div className={`w-1.5 h-1.5 rounded-full flex-shrink-0 mr-1.5 ${statusDot}`} />

      {/* Type icon */}
      <Icon className={`w-3.5 h-3.5 flex-shrink-0 mr-1.5 ${colorClass}`} />

      {/* Label */}
      <span className={`truncate ${colorClass}`}>
        <span className="opacity-60">{prefix}</span>
        {truncatedLabel}
      </span>

      {/* Badges */}
      <div className="ml-auto flex items-center gap-1.5 flex-shrink-0 pl-2 opacity-0 group-hover:opacity-100 transition-opacity">
        {model && (
          <span className="text-[10px] px-1 py-0 bg-bg-tertiary border border-border-subtle rounded text-text-muted">
            {model}
          </span>
        )}
        {tokens != null && (
          <span className="text-[10px] px-1 py-0 bg-bg-tertiary border border-border-subtle rounded text-text-muted">
            {tokens > 1000 ? `${(tokens / 1000).toFixed(1)}k` : tokens} tok
          </span>
        )}
        {cost != null && (
          <span className="text-[10px] px-1 py-0 bg-bg-tertiary border border-border-subtle rounded text-green-400/80">
            ${cost < 0.01 ? cost.toFixed(4) : cost.toFixed(3)}
          </span>
        )}
        {duration != null && (
          <span className="text-[10px] px-1 py-0 bg-bg-tertiary border border-border-subtle rounded text-text-muted">
            {duration > 1000 ? `${(duration / 1000).toFixed(1)}s` : `${duration}ms`}
          </span>
        )}
      </div>
    </div>
  );
}

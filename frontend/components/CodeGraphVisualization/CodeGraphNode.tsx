'use client';

import { memo } from 'react';
import { Handle, Position } from 'reactflow';
import {
  Network,
  Code,
  FileText,
  RefreshCw,
  ChevronRight,
  ChevronDown,
  Circle,
} from 'lucide-react';
import clsx from 'clsx';
import type { GraphNode as GraphNodeType } from '@/types';

interface CodeGraphNodeProps {
  data: GraphNodeType & {
    onExpand?: (nodeId: string) => void;
  };
}

const typeIcons: Record<string, React.ReactNode> = {
  entry_point: <Network className="w-4 h-4" />,
  function: <Code className="w-4 h-4" />,
  external: <FileText className="w-4 h-4 text-vsc-text-muted" />,
  cycle: <RefreshCw className="w-4 h-4 text-sev-medium" />,
};

const relevanceColors: Record<string, string> = {
  high: 'border-sev-critical bg-sev-critical/10',
  medium: 'border-sev-medium bg-sev-medium/10',
  low: 'border-vsc-border bg-vsc-sidebar',
  skip: 'border-vsc-border-subtle bg-vsc-bg opacity-60',
};

const relevanceBadgeColors: Record<string, string> = {
  high: 'bg-sev-critical text-white',
  medium: 'bg-sev-medium text-black',
  low: 'bg-vsc-border text-vsc-text-muted',
  skip: 'bg-vsc-border-subtle text-vsc-text-muted',
};

function CodeGraphNodeComponent({ data }: CodeGraphNodeProps) {
  const canExpand = data.type !== 'external' && data.type !== 'cycle' && !data.children_loaded;
  const isExpanded = data.is_expanded;

  const handleExpandClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (canExpand && data.onExpand) {
      data.onExpand(data.id);
    }
  };

  return (
    <div
      className={clsx(
        'px-3 py-2 rounded-lg border-2 min-w-[180px] max-w-[280px]',
        'transition-all duration-150 hover:shadow-lg cursor-pointer',
        relevanceColors[data.relevance_level],
        data.visited && 'ring-2 ring-vsc-accent ring-offset-1 ring-offset-vsc-bg'
      )}
    >
      <Handle type="target" position={Position.Top} className="!bg-vsc-border" />

      {/* Header row */}
      <div className="flex items-center gap-2">
        <span className="text-vsc-text-muted">
          {typeIcons[data.type] || <Code className="w-4 h-4" />}
        </span>

        <span className="text-sm font-medium truncate flex-1 text-vsc-text">
          {data.label}
        </span>

        {/* Relevance badge */}
        <span
          className={clsx(
            'text-xs px-1.5 py-0.5 rounded font-medium uppercase',
            relevanceBadgeColors[data.relevance_level]
          )}
        >
          {data.relevance_level === 'high' ? 'HIGH' :
           data.relevance_level === 'medium' ? 'MED' :
           data.relevance_level === 'low' ? 'LOW' : 'SKIP'}
        </span>

        {/* Expand button */}
        {(canExpand || isExpanded) && (
          <button
            onClick={handleExpandClick}
            className="p-0.5 hover:bg-vsc-border rounded"
            disabled={!canExpand}
          >
            {isExpanded ? (
              <ChevronDown className="w-4 h-4 text-vsc-text-muted" />
            ) : (
              <ChevronRight className="w-4 h-4 text-vsc-text-muted" />
            )}
          </button>
        )}
      </div>

      {/* File path */}
      {data.file_path && (
        <div className="text-xs text-vsc-text-muted truncate mt-1">
          {data.file_path}
          {data.line_number && `:${data.line_number}`}
        </div>
      )}

      {/* Footer row */}
      <div className="flex items-center justify-between mt-1.5">
        {/* Visited indicator */}
        <div className="flex items-center gap-1">
          {data.visited ? (
            <>
              <Circle className="w-2 h-2 fill-vsc-accent text-vsc-accent" />
              <span className="text-xs text-vsc-text-muted">Viewed</span>
            </>
          ) : (
            <span className="text-xs text-vsc-text-muted">
              {data.child_count > 0 && `(${data.child_count} calls)`}
            </span>
          )}
        </div>

        {/* Duration if visited */}
        {data.visit_duration_ms && (
          <span className="text-xs text-vsc-text-muted">
            {data.visit_duration_ms}ms
          </span>
        )}
      </div>

      <Handle type="source" position={Position.Bottom} className="!bg-vsc-border" />
    </div>
  );
}

export const CodeGraphNode = memo(CodeGraphNodeComponent);

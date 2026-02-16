'use client';

import React, { useCallback, useEffect, useRef } from 'react';
import type { BTNode } from '@/types';
import { BTNodeRow } from './BTNodeRow';

interface BehaviorTreeProps {
  nodes: Map<string, BTNode>;
  childIndex: Map<string, string[]>;
  rootId: string | null;
  expandedNodes: Set<string>;
  selectedNodeId: string | null;
  isLoading: boolean;
  onToggleExpand: (nodeId: string) => void;
  onSelectNode: (nodeId: string | null) => void;
  getChildren: (parentId: string) => BTNode[];
}

export function BehaviorTree({
  nodes,
  childIndex,
  rootId,
  expandedNodes,
  selectedNodeId,
  isLoading,
  onToggleExpand,
  onSelectNode,
  getChildren,
}: BehaviorTreeProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const wasAtBottomRef = useRef(true);
  const prevNodeCountRef = useRef(0);

  // Auto-scroll: if user was at the bottom, keep them at the bottom when new nodes arrive
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;

    const currentCount = nodes.size;
    if (currentCount > prevNodeCountRef.current && wasAtBottomRef.current) {
      // New nodes added and user was at bottom — scroll to bottom
      requestAnimationFrame(() => {
        el.scrollTop = el.scrollHeight;
      });
    }
    prevNodeCountRef.current = currentCount;
  }, [nodes.size]);

  const handleScroll = useCallback(() => {
    const el = containerRef.current;
    if (!el) return;
    // Consider "at bottom" if within 50px of the bottom
    wasAtBottomRef.current = el.scrollHeight - el.scrollTop - el.clientHeight < 50;
  }, []);

  // Recursively render tree
  const renderNode = useCallback(
    (nodeId: string, depth: number): React.ReactNode[] => {
      const node = nodes.get(nodeId);
      if (!node) return [];

      const children = getChildren(nodeId);
      const hasChildren = children.length > 0 || node.children_count > 0;
      const isExpanded = expandedNodes.has(nodeId);

      const rows: React.ReactNode[] = [
        <BTNodeRow
          key={nodeId}
          node={node}
          depth={depth}
          isExpanded={isExpanded}
          hasChildren={hasChildren}
          isSelected={selectedNodeId === nodeId}
          onToggleExpand={() => onToggleExpand(nodeId)}
          onSelect={() => onSelectNode(nodeId)}
        />,
      ];

      if (isExpanded && children.length > 0) {
        for (const child of children) {
          rows.push(...renderNode(child.id, depth + 1));
        }
      }

      return rows;
    },
    [nodes, getChildren, expandedNodes, selectedNodeId, onToggleExpand, onSelectNode]
  );

  if (isLoading) {
    return (
      <div className="flex-1 flex items-center justify-center text-text-muted">
        <div className="text-center">
          <div className="w-5 h-5 border-2 border-accent border-t-transparent rounded-full animate-spin mx-auto mb-2" />
          <p className="text-sm">Loading behavior tree...</p>
        </div>
      </div>
    );
  }

  if (!rootId || nodes.size === 0) {
    return (
      <div className="flex-1 flex items-center justify-center text-text-muted">
        <div className="text-center">
          <p className="text-sm">No behavior tree data yet.</p>
          <p className="text-xs mt-1">Start an agent to see its LLM behavior in real-time.</p>
        </div>
      </div>
    );
  }

  return (
    <div
      ref={containerRef}
      className="flex-1 overflow-auto font-mono"
      onScroll={handleScroll}
    >
      {renderNode(rootId, 0)}
    </div>
  );
}

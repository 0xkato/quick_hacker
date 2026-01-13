/**
 * TreeLayout Component
 *
 * Renders investigation spans as an interactive tree/DAG using React Flow.
 * Supports collapse/expand, outcome-based coloring, and event/artifact counts.
 */

import React, { useMemo, useState, useCallback } from 'react';
import ReactFlow, {
  Node,
  Edge as ReactFlowEdge,
  Background,
  Controls,
  MiniMap,
} from 'reactflow';
import 'reactflow/dist/style.css';

import HypothesisNode from './nodes/HypothesisNode';
import { Span, Edge, HypothesisNodeData } from './types';

interface TreeLayoutProps {
  spans: Record<string, Span>;
  edges: Edge[];
}

// Node types mapping for React Flow
const nodeTypes = {
  hypothesis: HypothesisNode,
};

/**
 * TreeLayout Component
 *
 * Converts span/edge data into React Flow nodes and edges with:
 * - Automatic tree layout
 * - Collapse/expand functionality
 * - Outcome-based visual styling
 * - Event and artifact count display
 */
const TreeLayout: React.FC<TreeLayoutProps> = ({ spans, edges }) => {
  // Track collapsed span IDs
  const [collapsedSpans, setCollapsedSpans] = useState<Set<string>>(new Set());

  // Toggle collapse state for a span
  const toggleCollapse = useCallback((spanId: string) => {
    setCollapsedSpans((prev) => {
      const next = new Set(prev);
      if (next.has(spanId)) {
        next.delete(spanId);
      } else {
        next.add(spanId);
      }
      return next;
    });
  }, []);

  // Check if a span should be hidden (parent is collapsed)
  const isSpanHidden = useCallback(
    (span: Span): boolean => {
      let current = span;
      while (current.parent_span_id) {
        if (collapsedSpans.has(current.parent_span_id)) {
          return true;
        }
        const parent = spans[current.parent_span_id];
        if (!parent) break;
        current = parent;
      }
      return false;
    },
    [spans, collapsedSpans]
  );

  // Convert spans to React Flow nodes
  const nodes = useMemo<Node<HypothesisNodeData>[]>(() => {
    return Object.values(spans)
      .filter((span) => !isSpanHidden(span))
      .map((span, index) => {
        const isCollapsed = collapsedSpans.has(span.span_id);

        return {
          id: span.span_id,
          type: 'hypothesis',
          position: { x: 0, y: index * 150 }, // Placeholder position, will be auto-laid out
          data: {
            span,
            isCollapsed,
            onToggleCollapse: () => toggleCollapse(span.span_id),
          },
        };
      });
  }, [spans, collapsedSpans, isSpanHidden, toggleCollapse]);

  // Convert edges to React Flow edges
  const reactFlowEdges = useMemo<ReactFlowEdge[]>(() => {
    return edges
      .filter((edge) => !edge.hidden)
      .filter((edge) => {
        // Filter out edges to/from hidden spans
        const sourceHidden = spans[edge.source] && isSpanHidden(spans[edge.source]);
        const targetHidden = spans[edge.target] && isSpanHidden(spans[edge.target]);
        return !sourceHidden && !targetHidden;
      })
      .map((edge) => {
        // Map edge type to React Flow edge type
        const type = edge.edge_type === 'evidence_link' ? 'smoothstep' : 'default';

        // Apply dashed style if specified
        const style = edge.style === 'dashed' ? { strokeDasharray: '5,5' } : undefined;

        return {
          id: edge.id,
          source: edge.source,
          target: edge.target,
          type,
          label: edge.label,
          style,
        };
      });
  }, [edges, spans, isSpanHidden]);

  // Nodes and edges are computed from props, no need for separate state

  // Empty state
  if (Object.keys(spans).length === 0) {
    return (
      <div className="flex items-center justify-center h-full w-full bg-gray-50">
        <div className="text-gray-500 text-lg">
          No investigation data available
        </div>
      </div>
    );
  }

  return (
    <div className="h-full w-full">
      <ReactFlow
        nodes={nodes}
        edges={reactFlowEdges}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.2 }}
        minZoom={0.1}
        maxZoom={2}
      >
        <Background />
        <Controls />
        <MiniMap
          nodeStrokeWidth={3}
          zoomable
          pannable
        />
      </ReactFlow>
    </div>
  );
};

export default TreeLayout;

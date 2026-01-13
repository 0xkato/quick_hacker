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
import ErrorBoundary from './ErrorBoundary';
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
 * - Simple vertical layout (advanced layout planned for future tasks)
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

  // Compute set of all hidden span IDs (descendants of collapsed spans)
  // This is O(n) once, instead of O(n²) on every render
  const hiddenSpanIds = useMemo(() => {
    const hidden = new Set<string>();

    // Helper to recursively mark all descendants as hidden
    const markDescendantsHidden = (spanId: string) => {
      Object.values(spans).forEach((span) => {
        if (span.parent_span_id === spanId) {
          hidden.add(span.span_id);
          markDescendantsHidden(span.span_id); // Recursively mark children
        }
      });
    };

    // Mark descendants of all collapsed spans
    collapsedSpans.forEach((collapsedSpanId) => {
      markDescendantsHidden(collapsedSpanId);
    });

    return hidden;
  }, [spans, collapsedSpans]);

  // Convert spans to React Flow nodes with tree layout
  const nodes = useMemo<Node<HypothesisNodeData>[]>(() => {
    // Calculate depth (level) for each span
    const depthMap = new Map<string, number>();
    const calculateDepth = (spanId: string): number => {
      if (depthMap.has(spanId)) {
        return depthMap.get(spanId)!;
      }
      const span = spans[spanId];
      if (!span) return 0;

      const depth = span.parent_span_id ? calculateDepth(span.parent_span_id) + 1 : 0;
      depthMap.set(spanId, depth);
      return depth;
    };

    // Calculate depth for all visible spans
    const visibleSpans = Object.values(spans)
      .filter((span) => !hiddenSpanIds.has(span.span_id));

    visibleSpans.forEach((span) => calculateDepth(span.span_id));

    // Count siblings at each depth level for Y positioning
    const siblingsAtDepth = new Map<number, number>();

    return visibleSpans.map((span) => {
      const isCollapsed = collapsedSpans.has(span.span_id);
      const depth = depthMap.get(span.span_id) || 0;

      // Track how many nodes we've placed at this depth
      const siblingIndex = siblingsAtDepth.get(depth) || 0;
      siblingsAtDepth.set(depth, siblingIndex + 1);

      return {
        id: span.span_id,
        type: 'hypothesis',
        position: {
          x: depth * 300,        // Horizontal spacing based on tree depth
          y: siblingIndex * 150  // Vertical spacing based on sibling position
        },
        data: {
          span,
          isCollapsed,
          onToggleCollapse: () => toggleCollapse(span.span_id),
        },
      };
    });
  }, [spans, collapsedSpans, hiddenSpanIds, toggleCollapse]);

  // Convert edges to React Flow edges
  const reactFlowEdges = useMemo<ReactFlowEdge[]>(() => {
    return edges
      .filter((edge) => !edge.hidden)
      .filter((edge) => {
        // Filter out edges to/from hidden spans using O(1) lookup
        const sourceHidden = hiddenSpanIds.has(edge.source);
        const targetHidden = hiddenSpanIds.has(edge.target);
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
  }, [edges, hiddenSpanIds]);

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
      <ErrorBoundary>
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
      </ErrorBoundary>
    </div>
  );
};

export default TreeLayout;

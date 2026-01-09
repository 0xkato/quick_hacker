'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import ReactFlow, {
  Node,
  Edge,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  MarkerType,
} from 'reactflow';
import dagre from 'dagre';
import 'reactflow/dist/style.css';
import { Filter, Expand, Minimize2, RotateCcw } from 'lucide-react';
import clsx from 'clsx';

import { CodeGraphNode } from './CodeGraphNode';
import type { CodeGraph, GraphNode, GraphEdge, RelevanceLevel, GraphStats } from '@/types';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

interface CodeGraphVisualizationProps {
  agentId: string | null;
  repoPath?: string;
}

const nodeTypes = {
  graphNode: CodeGraphNode,
};

// Layout using dagre
function getLayoutedElements(
  nodes: Node[],
  edges: Edge[],
  direction: 'TB' | 'LR' = 'TB'
) {
  const dagreGraph = new dagre.graphlib.Graph();
  dagreGraph.setDefaultEdgeLabel(() => ({}));
  dagreGraph.setGraph({ rankdir: direction, nodesep: 50, ranksep: 80 });

  nodes.forEach((node) => {
    dagreGraph.setNode(node.id, { width: 200, height: 80 });
  });

  edges.forEach((edge) => {
    dagreGraph.setEdge(edge.source, edge.target);
  });

  dagre.layout(dagreGraph);

  const layoutedNodes = nodes.map((node) => {
    const nodeWithPosition = dagreGraph.node(node.id);
    return {
      ...node,
      position: {
        x: nodeWithPosition.x - 100,
        y: nodeWithPosition.y - 40,
      },
    };
  });

  return { nodes: layoutedNodes, edges };
}

export function CodeGraphVisualization({ agentId, repoPath }: CodeGraphVisualizationProps) {
  const [graph, setGraph] = useState<CodeGraph | null>(null);
  const [stats, setStats] = useState<GraphStats | null>(null);
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [filters, setFilters] = useState<Set<RelevanceLevel>>(
    new Set<RelevanceLevel>(['high', 'medium', 'low'])
  );
  const [isLoading, setIsLoading] = useState(false);

  // Fetch graph data
  const fetchGraph = useCallback(async () => {
    if (!agentId) return;

    try {
      const response = await fetch(`${API_BASE}/api/agents/${agentId}/graph`);
      if (response.ok) {
        const data = await response.json();
        setGraph(data);
      }
    } catch (error) {
      console.error('Failed to fetch graph:', error);
    }
  }, [agentId]);

  // Fetch stats
  const fetchStats = useCallback(async () => {
    if (!agentId) return;

    try {
      const response = await fetch(`${API_BASE}/api/agents/${agentId}/graph/stats`);
      if (response.ok) {
        const data = await response.json();
        setStats(data);
      }
    } catch (error) {
      console.error('Failed to fetch stats:', error);
    }
  }, [agentId]);

  // Initialize graph
  const initializeGraph = useCallback(async () => {
    if (!agentId || !repoPath) return;

    setIsLoading(true);
    try {
      const response = await fetch(`${API_BASE}/api/agents/${agentId}/graph/initialize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repo_path: repoPath }),
      });
      if (response.ok) {
        const data = await response.json();
        setGraph(data);
      }
    } catch (error) {
      console.error('Failed to initialize graph:', error);
    } finally {
      setIsLoading(false);
    }
  }, [agentId, repoPath]);

  // Expand node
  const handleExpandNode = useCallback(async (nodeId: string) => {
    if (!agentId) return;

    try {
      const response = await fetch(
        `${API_BASE}/api/agents/${agentId}/graph/expand/${nodeId}`,
        { method: 'POST' }
      );
      if (response.ok) {
        fetchGraph();
      }
    } catch (error) {
      console.error('Failed to expand node:', error);
    }
  }, [agentId, fetchGraph]);

  // Convert graph data to ReactFlow format
  useEffect(() => {
    if (!graph) return;

    const filteredNodes = graph.nodes.filter(
      (n) => filters.has(n.relevance_level)
    );

    const nodeIds = new Set(filteredNodes.map((n) => n.id));
    const filteredEdges = graph.edges.filter(
      (e) => nodeIds.has(e.source) && nodeIds.has(e.target)
    );

    const rfNodes: Node[] = filteredNodes.map((node) => ({
      id: node.id,
      type: 'graphNode',
      position: { x: 0, y: 0 },
      data: { ...node, onExpand: handleExpandNode },
    }));

    const rfEdges: Edge[] = filteredEdges.map((edge) => ({
      id: edge.id,
      source: edge.source,
      target: edge.target,
      label: edge.label,
      markerEnd: { type: MarkerType.ArrowClosed },
      style: { stroke: '#404040' },
    }));

    const { nodes: layoutedNodes, edges: layoutedEdges } = getLayoutedElements(
      rfNodes,
      rfEdges
    );

    setNodes(layoutedNodes);
    setEdges(layoutedEdges);
  }, [graph, filters, handleExpandNode, setNodes, setEdges]);

  // Initial fetch
  useEffect(() => {
    fetchGraph();
    fetchStats();

    // Poll for updates
    const interval = setInterval(() => {
      fetchGraph();
      fetchStats();
    }, 5000);

    return () => clearInterval(interval);
  }, [fetchGraph, fetchStats]);

  // Filter toggle
  const toggleFilter = (level: RelevanceLevel) => {
    setFilters((prev) => {
      const next = new Set(prev);
      if (next.has(level)) {
        next.delete(level);
      } else {
        next.add(level);
      }
      return next;
    });
  };

  if (!agentId) {
    return (
      <div className="flex items-center justify-center h-full text-vsc-text-muted">
        Select an agent to view code graph
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      {/* Controls bar */}
      <div className="flex items-center justify-between p-2 border-b border-vsc-border bg-vsc-sidebar">
        {/* Filters */}
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-vsc-text-muted" />
          {(['high', 'medium', 'low', 'skip'] as RelevanceLevel[]).map((level) => (
            <button
              key={level}
              onClick={() => toggleFilter(level)}
              className={clsx(
                'px-2 py-1 text-xs rounded font-medium uppercase transition-colors',
                filters.has(level)
                  ? level === 'high'
                    ? 'bg-sev-critical text-white'
                    : level === 'medium'
                    ? 'bg-sev-medium text-black'
                    : level === 'low'
                    ? 'bg-vsc-border text-vsc-text'
                    : 'bg-vsc-border-subtle text-vsc-text-muted'
                  : 'bg-vsc-bg text-vsc-text-muted border border-vsc-border'
              )}
            >
              {level}
            </button>
          ))}
        </div>

        {/* Stats */}
        {stats && (
          <div className="flex items-center gap-4 text-xs text-vsc-text-muted">
            <span>Entry points: {stats.entry_points}</span>
            <span>Visited: {stats.visited}/{stats.total_nodes}</span>
            <span className="text-sev-critical">
              High unvisited: {stats.high_relevance_unvisited}
            </span>
          </div>
        )}

        {/* Actions */}
        <div className="flex items-center gap-2">
          {repoPath && (
            <button
              onClick={initializeGraph}
              disabled={isLoading}
              className="px-2 py-1 text-xs bg-vsc-accent text-white rounded hover:bg-vsc-accent/80 disabled:opacity-50"
            >
              {isLoading ? 'Loading...' : 'Refresh'}
            </button>
          )}
        </div>
      </div>

      {/* Graph */}
      <div className="flex-1">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          nodeTypes={nodeTypes}
          fitView
          minZoom={0.1}
          maxZoom={2}
        >
          <Background color="#333" gap={16} />
          <Controls />
          <MiniMap
            nodeColor={(node) => {
              const data = node.data as GraphNode;
              if (data.visited) return '#007acc';
              switch (data.relevance_level) {
                case 'high': return '#e51400';
                case 'medium': return '#e5a000';
                case 'low': return '#404040';
                default: return '#252525';
              }
            }}
          />
        </ReactFlow>
      </div>
    </div>
  );
}

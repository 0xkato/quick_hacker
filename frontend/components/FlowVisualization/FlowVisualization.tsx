'use client';

import { useEffect, useMemo, useState, useCallback, useRef } from 'react';
import ReactFlow, {
  Node,
  Edge,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  MarkerType,
  Position,
  NodeMouseHandler,
} from 'reactflow';
import 'reactflow/dist/style.css';
import {
  Search,
  FileText,
  AlertTriangle,
  Code,
  MessageSquare,
  Loader2,
  CheckCircle,
  XCircle,
  Brain,
  Scan,
} from 'lucide-react';
import clsx from 'clsx';
import { FlowNodePopover } from './FlowNodePopover';

// Types matching backend
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

interface FlowEdge {
  id: string;
  source: string;
  target: string;
  label?: string;
}

interface InvestigationFlow {
  session_id: string;
  nodes: FlowNode[];
  edges: FlowEdge[];
  current_node_id?: string;
}

interface FlowVisualizationProps {
  agentId: string | null;
  flow: InvestigationFlow | null;
}

// Get border color based on confidence score
function getConfidenceBorderColor(confidence?: number): string {
  if (confidence === undefined) return '';
  if (confidence >= 0.8) return 'ring-2 ring-vsc-success ring-offset-1 ring-offset-vsc-bg';
  if (confidence >= 0.6) return 'ring-2 ring-sev-medium ring-offset-1 ring-offset-vsc-bg';
  if (confidence >= 0.4) return 'ring-2 ring-sev-high ring-offset-1 ring-offset-vsc-bg';
  return 'ring-2 ring-sev-critical ring-offset-1 ring-offset-vsc-bg';
}

// Custom node component
function FlowNodeComponent({ data }: { data: FlowNode }) {
  const statusColors = {
    pending: 'border-vsc-border bg-vsc-sidebar',
    running: 'border-vsc-accent bg-vsc-accent/20 animate-pulse',
    completed: 'border-vsc-success bg-vsc-success/20',
    failed: 'border-sev-critical bg-sev-critical/20',
  };

  const typeIcons: Record<string, React.ReactNode> = {
    user_input: <MessageSquare className="w-4 h-4" />,
    tool_call: <Code className="w-4 h-4" />,
    tool_result: <FileText className="w-4 h-4" />,
    analysis: <Brain className="w-4 h-4" />,
    finding: <AlertTriangle className="w-4 h-4 text-sev-high" />,
    code_read: <FileText className="w-4 h-4" />,
    search: <Search className="w-4 h-4" />,
    scan: <Scan className="w-4 h-4" />,
  };

  const statusIcons = {
    pending: null,
    running: <Loader2 className="w-3 h-3 animate-spin text-vsc-accent" />,
    completed: <CheckCircle className="w-3 h-3 text-vsc-success" />,
    failed: <XCircle className="w-3 h-3 text-sev-critical" />,
  };

  const confidenceRing = getConfidenceBorderColor(data.confidence_score);

  return (
    <div
      className={clsx(
        'px-3 py-2 rounded-lg border-2 min-w-[120px] max-w-[200px] bg-vsc-bg cursor-pointer',
        'transition-all duration-150 hover:scale-105 hover:shadow-lg',
        statusColors[data.status],
        confidenceRing
      )}
      title={data.llm_reasoning ? `${data.label}\n\nClick for details` : data.label}
    >
      <div className="flex items-center gap-2">
        <span className="text-vsc-text-muted">
          {typeIcons[data.type] || <Code className="w-4 h-4" />}
        </span>
        <span className="text-vsc-xs font-medium truncate flex-1 text-vsc-text">
          {data.label}
        </span>
        {statusIcons[data.status]}
      </div>

      <div className="flex items-center justify-between mt-1">
        {data.duration_ms !== undefined && (
          <div className="text-vsc-xs text-vsc-text-muted">
            {data.duration_ms}ms
          </div>
        )}
        {data.confidence_score !== undefined && (
          <div className="text-vsc-xs text-vsc-text-muted">
            {(data.confidence_score * 100).toFixed(0)}%
          </div>
        )}
      </div>

      {data.data && data.type === 'finding' && (
        <div className="mt-1">
          <span
            className={clsx(
              'text-vsc-xs px-1.5 py-0.5 rounded uppercase font-medium',
              data.data.severity === 'critical' && 'bg-sev-critical/30 text-sev-critical',
              data.data.severity === 'high' && 'bg-sev-high/30 text-sev-high',
              data.data.severity === 'medium' && 'bg-sev-medium/30 text-sev-medium',
              data.data.severity === 'low' && 'bg-sev-low/30 text-sev-low'
            )}
          >
            {(data.data.severity as string) || 'unknown'}
          </span>
        </div>
      )}

      {/* Indicator that node has reasoning/context */}
      {(data.llm_reasoning || data.code_context || data.tool_result_summary) && (
        <div className="absolute -top-1 -right-1 w-2 h-2 rounded-full bg-vsc-accent" />
      )}
    </div>
  );
}

const nodeTypes = {
  flowNode: FlowNodeComponent,
};

export function FlowVisualization({ agentId, flow }: FlowVisualizationProps) {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [selectedNode, setSelectedNode] = useState<FlowNode | null>(null);
  const [popoverPosition, setPopoverPosition] = useState({ x: 0, y: 0 });
  const containerRef = useRef<HTMLDivElement>(null);

  // Handle node click to show popover
  const onNodeClick: NodeMouseHandler = useCallback((event, node) => {
    const nodeData = node.data as FlowNode;

    // Get position relative to container
    if (containerRef.current) {
      const rect = containerRef.current.getBoundingClientRect();
      const x = event.clientX - rect.left;
      const y = event.clientY - rect.top;
      setPopoverPosition({ x, y });
    }

    setSelectedNode(nodeData);
  }, []);

  // Close popover
  const closePopover = useCallback(() => {
    setSelectedNode(null);
  }, []);

  // Close popover when clicking outside
  const onPaneClick = useCallback(() => {
    setSelectedNode(null);
  }, []);

  // Convert investigation flow to ReactFlow nodes/edges
  useEffect(() => {
    if (!flow || flow.nodes.length === 0) {
      setNodes([]);
      setEdges([]);
      return;
    }

    // Layout nodes in a tree structure
    const nodePositions = calculateLayout(flow.nodes, flow.edges);

    const rfNodes: Node[] = flow.nodes.map((node, index) => ({
      id: node.id,
      type: 'flowNode',
      position: nodePositions.get(node.id) || { x: 100, y: index * 80 },
      data: node,
      sourcePosition: Position.Right,
      targetPosition: Position.Left,
    }));

    const rfEdges: Edge[] = flow.edges.map((edge) => ({
      id: edge.id,
      source: edge.source,
      target: edge.target,
      label: edge.label,
      animated: isNodeRunning(flow.nodes, edge.target),
      markerEnd: {
        type: MarkerType.ArrowClosed,
        width: 15,
        height: 15,
      },
      style: {
        stroke: isNodeRunning(flow.nodes, edge.target) ? '#007acc' : '#404040',
      },
    }));

    setNodes(rfNodes);
    setEdges(rfEdges);
  }, [flow, setNodes, setEdges]);

  // Stats
  const stats = useMemo(() => {
    if (!flow) return null;
    return {
      total: flow.nodes.length,
      completed: flow.nodes.filter((n) => n.status === 'completed').length,
      findings: flow.nodes.filter((n) => n.type === 'finding').length,
      searches: flow.nodes.filter((n) => n.type === 'search').length,
      reads: flow.nodes.filter((n) => n.type === 'code_read').length,
    };
  }, [flow]);

  if (!agentId) {
    return (
      <div className="h-full flex items-center justify-center text-vsc-text-muted">
        <div className="text-center">
          <Brain className="w-12 h-12 mx-auto mb-3 opacity-50" />
          <p>Select an agent to view investigation flow</p>
        </div>
      </div>
    );
  }

  if (!flow || flow.nodes.length === 0) {
    return (
      <div className="h-full flex items-center justify-center text-vsc-text-muted">
        <div className="text-center">
          <Loader2 className="w-12 h-12 mx-auto mb-3 opacity-50" />
          <p>Waiting for investigation to start...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full w-full relative" ref={containerRef}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={onNodeClick}
        onPaneClick={onPaneClick}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.2 }}
        minZoom={0.1}
        maxZoom={2}
        defaultViewport={{ x: 0, y: 0, zoom: 0.8 }}
      >
        <Background color="#333" gap={20} />
        <Controls className="!bg-vsc-sidebar !border-vsc-border" />
        <MiniMap
          nodeColor={(node) => {
            const data = node.data as FlowNode;
            // Color by confidence if available
            if (data.confidence_score !== undefined) {
              if (data.confidence_score >= 0.8) return '#4caf50';
              if (data.confidence_score >= 0.6) return '#f9a825';
              if (data.confidence_score >= 0.4) return '#ff9800';
              return '#f44336';
            }
            if (data.status === 'running') return '#007acc';
            if (data.status === 'completed') return '#4caf50';
            if (data.status === 'failed') return '#f44336';
            if (data.type === 'finding') return '#ff9800';
            return '#555';
          }}
          style={{ background: '#1e1e1e' }}
        />
      </ReactFlow>

      {/* Node detail popover */}
      {selectedNode && (
        <FlowNodePopover
          node={selectedNode}
          position={popoverPosition}
          onClose={closePopover}
        />
      )}

      {/* Legend */}
      <div className="absolute bottom-4 left-4 bg-vsc-sidebar border border-vsc-border rounded-lg p-3 text-vsc-xs">
        <div className="font-medium mb-2 text-vsc-text-muted">Node Types</div>
        <div className="space-y-1.5 text-vsc-text">
          <div className="flex items-center gap-2">
            <MessageSquare className="w-3 h-3 text-vsc-text-muted" />
            <span>User Input</span>
          </div>
          <div className="flex items-center gap-2">
            <Search className="w-3 h-3 text-vsc-text-muted" />
            <span>Search</span>
          </div>
          <div className="flex items-center gap-2">
            <FileText className="w-3 h-3 text-vsc-text-muted" />
            <span>Read File</span>
          </div>
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-3 h-3 text-sev-high" />
            <span>Finding</span>
          </div>
        </div>

        <div className="border-t border-vsc-border mt-2 pt-2">
          <div className="font-medium mb-2 text-vsc-text-muted">Confidence</div>
          <div className="space-y-1 text-vsc-text">
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-vsc-success" />
              <span>High (80%+)</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-sev-medium" />
              <span>Medium (60%+)</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-sev-high" />
              <span>Low (40%+)</span>
            </div>
          </div>
        </div>

        <div className="border-t border-vsc-border mt-2 pt-2 text-vsc-text-muted">
          <span className="italic">Click nodes for details</span>
        </div>
      </div>

      {/* Stats */}
      {stats && (
        <div className="absolute top-4 right-4 bg-vsc-sidebar border border-vsc-border rounded-lg p-3 text-vsc-xs">
          <div className="font-medium mb-2 text-vsc-text-muted">Statistics</div>
          <div className="space-y-1 text-vsc-text">
            <div className="flex justify-between gap-4">
              <span className="text-vsc-text-muted">Nodes:</span>
              <span>{stats.total}</span>
            </div>
            <div className="flex justify-between gap-4">
              <span className="text-vsc-text-muted">Searches:</span>
              <span>{stats.searches}</span>
            </div>
            <div className="flex justify-between gap-4">
              <span className="text-vsc-text-muted">Files read:</span>
              <span>{stats.reads}</span>
            </div>
            <div className="flex justify-between gap-4">
              <span className="text-vsc-text-muted">Findings:</span>
              <span className="text-sev-high">{stats.findings}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// Helper: Check if a node is currently running
function isNodeRunning(nodes: FlowNode[], nodeId: string): boolean {
  const node = nodes.find((n) => n.id === nodeId);
  return node?.status === 'running';
}

// Helper: Calculate node positions in a hierarchical layout
function calculateLayout(
  nodes: FlowNode[],
  edges: FlowEdge[]
): Map<string, { x: number; y: number }> {
  const positions = new Map<string, { x: number; y: number }>();

  if (nodes.length === 0) return positions;

  // Build adjacency list
  const children = new Map<string, string[]>();
  const parents = new Map<string, string[]>();

  for (const edge of edges) {
    if (!children.has(edge.source)) children.set(edge.source, []);
    children.get(edge.source)!.push(edge.target);

    if (!parents.has(edge.target)) parents.set(edge.target, []);
    parents.get(edge.target)!.push(edge.source);
  }

  // Find root nodes (no parents)
  const roots = nodes.filter((n) => !parents.has(n.id) || parents.get(n.id)!.length === 0);

  // BFS to assign levels
  const levels = new Map<string, number>();
  const queue = roots.map((r) => ({ id: r.id, level: 0 }));
  const visited = new Set<string>();

  while (queue.length > 0) {
    const { id, level } = queue.shift()!;
    if (visited.has(id)) continue;
    visited.add(id);

    levels.set(id, Math.max(levels.get(id) || 0, level));

    const childIds = children.get(id) || [];
    for (const childId of childIds) {
      queue.push({ id: childId, level: level + 1 });
    }
  }

  // Group nodes by level
  const byLevel = new Map<number, string[]>();
  Array.from(levels.entries()).forEach(([id, level]) => {
    if (!byLevel.has(level)) byLevel.set(level, []);
    byLevel.get(level)!.push(id);
  });

  // Position nodes
  const levelWidth = 220;
  const nodeHeight = 80;

  Array.from(byLevel.entries()).forEach(([level, nodeIds]) => {
    const levelY = (nodeIds.length - 1) * nodeHeight * -0.5;

    nodeIds.forEach((id: string, index: number) => {
      positions.set(id, {
        x: level * levelWidth,
        y: levelY + index * nodeHeight,
      });
    });
  });

  return positions;
}

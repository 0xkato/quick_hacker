'use client';

import { useEffect, useMemo, useState, useCallback, useRef } from 'react';
import ReactFlow, {
  Node,
  Edge,
  Background,
  Controls,
  MiniMap,
  Handle,
  useNodesState,
  useEdgesState,
  MarkerType,
  Position,
  NodeMouseHandler,
  ReactFlowInstance,
} from 'reactflow';
import 'reactflow/dist/style.css';
import {
  Search,
  FileText,
  AlertTriangle,
  Folder,
  Code,
  MessageSquare,
  Loader2,
  CheckCircle,
  X,
  XCircle,
  Brain,
  Scan,
  Network,
  ArrowRight,
  ExternalLink,
  Shield,
  Filter,
} from 'lucide-react';
import clsx from 'clsx';
import { FlowNodePopover } from './FlowNodePopover';
import { CollapseButton } from './CollapseButton';
import { SearchToolbar } from './SearchToolbar';
import { parseSearchQuery, matchesQuery } from './searchUtils';
import { computeStructuredTraceRiskLevels, getStructuredTraceRiskRingClass } from './structuredTraceRisk';
import { indexNodesByType, expandAncestors } from './flowNavigator';
import { buildFlowContextPack } from './flowContextPack';

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
  kind?: string;
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
  emptySelectionText?: string;
  emptyFlowText?: string;
  onQueueInvestigation?: (nodeId: string) => Promise<void> | void;
  onOpenFile?: (filePath: string) => void;
  findings?: any[];
  onOpenChat?: (payload: { contextPack: unknown; filePath?: string; seedText?: string }) => void;
  variant?: 'investigation' | 'calltree' | 'structured';
}

interface CollapsedState {
  [nodeId: string]: boolean;
}

// Get border color based on confidence score
function getConfidenceBorderColor(confidence?: number): string {
  if (confidence === undefined) return '';
  if (confidence >= 0.8) return 'ring-2 ring-vsc-success ring-offset-1 ring-offset-vsc-bg';
  if (confidence >= 0.6) return 'ring-2 ring-sev-medium ring-offset-1 ring-offset-vsc-bg';
  if (confidence >= 0.4) return 'ring-2 ring-sev-high ring-offset-1 ring-offset-vsc-bg';
  return 'ring-2 ring-sev-critical ring-offset-1 ring-offset-vsc-bg';
}

// Get border color for triage gateway based on dominant disposition
function getTriageGatewayBorderColor(byDisposition?: Record<string, number>): string {
  if (!byDisposition || typeof byDisposition !== 'object') return '';

  // Priority order: valid_security_issue/bug > misconfiguration > hardening > by_design > speculative
  const dispositionPriority: Record<string, number> = {
    valid_security_issue: 5,
    bug: 5,
    misconfiguration: 4,
    hardening: 3,
    by_design: 2,
    speculative: 1,
  };

  const dispositionColors: Record<string, string> = {
    valid_security_issue: 'ring-2 ring-sev-critical ring-offset-1 ring-offset-vsc-bg',
    bug: 'ring-2 ring-sev-high ring-offset-1 ring-offset-vsc-bg',
    misconfiguration: 'ring-2 ring-sev-medium ring-offset-1 ring-offset-vsc-bg',
    hardening: 'ring-2 ring-blue-500 ring-offset-1 ring-offset-vsc-bg',
    by_design: 'ring-2 ring-vsc-text-muted ring-offset-1 ring-offset-vsc-bg',
    speculative: 'ring-2 ring-vsc-border ring-offset-1 ring-offset-vsc-bg',
  };

  // Find dominant disposition by priority
  let dominantDisposition = '';
  let highestPriority = 0;
  let highestCount = 0;

  for (const [disposition, count] of Object.entries(byDisposition)) {
    if (typeof count !== 'number' || count <= 0) continue;

    const normalizedDisposition = disposition.toLowerCase();
    const priority = dispositionPriority[normalizedDisposition] || 0;
    if (priority > highestPriority || (priority === highestPriority && count > highestCount)) {
      dominantDisposition = normalizedDisposition;
      highestPriority = priority;
      highestCount = count;
    }
  }

  return dispositionColors[dominantDisposition] || '';
}

// Extended data type for node component
interface FlowNodeData extends FlowNode {
  isCollapsed?: boolean;
  descendantCount?: number;
  onToggleCollapse?: (nodeId: string) => void;
  viewVariant?: 'investigation' | 'calltree' | 'structured';
  structured_risk?: 'none' | 'sink' | 'finding';
}

// Custom node component
function FlowNodeComponent({ data }: { data: FlowNodeData }) {
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
    entry_point: <Network className="w-4 h-4" />,
    dangerous_sink: <AlertTriangle className="w-4 h-4 text-sev-medium" />,
    investigation: <Brain className="w-4 h-4" />,
    structured_root: <Network className="w-4 h-4 text-vsc-accent" />,
    global_recon: <Scan className="w-4 h-4 text-vsc-text-muted" />,
    folder: <Folder className="w-4 h-4 text-vsc-text-muted" />,
    steps: <Code className="w-4 h-4 text-vsc-text-muted" />,
    sinks_group: <AlertTriangle className="w-4 h-4 text-sev-medium" />,
    // NEW architectural nodes
    file: <FileText className="w-4 h-4 text-blue-400" />,
    function: <Code className="w-4 h-4 text-purple-400" />,
    call: <ArrowRight className="w-4 h-4 text-green-400" />,
    external: <ExternalLink className="w-4 h-4 text-gray-400" />,
    auth_boundary: <Shield className="w-4 h-4 text-yellow-400" />,
    cycle: <AlertTriangle className="w-4 h-4 text-sev-medium" />,
    triage_gateway: <Filter className="w-4 h-4 text-vsc-accent" />,
  };

  const statusIcons = {
    pending: null,
    running: <Loader2 className="w-3 h-3 animate-spin text-vsc-accent" />,
    completed: <CheckCircle className="w-3 h-3 text-vsc-success" />,
    failed: <XCircle className="w-3 h-3 text-sev-critical" />,
  };

  // Apply appropriate border color based on node type
  let borderRing = '';
  const isTouchedEntrypoint = data.type === 'entry_point' && Boolean((data.data as any)?.touched);
  if (data.viewVariant === 'structured') {
    borderRing = getStructuredTraceRiskRingClass({
      risk: data.structured_risk || 'none',
      isTouchedEntrypoint,
    });
  } else {
    if (data.type === 'triage_gateway' && data.data?.by_disposition) {
      borderRing = getTriageGatewayBorderColor(data.data.by_disposition as Record<string, number>);
    } else if (data.confidence_score !== undefined) {
      borderRing = getConfidenceBorderColor(data.confidence_score);
    }
    if (isTouchedEntrypoint && !borderRing) {
      borderRing = 'ring-2 ring-vsc-accent ring-offset-1 ring-offset-vsc-bg';
    }
  }

  return (
    <div
      className={clsx(
        'relative',
        'px-3 py-2 rounded-lg border-2 min-w-[120px] max-w-[200px] bg-vsc-bg cursor-pointer',
        'transition-all duration-150 hover:scale-105 hover:shadow-lg',
        statusColors[data.status],
        borderRing
      )}
      title={data.llm_reasoning ? `${data.label}\n\nClick for details` : data.label}
    >
      <Handle type="target" position={Position.Left} isConnectable={false} style={{ opacity: 0 }} />
      <Handle type="source" position={Position.Right} isConnectable={false} style={{ opacity: 0 }} />

      {/* Collapse button */}
      {data.onToggleCollapse && (
        <CollapseButton
          nodeId={data.id}
          isCollapsed={data.isCollapsed || false}
          descendantCount={data.descendantCount || 0}
          onToggle={data.onToggleCollapse}
        />
      )}
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

      {data.data && data.type === 'triage_gateway' && (
        <div className="mt-2 space-y-1 text-vsc-xs">
          <div className="flex justify-between">
            <span className="text-vsc-text-muted">Reportable:</span>
            <span className="text-vsc-success font-medium">
              {typeof data.data.reportable_count === 'number' ? data.data.reportable_count : 0}
            </span>
          </div>
          <div className="flex justify-between">
            <span className="text-vsc-text-muted">Filtered:</span>
            <span className="text-vsc-text-muted">
              {typeof data.data.triaged_count === 'number' && typeof data.data.reportable_count === 'number'
                ? data.data.triaged_count - data.data.reportable_count
                : 0}
            </span>
          </div>
          {typeof data.data.by_disposition === 'object' && data.data.by_disposition !== null && (
            <div className="text-vsc-xs text-vsc-text-muted pt-1 border-t border-vsc-border">
              {Object.entries(data.data.by_disposition as Record<string, number>)
                .filter(([_, count]) => count > 0)
                .sort(([_, a], [__, b]) => (b as number) - (a as number))
                .slice(0, 3)
                .map(([disposition, count]) => (
                  <div key={disposition} className="flex justify-between">
                    <span className="truncate">{disposition}:</span>
                    <span>{count as number}</span>
                  </div>
                ))}
            </div>
          )}
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

/**
 * Interactive flow tree visualization with search, collapse, and filtering.
 *
 * Features:
 * - Collapsible subtrees (click chevron on nodes)
 * - Search with type filters (type:file, function:*, etc.)
 * - Keyboard shortcuts (Cmd+F, Cmd+G, Escape)
 * - Real-time updates via WebSocket/polling
 *
 * @param agentId - Agent identifier for this flow
 * @param flow - Investigation flow data from backend
 * @param onQueueInvestigation - Callback when user queues a node for investigation
 * @param variant - Display mode: 'investigation' or 'calltree'
 * @param emptySelectionText - Text shown when no agent is selected
 * @param emptyFlowText - Text shown when flow has no nodes
 */
export function FlowVisualization({
  agentId,
  flow,
  emptySelectionText,
  emptyFlowText,
  onQueueInvestigation,
  onOpenFile,
  findings,
  onOpenChat,
  variant = 'investigation',
}: FlowVisualizationProps) {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [reactFlowInstance, setReactFlowInstance] = useState<ReactFlowInstance | null>(null);
  const [selectedNode, setSelectedNode] = useState<FlowNode | null>(null);
  const [popoverPosition, setPopoverPosition] = useState({ x: 0, y: 0 });
  const containerRef = useRef<HTMLDivElement>(null);
  const [isQueueing, setIsQueueing] = useState(false);
  const [queueError, setQueueError] = useState<string | null>(null);

  // Collapsed nodes state
  const [collapsedNodes, setCollapsedNodes] = useState<CollapsedState>({});

  // Search state
  const [searchQuery, setSearchQuery] = useState('');
  const [searchMatches, setSearchMatches] = useState<string[]>([]);
  const [currentMatchIndex, setCurrentMatchIndex] = useState(0);

  // Structured Trace quick-jump navigator (via clickable legend).
  type NavigatorKind = 'finding' | 'dangerous_sink' | 'entry_point';
  const [navigatorKind, setNavigatorKind] = useState<NavigatorKind | null>(null);
  const [navigatorSelectedId, setNavigatorSelectedId] = useState<string | null>(null);

  // Toggle collapse for a node
  const toggleCollapse = useCallback((nodeId: string) => {
    setCollapsedNodes(prev => ({
      ...prev,
      [nodeId]: !prev[nodeId]
    }));
  }, []);

  // Structured Trace: collapse "steps" nodes by default as they appear.
  useEffect(() => {
    if (variant !== 'structured' || !flow) return;
    setCollapsedNodes(prev => {
      let changed = false;
      const next = { ...prev };
      for (const node of flow.nodes || []) {
        if (node.type === 'steps' && next[node.id] === undefined) {
          next[node.id] = true;
          changed = true;
        }
      }
      return changed ? next : prev;
    });
  }, [variant, flow]);

  // Get all descendants of a node
  const getDescendants = useCallback((nodeId: string, edges: Edge[]): string[] => {
    const descendants: string[] = [];
    const queue = [nodeId];
    const visited = new Set<string>();

    while (queue.length > 0) {
      const current = queue.shift()!;
      if (visited.has(current)) continue;
      visited.add(current);

      // Find children
      const children = edges
        .filter(e => e.source === current)
        .map(e => e.target);

      descendants.push(...children);
      queue.push(...children);
    }

    return descendants;
  }, []);

  /**
   * Gets all ancestor nodes by following parent edges.
   * Assumes tree structure (each node has at most one parent).
   * @param nodeId - The starting node ID
   * @param edges - The graph edges
   * @returns Array of ancestor node IDs in order from immediate parent to root
   */
  const getAncestors = useCallback((nodeId: string, edges: Edge[]): string[] => {
    const ancestors: string[] = [];
    let current = nodeId;

    while (current) {
      const parent = edges.find(e => e.target === current);
      if (!parent) break;
      ancestors.push(parent.source);
      current = parent.source;
    }

    return ancestors;
  }, []);

  // Search handlers
  const handleSearch = useCallback((query: string) => {
    setSearchQuery(query);
    setCurrentMatchIndex(0);

    if (!query.trim()) {
      setSearchMatches([]);
      setCurrentMatchIndex(0);  // Reset index when clearing
      return;
    }

    const parsedQuery = parseSearchQuery(query);
    const matches = new Set<string>();

    // Find matching nodes
    nodes.forEach(node => {
      if (matchesQuery(node, parsedQuery)) {
        matches.add(node.id);
        // Include ancestors to keep path visible
        const ancestors = getAncestors(node.id, edges);
        ancestors.forEach(id => matches.add(id));
      }
    });

    setSearchMatches(Array.from(matches));
  }, [nodes, edges, getAncestors]);

  const handleNavigate = useCallback((direction: 'up' | 'down') => {
    setCurrentMatchIndex(prev => {
      if (direction === 'up') {
        return prev > 0 ? prev - 1 : searchMatches.length - 1;
      } else {
        return prev < searchMatches.length - 1 ? prev + 1 : 0;
      }
    });
  }, [searchMatches.length]);

  // Count descendants of a node
  const getDescendantCount = useCallback((nodeId: string, edges: Edge[]): number => {
    return getDescendants(nodeId, edges).length;
  }, [getDescendants]);

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

  const handleQueueInvestigation = useCallback(async () => {
    if (!selectedNode || !onQueueInvestigation) return;
    setIsQueueing(true);
    setQueueError(null);
    try {
      await onQueueInvestigation(selectedNode.id);
    } catch (err) {
      setQueueError(err instanceof Error ? err.message : 'Failed to queue investigation');
    } finally {
      setIsQueueing(false);
    }
  }, [onQueueInvestigation, selectedNode]);

  const handleOpenChatForNode = useCallback(
    (node: FlowNode) => {
      if (!onOpenChat) return;
      const contextPack = buildFlowContextPack({
        flow: flow || { session_id: agentId || '', nodes: [], edges: [] },
        nodeId: node.id,
        findings: Array.isArray(findings) ? findings : [],
      });

      const data = (node.data as any) || {};
      let filePath: string | undefined;
      if (typeof data.file_path === 'string' && data.file_path.trim()) {
        filePath = data.file_path.trim();
      } else if (typeof data.file === 'string' && data.file.trim()) {
        filePath = data.file.trim();
      } else if (typeof (contextPack as any)?.finding?.file_path === 'string') {
        filePath = String((contextPack as any).finding.file_path);
      }

      const seedText =
        'Validate this node: confirm reachability + dataflow, and suggest the next best checks to prove or disprove impact.';

      onOpenChat({ contextPack, filePath, seedText });
    },
    [agentId, findings, flow, onOpenChat]
  );

  const focusNode = useCallback(
    (nodeId: string) => {
      if (!nodeId) return;
      setCollapsedNodes((prev) =>
        expandAncestors(prev, nodeId, edges as unknown as { source: string; target: string }[])
      );
      setNavigatorSelectedId(nodeId);

      // Best-effort viewport centering (after expand).
      requestAnimationFrame(() => {
        if (!reactFlowInstance) return;
        const target = nodes.find((n) => n.id === nodeId);
        if (!target) return;
        const x = target.position.x + (target.width ?? 160) / 2;
        const y = target.position.y + (target.height ?? 60) / 2;
        reactFlowInstance.setCenter(x, y, { zoom: 1.1, duration: 300 });
      });
    },
    [edges, nodes, reactFlowInstance]
  );

  // Convert investigation flow to ReactFlow nodes/edges
  useEffect(() => {
    if (!flow || flow.nodes.length === 0) {
      setNodes([]);
      setEdges([]);
      return;
    }

    const isStructuralNode = (node: FlowNode) => (node.data as any)?.trace_kind === 'structural';
    const isStructuredEdge = (edge: FlowEdge) => (edge.kind || 'legacy') === 'structured';

    let nodesForView: FlowNode[] = [];
    let edgesForView: FlowEdge[] = [];

    if (variant === 'structured') {
      edgesForView = flow.edges.filter(isStructuredEdge);
      const nodeIds = new Set(edgesForView.flatMap((e) => [e.source, e.target]));
      nodesForView = flow.nodes.filter((n) => nodeIds.has(n.id));
    } else {
      nodesForView = flow.nodes.filter((n) => !isStructuralNode(n));
      const allowed = new Set(nodesForView.map((n) => n.id));
      edgesForView = flow.edges
        .filter((e) => !isStructuredEdge(e))
        .filter((e) => allowed.has(e.source) && allowed.has(e.target));
    }

    // Layout nodes in a tree structure
    const nodePositions = calculateLayout(nodesForView, edgesForView);

    const structuredRiskLevels =
      variant === 'structured'
        ? computeStructuredTraceRiskLevels(nodesForView as any, edgesForView as any)
        : null;

    const rfNodes: Node[] = nodesForView.map((node, index) => {
      const descendantCount = getDescendantCount(node.id, edgesForView as unknown as Edge[]);
      const isCollapsed = collapsedNodes[node.id] || false;

      return {
        id: node.id,
        type: 'flowNode',
        position: nodePositions.get(node.id) || { x: 100, y: index * 80 },
        data: {
          ...node,
          viewVariant: variant,
          structured_risk:
            variant === 'structured'
              ? (structuredRiskLevels?.[node.id] as FlowNodeData['structured_risk'])
              : undefined,
          isCollapsed,
          descendantCount,
          onToggleCollapse: toggleCollapse,
        } as FlowNodeData,
        sourcePosition: Position.Right,
        targetPosition: Position.Left,
      };
    });

    const rfEdges: Edge[] = edgesForView.map((edge) => ({
      id: edge.id,
      source: edge.source,
      target: edge.target,
      label: edge.label,
      animated: isNodeRunning(nodesForView, edge.target),
      markerEnd: {
        type: MarkerType.ArrowClosed,
        width: 15,
        height: 15,
      },
      style: {
        stroke: isNodeRunning(nodesForView, edge.target) ? '#007acc' : '#404040',
      },
    }));

    setNodes(rfNodes);
    setEdges(rfEdges);
  }, [flow, variant, setNodes, setEdges, collapsedNodes, getDescendantCount, toggleCollapse]);

  const navigableFlowNodes = useMemo(
    () => nodes.map((n) => n.data as unknown as FlowNode),
    [nodes]
  );
  const findingItems = useMemo(
    () => indexNodesByType(navigableFlowNodes as any, 'finding'),
    [navigableFlowNodes]
  );
  const sinkItems = useMemo(
    () => indexNodesByType(navigableFlowNodes as any, 'dangerous_sink'),
    [navigableFlowNodes]
  );
  const entrypointItems = useMemo(
    () => indexNodesByType(navigableFlowNodes as any, 'entry_point'),
    [navigableFlowNodes]
  );

  const navigatorItems = useMemo(() => {
    if (navigatorKind === 'finding') return findingItems;
    if (navigatorKind === 'dangerous_sink') return sinkItems;
    if (navigatorKind === 'entry_point') return entrypointItems;
    return [];
  }, [navigatorKind, findingItems, sinkItems, entrypointItems]);

  const navigatorTitle = useMemo(() => {
    if (navigatorKind === 'finding') return `Findings (${findingItems.length})`;
    if (navigatorKind === 'dangerous_sink') return `Sinks (${sinkItems.length})`;
    if (navigatorKind === 'entry_point') return `Entrypoints (${entrypointItems.length})`;
    return '';
  }, [navigatorKind, findingItems.length, sinkItems.length, entrypointItems.length]);

  // Calculate which nodes to show based on collapse state
  const visibleNodes = useMemo(() => {
    const hidden = new Set<string>();
    const matchSet = new Set(searchMatches);
    const hasSearch = searchQuery.trim().length > 0;

    // Mark descendants of collapsed nodes as hidden
    Object.entries(collapsedNodes).forEach(([nodeId, isCollapsed]) => {
      if (isCollapsed) {
        const descendants = getDescendants(nodeId, edges);
        descendants.forEach(id => hidden.add(id));
      }
    });

    // Update nodes with visibility, collapse data, and search highlighting
    return nodes.map(node => {
      const isMatch = matchSet.has(node.id);
      const isVisible = !hasSearch || isMatch;

      return {
        ...node,
        hidden: hidden.has(node.id),
        style: {
          ...node.style,
          opacity: isVisible ? 1 : 0.3,  // Dim non-matching nodes
          borderColor: isMatch && hasSearch ? '#facc15' : undefined,  // Yellow for matches
          borderWidth: isMatch && hasSearch ? '2px' : '1px',
        },
      };
    });
  }, [nodes, edges, collapsedNodes, searchQuery, searchMatches, getDescendants]);

  // Keyboard shortcuts for search
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Cmd/Ctrl + F: Focus search
      if ((e.metaKey || e.ctrlKey) && e.key === 'f') {
        e.preventDefault();
        // Focus search input
        const searchInput = document.getElementById('flow-search-input') as HTMLInputElement;
        if (searchInput) {
          searchInput.focus();
          searchInput.select();
        }
      }

      // Cmd/Ctrl + G: Next match
      if ((e.metaKey || e.ctrlKey) && e.key === 'g') {
        e.preventDefault();
        if (searchMatches.length > 0) {
          handleNavigate(e.shiftKey ? 'up' : 'down');
        }
      }

      // Escape: Clear search
      if (e.key === 'Escape' && (searchQuery || searchMatches.length > 0)) {
        e.preventDefault();
        setSearchQuery('');
        setSearchMatches([]);
        setCurrentMatchIndex(0);  // Reset index when clearing
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [searchQuery, searchMatches, handleNavigate]);

  // Stats
  type InvestigationStats = {
    kind: 'investigation';
    total: number;
    searches: number;
    reads: number;
    findings: number;
  };
  type CallTreeStats = {
    kind: 'calltree';
    total: number;
    functions: number;
    external: number;
    cycles: number;
    files: number;
  };

  const stats = useMemo<InvestigationStats | CallTreeStats | null>(() => {
    if (!flow) return null;

    if (variant === 'calltree') {
      const files = new Set<string>();
      for (const node of flow.nodes) {
        const file = node.data?.file;
        if (typeof file === 'string' && file.trim()) files.add(file.trim());
      }

      return {
        kind: 'calltree',
        total: flow.nodes.length,
        functions: flow.nodes.filter((n) => n.type === 'function').length,
        external: flow.nodes.filter((n) => n.type === 'external').length,
        cycles: flow.nodes.filter((n) => n.type === 'cycle').length,
        files: files.size,
      };
    }

    return {
      kind: 'investigation',
      total: flow.nodes.length,
      findings: flow.nodes.filter((n) => n.type === 'finding').length,
      searches: flow.nodes.filter((n) => n.type === 'search').length,
      reads: flow.nodes.filter((n) => n.type === 'code_read').length,
    };
  }, [flow, variant]);

  if (!agentId) {
    return (
      <div className="h-full flex items-center justify-center text-vsc-text-muted">
        <div className="text-center">
          <Brain className="w-12 h-12 mx-auto mb-3 opacity-50" />
          <p>{emptySelectionText || 'Select an agent to view investigation flow'}</p>
        </div>
      </div>
    );
  }

  if (!flow || flow.nodes.length === 0) {
    return (
      <div className="h-full flex items-center justify-center text-vsc-text-muted">
        <div className="text-center">
          <Loader2 className="w-12 h-12 mx-auto mb-3 opacity-50" />
          <p>{emptyFlowText || 'Waiting for investigation to start...'}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full w-full relative" ref={containerRef}>
      <SearchToolbar
        onSearch={handleSearch}
        resultCount={searchMatches.length}
        currentIndex={currentMatchIndex}
        onNavigate={handleNavigate}
      />
      <ReactFlow
        nodes={visibleNodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={onNodeClick}
        onPaneClick={onPaneClick}
        nodeTypes={nodeTypes}
        onInit={setReactFlowInstance}
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
            if (variant === 'structured') {
              const risk = (data as any)?.structured_risk;
              if (risk === 'finding') return '#f44336';
              if (risk === 'sink') return '#f9a825';
              return '#4caf50';
            }
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
          onQueueInvestigation={onQueueInvestigation ? handleQueueInvestigation : undefined}
          isQueueing={isQueueing}
          queueError={queueError}
          onOpenFile={onOpenFile}
          onOpenChat={onOpenChat ? handleOpenChatForNode : undefined}
        />
      )}

      {/* Legend + Structured Trace quick-jump */}
      <div className="absolute bottom-4 left-4 space-y-2">
        {variant === 'structured' && navigatorKind && (
          <div className="bg-vsc-sidebar border border-vsc-border rounded-lg p-3 text-vsc-xs w-[320px] shadow-xl">
            <div className="flex items-center justify-between mb-2">
              <div className="font-medium text-vsc-text-muted">{navigatorTitle}</div>
              <button
                type="button"
                onClick={() => setNavigatorKind(null)}
                className="p-1 rounded hover:bg-vsc-hover text-vsc-text-muted hover:text-vsc-text"
                aria-label="Close navigator"
                title="Close"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
            {navigatorItems.length === 0 ? (
              <div className="text-vsc-text-muted">No nodes.</div>
            ) : (
              <div className="max-h-56 overflow-auto space-y-1">
                {navigatorItems.map((item: any) => {
                  const severity = typeof item.severity === 'string' ? item.severity : undefined;
                  return (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => focusNode(String(item.id))}
                      className={clsx(
                        'w-full text-left px-2 py-1 rounded border border-transparent hover:border-vsc-border-subtle hover:bg-vsc-bg/60',
                        navigatorSelectedId === item.id && 'bg-vsc-bg/60 border-vsc-border-subtle'
                      )}
                      title={item.label}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <div className="text-vsc-text truncate">{item.label}</div>
                        {navigatorKind === 'finding' && (
                          <span
                            className={clsx(
                              'text-[10px] px-1.5 py-0.5 rounded uppercase font-medium flex-shrink-0',
                              severity === 'critical' && 'bg-sev-critical/30 text-sev-critical',
                              severity === 'high' && 'bg-sev-high/30 text-sev-high',
                              severity === 'medium' && 'bg-sev-medium/30 text-sev-medium',
                              severity === 'low' && 'bg-sev-low/30 text-sev-low',
                              (!severity || severity === 'unknown') && 'bg-vsc-border/50 text-vsc-text-muted'
                            )}
                          >
                            {severity || 'unknown'}
                          </span>
                        )}
                      </div>
                      {typeof item.file_path === 'string' && item.file_path.trim() && (
                        <div className="text-vsc-text-muted truncate mt-0.5">
                          {item.file_path}
                          {typeof item.line_number === 'number' && item.line_number > 0
                            ? `:${item.line_number}`
                            : ''}
                        </div>
                      )}
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        )}

        <div className="bg-vsc-sidebar border border-vsc-border rounded-lg p-3 text-vsc-xs">
          <div className="font-medium mb-2 text-vsc-text-muted">Node Types</div>
          {variant === 'calltree' ? (
            <div className="space-y-1.5 text-vsc-text">
              <div className="flex items-center gap-2">
                <Network className="w-3 h-3 text-vsc-text-muted" />
                <span>Entry Point / Sink</span>
              </div>
              <div className="flex items-center gap-2">
                <FileText className="w-3 h-3 text-blue-400" />
                <span>File Explored</span>
              </div>
              <div className="flex items-center gap-2">
                <Code className="w-3 h-3 text-purple-400" />
                <span>Function Analyzed</span>
              </div>
              <div className="flex items-center gap-2">
                <ArrowRight className="w-3 h-3 text-green-400" />
                <span>Function Call</span>
              </div>
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-3 h-3 text-sev-high" />
                <span>Finding</span>
              </div>
            </div>
          ) : variant === 'structured' ? (
            <div className="space-y-1.5 text-vsc-text">
              <div className="flex items-center gap-2">
                <Network className="w-3 h-3 text-vsc-accent" />
                <span>Structured Trace</span>
              </div>
              <div className="flex items-center gap-2">
                <Scan className="w-3 h-3 text-vsc-text-muted" />
                <span>Global Recon</span>
              </div>
              <button
                type="button"
                onClick={() => setNavigatorKind((prev) => (prev === 'entry_point' ? null : 'entry_point'))}
                className="w-full flex items-center justify-between gap-2 px-1 py-0.5 rounded hover:bg-vsc-hover"
                title="Jump to entrypoints"
              >
                <span className="flex items-center gap-2 min-w-0">
                  <Network className="w-3 h-3 text-vsc-text-muted" />
                  <span className="truncate">Entrypoint (touched = highlighted)</span>
                </span>
                <span className="text-vsc-text-muted tabular-nums">{entrypointItems.length}</span>
              </button>
              <div className="flex items-center gap-2">
                <Folder className="w-3 h-3 text-vsc-text-muted" />
                <span>Folder</span>
              </div>
              <div className="flex items-center gap-2">
                <FileText className="w-3 h-3 text-blue-400" />
                <span>File</span>
              </div>
              <div className="flex items-center gap-2">
                <Code className="w-3 h-3 text-purple-400" />
                <span>Function</span>
              </div>
              <div className="flex items-center gap-2">
                <Code className="w-3 h-3 text-vsc-text-muted" />
                <span>Steps (collapsed)</span>
              </div>
              <button
                type="button"
                onClick={() =>
                  setNavigatorKind((prev) => (prev === 'dangerous_sink' ? null : 'dangerous_sink'))
                }
                className="w-full flex items-center justify-between gap-2 px-1 py-0.5 rounded hover:bg-vsc-hover"
                title="Jump to sinks"
              >
                <span className="flex items-center gap-2 min-w-0">
                  <AlertTriangle className="w-3 h-3 text-sev-medium" />
                  <span className="truncate">Dangerous Sink</span>
                </span>
                <span className="text-vsc-text-muted tabular-nums">{sinkItems.length}</span>
              </button>
              <button
                type="button"
                onClick={() => setNavigatorKind((prev) => (prev === 'finding' ? null : 'finding'))}
                className="w-full flex items-center justify-between gap-2 px-1 py-0.5 rounded hover:bg-vsc-hover"
                title="Jump to findings"
              >
                <span className="flex items-center gap-2 min-w-0">
                  <AlertTriangle className="w-3 h-3 text-sev-high" />
                  <span className="truncate">Finding</span>
                </span>
                <span className="text-vsc-text-muted tabular-nums">{findingItems.length}</span>
              </button>
            </div>
          ) : (
            <div className="space-y-1.5 text-vsc-text">
              <div className="flex items-center gap-2">
                <Network className="w-3 h-3 text-vsc-text-muted" />
                <span>Entry Point</span>
              </div>
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-3 h-3 text-sev-medium" />
                <span>Dangerous Sink</span>
              </div>
              <div className="flex items-center gap-2">
                <Code className="w-3 h-3 text-vsc-text-muted" />
                <span>Function</span>
              </div>
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
          )}

          {variant === 'investigation' &&
            flow.nodes.some((n) => n.confidence_score !== undefined) && (
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
            )}

          <div className="border-t border-vsc-border mt-2 pt-2 text-vsc-text-muted">
            <span className="italic">Click nodes for details</span>
          </div>
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
            {stats.kind === 'calltree' ? (
              <>
                <div className="flex justify-between gap-4">
                  <span className="text-vsc-text-muted">Functions:</span>
                  <span>{stats.functions}</span>
                </div>
                <div className="flex justify-between gap-4">
                  <span className="text-vsc-text-muted">External calls:</span>
                  <span>{stats.external}</span>
                </div>
                <div className="flex justify-between gap-4">
                  <span className="text-vsc-text-muted">Cycles:</span>
                  <span>{stats.cycles}</span>
                </div>
                <div className="flex justify-between gap-4">
                  <span className="text-vsc-text-muted">Files referenced:</span>
                  <span>{stats.files}</span>
                </div>
              </>
            ) : (
              <>
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
              </>
            )}
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

/**
 * Calculate positions for multiple investigation trees with no overlap.
 */
function calculateLayout(
  nodes: FlowNode[],
  edges: FlowEdge[]
): Map<string, { x: number; y: number }> {
  const positions = new Map<string, { x: number; y: number }>();

  if (nodes.length === 0) return positions;

  // Build adjacency lists
  const children = new Map<string, string[]>();
  const parents = new Map<string, string[]>();

  for (const edge of edges) {
    if (!children.has(edge.source)) children.set(edge.source, []);
    children.get(edge.source)!.push(edge.target);

    if (!parents.has(edge.target)) parents.set(edge.target, []);
    parents.get(edge.target)!.push(edge.source);
  }

  // Find root nodes (each starts an investigation tree)
  const roots = nodes.filter(n =>
    !parents.has(n.id) || parents.get(n.id)!.length === 0
  );

  // Layout constants
  const TREE_HORIZONTAL_SPACING = 400;
  const NODE_WIDTH = 220;
  const NODE_HEIGHT = 100;

  let currentXOffset = 0;

  // Layout each tree separately
  for (const root of roots) {
    const visitedWidth = new Set<string>();
    const subtreeWidth = calculateSubtreeWidth(root.id, children, NODE_WIDTH, visitedWidth);

    const visitedLayout = new Set<string>();
    layoutSubtree(
      root.id,
      children,
      positions,
      currentXOffset,
      0,
      NODE_WIDTH,
      NODE_HEIGHT,
      visitedLayout
    );

    currentXOffset += subtreeWidth + TREE_HORIZONTAL_SPACING;
  }

  return positions;
}

/**
 * Calculate width needed for a subtree.
 */
function calculateSubtreeWidth(
  nodeId: string,
  children: Map<string, string[]>,
  nodeWidth: number,
  visited: Set<string>
): number {
  // Prevent infinite recursion on cycles
  if (visited.has(nodeId)) return nodeWidth;
  visited.add(nodeId);

  const childIds = children.get(nodeId) || [];

  if (childIds.length === 0) {
    return nodeWidth;
  }

  // Subtree width is sum of all children's subtree widths
  const childrenWidth = childIds.reduce((sum, childId) => {
    return sum + calculateSubtreeWidth(childId, children, nodeWidth, visited);
  }, 0);

  return Math.max(nodeWidth, childrenWidth);
}

/**
 * Recursively layout a subtree.
 */
function layoutSubtree(
  nodeId: string,
  children: Map<string, string[]>,
  positions: Map<string, { x: number; y: number }>,
  x: number,
  depth: number,
  nodeWidth: number,
  nodeHeight: number,
  visited: Set<string>
): number {
  // Prevent infinite recursion on cycles
  if (visited.has(nodeId)) return nodeWidth;
  visited.add(nodeId);

  const childIds = children.get(nodeId) || [];

  if (childIds.length === 0) {
    // Leaf node
    positions.set(nodeId, { x, y: depth * nodeHeight });
    return nodeWidth;
  }

  // Layout children left-to-right
  let currentChildX = x;
  const childCenters: number[] = [];

  for (const childId of childIds) {
    const childWidth = layoutSubtree(
      childId,
      children,
      positions,
      currentChildX,
      depth + 1,
      nodeWidth,
      nodeHeight,
      visited
    );

    // Store center position of this child
    childCenters.push(currentChildX + childWidth / 2);
    currentChildX += childWidth;
  }

  // Position parent centered over children
  const leftmost = childCenters[0];
  const rightmost = childCenters[childCenters.length - 1];
  const centerX = (leftmost + rightmost) / 2;

  positions.set(nodeId, { x: centerX, y: depth * nodeHeight });

  // Return total width used by this subtree
  return currentChildX - x;
}

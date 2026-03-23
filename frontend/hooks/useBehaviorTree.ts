'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import type { BTNode, BTNodeUpdate } from '@/types';

interface UseBehaviorTreeOptions {
  selectedAgentId: string | null;
  isAuthenticated: boolean;
}

interface UseBehaviorTreeResult {
  nodes: Map<string, BTNode>;
  childIndex: Map<string, string[]>;
  rootId: string | null;
  expandedNodes: Set<string>;
  selectedNodeId: string | null;
  isLoading: boolean;
  addNode: (node: BTNode) => void;
  addNodes: (nodes: BTNode[]) => void;
  updateNode: (update: BTNodeUpdate) => void;
  loadFullTree: (agentId: string) => Promise<void>;
  getChildren: (parentId: string) => BTNode[];
  toggleExpand: (nodeId: string) => void;
  expandAll: () => void;
  collapseAll: () => void;
  selectNode: (nodeId: string | null) => void;
}

export function useBehaviorTree({ selectedAgentId, isAuthenticated }: UseBehaviorTreeOptions): UseBehaviorTreeResult {
  const [nodes, setNodes] = useState<Map<string, BTNode>>(new Map());
  const [childIndex, setChildIndex] = useState<Map<string, string[]>>(new Map());
  const [rootId, setRootId] = useState<string | null>(null);
  const [expandedNodes, setExpandedNodes] = useState<Set<string>>(new Set());
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  // Use refs for stable callback identities in WS handlers
  const nodesRef = useRef(nodes);
  const childIndexRef = useRef(childIndex);
  nodesRef.current = nodes;
  childIndexRef.current = childIndex;

  const addNode = useCallback((node: BTNode) => {
    setNodes(prev => {
      const next = new Map(prev);
      next.set(node.id, node);
      // Update parent children_count
      if (node.parent_id) {
        const parent = next.get(node.parent_id);
        if (parent) {
          next.set(parent.id, { ...parent, children_count: parent.children_count + 1 });
        }
      }
      return next;
    });
    setChildIndex(prev => {
      const next = new Map(prev);
      const parentKey = node.parent_id || '__root__';
      const children = next.get(parentKey) || [];
      if (!children.includes(node.id)) {
        next.set(parentKey, [...children, node.id]);
      }
      return next;
    });
    // Set root if session node
    if (node.node_type === 'session') {
      setRootId(node.id);
      setExpandedNodes(prev => new Set(prev).add(node.id));
    }
    // Auto-expand phase and wave nodes
    if (node.node_type === 'phase' || node.node_type === 'wave' || node.node_type === 'signal') {
      setExpandedNodes(prev => new Set(prev).add(node.id));
    }
  }, []);

  const addNodes = useCallback((newNodes: BTNode[]) => {
    setNodes(prev => {
      const next = new Map(prev);
      for (const node of newNodes) {
        next.set(node.id, node);
      }
      return next;
    });
    setChildIndex(prev => {
      const next = new Map(prev);
      for (const node of newNodes) {
        const parentKey = node.parent_id || '__root__';
        const children = next.get(parentKey) || [];
        if (!children.includes(node.id)) {
          next.set(parentKey, [...children, node.id]);
        }
      }
      return next;
    });
    // Find and set root
    const sessionNode = newNodes.find(n => n.node_type === 'session');
    if (sessionNode) {
      setRootId(sessionNode.id);
    }
    // Auto-expand structural nodes
    const autoExpand = new Set<string>();
    for (const node of newNodes) {
      if (['session', 'phase', 'wave', 'signal'].includes(node.node_type)) {
        autoExpand.add(node.id);
      }
    }
    if (autoExpand.size > 0) {
      setExpandedNodes(prev => {
        const next = new Set(prev);
        autoExpand.forEach(id => next.add(id));
        return next;
      });
    }
  }, []);

  const updateNode = useCallback((update: BTNodeUpdate) => {
    setNodes(prev => {
      const existing = prev.get(update.id);
      if (!existing) return prev;
      const next = new Map(prev);
      const updated = { ...existing };
      if (update.status !== undefined) updated.status = update.status;
      if (update.label !== undefined) updated.label = update.label;
      if (update.children_count !== undefined) updated.children_count = update.children_count;
      if (update.data_merge) {
        updated.data = { ...updated.data, ...update.data_merge };
      }
      next.set(update.id, updated);
      return next;
    });
  }, []);

  // Behavior tree router does not exist on the backend — stub loadFullTree as a no-op.
  const loadFullTree = useCallback(async (_agentId: string) => {
    setIsLoading(true);
    try {
      // No backend behavior-tree endpoint available.
      // Tree nodes are populated via WebSocket bt_node_add / bt_node_batch events.
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Reset when agent changes
  useEffect(() => {
    setNodes(new Map());
    setChildIndex(new Map());
    setRootId(null);
    setExpandedNodes(new Set());
    setSelectedNodeId(null);

    if (selectedAgentId && isAuthenticated) {
      loadFullTree(selectedAgentId);
    }
  }, [selectedAgentId, isAuthenticated, loadFullTree]);

  const getChildren = useCallback((parentId: string): BTNode[] => {
    const childIds = childIndexRef.current.get(parentId) || [];
    const result: BTNode[] = [];
    for (const id of childIds) {
      const node = nodesRef.current.get(id);
      if (node) result.push(node);
    }
    return result;
  }, []);

  const toggleExpand = useCallback((nodeId: string) => {
    setExpandedNodes(prev => {
      const next = new Set(prev);
      if (next.has(nodeId)) {
        next.delete(nodeId);
      } else {
        next.add(nodeId);
      }
      return next;
    });
  }, []);

  const expandAll = useCallback(() => {
    setExpandedNodes(prev => {
      const next = new Set(prev);
      nodesRef.current.forEach((_, id) => next.add(id));
      return next;
    });
  }, []);

  const collapseAll = useCallback(() => {
    // Keep only session and phase nodes expanded
    setExpandedNodes(_ => {
      const next = new Set<string>();
      nodesRef.current.forEach((node, id) => {
        if (node.node_type === 'session') next.add(id);
      });
      return next;
    });
  }, []);

  const selectNode = useCallback((nodeId: string | null) => {
    setSelectedNodeId(nodeId);
  }, []);

  return {
    nodes,
    childIndex,
    rootId,
    expandedNodes,
    selectedNodeId,
    isLoading,
    addNode,
    addNodes,
    updateNode,
    loadFullTree,
    getChildren,
    toggleExpand,
    expandAll,
    collapseAll,
    selectNode,
  };
}

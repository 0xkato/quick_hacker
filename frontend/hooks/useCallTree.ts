'use client';

import { useState, useEffect } from 'react';
import type { CallTreeRoute, InvestigationFlow } from '@/types';
import { calltree as calltreeApi } from '@/lib/api';

export type DiagramMode = 'investigation' | 'calltree' | 'structured';

export interface UseCallTreeOptions {
  projectId: string | null;
  diagramMode: DiagramMode;
  isAuthenticated: boolean;
}

export interface UseCallTreeResult {
  diagramMode: DiagramMode;
  callTreeRoutes: CallTreeRoute[];
  selectedRouteId: string | null;
  callTreeFlow: InvestigationFlow | null;
  isCallTreeRoutesLoading: boolean;
  isCallTreeLoading: boolean;
  setDiagramMode: (mode: DiagramMode) => void;
  setSelectedRouteId: (routeId: string | null) => void;
  setCallTreeFlow: React.Dispatch<React.SetStateAction<InvestigationFlow | null>>;
}

export function useCallTree({
  projectId,
  diagramMode,
  isAuthenticated,
}: UseCallTreeOptions): UseCallTreeResult {
  const [currentDiagramMode, setDiagramMode] = useState<DiagramMode>(diagramMode);
  const [callTreeRoutes, setCallTreeRoutes] = useState<CallTreeRoute[]>([]);
  const [selectedRouteId, setSelectedRouteId] = useState<string | null>(null);
  const [callTreeFlow, setCallTreeFlow] = useState<InvestigationFlow | null>(null);
  const [isCallTreeRoutesLoading, setIsCallTreeRoutesLoading] = useState(false);
  const [isCallTreeLoading, setIsCallTreeLoading] = useState(false);

  // Keep internal state in sync with external mode selection.
  useEffect(() => {
    setDiagramMode(diagramMode);
  }, [diagramMode]);

  // Load call-tree routes when enabled
  useEffect(() => {
    if (!isAuthenticated || !projectId || currentDiagramMode !== 'calltree') {
      setCallTreeRoutes([]);
      setSelectedRouteId(null);
      setCallTreeFlow(null);
      setIsCallTreeRoutesLoading(false);
      setIsCallTreeLoading(false);
      return;
    }

    let cancelled = false;
    setIsCallTreeRoutesLoading(true);

    (async () => {
      try {
        const routes = await calltreeApi.listRoutes(projectId);
        if (!cancelled) {
          setCallTreeRoutes(routes);
          setSelectedRouteId((prev) => {
            if (!prev) return prev;
            if (routes.some((r) => r.id === prev)) return prev;
            setCallTreeFlow(null);
            return null;
          });
        }
      } catch (err) {
        console.error('Failed to load call-tree routes:', err);
        if (!cancelled) setCallTreeRoutes([]);
      } finally {
        if (!cancelled) setIsCallTreeRoutesLoading(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [projectId, currentDiagramMode, isAuthenticated]);

  // Build call tree when a route is selected
  useEffect(() => {
    if (!isAuthenticated || !projectId || currentDiagramMode !== 'calltree' || !selectedRouteId) {
      setCallTreeFlow(null);
      setIsCallTreeLoading(false);
      return;
    }

    let cancelled = false;
    setIsCallTreeLoading(true);

    (async () => {
      try {
        const flow = await calltreeApi.getTree(projectId, selectedRouteId, {
          maxDepth: 6,
          maxNodes: 250,
          includeExternal: true,
        });
        if (!cancelled) setCallTreeFlow(flow);
      } catch (err) {
        console.error('Failed to build call tree:', err);
        if (!cancelled) setCallTreeFlow(null);
      } finally {
        if (!cancelled) setIsCallTreeLoading(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [projectId, currentDiagramMode, selectedRouteId, isAuthenticated]);

  return {
    diagramMode: currentDiagramMode,
    callTreeRoutes,
    selectedRouteId,
    callTreeFlow,
    isCallTreeRoutesLoading,
    isCallTreeLoading,
    setDiagramMode,
    setSelectedRouteId,
    setCallTreeFlow,
  };
}

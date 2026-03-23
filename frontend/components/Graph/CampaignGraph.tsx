'use client';
import { useEffect, useState, useCallback } from 'react';
import ReactFlow, { Background, Controls, MiniMap, Node, Edge, Position } from 'reactflow';
import 'reactflow/dist/style.css';
import { campaigns as campaignsApi } from '@/lib/api';

interface CampaignGraphProps {
  campaignId: string | null;
}

const nodeColors: Record<string, string> = {
  campaign: '#3b82f6',
  targets: '#8b5cf6',
  lanes: '#06b6d4',
  runs: '#22c55e',
  artifacts: '#f59e0b',
  issues: '#ef4444',
  steering: '#ec4899',
};

export function CampaignGraph({ campaignId }: CampaignGraphProps) {
  const [nodes, setNodes] = useState<Node[]>([]);
  const [edges, setEdges] = useState<Edge[]>([]);

  const fetchGraph = useCallback(async () => {
    if (!campaignId) return;
    try {
      const data = await campaignsApi.getGraph(campaignId) as { nodes?: any[]; edges?: any[] };
      const graphNodes = (data.nodes || []).map((n: any, i: number) => ({
        id: n.id,
        type: 'default',
        position: { x: 250, y: i * 120 + 50 },
        data: {
          label: (
            <div style={{ padding: '8px 12px', textAlign: 'center' }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: '#fff' }}>{n.label}</div>
              {n.data?.status && <div style={{ fontSize: 9, color: '#ccc', marginTop: 2 }}>{n.data.status}</div>}
              {n.data?.phase && <div style={{ fontSize: 9, color: '#aaa', marginTop: 1 }}>{n.data.phase}</div>}
            </div>
          ),
        },
        style: {
          background: nodeColors[n.type] || '#6b7280',
          border: 'none',
          borderRadius: 8,
          color: '#fff',
          minWidth: 160,
        },
        sourcePosition: Position.Bottom,
        targetPosition: Position.Top,
      }));

      const graphEdges = (data.edges || []).map((e: any) => ({
        id: e.id,
        source: e.source,
        target: e.target,
        animated: true,
        style: { stroke: '#555' },
      }));

      setNodes(graphNodes);
      setEdges(graphEdges);
    } catch (e) {
      console.error('Failed to load graph:', e);
    }
  }, [campaignId]);

  useEffect(() => {
    fetchGraph();
    if (!campaignId) return;
    const interval = setInterval(fetchGraph, 10000);
    return () => clearInterval(interval);
  }, [fetchGraph, campaignId]);

  if (!campaignId) {
    return (
      <div className="flex items-center justify-center h-full text-xs text-[var(--text-muted)]">
        Select a campaign to view the execution graph.
      </div>
    );
  }

  if (nodes.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-xs text-[var(--text-muted)]">
        <div className="text-center">
          <div className="text-lg mb-2">Waiting for campaign data...</div>
        </div>
      </div>
    );
  }

  return (
    <div style={{ width: '100%', height: '100%' }}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        fitView
        attributionPosition="bottom-left"
      >
        <Background color="#333" gap={20} />
        <Controls />
        <MiniMap
          nodeStrokeColor={() => '#555'}
          nodeColor={(n) => nodeColors[n.type || ''] || '#6b7280'}
          style={{ background: '#1e1e1e' }}
        />
      </ReactFlow>
    </div>
  );
}

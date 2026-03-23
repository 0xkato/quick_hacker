'use client';
import { useState } from 'react';
import type { Campaign, CampaignCreateRequest, CampaignPreset, LaneSpec } from '@/types';

interface CampaignManagerProps {
  campaigns: Campaign[];
  selectedCampaignId: string | null;
  onSelectCampaign: (id: string) => void;
  onCreateCampaign: (req: CampaignCreateRequest) => Promise<Campaign>;
  onStartCampaign: (id: string) => Promise<void>;
  onPauseCampaign: (id: string) => Promise<void>;
  onResumeCampaign: (id: string) => Promise<void>;
  onCancelCampaign: (id: string) => Promise<void>;
  repoId: string | null;
  lanes?: LaneSpec[];
}

export function CampaignManager({ campaigns, selectedCampaignId, onSelectCampaign, onCreateCampaign, onStartCampaign, onPauseCampaign, onResumeCampaign, onCancelCampaign, repoId, lanes }: CampaignManagerProps) {
  const [preset, setPreset] = useState<CampaignPreset>('quick');
  const [isCreating, setIsCreating] = useState(false);

  const handleCreate = async () => {
    if (!repoId) return;
    setIsCreating(true);
    try {
      const campaign = await onCreateCampaign({ repo_id: repoId, campaign_preset: preset });
      await onStartCampaign(campaign.id);
    } catch (e) {
      console.error('Failed to create campaign:', e);
    } finally {
      setIsCreating(false);
    }
  };

  const statusColor = (s: string) => {
    switch (s) {
      case 'running': return 'text-green-400';
      case 'planning': case 'extracting': case 'compiling': return 'text-cyan-400';
      case 'completed': return 'text-blue-400';
      case 'failed': return 'text-red-400';
      case 'paused': return 'text-yellow-400';
      case 'cancelled': return 'text-gray-400';
      case 'created': return 'text-gray-300';
      default: return 'text-gray-300';
    }
  };

  return (
    <div className="flex flex-col h-full">
      {/* Create form */}
      <div className="p-3 border-b border-[var(--border-primary)]">
        <h3 className="text-sm font-medium text-[var(--text-primary)] mb-2">New Campaign</h3>
        <div className="flex gap-2 mb-2">
          <select
            value={preset}
            onChange={e => setPreset(e.target.value as CampaignPreset)}
            className="flex-1 bg-[var(--bg-tertiary)] text-[var(--text-primary)] text-xs rounded px-2 py-1.5 border border-[var(--border-primary)]"
          >
            <option value="quick">Quick (~10 min)</option>
            <option value="medium">Medium (~30 min)</option>
            <option value="advanced">Advanced (~2 hrs)</option>
            <option value="pro">Pro (~6 hrs)</option>
            <option value="ultra">Ultra (~24 hrs)</option>
            <option value="evil">Evil (~72 hrs)</option>
          </select>
        </div>
        <button
          onClick={handleCreate}
          disabled={!repoId || isCreating}
          className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-xs font-medium py-1.5 px-3 rounded"
        >
          {isCreating ? 'Starting...' : 'Start Campaign'}
        </button>
      </div>

      {/* Campaign list */}
      <div className="flex-1 overflow-y-auto">
        {campaigns.length === 0 && (
          <div className="p-4 text-xs text-[var(--text-muted)] text-center">No campaigns yet</div>
        )}
        {campaigns.map(c => (
          <div
            key={c.id}
            onClick={() => onSelectCampaign(c.id)}
            className={`p-3 border-b border-[var(--border-primary)] cursor-pointer hover:bg-[var(--bg-secondary)] ${selectedCampaignId === c.id ? 'bg-[var(--bg-secondary)]' : ''}`}
          >
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs font-medium text-[var(--text-primary)]">{c.preset} campaign</span>
              <span className={`text-xs font-medium ${statusColor(c.status)}`}>{c.status}</span>
            </div>
            <div className="text-[10px] text-[var(--text-muted)]">{c.id} &middot; {new Date(c.created_at).toLocaleTimeString()}</div>
            {c.status === 'running' && (
              <div className="mt-1 flex gap-1">
                <button onClick={e => { e.stopPropagation(); onPauseCampaign(c.id); }} className="text-[10px] text-yellow-400 hover:underline">Pause</button>
                <button onClick={e => { e.stopPropagation(); onCancelCampaign(c.id); }} className="text-[10px] text-red-400 hover:underline">Cancel</button>
              </div>
            )}
            {c.status === 'paused' && (
              <div className="mt-1 flex gap-1">
                <button onClick={e => { e.stopPropagation(); onResumeCampaign(c.id); }} className="text-[10px] text-green-400 hover:underline">Resume</button>
                <button onClick={e => { e.stopPropagation(); onCancelCampaign(c.id); }} className="text-[10px] text-red-400 hover:underline">Cancel</button>
              </div>
            )}
            {(c.status === 'created' || c.status === 'failed') && (
              <div className="mt-1 flex gap-1">
                <button onClick={e => { e.stopPropagation(); onStartCampaign(c.id); }} className="text-[10px] text-green-400 hover:underline">Start</button>
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Lanes section */}
      {selectedCampaignId && lanes && lanes.length > 0 && (
        <div className="border-t border-[var(--border-primary)]">
          <div className="p-2 bg-[var(--bg-tertiary)]">
            <span className="text-xs text-[var(--text-muted)]">{lanes.length} lanes</span>
          </div>
          {lanes.map(l => (
            <div key={l.id} className="p-2 border-b border-[var(--border-primary)] text-[10px]">
              <div className="flex justify-between">
                <span className="text-[var(--text-primary)]">{l.engine} · {l.structure_model}</span>
                <span className={l.status === 'validated' ? 'text-green-400' : l.status === 'retired' ? 'text-red-400' : 'text-gray-400'}>{l.status}</span>
              </div>
              <div className="text-[var(--text-muted)]">{l.oracle_packs?.join(', ')}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

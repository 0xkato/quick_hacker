'use client';
import { useState, useEffect, useCallback } from 'react';
import type { Campaign, CampaignCreateRequest, CampaignPreset, LaneSpec, Target } from '@/types';

interface CampaignManagerProps {
  campaigns: Campaign[];
  selectedCampaignId: string | null;
  onSelectCampaign: (id: string) => void;
  onCreateCampaign: (req: CampaignCreateRequest) => Promise<Campaign>;
  onStartCampaign: (id: string) => Promise<void>;
  onPauseCampaign: (id: string) => Promise<void>;
  onResumeCampaign: (id: string) => Promise<void>;
  onCancelCampaign: (id: string) => Promise<void>;
  onDeleteCampaign?: (id: string) => Promise<void>;
  repoId: string | null;
  lanes?: LaneSpec[];
  targets?: Target[];
  isLoading?: boolean;
}

const ENGINES = [
  { id: 'schemathesis', label: 'Schemathesis', desc: 'API/OpenAPI fuzzing' },
  { id: 'aflpp', label: 'AFL++', desc: 'C/C++ binary fuzzing' },
  { id: 'atheris', label: 'Atheris', desc: 'Python coverage-guided' },
  { id: 'hypothesis', label: 'Hypothesis', desc: 'Python property-based' },
  { id: 'jazzer', label: 'Jazzer', desc: 'Java/JVM fuzzing' },
  { id: 'go_fuzz', label: 'Go Fuzz', desc: 'Go native fuzzing' },
  { id: 'cargo_fuzz', label: 'Cargo Fuzz', desc: 'Rust fuzzing' },
  { id: 'echidna', label: 'Echidna', desc: 'Solidity contracts' },
  { id: 'foundry', label: 'Foundry', desc: 'Solidity (forge)' },
  { id: 'boofuzz', label: 'Boofuzz', desc: 'Network protocols' },
  { id: 'restler', label: 'RESTler', desc: 'Stateful REST API' },
  { id: 'grammarinator', label: 'Grammarinator', desc: 'Grammar-based' },
  { id: 'sqlsmith', label: 'SQLsmith', desc: 'Database fuzzing' },
  { id: 'radamsa', label: 'Radamsa', desc: 'Generic mutation' },
];

const PRESETS: { id: CampaignPreset; label: string; time: string }[] = [
  { id: 'quick', label: 'Quick', time: '~10 min' },
  { id: 'medium', label: 'Medium', time: '~30 min' },
  { id: 'advanced', label: 'Advanced', time: '~2 hrs' },
  { id: 'pro', label: 'Pro', time: '~6 hrs' },
  { id: 'ultra', label: 'Ultra', time: '~24 hrs' },
  { id: 'evil', label: 'Evil', time: '~72 hrs' },
];

function _elapsed(start: string, end?: string | null): string {
  const startMs = new Date(start).getTime();
  const endMs = end ? new Date(end).getTime() : Date.now();
  const sec = Math.floor((endMs - startMs) / 1000);
  if (sec < 60) return `${sec}s`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m ${sec % 60}s`;
  return `${Math.floor(sec / 3600)}h ${Math.floor((sec % 3600) / 60)}m`;
}

export function CampaignManager({
  campaigns, selectedCampaignId, onSelectCampaign,
  onCreateCampaign, onStartCampaign, onPauseCampaign, onResumeCampaign,
  onCancelCampaign, onDeleteCampaign, repoId, lanes, targets, isLoading,
}: CampaignManagerProps) {
  const [preset, setPreset] = useState<CampaignPreset>('advanced');
  const [targetScope, setTargetScope] = useState('');
  const [directedTargets, setDirectedTargets] = useState('');
  const [enabledEngines, setEnabledEngines] = useState<string[]>(ENGINES.map(e => e.id));
  const [maxParallelLanes, setMaxParallelLanes] = useState(2);
  const [lmProvider, setLmProvider] = useState('claude_cli');
  const [lmModel, setLmModel] = useState('claude-opus-4-6');
  const [steeringInterval, setSteeringInterval] = useState(120);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [isCreating, setIsCreating] = useState(false);
  const [showForm, setShowForm] = useState(true);
  const [, setTick] = useState(0);

  // Re-render every 5s to update elapsed time for running campaigns
  useEffect(() => {
    const hasRunning = campaigns.some(c => c.status === 'running' || c.status === 'extracting' || c.status === 'planning' || c.status === 'compiling');
    if (!hasRunning) return;
    const iv = setInterval(() => setTick(t => t + 1), 5000);
    return () => clearInterval(iv);
  }, [campaigns]);

  const toggleEngine = useCallback((id: string) => {
    setEnabledEngines(prev =>
      prev.includes(id) ? prev.filter(e => e !== id) : [...prev, id]
    );
  }, []);

  const handleCreate = async () => {
    if (!repoId) return;
    setIsCreating(true);
    try {
      const req: CampaignCreateRequest = {
        repo_id: repoId,
        campaign_preset: preset,
        target_scope: targetScope || undefined,
        directed_targets: directedTargets ? directedTargets.split(',').map(s => s.trim()).filter(Boolean) : undefined,
        enabled_engines: enabledEngines,
        max_parallel_lanes: maxParallelLanes,
        lm_provider: lmProvider,
        lm_model: lmModel,
        steering_interval_seconds: steeringInterval,
      };
      const campaign = await onCreateCampaign(req);
      await onStartCampaign(campaign.id);
      setShowForm(false);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Campaign creation failed';
      console.error('Failed:', e);
      alert(msg);
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
      default: return 'text-gray-300';
    }
  };

  const statusPhaseLabel = (s: string) => {
    switch (s) {
      case 'created': return 'Ready to start';
      case 'extracting': return 'Extracting targets...';
      case 'planning': return 'Planning lanes...';
      case 'compiling': return 'Compiling harnesses...';
      case 'running': return 'Fuzzing in progress';
      case 'paused': return 'Paused';
      case 'completed': return 'Campaign complete';
      case 'failed': return 'Campaign failed';
      case 'cancelled': return 'Cancelled';
      default: return s;
    }
  };

  const selectedCampaign = campaigns.find(c => c.id === selectedCampaignId);

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="p-3 border-b border-[var(--border-primary)] flex items-center justify-between">
        <h3 className="text-sm font-medium text-[var(--text-primary)]">Campaigns</h3>
        <button
          onClick={() => setShowForm(!showForm)}
          className="text-[10px] text-blue-400 hover:underline"
        >
          {showForm ? 'Hide Form' : 'New Campaign'}
        </button>
      </div>

      {/* Creation Form */}
      {showForm && (
        <div className="p-3 border-b border-[var(--border-primary)] space-y-2 max-h-[60%] overflow-y-auto">
          {/* Preset */}
          <div>
            <label className="text-[10px] text-[var(--text-muted)] block mb-1">Campaign Preset</label>
            <div className="grid grid-cols-3 gap-1">
              {PRESETS.map(p => (
                <button
                  key={p.id}
                  onClick={() => setPreset(p.id)}
                  className={`text-[10px] py-1.5 px-2 rounded border ${
                    preset === p.id
                      ? 'border-blue-500 bg-blue-500/20 text-blue-400'
                      : 'border-[var(--border-primary)] text-[var(--text-muted)] hover:border-[var(--text-muted)]'
                  }`}
                >
                  <div className="font-medium">{p.label}</div>
                  <div className="text-[8px] opacity-70">{p.time}</div>
                </button>
              ))}
            </div>
          </div>

          {/* Target Scope */}
          <div>
            <label className="text-[10px] text-[var(--text-muted)] block mb-1">Target Scope</label>
            <input
              type="text"
              value={targetScope}
              onChange={e => setTargetScope(e.target.value)}
              placeholder="e.g., subsys/bluetooth or src/parser"
              className="w-full bg-[var(--bg-tertiary)] text-[var(--text-primary)] text-xs rounded px-2 py-1.5 border border-[var(--border-primary)]"
            />
          </div>

          {/* Directed Targets */}
          <div>
            <label className="text-[10px] text-[var(--text-muted)] block mb-1">Directed Targets</label>
            <textarea
              value={directedTargets}
              onChange={e => setDirectedTargets(e.target.value)}
              placeholder="e.g., host/l2cap.c:bt_l2cap_recv,host/hci_core.c:hci_event"
              rows={2}
              className="w-full bg-[var(--bg-tertiary)] text-[var(--text-primary)] text-xs rounded px-2 py-1.5 border border-[var(--border-primary)] resize-none"
            />
          </div>

          {/* LM Provider */}
          <div>
            <label className="text-[10px] text-[var(--text-muted)] block mb-1">LM Provider</label>
            <select
              value={lmProvider}
              onChange={e => setLmProvider(e.target.value)}
              className="w-full bg-[var(--bg-tertiary)] text-[var(--text-primary)] text-xs rounded px-2 py-1.5 border border-[var(--border-primary)]"
            >
              <option value="claude_cli">Claude CLI (subscription)</option>
              <option value="anthropic_sdk">Anthropic SDK (API key)</option>
              <option value="codex_cli">Codex CLI (OpenAI)</option>
            </select>
          </div>

          {/* LM Model */}
          <div>
            <label className="text-[10px] text-[var(--text-muted)] block mb-1">Model</label>
            <input
              type="text"
              value={lmModel}
              onChange={e => setLmModel(e.target.value)}
              placeholder="e.g., claude-opus-4-6, gpt-5.4-codex"
              className="w-full bg-[var(--bg-tertiary)] text-[var(--text-primary)] text-xs rounded px-2 py-1.5 border border-[var(--border-primary)]"
            />
          </div>

          {/* Advanced toggle */}
          <button
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="text-[10px] text-[var(--text-muted)] hover:text-[var(--text-primary)] w-full text-left"
          >
            {showAdvanced ? '\u25BE Hide advanced' : '\u25B8 Show advanced options'}
          </button>

          {showAdvanced && (
            <div className="space-y-2 pl-2 border-l border-[var(--border-primary)]">
              {/* Max Parallel Lanes */}
              <div className="flex items-center justify-between">
                <label className="text-[10px] text-[var(--text-muted)]">Max Parallel Lanes</label>
                <input
                  type="number"
                  value={maxParallelLanes}
                  onChange={e => setMaxParallelLanes(parseInt(e.target.value) || 2)}
                  min={1} max={16}
                  className="w-16 bg-[var(--bg-tertiary)] text-[var(--text-primary)] text-xs rounded px-2 py-1 border border-[var(--border-primary)] text-center"
                />
              </div>

              {/* Steering Interval */}
              <div className="flex items-center justify-between">
                <label className="text-[10px] text-[var(--text-muted)]">Steering Interval (sec)</label>
                <input
                  type="number"
                  value={steeringInterval}
                  onChange={e => setSteeringInterval(parseInt(e.target.value) || 120)}
                  min={30} max={3600}
                  className="w-16 bg-[var(--bg-tertiary)] text-[var(--text-primary)] text-xs rounded px-2 py-1 border border-[var(--border-primary)] text-center"
                />
              </div>

              {/* Engines */}
              <div>
                <label className="text-[10px] text-[var(--text-muted)] block mb-1">Enabled Engines</label>
                <div className="grid grid-cols-2 gap-1">
                  {ENGINES.map(eng => (
                    <label
                      key={eng.id}
                      className={`flex items-center gap-1.5 text-[9px] p-1 rounded cursor-pointer ${
                        enabledEngines.includes(eng.id) ? 'bg-[var(--bg-tertiary)] text-[var(--text-primary)]' : 'text-[var(--text-muted)]'
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={enabledEngines.includes(eng.id)}
                        onChange={() => toggleEngine(eng.id)}
                        className="w-3 h-3"
                      />
                      <div>
                        <div className="font-medium">{eng.label}</div>
                        <div className="text-[8px] opacity-60">{eng.desc}</div>
                      </div>
                    </label>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Start button */}
          <button
            onClick={handleCreate}
            disabled={!repoId || isCreating}
            className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-xs font-medium py-2 px-3 rounded"
          >
            {isCreating ? 'Starting Campaign...' : 'Start Campaign'}
          </button>
        </div>
      )}

      {/* Campaign List */}
      <div className="flex-1 overflow-y-auto">
        {isLoading && campaigns.length === 0 && (
          <div className="p-4 text-xs text-[var(--text-muted)] text-center animate-pulse">Loading...</div>
        )}
        {!isLoading && campaigns.length === 0 && (
          <div className="p-4 text-xs text-[var(--text-muted)] text-center">No campaigns yet</div>
        )}

        {campaigns.map(c => (
          <div
            key={c.id}
            onClick={() => onSelectCampaign(c.id)}
            className={`p-3 border-b border-[var(--border-primary)] cursor-pointer hover:bg-[var(--bg-secondary)] ${
              selectedCampaignId === c.id ? 'bg-[var(--bg-secondary)] border-l-2 border-l-blue-500' : ''
            }`}
          >
            {/* Campaign header */}
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs font-medium text-[var(--text-primary)]">
                {c.preset} campaign
              </span>
              <span className={`text-[10px] font-medium ${statusColor(c.status)}`}>
                {c.status}
              </span>
            </div>

            {/* Phase label */}
            <div className="text-[10px] text-[var(--text-muted)] mb-1">
              {statusPhaseLabel(c.status)}
            </div>

            {/* Campaign ID + time */}
            <div className="text-[9px] text-[var(--text-muted)] flex items-center gap-2">
              <span className="font-mono">{c.id}</span>
              <span>&middot;</span>
              <span>{new Date(c.created_at).toLocaleTimeString()}</span>
              {c.started_at && (
                <>
                  <span>&middot;</span>
                  <span>{_elapsed(c.started_at, c.completed_at)}</span>
                </>
              )}
            </div>

            {/* Action buttons */}
            <div className="mt-1.5 flex gap-2">
              {c.status === 'running' && (
                <>
                  <button onClick={e => { e.stopPropagation(); onPauseCampaign(c.id); }} className="text-[10px] text-yellow-400 hover:underline">Pause</button>
                  <button onClick={e => { e.stopPropagation(); onCancelCampaign(c.id); }} className="text-[10px] text-red-400 hover:underline">Cancel</button>
                </>
              )}
              {c.status === 'paused' && (
                <>
                  <button onClick={e => { e.stopPropagation(); onResumeCampaign(c.id); }} className="text-[10px] text-green-400 hover:underline">Resume</button>
                  <button onClick={e => { e.stopPropagation(); onCancelCampaign(c.id); }} className="text-[10px] text-red-400 hover:underline">Cancel</button>
                </>
              )}
              {(c.status === 'created' || c.status === 'failed') && (
                <button onClick={e => { e.stopPropagation(); onStartCampaign(c.id); }} className="text-[10px] text-green-400 hover:underline">Start</button>
              )}
              {onDeleteCampaign && (
                <button onClick={e => { e.stopPropagation(); onDeleteCampaign(c.id); }} className="text-[10px] text-red-400 hover:underline">Delete</button>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Selected campaign details -- Targets + Lanes */}
      {selectedCampaign && (
        <div className="border-t border-[var(--border-primary)] max-h-[40%] overflow-y-auto">
          {/* Targets summary */}
          {targets && targets.length > 0 && (
            <div className="p-2 border-b border-[var(--border-primary)]">
              <div className="text-[10px] text-[var(--text-muted)] mb-1">{targets.length} targets discovered</div>
              {targets.slice(0, 5).map(t => (
                <div key={t.id} className="text-[9px] text-[var(--text-primary)] flex items-center gap-1 py-0.5">
                  <span className="text-[var(--text-muted)]">{t.kind === 'api_route' ? '\uD83C\uDF10' : t.kind === 'native_function' ? '\u26A1' : '\uD83D\uDCC4'}</span>
                  <span className="font-mono truncate">{t.entrypoint}</span>
                  {t.language && <span className="text-[var(--text-muted)]">({t.language})</span>}
                </div>
              ))}
              {targets.length > 5 && (
                <div className="text-[9px] text-[var(--text-muted)]">+{targets.length - 5} more</div>
              )}
            </div>
          )}

          {/* Lanes with engine info */}
          {lanes && lanes.length > 0 && (
            <div className="p-2">
              <div className="text-[10px] text-[var(--text-muted)] mb-1">{lanes.length} lanes</div>
              {lanes.map(l => (
                <div key={l.id} className="text-[9px] py-0.5 flex items-center justify-between">
                  <div className="flex items-center gap-1">
                    <span className="font-medium text-[var(--text-primary)]">{l.engine}</span>
                    <span className="text-[var(--text-muted)]">&middot; {l.structure_model}</span>
                  </div>
                  <span className={
                    l.status === 'validated' ? 'text-green-400' :
                    l.status === 'retired' ? 'text-red-400' :
                    l.status === 'compiled' ? 'text-cyan-400' :
                    'text-gray-400'
                  }>
                    {l.status}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

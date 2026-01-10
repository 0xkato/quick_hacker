'use client';

import { useState, useEffect } from 'react';
import {
  Play,
  Pause,
  Square,
  Trash2,
  Plus,
  Bug,
  Zap,
  Wrench,
  X,
  Layers,
  Settings,
  FileText,
} from 'lucide-react';
import clsx from 'clsx';
import type { Agent, AgentType, ProviderType, AgentCreateRequest, AgentProgress } from '@/types';
import { agents as agentsApi, settings as settingsApi, type AppSettings } from '@/lib/api';

interface AgentManagerProps {
  repoId: string | null;
  agents: Agent[];
  progress: Record<string, AgentProgress>;
  onAgentCreated: (agent: Agent) => void;
  onAgentUpdated: (agent: Agent) => void;
  onAgentDeleted: (agentId: string) => void;
  onViewReport?: (agentId: string) => void;
}

const AGENT_TYPES: { value: AgentType; label: string; icon: React.ReactNode; description: string }[] = [
  {
    value: 'quick_audit',
    label: 'Quick',
    icon: <Zap className="w-4 h-4" />,
    description: 'Fast pattern scan',
  },
  {
    value: 'deep_audit',
    label: 'Audit',
    icon: <Layers className="w-4 h-4" />,
    description: 'Marathon deep coverage',
  },
  {
    value: 'strict_analysis',
    label: 'Strict',
    icon: <Bug className="w-4 h-4" />,
    description: 'Zero false positives',
  },
  {
    value: 'ultra_strict',
    label: 'Ultra',
    icon: <Bug className="w-4 h-4" />,
    description: 'Double verification',
  },
  {
    value: 'custom',
    label: 'Custom',
    icon: <Wrench className="w-4 h-4" />,
    description: 'User-defined',
  },
];

const PROVIDERS: { value: ProviderType; label: string }[] = [
  { value: 'anthropic', label: 'Anthropic' },
  { value: 'openai', label: 'OpenAI' },
  { value: 'ollama', label: 'Ollama (Local)' },
];

// Suggested models (user can type any model name)
const SUGGESTED_MODELS: Record<ProviderType, string[]> = {
  anthropic: [
    'claude-opus-4-5-20251101',
    'claude-sonnet-4-20250514',
    'claude-3-5-haiku-20241022',
  ],
  openai: [
    'gpt-5.2',
    'gpt-4o',
    'gpt-4o-mini',
    'gpt-4-turbo',
    'o1',
    'o1-mini',
  ],
  ollama: [
    'llama3.1',
    'llama3.3:70b',
    'codellama',
    'deepseek-coder:33b',
    'qwen2.5-coder:32b',
  ],
};

interface CreateAgentModalProps {
  repoId: string;
  onClose: () => void;
  onCreated: (agent: Agent) => void;
}

function CreateAgentModal({ repoId, onClose, onCreated }: CreateAgentModalProps) {
  const [agentType, setAgentType] = useState<AgentType>('quick_audit');
  const [provider, setProvider] = useState<ProviderType>('anthropic');
  const [model, setModel] = useState('');
  const [apiKey, setApiKey] = useState('');
  const [customPrompt, setCustomPrompt] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [appSettings, setAppSettings] = useState<AppSettings | null>(null);
  const [useDefaults, setUseDefaults] = useState(true);
  const [settingsLoaded, setSettingsLoaded] = useState(false);

  // Fetch settings on mount
  useEffect(() => {
    async function loadSettings() {
      try {
        const settings = await settingsApi.getAll();
        setAppSettings(settings);

        // Apply defaults from settings
        if (settings.agent_defaults) {
          const defaultProvider = settings.agent_defaults.default_provider as ProviderType;
          const defaultModel = settings.agent_defaults.default_model;

          // Check if the provider has an API key configured
          const providerSettings = settings.providers[defaultProvider];
          if (providerSettings?.api_key && providerSettings.api_key !== '****') {
            setProvider(defaultProvider);
            setModel(defaultModel || providerSettings.default_model || '');
          } else {
            // Fall back to first provider with an API key
            for (const [provName, provSettings] of Object.entries(settings.providers)) {
              if (provSettings.api_key && provSettings.api_key !== '****' && provName !== 'ollama') {
                setProvider(provName as ProviderType);
                setModel(provSettings.default_model || '');
                break;
              }
            }
          }
        }
        setSettingsLoaded(true);
      } catch (err) {
        console.error('Failed to load settings:', err);
        // Fall back to hardcoded defaults
        setModel('claude-sonnet-4-20250514');
        setSettingsLoaded(true);
      }
    }
    loadSettings();
  }, []);

  // Get model suggestions from settings (combine available + custom) or fallback
  const providerModels = appSettings?.providers[provider];
  const modelSuggestions = providerModels
    ? [...(providerModels.available_models || []), ...(providerModels.custom_models || [])]
    : SUGGESTED_MODELS[provider] || [];

  // Check if API key is configured for current provider
  const hasApiKeyConfigured = appSettings?.providers[provider]?.api_key
    && appSettings.providers[provider].api_key !== '****'
    && appSettings.providers[provider].api_key.length > 4;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError(null);

    try {
      const request: AgentCreateRequest = {
        repo_id: repoId,
        agent_type: agentType,
        provider_config: {
          provider,
          model,
          api_key: apiKey || undefined,
        },
        custom_prompt: customPrompt || undefined,
      };

      const agent = await agentsApi.create(request);
      const startedAgent = await agentsApi.start(agent.id);
      onCreated(startedAgent);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create agent');
    } finally {
      setIsLoading(false);
    }
  };

  // Show loading while settings are being fetched
  if (!settingsLoaded) {
    return (
      <div className="modal-overlay" onClick={(e) => e.target === e.currentTarget && onClose()}>
        <div className="modal-content">
          <div className="modal-header">
            <h2 className="text-vsc-base font-medium">Create New Agent</h2>
            <button onClick={onClose} className="btn-icon">
              <X className="w-4 h-4" />
            </button>
          </div>
          <div className="modal-body flex items-center justify-center py-8">
            <div className="text-vsc-text-muted">Loading settings...</div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="modal-overlay" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal-content">
        <div className="modal-header">
          <div>
            <h2 className="text-vsc-base font-medium">Create New Agent</h2>
            {hasApiKeyConfigured && (
              <p className="text-vsc-xs text-vsc-text-muted mt-0.5">
                Using saved settings from configuration
              </p>
            )}
          </div>
          <button onClick={onClose} className="btn-icon">
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="modal-body space-y-4">
          {/* Agent Type */}
          <div>
            <label className="block text-vsc-xs text-vsc-text-muted mb-2 uppercase tracking-wider">
              Agent Type
            </label>
            <div className="grid grid-cols-3 sm:grid-cols-6 gap-1.5">
              {AGENT_TYPES.map((type) => (
                <button
                  key={type.value}
                  type="button"
                  onClick={() => setAgentType(type.value)}
                  className={clsx(
                    'p-2 rounded border text-left transition-colors',
                    agentType === type.value
                      ? 'border-vsc-accent bg-vsc-accent/10'
                      : 'border-vsc-border-subtle hover:border-vsc-border bg-vsc-input'
                  )}
                >
                  <div className="flex items-center gap-2 mb-1 text-vsc-text">
                    {type.icon}
                    <span className="text-vsc-sm font-medium">{type.label}</span>
                  </div>
                  <p className="text-vsc-xs text-vsc-text-muted">{type.description}</p>
                </button>
              ))}
            </div>
          </div>

          {/* Provider */}
          <div>
            <label className="block text-vsc-xs text-vsc-text-muted mb-2 uppercase tracking-wider">
              AI Provider
            </label>
            <select
              value={provider}
              onChange={(e) => {
                const p = e.target.value as ProviderType;
                setProvider(p);
                // Set model from settings or first suggested model
                const provSettings = appSettings?.providers[p];
                setModel(provSettings?.default_model || SUGGESTED_MODELS[p]?.[0] || '');
              }}
              className="select"
            >
              {PROVIDERS.map((p) => {
                const provSettings = appSettings?.providers[p.value];
                const hasKey = provSettings?.api_key && provSettings.api_key !== '****' && provSettings.api_key.length > 4;
                const isOllama = p.value === 'ollama';
                return (
                  <option key={p.value} value={p.value}>
                    {p.label} {hasKey || isOllama ? '✓' : '(no API key)'}
                  </option>
                );
              })}
            </select>
            {hasApiKeyConfigured && (
              <p className="text-vsc-xs text-vsc-success mt-1 flex items-center gap-1">
                <Settings className="w-3 h-3" />
                Using API key from settings
              </p>
            )}
          </div>

          {/* Model - Text input with suggestions */}
          <div>
            <label className="block text-vsc-xs text-vsc-text-muted mb-2 uppercase tracking-wider">
              Model
              {providerModels?.default_model && model === providerModels.default_model && (
                <span className="ml-2 text-vsc-success normal-case">(default)</span>
              )}
            </label>
            <input
              type="text"
              value={model}
              onChange={(e) => setModel(e.target.value)}
              placeholder={providerModels?.default_model || "Enter model name..."}
              className="input"
              list="model-suggestions"
            />
            <datalist id="model-suggestions">
              {modelSuggestions.map((m) => (
                <option key={m} value={m} />
              ))}
            </datalist>
            <p className="text-vsc-xs text-vsc-text-muted mt-1">
              {modelSuggestions.length > 0
                ? 'Type any model name or select from suggestions'
                : 'Enter the model name to use'}
            </p>
          </div>

          {/* API Key - Only show if not configured in settings */}
          {provider !== 'ollama' && !hasApiKeyConfigured && (
            <div>
              <label className="block text-vsc-xs text-vsc-text-muted mb-2 uppercase tracking-wider">
                API Key <span className="text-vsc-text-muted normal-case">(required - not found in settings)</span>
              </label>
              <input
                type="password"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder="sk-..."
                className="input"
                required={!hasApiKeyConfigured}
              />
              <p className="text-vsc-xs text-vsc-text-muted mt-1">
                Tip: Save your API key in Settings to avoid entering it each time
              </p>
            </div>
          )}

          {/* Custom Prompt */}
          {agentType === 'custom' && (
            <div>
              <label className="block text-vsc-xs text-vsc-text-muted mb-2 uppercase tracking-wider">
                Custom Instructions
              </label>
              <textarea
                value={customPrompt}
                onChange={(e) => setCustomPrompt(e.target.value)}
                placeholder="Focus on authentication bypasses and logic flaws..."
                rows={3}
                className="input resize-none"
              />
            </div>
          )}

          {error && (
            <div className="text-vsc-error text-vsc-sm bg-vsc-error/10 p-2 rounded border border-vsc-error/30">
              {error}
            </div>
          )}
        </form>

        <div className="modal-footer">
          <button type="button" onClick={onClose} className="btn btn-secondary">
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            disabled={isLoading}
            className="btn btn-primary"
          >
            {isLoading ? 'Creating...' : 'Create & Start'}
          </button>
        </div>
      </div>
    </div>
  );
}

function AgentCard({
  agent,
  progress,
  onAction,
  onViewReport,
}: {
  agent: Agent;
  progress?: AgentProgress;
  onAction: (action: 'pause' | 'resume' | 'cancel' | 'delete') => void;
  onViewReport?: () => void;
}) {
  const isRunning = agent.status === 'running';
  const isPaused = agent.status === 'paused';
  const isCompleted = agent.status === 'completed';
  const isFinished = ['completed', 'failed', 'cancelled'].includes(agent.status);

  // Get agent type label
  const agentTypeLabel = AGENT_TYPES.find(t => t.value === agent.agent_type)?.label || agent.agent_type;

  // Truncate file path from left to show filename
  const truncateFromLeft = (path: string, maxLen: number = 30) => {
    if (path.length <= maxLen) return path;
    return '...' + path.slice(-(maxLen - 3));
  };

  return (
    <div className="soft-card">
      {/* Header row */}
      <div className="flex items-center justify-between mb-3">
        <span className="font-medium text-vsc-sm text-vsc-text truncate flex-1 mr-2">
          {agent.name}
        </span>
        <span
          className="text-vsc-xs px-2 py-0.5 rounded bg-vsc-accent/30 text-vsc-accent"
          style={{ borderRadius: 'var(--radius-sm)' }}
        >
          {agentTypeLabel}
        </span>
      </div>

      {/* Progress section - only when running */}
      {progress && isRunning && (
        <div className="mb-3">
          <div className="progress-bar mb-1.5">
            <div
              className="progress-bar-fill"
              style={{ width: `${(progress.current / progress.total) * 100}%` }}
            />
          </div>
          <div className="flex justify-between text-vsc-xs text-vsc-text-muted">
            <span>{progress.current}/{progress.total} files</span>
            <span>{Math.round((progress.current / progress.total) * 100)}%</span>
          </div>
        </div>
      )}

      {/* Current file - only when running */}
      {progress?.file && isRunning && (
        <div
          className="mb-3 px-2 py-1.5 font-mono text-vsc-xs text-vsc-text-muted truncate"
          style={{
            background: '#333333',
            borderRadius: 'var(--radius-sm)'
          }}
        >
          {truncateFromLeft(progress.file)}
        </div>
      )}

      {/* Status badge for non-running states */}
      {!isRunning && (
        <div className="mb-3">
          <span className={clsx('agent-status', agent.status)}>{agent.status}</span>
          <span className="text-vsc-xs text-vsc-text-muted ml-2">
            {agent.findings_count} findings
          </span>
        </div>
      )}

      {/* Controls row */}
      <div className="flex items-center gap-2">
        {isRunning && (
          <button
            onClick={() => onAction('pause')}
            className="btn-icon"
            title="Pause"
          >
            <Pause className="w-4 h-4" />
          </button>
        )}
        {isPaused && (
          <button
            onClick={() => onAction('resume')}
            className="btn-icon"
            title="Resume"
          >
            <Play className="w-4 h-4" />
          </button>
        )}
        {(isRunning || isPaused) && (
          <button
            onClick={() => onAction('cancel')}
            className="btn-icon hover:text-vsc-error"
            title="Cancel"
          >
            <Square className="w-4 h-4" />
          </button>
        )}
        {isCompleted && onViewReport && (
          <button
            onClick={onViewReport}
            className="btn-icon hover:text-vsc-accent"
            title="View Report"
          >
            <FileText className="w-4 h-4" />
          </button>
        )}
        {isFinished && (
          <button
            onClick={() => onAction('delete')}
            className="btn-icon hover:text-vsc-error"
            title="Delete"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        )}
      </div>
    </div>
  );
}

export function AgentManager({
  repoId,
  agents,
  progress,
  onAgentCreated,
  onAgentUpdated,
  onAgentDeleted,
  onViewReport,
}: AgentManagerProps) {
  const [showCreateModal, setShowCreateModal] = useState(false);

  const handleAgentAction = async (
    agentId: string,
    action: 'pause' | 'resume' | 'cancel' | 'delete'
  ) => {
    try {
      switch (action) {
        case 'pause':
          onAgentUpdated(await agentsApi.pause(agentId));
          break;
        case 'resume':
          onAgentUpdated(await agentsApi.resume(agentId));
          break;
        case 'cancel':
          onAgentUpdated(await agentsApi.cancel(agentId));
          break;
        case 'delete':
          await agentsApi.delete(agentId);
          onAgentDeleted(agentId);
          break;
      }
    } catch (err) {
      console.error(`Failed to ${action} agent:`, err);
    }
  };

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center justify-between px-3 py-2 border-b border-vsc-border-subtle">
        <span className="text-vsc-xs text-vsc-text-muted">
          {agents.length} agent{agents.length !== 1 ? 's' : ''}
        </span>
        <button
          onClick={() => setShowCreateModal(true)}
          disabled={!repoId}
          className="btn btn-primary btn-sm"
        >
          <Plus className="w-3 h-3" />
          New
        </button>
      </div>

      <div className="flex-1 overflow-auto p-2 space-y-2">
        {agents.length === 0 ? (
          <div className="empty-state">
            <Bug className="empty-state-icon" />
            <p className="empty-state-text">No agents</p>
            {repoId && (
              <p className="text-vsc-xs mt-1">Click &quot;New&quot; to create one</p>
            )}
          </div>
        ) : (
          agents.map((agent) => (
            <AgentCard
              key={agent.id}
              agent={agent}
              progress={progress[agent.id]}
              onAction={(action) => handleAgentAction(agent.id, action)}
              onViewReport={onViewReport ? () => onViewReport(agent.id) : undefined}
            />
          ))
        )}
      </div>

      {showCreateModal && repoId && (
        <CreateAgentModal
          repoId={repoId}
          onClose={() => setShowCreateModal(false)}
          onCreated={onAgentCreated}
        />
      )}
    </div>
  );
}

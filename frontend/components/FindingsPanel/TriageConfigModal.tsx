'use client';

import { useState, useEffect } from 'react';
import { X, Loader2, Zap, Settings } from 'lucide-react';
import clsx from 'clsx';
import { settings as settingsApi, type AppSettings } from '@/lib/api';
import type { ProviderType } from '@/types';

interface TriageConfigModalProps {
  findingsCount: number;
  onClose: () => void;
  onStartTriage: (config: TriageConfig) => void;
}

export interface TriageConfig {
  provider: ProviderType;
  model: string;
  apiKey?: string;
  useClaudeSDK: boolean;
  useClaudeCodeAuth: boolean;
}

const PROVIDERS: { value: ProviderType; label: string }[] = [
  { value: 'anthropic', label: 'Anthropic' },
  { value: 'openai', label: 'OpenAI' },
];

const SUGGESTED_MODELS: Record<ProviderType, string[]> = {
  anthropic: [
    'claude-sonnet-4-20250514',
    'claude-3-5-haiku-20241022',
  ],
  openai: [
    'gpt-4o',
    'gpt-4o-mini',
  ],
  codex_cli: ['gpt-4o'],
  ollama: ['llama3.1'],
};

export function TriageConfigModal({ findingsCount, onClose, onStartTriage }: TriageConfigModalProps) {
  const [provider, setProvider] = useState<ProviderType>('anthropic');
  const [model, setModel] = useState('claude-sonnet-4-20250514');
  const [apiKey, setApiKey] = useState('');
  const [useClaudeSDK, setUseClaudeSDK] = useState(true);
  const [useClaudeCodeAuth, setUseClaudeCodeAuth] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [appSettings, setAppSettings] = useState<AppSettings | null>(null);
  const [settingsLoaded, setSettingsLoaded] = useState(false);

  // Load settings on mount
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
          }
        }
        setSettingsLoaded(true);
      } catch (err) {
        console.error('Failed to load settings:', err);
        setSettingsLoaded(true);
      }
    }
    loadSettings();
  }, []);

  // Get model suggestions
  const providerModels = appSettings?.providers[provider];
  const modelSuggestions = providerModels
    ? [...(providerModels.available_models || []), ...(providerModels.custom_models || [])]
    : SUGGESTED_MODELS[provider] || [];

  // Check if API key is configured
  const hasApiKeyConfigured = appSettings?.providers[provider]?.api_key
    && appSettings.providers[provider].api_key !== '****'
    && appSettings.providers[provider].api_key.length > 4;

  // API key required unless using Claude Code auth
  const requiresApiKey = provider !== 'ollama' && !(provider === 'anthropic' && useClaudeSDK && useClaudeCodeAuth);

  const handleStart = () => {
    setIsLoading(true);
    onStartTriage({
      provider,
      model,
      apiKey: apiKey || undefined,
      useClaudeSDK,
      useClaudeCodeAuth,
    });
  };

  if (!settingsLoaded) {
    return (
      <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
        <div className="bg-bg-primary border border-border-default rounded-lg shadow-xl w-full max-w-md p-8">
          <div className="text-text-muted text-center">Loading settings...</div>
        </div>
      </div>
    );
  }

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="bg-bg-primary border border-border-default rounded-lg shadow-xl w-full max-w-md">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-border-subtle">
          <div className="flex items-center gap-2">
            <Zap className="w-5 h-5 text-accent" />
            <h2 className="text-lg font-semibold">Triage Configuration</h2>
          </div>
          <button onClick={onClose} className="p-1 hover:bg-bg-secondary rounded">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-4 space-y-4">
          <p className="text-sm text-text-muted">
            Analyze {findingsCount} finding{findingsCount !== 1 ? 's' : ''} to determine validity and disposition.
          </p>

          {/* Provider Selection */}
          <div>
            <label className="block text-xs text-text-muted mb-2 uppercase tracking-wider">
              AI Provider
            </label>
            <select
              value={provider}
              onChange={(e) => {
                const p = e.target.value as ProviderType;
                setProvider(p);
                const provSettings = appSettings?.providers[p];
                setModel(provSettings?.default_model || SUGGESTED_MODELS[p]?.[0] || '');
              }}
              className="w-full px-3 py-2 bg-bg-secondary border border-border-default rounded text-text-primary"
            >
              {PROVIDERS.map((p) => {
                const provSettings = appSettings?.providers[p.value];
                const hasKey = provSettings?.api_key && provSettings.api_key !== '****' && provSettings.api_key.length > 4;
                return (
                  <option key={p.value} value={p.value}>
                    {p.label} {hasKey ? '✓' : '(no API key)'}
                  </option>
                );
              })}
            </select>
            {hasApiKeyConfigured && (
              <p className="text-xs text-green-500 mt-1 flex items-center gap-1">
                <Settings className="w-3 h-3" />
                Using API key from settings
              </p>
            )}
          </div>

          {/* Claude SDK Toggle - Only for Anthropic */}
          {provider === 'anthropic' && (
            <div className="space-y-3">
              <div className="flex items-center gap-3 p-3 rounded border border-border-subtle bg-bg-secondary">
                <input
                  type="checkbox"
                  id="use-claude-sdk"
                  checked={useClaudeSDK}
                  onChange={(e) => setUseClaudeSDK(e.target.checked)}
                  className="rounded"
                />
                <label htmlFor="use-claude-sdk" className="flex-1 cursor-pointer">
                  <span className="text-sm font-medium text-text-primary">Use Claude Agent SDK</span>
                  <p className="text-xs text-text-muted mt-0.5">
                    Native tool loop with better performance.
                  </p>
                </label>
              </div>

              {/* Auth Mode Toggle - Only when Claude SDK is enabled */}
              {useClaudeSDK && (
                <div className="ml-6 p-3 rounded border border-border-subtle bg-bg-primary">
                  <div className="text-xs text-text-muted uppercase tracking-wider mb-2">Authentication</div>
                  <div className="space-y-2">
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="radio"
                        name="auth-mode"
                        checked={useClaudeCodeAuth}
                        onChange={() => setUseClaudeCodeAuth(true)}
                        className="rounded"
                      />
                      <div>
                        <span className="text-sm font-medium text-text-primary">Claude Code (subscription)</span>
                        <p className="text-xs text-text-muted">Uses your Claude Code login - no API key needed</p>
                        <p className="text-xs text-yellow-500">May conflict with custom tools/hooks</p>
                      </div>
                    </label>
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="radio"
                        name="auth-mode"
                        checked={!useClaudeCodeAuth}
                        onChange={() => setUseClaudeCodeAuth(false)}
                        className="rounded"
                      />
                      <div>
                        <span className="text-sm font-medium text-text-primary">API Key (Recommended)</span>
                        <p className="text-xs text-text-muted">Uses Anthropic API key - avoids tool conflicts</p>
                      </div>
                    </label>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Model Selection */}
          <div>
            <label className="block text-xs text-text-muted mb-2 uppercase tracking-wider">
              Model
            </label>
            <select
              value={model}
              onChange={(e) => setModel(e.target.value)}
              className="w-full px-3 py-2 bg-bg-secondary border border-border-default rounded text-text-primary"
            >
              {modelSuggestions.map((m) => (
                <option key={m} value={m}>{m}</option>
              ))}
            </select>
          </div>

          {/* API Key (only if required and not using Claude Code auth) */}
          {requiresApiKey && !hasApiKeyConfigured && (
            <div>
              <label className="block text-xs text-text-muted mb-2 uppercase tracking-wider">
                API Key
              </label>
              <input
                type="password"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder="Enter API key or save in Settings"
                className="w-full px-3 py-2 bg-bg-secondary border border-border-default rounded text-text-primary placeholder:text-text-muted"
              />
              <p className="mt-1 text-xs text-yellow-500">
                No API key configured. Go to Settings to save one, or enter it here.
              </p>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex justify-end gap-2 p-4 border-t border-border-subtle">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm text-text-muted hover:text-text-primary"
          >
            Cancel
          </button>
          <button
            onClick={handleStart}
            disabled={isLoading || (requiresApiKey && !hasApiKeyConfigured && !apiKey)}
            className={clsx(
              'px-4 py-2 text-sm rounded flex items-center gap-2',
              'bg-accent text-white hover:bg-accent/90',
              'disabled:opacity-50 disabled:cursor-not-allowed'
            )}
          >
            {isLoading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Triaging...
              </>
            ) : (
              <>
                <Zap className="w-4 h-4" />
                Start Triage
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}

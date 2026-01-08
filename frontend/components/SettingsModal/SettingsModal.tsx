'use client';

import { useState, useEffect } from 'react';
import {
  X,
  Settings,
  Key,
  Bot,
  Sliders,
  Save,
  CheckCircle,
  XCircle,
  Loader2,
  Eye,
  EyeOff,
  RefreshCw,
  Plus,
  Trash2,
} from 'lucide-react';
import {
  settings,
  authApiKeys,
  type AppSettings,
  type ProviderSettings,
  type AgentDefaults,
  type UIPreferences,
} from '@/lib/api';

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

type Tab = 'providers' | 'agents' | 'ui';

export function SettingsModal({ isOpen, onClose }: SettingsModalProps) {
  const [activeTab, setActiveTab] = useState<Tab>('providers');
  const [appSettings, setAppSettings] = useState<AppSettings | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [testResults, setTestResults] = useState<Record<string, { status: string; message: string }>>({});
  const [validationResults, setValidationResults] = useState<Record<string, { status: string; message: string }>>({});
  const [isValidating, setIsValidating] = useState<Record<string, boolean>>({});

  // Form state
  const [providerForms, setProviderForms] = useState<Record<string, Partial<ProviderSettings>>>({});
  const [agentForm, setAgentForm] = useState<Partial<AgentDefaults>>({});
  const [uiForm, setUiForm] = useState<Partial<UIPreferences>>({});
  const [showKeys, setShowKeys] = useState<Record<string, boolean>>({});
  const [newModelInputs, setNewModelInputs] = useState<Record<string, string>>({});

  // Load settings
  useEffect(() => {
    if (isOpen) {
      loadSettings();
    }
  }, [isOpen]);

  const loadSettings = async () => {
    setIsLoading(true);
    try {
      const data = await settings.getAll();
      setAppSettings(data);

      // Initialize forms
      const providerData: Record<string, Partial<ProviderSettings>> = {};
      for (const [name, provider] of Object.entries(data.providers)) {
        providerData[name] = { ...provider };
      }
      setProviderForms(providerData);
      setAgentForm({ ...data.agent_defaults });
      setUiForm({ ...data.ui_preferences });
    } catch (error) {
      console.error('Failed to load settings:', error);
    } finally {
      setIsLoading(false);
    }
  };

  // Validate API key before saving
  const validateApiKey = async (provider: string, apiKey: string): Promise<boolean> => {
    if (!apiKey || apiKey.trim() === '') {
      return true; // Empty key is valid (user may want to clear it)
    }

    setIsValidating((prev) => ({ ...prev, [provider]: true }));
    setValidationResults((prev) => ({ ...prev, [provider]: { status: 'loading', message: 'Validating...' } }));

    try {
      const result = await authApiKeys.validate(provider, apiKey);
      if (result.valid) {
        setValidationResults((prev) => ({ ...prev, [provider]: { status: 'success', message: 'API key is valid' } }));
        return true;
      } else {
        setValidationResults((prev) => ({
          ...prev,
          [provider]: { status: 'error', message: result.error || 'Invalid API key' }
        }));
        return false;
      }
    } catch (error) {
      setValidationResults((prev) => ({
        ...prev,
        [provider]: { status: 'error', message: error instanceof Error ? error.message : 'Validation failed' }
      }));
      return false;
    } finally {
      setIsValidating((prev) => ({ ...prev, [provider]: false }));
    }
  };

  // Save provider settings
  const saveProvider = async (provider: string) => {
    setIsSaving(true);
    try {
      const providerData = providerForms[provider] || {};
      const apiKey = providerData.api_key;

      // If API key is provided and has changed, validate and save it using the auth endpoint
      if (apiKey && apiKey.trim() !== '' && !apiKey.startsWith('sk-...')) {
        // Validate the API key first
        const isValid = await validateApiKey(provider, apiKey);
        if (!isValid) {
          setIsSaving(false);
          return; // Don't save if validation failed
        }

        // Save API key using the per-user auth endpoint
        await authApiKeys.save(provider, apiKey);
      }

      // Save other provider settings (excluding api_key which is handled separately)
      const { api_key: _, ...otherSettings } = providerData;
      await settings.updateProvider(provider, otherSettings);

      await loadSettings();
      setValidationResults((prev) => ({ ...prev, [provider]: { status: 'success', message: 'Settings saved' } }));
    } catch (error) {
      console.error('Failed to save provider:', error);
      setValidationResults((prev) => ({
        ...prev,
        [provider]: { status: 'error', message: error instanceof Error ? error.message : 'Failed to save' }
      }));
    } finally {
      setIsSaving(false);
    }
  };

  // Test provider connection
  const testProvider = async (provider: string) => {
    setTestResults((prev) => ({ ...prev, [provider]: { status: 'loading', message: 'Testing...' } }));
    try {
      const result = await settings.testProvider(provider);
      setTestResults((prev) => ({ ...prev, [provider]: result }));
    } catch (error) {
      setTestResults((prev) => ({
        ...prev,
        [provider]: { status: 'error', message: error instanceof Error ? error.message : 'Test failed' },
      }));
    }
  };

  // Save agent defaults
  const saveAgentDefaults = async () => {
    setIsSaving(true);
    try {
      await settings.updateAgentDefaults(agentForm);
      await loadSettings();
    } catch (error) {
      console.error('Failed to save agent defaults:', error);
    } finally {
      setIsSaving(false);
    }
  };

  // Save UI preferences
  const saveUIPreferences = async () => {
    setIsSaving(true);
    try {
      await settings.updateUIPreferences(uiForm);
      await loadSettings();
    } catch (error) {
      console.error('Failed to save UI preferences:', error);
    } finally {
      setIsSaving(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <div className="bg-vsc-sidebar w-[700px] max-h-[80vh] rounded-lg border border-vsc-border-subtle shadow-2xl flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-vsc-border-subtle">
          <div className="flex items-center gap-2">
            <Settings className="w-5 h-5" />
            <h2 className="text-lg font-semibold">Settings</h2>
          </div>
          <button onClick={onClose} className="btn-icon">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-vsc-border-subtle">
          {[
            { id: 'providers', label: 'API Providers', icon: Key },
            { id: 'agents', label: 'Agent Defaults', icon: Bot },
            { id: 'ui', label: 'UI Preferences', icon: Sliders },
          ].map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setActiveTab(id as Tab)}
              className={`flex-1 flex items-center justify-center gap-2 px-4 py-2.5 text-sm transition-colors ${
                activeTab === id
                  ? 'bg-vsc-bg text-vsc-text border-b-2 border-vsc-focus'
                  : 'text-vsc-text-muted hover:text-vsc-text hover:bg-vsc-hover'
              }`}
            >
              <Icon className="w-4 h-4" />
              {label}
            </button>
          ))}
        </div>

        {/* Content */}
        <div className="flex-1 overflow-auto p-4">
          {isLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-8 h-8 animate-spin text-vsc-text-muted" />
            </div>
          ) : (
            <>
              {/* Providers Tab */}
              {activeTab === 'providers' && (
                <div className="space-y-6">
                  {Object.entries(providerForms).map(([name, provider]) => (
                    <div key={name} className="bg-vsc-bg rounded-lg p-4 border border-vsc-border-subtle">
                      <div className="flex items-center justify-between mb-4">
                        <div className="flex items-center gap-2">
                          <h3 className="font-medium capitalize">{name}</h3>
                          {testResults[name] && (
                            <span
                              className={`text-xs flex items-center gap-1 ${
                                testResults[name].status === 'success'
                                  ? 'text-vsc-success'
                                  : testResults[name].status === 'error'
                                  ? 'text-vsc-error'
                                  : 'text-vsc-text-muted'
                              }`}
                            >
                              {testResults[name].status === 'success' && <CheckCircle className="w-3 h-3" />}
                              {testResults[name].status === 'error' && <XCircle className="w-3 h-3" />}
                              {testResults[name].status === 'loading' && <Loader2 className="w-3 h-3 animate-spin" />}
                              {testResults[name].message}
                            </span>
                          )}
                        </div>
                        <label className="flex items-center gap-2">
                          <input
                            type="checkbox"
                            checked={provider.enabled}
                            onChange={(e) =>
                              setProviderForms((prev) => ({
                                ...prev,
                                [name]: { ...prev[name], enabled: e.target.checked },
                              }))
                            }
                            className="rounded"
                          />
                          <span className="text-sm">Enabled</span>
                        </label>
                      </div>

                      <div className="space-y-3">
                        {name !== 'ollama' && (
                          <div>
                            <label className="block text-sm text-vsc-text-muted mb-1">API Key</label>
                            <div className="flex gap-2">
                              <div className="relative flex-1">
                                <input
                                  type={showKeys[name] ? 'text' : 'password'}
                                  value={provider.api_key || ''}
                                  onChange={(e) =>
                                    setProviderForms((prev) => ({
                                      ...prev,
                                      [name]: { ...prev[name], api_key: e.target.value },
                                    }))
                                  }
                                  placeholder="Enter API key..."
                                  className="input w-full pr-10"
                                />
                                <button
                                  onClick={() => setShowKeys((prev) => ({ ...prev, [name]: !prev[name] }))}
                                  className="absolute right-2 top-1/2 -translate-y-1/2 text-vsc-text-muted hover:text-vsc-text"
                                >
                                  {showKeys[name] ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                                </button>
                              </div>
                            </div>
                            {validationResults[name] && (
                              <p
                                className={`text-xs mt-1 flex items-center gap-1 ${
                                  validationResults[name].status === 'success'
                                    ? 'text-vsc-success'
                                    : validationResults[name].status === 'error'
                                    ? 'text-vsc-error'
                                    : 'text-vsc-text-muted'
                                }`}
                              >
                                {validationResults[name].status === 'success' && <CheckCircle className="w-3 h-3" />}
                                {validationResults[name].status === 'error' && <XCircle className="w-3 h-3" />}
                                {validationResults[name].status === 'loading' && <Loader2 className="w-3 h-3 animate-spin" />}
                                {validationResults[name].message}
                              </p>
                            )}
                            <p className="text-xs text-vsc-text-muted mt-1">
                              API keys are stored securely per-user. They will be validated before saving.
                            </p>
                          </div>
                        )}

                        {name === 'ollama' && (
                          <div>
                            <label className="block text-sm text-vsc-text-muted mb-1">Base URL</label>
                            <input
                              type="text"
                              value={provider.base_url || ''}
                              onChange={(e) =>
                                setProviderForms((prev) => ({
                                  ...prev,
                                  [name]: { ...prev[name], base_url: e.target.value },
                                }))
                              }
                              placeholder="http://localhost:11434"
                              className="input w-full"
                            />
                          </div>
                        )}

                        <div>
                          <label className="block text-sm text-vsc-text-muted mb-1">Default Model</label>
                          <input
                            type="text"
                            value={provider.default_model || ''}
                            onChange={(e) =>
                              setProviderForms((prev) => ({
                                ...prev,
                                [name]: { ...prev[name], default_model: e.target.value },
                              }))
                            }
                            placeholder="Enter model name (e.g., gpt-4o, claude-sonnet-4-20250514)"
                            className="input w-full"
                            list={`models-${name}`}
                          />
                          <datalist id={`models-${name}`}>
                            {[...(provider.available_models || []), ...(provider.custom_models || [])].map((model) => (
                              <option key={model} value={model} />
                            ))}
                          </datalist>
                          <p className="text-xs text-vsc-text-muted mt-1">
                            Type any model name or select from suggestions
                          </p>
                        </div>

                        {/* Custom Models Management */}
                        <div>
                          <label className="block text-sm text-vsc-text-muted mb-1">Custom Models</label>
                          <div className="flex gap-2 mb-2">
                            <input
                              type="text"
                              value={newModelInputs[name] || ''}
                              onChange={(e) =>
                                setNewModelInputs((prev) => ({ ...prev, [name]: e.target.value }))
                              }
                              placeholder="Add custom model name..."
                              className="input flex-1"
                              onKeyDown={(e) => {
                                if (e.key === 'Enter' && newModelInputs[name]?.trim()) {
                                  e.preventDefault();
                                  const newModel = newModelInputs[name].trim();
                                  setProviderForms((prev) => ({
                                    ...prev,
                                    [name]: {
                                      ...prev[name],
                                      custom_models: [...(prev[name]?.custom_models || []), newModel],
                                    },
                                  }));
                                  setNewModelInputs((prev) => ({ ...prev, [name]: '' }));
                                }
                              }}
                            />
                            <button
                              onClick={() => {
                                if (newModelInputs[name]?.trim()) {
                                  const newModel = newModelInputs[name].trim();
                                  setProviderForms((prev) => ({
                                    ...prev,
                                    [name]: {
                                      ...prev[name],
                                      custom_models: [...(prev[name]?.custom_models || []), newModel],
                                    },
                                  }));
                                  setNewModelInputs((prev) => ({ ...prev, [name]: '' }));
                                }
                              }}
                              className="btn btn-secondary btn-sm"
                              disabled={!newModelInputs[name]?.trim()}
                            >
                              <Plus className="w-4 h-4" />
                            </button>
                          </div>
                          {(provider.custom_models || []).length > 0 && (
                            <div className="flex flex-wrap gap-1">
                              {(provider.custom_models || []).map((model, idx) => (
                                <span
                                  key={idx}
                                  className="inline-flex items-center gap-1 px-2 py-0.5 bg-vsc-sidebar rounded text-xs"
                                >
                                  {model}
                                  <button
                                    onClick={() => {
                                      setProviderForms((prev) => ({
                                        ...prev,
                                        [name]: {
                                          ...prev[name],
                                          custom_models: (prev[name]?.custom_models || []).filter((_, i) => i !== idx),
                                        },
                                      }));
                                    }}
                                    className="text-vsc-text-muted hover:text-vsc-error"
                                  >
                                    <X className="w-3 h-3" />
                                  </button>
                                </span>
                              ))}
                            </div>
                          )}
                        </div>

                        <div className="flex gap-2 pt-2">
                          <button
                            onClick={() => testProvider(name)}
                            className="btn btn-secondary btn-sm flex items-center gap-1"
                            disabled={isSaving}
                          >
                            <RefreshCw className="w-3 h-3" />
                            Test Connection
                          </button>
                          <button
                            onClick={() => saveProvider(name)}
                            className="btn btn-primary btn-sm flex items-center gap-1"
                            disabled={isSaving}
                          >
                            {isSaving ? <Loader2 className="w-3 h-3 animate-spin" /> : <Save className="w-3 h-3" />}
                            Save
                          </button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* Agents Tab */}
              {activeTab === 'agents' && (
                <div className="space-y-4">
                  <div className="bg-vsc-bg rounded-lg p-4 border border-vsc-border-subtle">
                    <h3 className="font-medium mb-4">Default Agent Settings</h3>

                    <div className="space-y-4">
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <label className="block text-sm text-vsc-text-muted mb-1">Default Provider</label>
                          <select
                            value={agentForm.default_provider || ''}
                            onChange={(e) => setAgentForm((prev) => ({ ...prev, default_provider: e.target.value }))}
                            className="input w-full"
                          >
                            <option value="openai">OpenAI</option>
                            <option value="anthropic">Anthropic</option>
                            <option value="ollama">Ollama</option>
                          </select>
                        </div>

                        <div>
                          <label className="block text-sm text-vsc-text-muted mb-1">Max Concurrent Agents</label>
                          <input
                            type="number"
                            min={1}
                            max={10}
                            value={agentForm.max_concurrent_agents || 5}
                            onChange={(e) =>
                              setAgentForm((prev) => ({ ...prev, max_concurrent_agents: parseInt(e.target.value) }))
                            }
                            className="input w-full"
                          />
                        </div>
                      </div>

                      <div>
                        <label className="block text-sm text-vsc-text-muted mb-1">Default Model</label>
                        <input
                          type="text"
                          value={agentForm.default_model || ''}
                          onChange={(e) => setAgentForm((prev) => ({ ...prev, default_model: e.target.value }))}
                          placeholder="Enter model name (e.g., claude-sonnet-4-20250514)"
                          className="input w-full"
                          list="agent-default-models"
                        />
                        <datalist id="agent-default-models">
                          {agentForm.default_provider === 'openai' && (
                            <>
                              <option value="gpt-4o" />
                              <option value="gpt-4o-mini" />
                              <option value="gpt-4-turbo" />
                              <option value="o1" />
                              <option value="o1-mini" />
                            </>
                          )}
                          {agentForm.default_provider === 'anthropic' && (
                            <>
                              <option value="claude-opus-4-5-20251101" />
                              <option value="claude-sonnet-4-20250514" />
                              <option value="claude-3-5-haiku-20241022" />
                            </>
                          )}
                          {agentForm.default_provider === 'ollama' && (
                            <>
                              <option value="llama3.1" />
                              <option value="llama3.3:70b" />
                              <option value="codellama" />
                              <option value="deepseek-coder:33b" />
                              <option value="qwen2.5-coder:32b" />
                            </>
                          )}
                        </datalist>
                        <p className="text-xs text-vsc-text-muted mt-1">
                          Type any model name or select from suggestions
                        </p>
                      </div>

                      <div>
                        <label className="block text-sm text-vsc-text-muted mb-1">
                          Confidence Threshold: {((agentForm.confidence_threshold || 0.85) * 100).toFixed(0)}%
                        </label>
                        <input
                          type="range"
                          min={50}
                          max={99}
                          value={(agentForm.confidence_threshold || 0.85) * 100}
                          onChange={(e) =>
                            setAgentForm((prev) => ({ ...prev, confidence_threshold: parseInt(e.target.value) / 100 }))
                          }
                          className="w-full"
                        />
                      </div>

                      <div className="flex flex-col gap-2">
                        <label className="flex items-center gap-2">
                          <input
                            type="checkbox"
                            checked={agentForm.strict_mode_default}
                            onChange={(e) => setAgentForm((prev) => ({ ...prev, strict_mode_default: e.target.checked }))}
                            className="rounded"
                          />
                          <span className="text-sm">Enable strict mode by default (zero false positive tolerance)</span>
                        </label>

                        <label className="flex items-center gap-2">
                          <input
                            type="checkbox"
                            checked={agentForm.auto_verify_findings}
                            onChange={(e) =>
                              setAgentForm((prev) => ({ ...prev, auto_verify_findings: e.target.checked }))
                            }
                            className="rounded"
                          />
                          <span className="text-sm">Auto-verify findings through multi-gate pipeline</span>
                        </label>
                      </div>

                      <button
                        onClick={saveAgentDefaults}
                        className="btn btn-primary btn-sm flex items-center gap-1"
                        disabled={isSaving}
                      >
                        {isSaving ? <Loader2 className="w-3 h-3 animate-spin" /> : <Save className="w-3 h-3" />}
                        Save Agent Defaults
                      </button>
                    </div>
                  </div>
                </div>
              )}

              {/* UI Tab */}
              {activeTab === 'ui' && (
                <div className="space-y-4">
                  <div className="bg-vsc-bg rounded-lg p-4 border border-vsc-border-subtle">
                    <h3 className="font-medium mb-4">UI Preferences</h3>

                    <div className="space-y-4">
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <label className="block text-sm text-vsc-text-muted mb-1">Theme</label>
                          <select
                            value={uiForm.theme || 'dark'}
                            onChange={(e) => setUiForm((prev) => ({ ...prev, theme: e.target.value }))}
                            className="input w-full"
                          >
                            <option value="dark">Dark</option>
                            <option value="light">Light</option>
                          </select>
                        </div>

                        <div>
                          <label className="block text-sm text-vsc-text-muted mb-1">Editor Font Size</label>
                          <input
                            type="number"
                            min={10}
                            max={24}
                            value={uiForm.editor_font_size || 14}
                            onChange={(e) =>
                              setUiForm((prev) => ({ ...prev, editor_font_size: parseInt(e.target.value) }))
                            }
                            className="input w-full"
                          />
                        </div>

                        <div>
                          <label className="block text-sm text-vsc-text-muted mb-1">Chat Position</label>
                          <select
                            value={uiForm.chat_position || 'left'}
                            onChange={(e) => setUiForm((prev) => ({ ...prev, chat_position: e.target.value }))}
                            className="input w-full"
                          >
                            <option value="left">Left</option>
                            <option value="right">Right</option>
                          </select>
                        </div>

                        <div>
                          <label className="block text-sm text-vsc-text-muted mb-1">Chat Width (px)</label>
                          <input
                            type="number"
                            min={300}
                            max={800}
                            value={uiForm.chat_width || 400}
                            onChange={(e) => setUiForm((prev) => ({ ...prev, chat_width: parseInt(e.target.value) }))}
                            className="input w-full"
                          />
                        </div>
                      </div>

                      <div className="flex flex-col gap-2">
                        <label className="flex items-center gap-2">
                          <input
                            type="checkbox"
                            checked={uiForm.show_line_numbers}
                            onChange={(e) => setUiForm((prev) => ({ ...prev, show_line_numbers: e.target.checked }))}
                            className="rounded"
                          />
                          <span className="text-sm">Show line numbers in editor</span>
                        </label>

                        <label className="flex items-center gap-2">
                          <input
                            type="checkbox"
                            checked={uiForm.auto_expand_findings}
                            onChange={(e) => setUiForm((prev) => ({ ...prev, auto_expand_findings: e.target.checked }))}
                            className="rounded"
                          />
                          <span className="text-sm">Auto-expand findings panel</span>
                        </label>
                      </div>

                      <button
                        onClick={saveUIPreferences}
                        className="btn btn-primary btn-sm flex items-center gap-1"
                        disabled={isSaving}
                      >
                        {isSaving ? <Loader2 className="w-3 h-3 animate-spin" /> : <Save className="w-3 h-3" />}
                        Save UI Preferences
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

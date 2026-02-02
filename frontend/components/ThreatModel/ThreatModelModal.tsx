'use client';

import { useEffect, useMemo, useState } from 'react';
import { AlertTriangle, CheckCircle, ChevronDown, ChevronRight, Save, Shield, X } from 'lucide-react';
import {
  APIError,
  projects,
  type AttackerCapability,
  type Asset,
  type ExecutionContext,
  type ThreatModelPreset,
  type ThreatModelProfile,
  type ThreatModelProfileResponse,
  type ValidationProfile,
  type ValidationProfilePreset,
} from '@/lib/api';

interface ThreatModelModalProps {
  isOpen: boolean;
  onClose: () => void;
  projectId: string;
  presetPreview?: ThreatModelPreset | null;
  onProfileUpdated?: () => void;
}

type Tab = 'visual' | 'json';

const EXECUTION_CONTEXTS: Array<{ value: ExecutionContext; label: string; description: string }> = [
  { value: 'product_runtime', label: 'Product runtime', description: 'User-facing product execution paths.' },
  { value: 'server_runtime', label: 'Server runtime', description: 'Backend services handling requests/jobs.' },
  { value: 'dev_tooling', label: 'Dev tooling', description: 'Developer CLIs/scripts used locally.' },
  { value: 'ci_pipeline', label: 'CI pipeline', description: 'Automation that runs in CI.' },
  { value: 'test_harness', label: 'Test harness', description: 'Test runners/servers/harness tooling.' },
  { value: 'test_code', label: 'Test code', description: 'Test cases/fixtures; usually noisy by design.' },
  { value: 'build_release', label: 'Build/release', description: 'Release tooling and packaging.' },
];

const ATTACKER_CAPABILITIES: Array<{ value: AttackerCapability; label: string; description: string; warn?: boolean }> = [
  { value: 'remote_network', label: 'Remote network', description: 'Attacker controls network requests.' },
  { value: 'remote_web_content', label: 'Remote web content', description: 'Attacker controls browser content.' },
  { value: 'untrusted_file_input', label: 'Untrusted file input', description: 'Attacker controls file formats / payloads.' },
  {
    value: 'untrusted_repo_content',
    label: 'Untrusted repo content',
    description: 'Attacker controls repo checkout contents (PRs/supply chain).',
    warn: true,
  },
  {
    value: 'untrusted_ci_artifact',
    label: 'Untrusted CI artifacts',
    description: 'Attacker controls CI build artifacts.',
    warn: true,
  },
  {
    value: 'local_unprivileged_user',
    label: 'Local unprivileged user',
    description: 'Attacker has local access (developer machine / host).',
    warn: true,
  },
];

const ASSETS: Array<{ value: Asset; label: string; description: string }> = [
  { value: 'user_data', label: 'User data', description: 'Protect user-controlled or user-owned data.' },
  { value: 'credentials_secrets', label: 'Credentials/secrets', description: 'Prevent leakage of secrets/API keys.' },
  { value: 'availability', label: 'Availability', description: 'Prevent crashes/DoS and keep service running.' },
  { value: 'integrity_of_build', label: 'Build integrity', description: 'Prevent build/CI compromise.' },
  { value: 'integrity_of_release_artifacts', label: 'Release artifact integrity', description: 'Prevent tampering with shipped artifacts.' },
  { value: 'developer_machine_integrity', label: 'Developer machine integrity', description: 'Protect developer workstation environment.' },
];

// === Validation Profile Options ===

const VALIDATION_PRESETS: Array<{ value: ValidationProfilePreset; label: string; description: string }> = [
  { value: 'large_c_codebase', label: 'Large C/C++ Codebase', description: 'Chromium-style: strict evidence, remote attackers only, skip test/third_party.' },
  { value: 'webapp', label: 'Web Application', description: 'Web-focused: network and web content attackers.' },
  { value: 'strict', label: 'Strict', description: 'Maximum strictness: full evidence chain required.' },
  { value: 'blank', label: 'Blank', description: 'No filtering: all findings pass through.' },
];

const VERIFIER_OPTIONS: Array<{ value: string; label: string; description: string }> = [
  { value: 'gdb', label: 'GDB', description: 'Use GDB for memory corruption verification.' },
];

function toggleItem<T extends string>(items: T[], value: T): T[] {
  return items.includes(value) ? items.filter((v) => v !== value) : [...items, value];
}

function normalizeSet(values: string[] | undefined): string[] {
  return Array.from(new Set(values || [])).sort();
}

function equalAsSets(a: string[] | undefined, b: string[] | undefined): boolean {
  const aa = normalizeSet(a);
  const bb = normalizeSet(b);
  if (aa.length !== bb.length) return false;
  return aa.every((v, i) => v === bb[i]);
}

function deriveAttackerControlledChannels(capabilities: AttackerCapability[]): string[] {
  const capToChannels: Record<AttackerCapability, string[]> = {
    remote_network: ['network'],
    remote_web_content: ['web_content'],
    untrusted_file_input: ['file_input'],
    untrusted_repo_content: ['repo_checkout'],
    untrusted_ci_artifact: ['ci_artifact'],
    local_unprivileged_user: ['env', 'config', 'ipc', 'file_input'],
  };
  const out = new Set<string>();
  for (const cap of capabilities) {
    for (const c of capToChannels[cap] || []) out.add(c);
  }
  return Array.from(out).sort();
}

function validateProfileShape(obj: unknown): { ok: boolean; error?: string; profile?: ThreatModelProfile } {
  if (!obj || typeof obj !== 'object') return { ok: false, error: 'Must be a JSON object.' };
  const raw = obj as any;
  if (!Array.isArray(raw.execution_contexts)) return { ok: false, error: 'execution_contexts must be an array.' };
  if (!Array.isArray(raw.attacker_capabilities)) return { ok: false, error: 'attacker_capabilities must be an array.' };
  if (!Array.isArray(raw.assets)) return { ok: false, error: 'assets must be an array.' };

  const ctxAllowed = new Set(EXECUTION_CONTEXTS.map((x) => x.value));
  const capsAllowed = new Set(ATTACKER_CAPABILITIES.map((x) => x.value));
  const assetsAllowed = new Set(ASSETS.map((x) => x.value));

  for (const v of raw.execution_contexts) {
    if (typeof v !== 'string' || !ctxAllowed.has(v as ExecutionContext)) return { ok: false, error: `Invalid execution_context: ${String(v)}` };
  }
  for (const v of raw.attacker_capabilities) {
    if (typeof v !== 'string' || !capsAllowed.has(v as AttackerCapability)) return { ok: false, error: `Invalid attacker_capability: ${String(v)}` };
  }
  for (const v of raw.assets) {
    if (typeof v !== 'string' || !assetsAllowed.has(v as Asset)) return { ok: false, error: `Invalid asset: ${String(v)}` };
  }

  return {
    ok: true,
    profile: {
      execution_contexts: raw.execution_contexts,
      attacker_capabilities: raw.attacker_capabilities,
      assets: raw.assets,
    },
  };
}

export function ThreatModelModal({
  isOpen,
  onClose,
  projectId,
  presetPreview,
  onProfileUpdated,
}: ThreatModelModalProps) {
  const [activeTab, setActiveTab] = useState<Tab>('visual');
  const [isLoading, setIsLoading] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const [effective, setEffective] = useState<ThreatModelProfileResponse | null>(null);
  const [selectedPreset, setSelectedPreset] = useState<ThreatModelPreset>('AB');
  const [draft, setDraft] = useState<ThreatModelProfile | null>(null);

  const [jsonText, setJsonText] = useState('');
  const [jsonError, setJsonError] = useState<string | null>(null);

  // Validation Profile state
  const [validationExpanded, setValidationExpanded] = useState(false);
  const [validationProfile, setValidationProfile] = useState<ValidationProfile | null>(null);
  const [excludedPathsText, setExcludedPathsText] = useState('');
  const [enabledVerifiers, setEnabledVerifiers] = useState<string[]>([]);
  const [validationJsonText, setValidationJsonText] = useState('');
  const [validationJsonError, setValidationJsonError] = useState<string | null>(null);
  const [showValidationJson, setShowValidationJson] = useState(false);
  const [selectedValidationPreset, setSelectedValidationPreset] = useState<ValidationProfilePreset | null>(null);
  const [isValidationSaving, setIsValidationSaving] = useState(false);

  const isDirty = useMemo(() => {
    if (!effective || !draft) return false;
    const base = effective.threat_model_profile;
    return (
      !equalAsSets(base.execution_contexts, draft.execution_contexts) ||
      !equalAsSets(base.attacker_capabilities, draft.attacker_capabilities) ||
      !equalAsSets(base.assets, draft.assets)
    );
  }, [effective, draft]);

  const attackerControlledChannels = useMemo(() => {
    const caps = draft?.attacker_capabilities || effective?.threat_model_profile?.attacker_capabilities || [];
    return deriveAttackerControlledChannels(caps);
  }, [draft, effective]);

  const hasHighNoiseCaps = useMemo(() => {
    const caps = new Set(draft?.attacker_capabilities || []);
    return ['untrusted_repo_content', 'untrusted_ci_artifact', 'local_unprivileged_user'].some((c) => caps.has(c as AttackerCapability));
  }, [draft]);

  const loadProfile = async () => {
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const data = await projects.getThreatModelProfile(projectId);
      setEffective(data);
      setDraft(data.threat_model_profile);
      setSelectedPreset(presetPreview || data.threat_model_preset);
      setJsonText(JSON.stringify(data.threat_model_profile, null, 2));
      setJsonError(null);
    } catch (err) {
      console.error('Failed to load threat model profile:', err);
      setErrorMessage(err instanceof Error ? err.message : 'Failed to load threat model profile');
    } finally {
      setIsLoading(false);
    }
  };

  const loadValidationProfile = async () => {
    try {
      const data = await projects.getValidationProfile(projectId);
      setValidationProfile(data);
      if (data) {
        setExcludedPathsText((data.excluded_paths || []).join('\n'));
        setEnabledVerifiers(data.enabled_verifiers || []);
        setValidationJsonText(JSON.stringify(data, null, 2));
      } else {
        setExcludedPathsText('');
        setEnabledVerifiers([]);
        setValidationJsonText('{}');
      }
    } catch (err) {
      console.error('Failed to load validation profile:', err);
      // Not critical - validation profile is optional
    }
  };

  const handleSaveValidationProfile = async () => {
    setIsValidationSaving(true);
    setErrorMessage(null);
    try {
      let profileToSave: ValidationProfile;

      if (showValidationJson) {
        // Parse from JSON
        try {
          profileToSave = JSON.parse(validationJsonText);
        } catch {
          setValidationJsonError('Invalid JSON');
          setIsValidationSaving(false);
          return;
        }
      } else {
        // Build from UI fields
        const paths = excludedPathsText
          .split('\n')
          .map((p) => p.trim())
          .filter((p) => p.length > 0);

        profileToSave = {
          ...validationProfile,
          excluded_paths: paths,
          enabled_verifiers: enabledVerifiers,
        };
      }

      const result = await projects.updateValidationProfile(projectId, profileToSave);
      setValidationProfile(result);
      setSelectedValidationPreset(null); // Custom profile now
      if (result) {
        setExcludedPathsText((result.excluded_paths || []).join('\n'));
        setEnabledVerifiers(result.enabled_verifiers || []);
        setValidationJsonText(JSON.stringify(result, null, 2));
        showValidationSuccess('Validation profile saved!');
      }
    } catch (err) {
      console.error('Failed to save validation profile:', err);
      setErrorMessage(err instanceof Error ? err.message : 'Failed to save validation profile');
    } finally {
      setIsValidationSaving(false);
    }
  };

  const handleApplyValidationPreset = async (preset: ValidationProfilePreset) => {
    setIsValidationSaving(true);
    setErrorMessage(null);
    try {
      const result = await projects.applyValidationProfilePreset(projectId, preset);
      setValidationProfile(result);
      setSelectedValidationPreset(preset);
      if (result) {
        setExcludedPathsText((result.excluded_paths || []).join('\n'));
        setEnabledVerifiers(result.enabled_verifiers || []);
        setValidationJsonText(JSON.stringify(result, null, 2));
        setValidationSuccessMessage(`Applied "${preset}" preset and saved!`);
        setTimeout(() => setValidationSuccessMessage(null), 4000);
      }
    } catch (err) {
      console.error('Failed to apply validation preset:', err);
      setErrorMessage(err instanceof Error ? err.message : 'Failed to apply validation preset');
    } finally {
      setIsValidationSaving(false);
    }
  };

  const [isAutoConfiguring, setIsAutoConfiguring] = useState(false);
  const [validationSuccessMessage, setValidationSuccessMessage] = useState<string | null>(null);

  const showValidationSuccess = (message: string) => {
    setValidationSuccessMessage(message);
    setTimeout(() => setValidationSuccessMessage(null), 4000);
  };

  const handleAutoConfigureValidation = async () => {
    setIsAutoConfiguring(true);
    setErrorMessage(null);
    setValidationSuccessMessage(null);
    try {
      const result = await projects.autoConfigureValidationProfile(projectId);
      setValidationProfile(result);
      setSelectedValidationPreset(null); // Custom profile
      if (result) {
        setExcludedPathsText((result.excluded_paths || []).join('\n'));
        setEnabledVerifiers(result.enabled_verifiers || []);
        setValidationJsonText(JSON.stringify(result, null, 2));
        const pathCount = result.excluded_paths?.length || 0;
        showValidationSuccess(`Auto-configured and saved! ${pathCount} paths excluded.`);
      }
    } catch (err) {
      console.error('Failed to auto-configure validation profile:', err);
      setErrorMessage(err instanceof Error ? err.message : 'Failed to auto-configure. Make sure the project has a valid path.');
    } finally {
      setIsAutoConfiguring(false);
    }
  };

  useEffect(() => {
    if (!isOpen) return;
    setActiveTab('visual');
    // Load both profiles in parallel for faster modal open
    void Promise.all([loadProfile(), loadValidationProfile()]);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isOpen, projectId]);

  useEffect(() => {
    if (!isOpen) return;
    if (presetPreview) setSelectedPreset(presetPreview);
  }, [isOpen, presetPreview]);

  const closeWithConfirm = () => {
    if (isDirty && !confirm('Discard unsaved changes?')) return;
    onClose();
  };

  const handleResetToPreset = async () => {
    if (!effective) return;
    if (!confirm(`Reset profile to preset ${selectedPreset}? This discards unsaved changes.`)) return;

    setIsSaving(true);
    setErrorMessage(null);
    try {
      const updated = await projects.updateThreatModelProfile(projectId, {
        action: 'reset_to_preset',
        preset: selectedPreset,
        expected_profile_hash: effective.profile_hash,
      });
      setEffective(updated);
      setDraft(updated.threat_model_profile);
      setSelectedPreset(updated.threat_model_preset);
      setJsonText(JSON.stringify(updated.threat_model_profile, null, 2));
      setJsonError(null);
      onProfileUpdated?.();
    } catch (err) {
      if (err instanceof APIError && err.status === 409) {
        const details = err.details as any;
        if (details?.current_profile) {
          setEffective(details.current_profile);
          setDraft(details.current_profile.threat_model_profile);
          setSelectedPreset(details.current_profile.threat_model_preset);
          setJsonText(JSON.stringify(details.current_profile.threat_model_profile, null, 2));
        }
        setErrorMessage('Threat model profile changed concurrently; reloaded latest.');
      } else {
        setErrorMessage(err instanceof Error ? err.message : 'Failed to reset profile');
      }
    } finally {
      setIsSaving(false);
    }
  };

  const handleSaveCustom = async () => {
    if (!effective || !draft) return;
    setIsSaving(true);
    setErrorMessage(null);
    try {
      const updated = await projects.updateThreatModelProfile(projectId, {
        action: 'save_custom',
        preset: effective.threat_model_preset,
        profile: draft,
        expected_profile_hash: effective.profile_hash,
      });
      setEffective(updated);
      setDraft(updated.threat_model_profile);
      setSelectedPreset(updated.threat_model_preset);
      setJsonText(JSON.stringify(updated.threat_model_profile, null, 2));
      setJsonError(null);
      onProfileUpdated?.();
    } catch (err) {
      if (err instanceof APIError && err.status === 409) {
        const details = err.details as any;
        if (details?.current_profile) {
          setEffective(details.current_profile);
          setSelectedPreset(details.current_profile.threat_model_preset);
        }
        setErrorMessage('Threat model profile changed concurrently; please retry.');
      } else {
        setErrorMessage(err instanceof Error ? err.message : 'Failed to save profile');
      }
    } finally {
      setIsSaving(false);
    }
  };

  const handleMarkReviewed = async () => {
    if (!effective) return;
    setIsSaving(true);
    setErrorMessage(null);
    try {
      const updated = await projects.updateThreatModelProfile(projectId, {
        action: 'mark_reviewed',
        expected_profile_hash: effective.profile_hash,
      });
      setEffective(updated);
      onProfileUpdated?.();
    } catch (err) {
      if (err instanceof APIError && err.status === 409) {
        setErrorMessage('Threat model profile changed concurrently; re-open to review the latest.');
      } else {
        setErrorMessage(err instanceof Error ? err.message : 'Failed to mark reviewed');
      }
    } finally {
      setIsSaving(false);
    }
  };

  const onJsonChanged = (text: string) => {
    setJsonText(text);
    try {
      const parsed = JSON.parse(text);
      const validated = validateProfileShape(parsed);
      if (!validated.ok || !validated.profile) {
        setJsonError(validated.error || 'Invalid JSON.');
        return;
      }
      setJsonError(null);
      setDraft(validated.profile);
    } catch (e) {
      setJsonError('Invalid JSON.');
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <div className="bg-vsc-sidebar w-[820px] max-h-[85vh] rounded-lg border border-vsc-border-subtle shadow-2xl flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-vsc-border-subtle">
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5" />
            <h2 className="text-lg font-semibold">Project Threat Model</h2>
            {effective?.profile_review_status === 'unreviewed' && (
              <span className="px-2 py-0.5 rounded text-vsc-xs bg-yellow-900/40 text-yellow-200 border border-yellow-800">
                Unreviewed
              </span>
            )}
          </div>
          <button onClick={closeWithConfirm} className="btn-icon">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-4">
          {isLoading || !effective || !draft ? (
            <div className="text-vsc-text-muted">Loading…</div>
          ) : (
            <>
              <div className="flex items-center justify-between gap-3 mb-4">
                <div className="flex items-center gap-3">
                  <div>
                    <div className="text-vsc-xs text-vsc-text-muted">Preset (preview)</div>
                    <div className="flex gap-2 mt-1">
                      {(['A', 'AB', 'ABC'] as ThreatModelPreset[]).map((p) => (
                        <button
                          key={p}
                          onClick={() => setSelectedPreset(p)}
                          className={`px-3 py-1 rounded border text-vsc-xs ${
                            selectedPreset === p
                              ? 'bg-vsc-input border-vsc-border text-vsc-text'
                              : 'bg-transparent border-vsc-border-subtle text-vsc-text-muted hover:text-vsc-text'
                          }`}
                        >
                          {p}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div className="text-vsc-xs text-vsc-text-muted">
                    Effective: <span className="text-vsc-text">{effective.threat_model_preset}</span> · Source:{' '}
                    <span className="text-vsc-text">{effective.profile_source}</span>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={handleResetToPreset}
                    disabled={isSaving}
                    className="px-3 py-1 rounded text-vsc-xs bg-vsc-input border border-vsc-border hover:bg-vsc-bg disabled:opacity-50"
                    title="Overwrite the profile with the selected preset mapping"
                  >
                    Reset to preset
                  </button>
                  {effective.profile_review_status === 'unreviewed' && !isDirty && (
                    <button
                      onClick={handleMarkReviewed}
                      disabled={isSaving}
                      className="px-3 py-1 rounded text-vsc-xs bg-green-700/60 border border-green-700 hover:bg-green-700/80 disabled:opacity-50 flex items-center gap-1"
                      title="Acknowledge this exact profile (optimistic concurrency enforced)"
                    >
                      <CheckCircle className="w-3 h-3" />
                      Mark reviewed
                    </button>
                  )}
                  <button
                    onClick={handleSaveCustom}
                    disabled={isSaving || !isDirty || !!jsonError}
                    className="px-3 py-1 rounded text-vsc-xs bg-vsc-accent/80 border border-vsc-accent hover:bg-vsc-accent disabled:opacity-50 flex items-center gap-1"
                    title="Save the current selections as a custom profile"
                  >
                    <Save className="w-3 h-3" />
                    Save
                  </button>
                </div>
              </div>

              {errorMessage && (
                <div className="mb-3 px-3 py-2 rounded bg-red-900/30 border border-red-800 text-vsc-xs text-red-200">
                  {errorMessage}
                </div>
              )}

              <div className="mb-3 px-3 py-2 rounded bg-vsc-bg border border-vsc-border-subtle text-vsc-xs text-vsc-text-muted">
                <div className="flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 text-yellow-400 mt-0.5" />
                  <div>
                    <div className="text-vsc-text">UNTRUSTED ≠ attacker-controlled</div>
                    <div>
                      Repo checkout content is treated as attacker-controlled only when{' '}
                      <span className="text-vsc-text">untrusted_repo_content</span> is enabled.
                    </div>
                    <div className="mt-1">
                      Derived attacker-controlled input channels:{' '}
                      <span className="text-vsc-text">{attackerControlledChannels.join(', ') || 'none'}</span>
                    </div>
                  </div>
                </div>
              </div>

              {hasHighNoiseCaps && (
                <div className="mb-3 px-3 py-2 rounded bg-yellow-900/30 border border-yellow-800 text-vsc-xs text-yellow-100">
                  High-noise capabilities enabled (expect more findings / hardening). Review carefully.
                </div>
              )}

              {/* Tabs */}
              <div className="flex gap-2 mb-3">
                <button
                  onClick={() => {
                    setActiveTab('visual');
                    setJsonError(null);
                  }}
                  className={`px-3 py-1 rounded border text-vsc-xs ${
                    activeTab === 'visual'
                      ? 'bg-vsc-input border-vsc-border text-vsc-text'
                      : 'bg-transparent border-vsc-border-subtle text-vsc-text-muted hover:text-vsc-text'
                  }`}
                >
                  Visual
                </button>
                <button
                  onClick={() => {
                    setActiveTab('json');
                    setJsonText(JSON.stringify(draft, null, 2));
                    setJsonError(null);
                  }}
                  className={`px-3 py-1 rounded border text-vsc-xs ${
                    activeTab === 'json'
                      ? 'bg-vsc-input border-vsc-border text-vsc-text'
                      : 'bg-transparent border-vsc-border-subtle text-vsc-text-muted hover:text-vsc-text'
                  }`}
                >
                  Advanced JSON
                </button>
              </div>

              {activeTab === 'json' ? (
                <div>
                  <textarea
                    value={jsonText}
                    onChange={(e) => onJsonChanged(e.target.value)}
                    className="w-full h-[380px] font-mono text-vsc-xs bg-vsc-input border border-vsc-border rounded p-3"
                    spellCheck={false}
                  />
                  {jsonError && (
                    <div className="mt-2 text-vsc-xs text-red-200 bg-red-900/30 border border-red-800 rounded px-3 py-2">
                      {jsonError}
                    </div>
                  )}
                </div>
              ) : (
                <div className="grid grid-cols-3 gap-3">
                  <div className="border border-vsc-border-subtle rounded p-3">
                    <div className="text-vsc-xs text-vsc-text-muted mb-2">Execution contexts</div>
                    {EXECUTION_CONTEXTS.map((item) => (
                      <label key={item.value} className="flex items-start gap-2 mb-2 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={draft.execution_contexts.includes(item.value)}
                          onChange={() =>
                            setDraft({
                              ...draft,
                              execution_contexts: toggleItem(draft.execution_contexts, item.value),
                            })
                          }
                        />
                        <span className="text-vsc-xs">
                          <span className="text-vsc-text">{item.label}</span>
                          <span className="text-vsc-text-muted"> — {item.description}</span>
                        </span>
                      </label>
                    ))}
                  </div>

                  <div className="border border-vsc-border-subtle rounded p-3">
                    <div className="text-vsc-xs text-vsc-text-muted mb-2">Attacker capabilities</div>
                    {ATTACKER_CAPABILITIES.map((item) => (
                      <label key={item.value} className="flex items-start gap-2 mb-2 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={draft.attacker_capabilities.includes(item.value)}
                          onChange={() =>
                            setDraft({
                              ...draft,
                              attacker_capabilities: toggleItem(draft.attacker_capabilities, item.value),
                            })
                          }
                        />
                        <span className="text-vsc-xs">
                          <span className="text-vsc-text">
                            {item.label}
                            {item.warn && <span className="ml-1 text-yellow-300">(high-noise)</span>}
                          </span>
                          <span className="text-vsc-text-muted"> — {item.description}</span>
                        </span>
                      </label>
                    ))}
                  </div>

                  <div className="border border-vsc-border-subtle rounded p-3">
                    <div className="text-vsc-xs text-vsc-text-muted mb-2">Assets</div>
                    {ASSETS.map((item) => (
                      <label key={item.value} className="flex items-start gap-2 mb-2 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={draft.assets.includes(item.value)}
                          onChange={() =>
                            setDraft({
                              ...draft,
                              assets: toggleItem(draft.assets, item.value),
                            })
                          }
                        />
                        <span className="text-vsc-xs">
                          <span className="text-vsc-text">{item.label}</span>
                          <span className="text-vsc-text-muted"> — {item.description}</span>
                        </span>
                      </label>
                    ))}
                  </div>
                </div>
              )}

              {/* Validation Profile Section */}
              <div className="mt-4 border border-vsc-border-subtle rounded">
                <button
                  onClick={() => setValidationExpanded(!validationExpanded)}
                  className="w-full flex items-center justify-between px-3 py-2 text-vsc-xs text-vsc-text hover:bg-vsc-input/50"
                >
                  <div className="flex items-center gap-2">
                    {validationExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                    <span className="font-medium">LLM Validation Profile</span>
                    {selectedValidationPreset && (
                      <span className="px-2 py-0.5 rounded bg-vsc-accent/20 text-vsc-accent text-vsc-xs">
                        {VALIDATION_PRESETS.find((p) => p.value === selectedValidationPreset)?.label || selectedValidationPreset}
                      </span>
                    )}
                  </div>
                  <span className="text-vsc-text-muted">Configure strict validation for findings</span>
                </button>

                {validationExpanded && (
                  <div className="px-3 py-3 border-t border-vsc-border-subtle">
                    {/* Auto-configure and Preset selector */}
                    <div className="mb-4">
                      <div className="flex items-center justify-between mb-3">
                        <div>
                          <div className="text-vsc-xs text-vsc-text-muted mb-2">Apply preset</div>
                          <div className="flex flex-wrap gap-2">
                            {VALIDATION_PRESETS.map((preset) => (
                              <button
                                key={preset.value}
                                onClick={() => handleApplyValidationPreset(preset.value)}
                                disabled={isValidationSaving || isAutoConfiguring}
                                className={`px-3 py-1 rounded border text-vsc-xs disabled:opacity-50 ${
                                  selectedValidationPreset === preset.value
                                    ? 'bg-vsc-accent/20 border-vsc-accent text-vsc-text'
                                    : 'bg-transparent border-vsc-border-subtle text-vsc-text-muted hover:text-vsc-text hover:border-vsc-border'
                                }`}
                                title={preset.description}
                              >
                                {preset.label}
                              </button>
                            ))}
                          </div>
                        </div>

                        <div className="text-right">
                          <div className="text-vsc-xs text-vsc-text-muted mb-2">Or let AI analyze your codebase</div>
                          <button
                            onClick={handleAutoConfigureValidation}
                            disabled={isValidationSaving || isAutoConfiguring}
                            className="px-4 py-2 rounded border text-vsc-xs bg-green-700/40 border-green-600 text-green-200 hover:bg-green-700/60 disabled:opacity-50 flex items-center gap-2 ml-auto"
                            title="Analyze codebase structure and auto-configure excluded paths"
                          >
                            {isAutoConfiguring ? (
                              <>
                                <span className="animate-spin">⟳</span>
                                Analyzing...
                              </>
                            ) : (
                              <>
                                <span>✨</span>
                                Auto-configure
                              </>
                            )}
                          </button>
                        </div>
                      </div>

                      {isAutoConfiguring && (
                        <div className="mb-3 px-3 py-2 rounded bg-green-900/20 border border-green-800 text-vsc-xs text-green-200">
                          Analyzing codebase structure to suggest optimal settings... This may take a few seconds.
                        </div>
                      )}

                      {validationSuccessMessage && (
                        <div className="mb-3 px-3 py-2 rounded bg-green-900/40 border border-green-600 text-vsc-xs text-green-200 flex items-center gap-2">
                          <span>✓</span>
                          {validationSuccessMessage}
                        </div>
                      )}
                    </div>

                    {/* Toggle between simple and JSON mode */}
                    <div className="flex gap-2 mb-3">
                      <button
                        onClick={() => setShowValidationJson(false)}
                        className={`px-3 py-1 rounded border text-vsc-xs ${
                          !showValidationJson
                            ? 'bg-vsc-input border-vsc-border text-vsc-text'
                            : 'bg-transparent border-vsc-border-subtle text-vsc-text-muted hover:text-vsc-text'
                        }`}
                      >
                        Simple
                      </button>
                      <button
                        onClick={() => {
                          setShowValidationJson(true);
                          setValidationJsonText(JSON.stringify(validationProfile || {}, null, 2));
                        }}
                        className={`px-3 py-1 rounded border text-vsc-xs ${
                          showValidationJson
                            ? 'bg-vsc-input border-vsc-border text-vsc-text'
                            : 'bg-transparent border-vsc-border-subtle text-vsc-text-muted hover:text-vsc-text'
                        }`}
                      >
                        Advanced JSON
                      </button>
                    </div>

                    {showValidationJson ? (
                      <div>
                        <textarea
                          value={validationJsonText}
                          onChange={(e) => {
                            setValidationJsonText(e.target.value);
                            setValidationJsonError(null);
                          }}
                          className="w-full h-48 font-mono text-vsc-xs bg-vsc-input border border-vsc-border rounded p-2"
                          spellCheck={false}
                        />
                        {validationJsonError && (
                          <div className="mt-2 text-vsc-xs text-red-200 bg-red-900/30 border border-red-800 rounded px-3 py-2">
                            {validationJsonError}
                          </div>
                        )}
                      </div>
                    ) : (
                      <div className="grid grid-cols-2 gap-4">
                        {/* Left column: Excluded paths */}
                        <div>
                          <div className="text-vsc-xs text-vsc-text-muted mb-2">
                            Excluded paths <span className="text-vsc-text-muted">(one per line)</span>
                          </div>
                          <textarea
                            value={excludedPathsText}
                            onChange={(e) => setExcludedPathsText(e.target.value)}
                            placeholder="test/&#10;third_party/&#10;tools/&#10;docs/"
                            className="w-full h-32 font-mono text-vsc-xs bg-vsc-input border border-vsc-border rounded p-2"
                            spellCheck={false}
                          />
                          <div className="mt-1 text-vsc-xs text-vsc-text-muted">
                            Findings in these paths are auto-filtered
                          </div>
                        </div>

                        {/* Right column: Verifiers */}
                        <div>
                          <div className="text-vsc-xs text-vsc-text-muted mb-2">Verification tools</div>
                          <div className="space-y-2">
                            {VERIFIER_OPTIONS.map((item) => (
                              <label key={item.value} className="flex items-start gap-2 cursor-pointer">
                                <input
                                  type="checkbox"
                                  checked={enabledVerifiers.includes(item.value)}
                                  onChange={() =>
                                    setEnabledVerifiers(
                                      enabledVerifiers.includes(item.value)
                                        ? enabledVerifiers.filter((v) => v !== item.value)
                                        : [...enabledVerifiers, item.value]
                                    )
                                  }
                                  className="mt-0.5"
                                />
                                <span className="text-vsc-xs">
                                  <span className="text-vsc-text">{item.label}</span>
                                  <span className="text-vsc-text-muted"> — {item.description}</span>
                                </span>
                              </label>
                            ))}
                          </div>

                          <div className="mt-4 text-vsc-xs text-vsc-text-muted">
                            <div className="mb-1">Current attacker roles:</div>
                            <div className="text-vsc-text">
                              {validationProfile?.attacker_roles
                                ? Object.keys(validationProfile.attacker_roles).join(', ') || 'None'
                                : 'Not configured'}
                            </div>
                            <div className="mt-2 mb-1">Trust boundaries:</div>
                            <div className="text-vsc-text">
                              {validationProfile?.trust_boundaries
                                ? Object.keys(validationProfile.trust_boundaries).join(', ') || 'None'
                                : 'Not configured'}
                            </div>
                            <div className="mt-2 text-yellow-400">
                              Use Advanced JSON mode to edit attacker roles and trust boundaries.
                            </div>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Save button */}
                    <div className="mt-4 flex justify-end">
                      <button
                        onClick={handleSaveValidationProfile}
                        disabled={isValidationSaving}
                        className="px-3 py-1 rounded text-vsc-xs bg-vsc-accent/80 border border-vsc-accent hover:bg-vsc-accent disabled:opacity-50 flex items-center gap-1"
                      >
                        <Save className="w-3 h-3" />
                        {isValidationSaving ? 'Saving...' : 'Save Validation Profile'}
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between px-4 py-3 border-t border-vsc-border-subtle text-vsc-xs text-vsc-text-muted">
          <div>
            Project: <span className="text-vsc-text">{projectId}</span>
          </div>
          <div>
            {effective ? (
              <>
                Hash: <span className="text-vsc-text">{effective.profile_hash.slice(0, 8)}…</span>
              </>
            ) : null}
          </div>
        </div>
      </div>
    </div>
  );
}


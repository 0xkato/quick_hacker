/**
 * API client for quick_hack backend
 */

import type {
  RepoInfo,
  RepoCloneRequest,
  FileNode,
  FileContent,
  Finding,
  Campaign,
  CampaignCreateRequest,
  Target,
  LaneSpec,
  Artifact,
  ArtifactBucket,
  CoverageSummary,
  SteeringDecision,
  Issue,
  SnapshotInfo,
  SessionSnapshot,
  BTNode,
} from '@/types';
import type {
  ProtocolPolicy,
  EvidenceQuest,
} from '@/types/protocol';

// Token management
let getAccessToken: (() => string | null) | null = null;
let refreshTokenFn: (() => Promise<boolean>) | null = null;

export function setAuthFunctions(
  getToken: () => string | null,
  refresh: () => Promise<boolean>
) {
  getAccessToken = getToken;
  refreshTokenFn = refresh;
}

// Backwards-compatible auth initialization hook (kept for callers).
// Auth is now fully managed by AuthContext + JWT storage, so this is a no-op.
export async function initializeAuth(): Promise<void> {
  return;
}

// Default timeout for API requests (10 seconds)
const DEFAULT_TIMEOUT = 10000;

async function fetchWithAuth(
  url: string,
  options: RequestInit = {},
  timeout: number = DEFAULT_TIMEOUT
): Promise<Response> {
  const token = getAccessToken?.();
  const headers: HeadersInit = {
    ...options.headers,
  };

  if (token) {
    (headers as Record<string, string>)['Authorization'] = `Bearer ${token}`;
  }

  // Create abort controller for timeout
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);

  try {
    let response = await fetch(url, { ...options, headers, signal: controller.signal });

    // If unauthorized, try to refresh token and retry
    if (response.status === 401 && refreshTokenFn) {
      const refreshed = await refreshTokenFn();
      if (refreshed) {
        const newToken = getAccessToken?.();
        if (newToken) {
          (headers as Record<string, string>)['Authorization'] = `Bearer ${newToken}`;
          response = await fetch(url, { ...options, headers, signal: controller.signal });
        }
      }
    }

    return response;
  } finally {
    clearTimeout(timeoutId);
  }
}

export interface ObservabilityStats {
  total_interactions: number;
  request_count: number;
  response_count: number;
  tool_executions: number;
  tool_counts: Record<string, number>;
  token_usage: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
}

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export class APIError extends Error {
  constructor(
    public status: number,
    message: string,
    public details?: unknown
  ) {
    super(message);
    this.name = 'APIError';
  }
}

async function request<T>(
  endpoint: string,
  options: RequestInit = {},
  timeout: number = DEFAULT_TIMEOUT
): Promise<T> {
  const url = `${API_BASE}${endpoint}`;

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...options.headers as Record<string, string>,
  };

  let response: Response;
  try {
    response = await fetchWithAuth(url, {
      ...options,
      headers,
    }, timeout);
  } catch (error) {
    if (error instanceof Error && error.name === 'AbortError') {
      throw new APIError(0, 'Request timed out - backend may be unavailable');
    }
    throw error;
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }));
    const message =
      typeof (error as any)?.detail === 'string'
        ? (error as any).detail
        : typeof (error as any)?.error_code === 'string'
          ? (error as any).error_code
          : 'Request failed';
    throw new APIError(response.status, message, error);
  }

  return response.json();
}

// === Git API ===

// Clone timeout - 30 minutes for large repos
const CLONE_TIMEOUT = 30 * 60 * 1000;

export const git = {
  async clone(req: RepoCloneRequest): Promise<RepoInfo> {
    return request<RepoInfo>('/api/git/clone', {
      method: 'POST',
      body: JSON.stringify(req),
    }, CLONE_TIMEOUT);
  },

  async list(): Promise<RepoInfo[]> {
    return request<RepoInfo[]>('/api/git/repos');
  },

  async get(repoId: string): Promise<RepoInfo> {
    return request<RepoInfo>(`/api/git/repos/${repoId}`);
  },

  async delete(repoId: string): Promise<void> {
    await request(`/api/git/repos/${repoId}`, { method: 'DELETE' });
  },

  async refresh(repoId: string): Promise<RepoInfo> {
    return request<RepoInfo>(`/api/git/repos/${repoId}/refresh`, {
      method: 'POST',
    });
  },
};

// === Files API ===

export const files = {
  async getTree(
    repoId: string,
    maxDepth = 1,
    path: string = '',
    options?: { maxChildren?: number; maxNodes?: number }
  ): Promise<FileNode> {
    const params = new URLSearchParams();
    params.set('max_depth', String(maxDepth));
    if (path) params.set('path', path);
    if (options?.maxChildren !== undefined) params.set('max_children', String(options.maxChildren));
    if (options?.maxNodes !== undefined) params.set('max_nodes', String(options.maxNodes));
    return request<FileNode>(`/api/files/${repoId}/tree?${params.toString()}`);
  },

  async getContent(repoId: string, path: string): Promise<FileContent> {
    return request<FileContent>(
      `/api/files/${repoId}/content?path=${encodeURIComponent(path)}`
    );
  },

  async listByExtension(
    repoId: string,
    extensions: string[],
    maxFiles = 500
  ): Promise<{ files: string[]; count: number }> {
    const ext = extensions.join(',');
    return request(`/api/files/${repoId}/files?extensions=${ext}&max_files=${maxFiles}`);
  },

  async search(
    repoId: string,
    pattern: string,
    maxResults = 100
  ): Promise<{ results: Array<{ file: string; line: number; content: string }>; count: number }> {
    return request(
      `/api/files/${repoId}/search?pattern=${encodeURIComponent(pattern)}&max_results=${maxResults}`
    );
  },
};

// === Campaign API ===

export const campaigns = {
  async create(data: CampaignCreateRequest): Promise<Campaign> {
    return request<Campaign>('/api/campaigns', { method: 'POST', body: JSON.stringify(data) });
  },
  async list(repoId?: string): Promise<Campaign[]> {
    const params = repoId ? `?repo_id=${repoId}` : '';
    return request<Campaign[]>(`/api/campaigns${params}`);
  },
  async get(id: string): Promise<Campaign> {
    return request<Campaign>(`/api/campaigns/${id}`);
  },
  async plan(id: string): Promise<Campaign> {
    return request<Campaign>(`/api/campaigns/${id}/plan`, { method: 'POST' });
  },
  async start(id: string): Promise<Campaign> {
    return request<Campaign>(`/api/campaigns/${id}/start`, { method: 'POST' });
  },
  async pause(id: string): Promise<Campaign> {
    return request<Campaign>(`/api/campaigns/${id}/pause`, { method: 'POST' });
  },
  async resume(id: string): Promise<Campaign> {
    return request<Campaign>(`/api/campaigns/${id}/resume`, { method: 'POST' });
  },
  async cancel(id: string): Promise<Campaign> {
    return request<Campaign>(`/api/campaigns/${id}/cancel`, { method: 'POST' });
  },
  async delete(id: string): Promise<{ status: string; id: string }> {
    return request(`/api/campaigns/${id}`, { method: 'DELETE' });
  },
  async getTargets(id: string): Promise<Target[]> {
    return request<Target[]>(`/api/campaigns/${id}/targets`);
  },
  async getLanes(id: string): Promise<LaneSpec[]> {
    return request<LaneSpec[]>(`/api/campaigns/${id}/lanes`);
  },
  async getArtifacts(id: string): Promise<Artifact[]> {
    return request<Artifact[]>(`/api/campaigns/${id}/artifacts`);
  },
  async getArtifactBuckets(id: string): Promise<ArtifactBucket[]> {
    return request<ArtifactBucket[]>(`/api/campaigns/${id}/artifact-buckets`);
  },
  async getCoverage(id: string): Promise<CoverageSummary> {
    return request<CoverageSummary>(`/api/campaigns/${id}/coverage`);
  },
  async getSteering(id: string): Promise<SteeringDecision[]> {
    return request<SteeringDecision[]>(`/api/campaigns/${id}/steering`);
  },
  async getIssues(id: string): Promise<Issue[]> {
    return request<Issue[]>(`/api/campaigns/${id}/issues`);
  },
  async getGraph(id: string) {
    return request(`/api/campaigns/${id}/graph`);
  },
  async getPlan(id: string) {
    return request(`/api/campaigns/${id}/plan`);
  },
  async getPlans(id: string) {
    return request(`/api/campaigns/${id}/plans`);
  },
  async createLane(id: string, data: Record<string, unknown>): Promise<LaneSpec> {
    return request<LaneSpec>(`/api/campaigns/${id}/lanes`, { method: 'POST', body: JSON.stringify(data) });
  },
};

export const targets = {
  async get(id: string) {
    return request(`/api/targets/${id}`);
  },
  async getLanes(id: string) {
    return request(`/api/targets/${id}/lanes`);
  },
  async reprioritize(id: string, priority_score: number) {
    return request(`/api/targets/${id}/reprioritize`, { method: 'POST', body: JSON.stringify({ priority_score }) });
  },
};

export const lanes = {
  async get(id: string) {
    return request(`/api/lanes/${id}`);
  },
  async getRuns(id: string) {
    return request(`/api/lanes/${id}/runs`);
  },
  async getHarnesses(id: string) {
    return request(`/api/lanes/${id}/harnesses`);
  },
  async getCoverage(id: string) {
    return request(`/api/lanes/${id}/coverage`);
  },
  async getOraclePacks(id: string) {
    return request(`/api/lanes/${id}/oracle-packs`);
  },
  async recompile(id: string) {
    return request(`/api/lanes/${id}/recompile`, { method: 'POST' });
  },
  async restart(id: string) {
    return request(`/api/lanes/${id}/restart`, { method: 'POST' });
  },
  async steer(id: string) {
    return request(`/api/lanes/${id}/steer`, { method: 'POST' });
  },
  async getCorpus(id: string) {
    return request(`/api/lanes/${id}/corpus`);
  },
  async pruneCorpus(id: string) {
    return request(`/api/lanes/${id}/corpus/prune`, { method: 'POST' });
  },
};

export const runs = {
  async get(id: string) {
    return request(`/api/runs/${id}`);
  },
  async getMetrics(id: string) {
    return request(`/api/runs/${id}/metrics`);
  },
  async cancel(id: string) {
    return request(`/api/runs/${id}/cancel`, { method: 'POST' });
  },
  async getLogs(id: string) {
    return request(`/api/runs/${id}/logs`);
  },
};

export const artifacts = {
  async get(id: string) {
    return request(`/api/artifacts/${id}`);
  },
  async replay(id: string) {
    return request(`/api/artifacts/${id}/replay`, { method: 'POST' });
  },
  async minimize(id: string) {
    return request(`/api/artifacts/${id}/minimize`, { method: 'POST' });
  },
  async classify(id: string, classification: string, analysis_outcome?: string) {
    return request(`/api/artifacts/${id}/classify`, { method: 'POST', body: JSON.stringify({ classification, analysis_outcome }) });
  },
  async getBucket(bucketId: string) {
    return request(`/api/artifacts/buckets/${bucketId}`);
  },
  async getEvidence(id: string) {
    return request(`/api/artifacts/${id}/evidence`);
  },
};

export const issues = {
  async get(id: string) {
    return request(`/api/issues/${id}`);
  },
  async revalidate(id: string) {
    return request(`/api/issues/${id}/revalidate`, { method: 'POST' });
  },
  async getRegressionTest(id: string) {
    return request(`/api/issues/${id}/regression-test`);
  },
};

export const harnesses = {
  async get(id: string) {
    return request(`/api/harnesses/${id}`);
  },
  async getValidation(id: string) {
    return request(`/api/harnesses/${id}/validation`);
  },
  async getRevisions(id: string) {
    return request(`/api/harnesses/${id}/revisions`);
  },
};

export const oraclePacks = {
  async get(id: string) {
    return request(`/api/oracle-packs/${id}`);
  },
  async getRevisions(id: string) {
    return request(`/api/oracle-packs/${id}/revisions`);
  },
};

// === Settings API ===

export interface ProviderSettings {
  enabled: boolean;
  api_key: string;
  base_url?: string;
  default_model: string;
  available_models: string[];
  custom_models: string[];  // User-added custom model names
  rate_limit: number;
}

export interface AgentDefaults {
  default_provider: string;
  default_model: string;
  strict_mode_default: boolean;
  max_concurrent_agents: number;
  auto_verify_findings: boolean;
  confidence_threshold: number;
}

export interface UIPreferences {
  theme: string;
  editor_font_size: number;
  show_line_numbers: boolean;
  auto_expand_findings: boolean;
  chat_position: string;
  chat_width: number;
  findings_panel_height: number;
}

export interface AppSettings {
  providers: Record<string, ProviderSettings>;
  agent_defaults: AgentDefaults;
  custom_prompts: Record<string, any>;
  ui_preferences: UIPreferences;
}

export const settings = {
  async getAll(): Promise<AppSettings> {
    return request<AppSettings>('/api/settings');
  },

  async getProviders(): Promise<Record<string, ProviderSettings>> {
    return request('/api/settings/providers');
  },

  async updateProvider(provider: string, data: Partial<ProviderSettings>): Promise<void> {
    await request(`/api/settings/providers/${provider}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },

  async testProvider(provider: string): Promise<{ status: string; message: string }> {
    return request(`/api/settings/providers/${provider}/test`, { method: 'POST' });
  },

  async getAgentDefaults(): Promise<AgentDefaults> {
    return request('/api/settings/agent-defaults');
  },

  async updateAgentDefaults(data: Partial<AgentDefaults>): Promise<void> {
    await request('/api/settings/agent-defaults', {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },

  async getUIPreferences(): Promise<UIPreferences> {
    return request('/api/settings/ui');
  },

  async updateUIPreferences(data: Partial<UIPreferences>): Promise<void> {
    await request('/api/settings/ui', {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },

  async getPrompts(): Promise<Record<string, any>> {
    return request('/api/settings/prompts');
  },

  async createPrompt(prompt: any): Promise<void> {
    await request('/api/settings/prompts', {
      method: 'POST',
      body: JSON.stringify(prompt),
    });
  },

  async deletePrompt(promptId: string): Promise<void> {
    await request(`/api/settings/prompts/${promptId}`, { method: 'DELETE' });
  },
};

// === Chat API ===

export interface ChatMessage {
  role: 'user' | 'assistant' | 'system';
  content: string;
}

export interface ChatContext {
  type?: string;
  current_file?: string;
  file_content?: string;
  findings?: Finding[];
  selected_text?: string;
  flow_context_pack?: unknown;
  // Campaign fields
  campaign_id?: string;
  selected_target_id?: string;
  selected_lane_id?: string;
  selected_run_id?: string;
  selected_artifact_id?: string;
  selected_issue_id?: string;
  selected_graph_node_id?: string;
  selection_range?: { start: number; end: number };
}

export const chat = {
  async send(
    messages: ChatMessage[],
    context?: ChatContext,
    provider?: string,
    model?: string
  ): Promise<{ content: string; model: string; provider: string }> {
    return request('/api/chat', {
      method: 'POST',
      body: JSON.stringify({
        messages,
        context,
        provider,
        model,
        stream: false,
      }),
    });
  },

  async *stream(
    messages: ChatMessage[],
    context?: ChatContext,
    provider?: string,
    model?: string
  ): AsyncGenerator<string, void, unknown> {
    const response = await fetchWithAuth(`${API_BASE}/api/chat/stream`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        messages,
        context,
        provider,
        model,
        stream: true,
      }),
    });

    if (!response.ok) {
      throw new APIError(response.status, 'Chat stream failed');
    }

    const reader = response.body?.getReader();
    if (!reader) return;

    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';

      for (const line of lines) {
        if (line.startsWith('data: ')) {
          try {
            const data = JSON.parse(line.slice(6));
            if (data.error) {
              throw new Error(data.error);
            }
            if (data.content) {
              yield data.content;
            }
            if (data.done) {
              return;
            }
          } catch (e) {
            // Skip invalid JSON
          }
        }
      }
    }
  },

  async getPrompts(): Promise<Record<string, string>> {
    return request('/api/chat/prompts');
  },
};

// === Projects API ===

export interface Project {
  id: string;
  name: string;
  description: string;
  threat_model?: 'A' | 'AB' | 'ABC';
  threat_model_preset?: 'A' | 'AB' | 'ABC';
  threat_model_profile?: {
    execution_contexts: string[];
    attacker_capabilities: string[];
    assets: string[];
  } | null;
  profile_source?: 'preset' | 'custom' | 'migrated';
  profile_review_status?: 'unreviewed' | 'reviewed';
  profile_reviewed_at?: string | null;
  profile_mapping_version?: number;
  input_channel_semantics_version?: number;
  prompt_threat_model_block_version?: number;
  repo_url: string | null;
  repo_name: string | null;
  repo_branch: string | null;
  languages: string[];
  file_count: number;
  created_at: string;
  last_accessed: string;
  is_cloned: boolean;
  path: string;
}

export interface ProjectStatus {
  in_project: boolean;
  current_project: Project | null;
}

export type ThreatModelPreset = 'A' | 'AB' | 'ABC';

export type ExecutionContext =
  | 'product_runtime'
  | 'server_runtime'
  | 'dev_tooling'
  | 'ci_pipeline'
  | 'test_harness'
  | 'test_code'
  | 'build_release';

export type AttackerCapability =
  | 'remote_network'
  | 'remote_web_content'
  | 'untrusted_file_input'
  | 'untrusted_repo_content'
  | 'untrusted_ci_artifact'
  | 'local_unprivileged_user';

export type Asset =
  | 'user_data'
  | 'credentials_secrets'
  | 'availability'
  | 'integrity_of_build'
  | 'integrity_of_release_artifacts'
  | 'developer_machine_integrity';

export interface ThreatModelProfile {
  execution_contexts: ExecutionContext[];
  attacker_capabilities: AttackerCapability[];
  assets: Asset[];
}

export interface ThreatModelProfileResponse {
  threat_model_preset: ThreatModelPreset;
  profile_source: 'preset' | 'custom' | 'migrated';
  profile_review_status: 'unreviewed' | 'reviewed';
  profile_reviewed_at: string | null;
  profile_mapping_version: number;
  input_channel_semantics_version: number;
  prompt_threat_model_block_version: number;
  threat_model_profile: ThreatModelProfile;
  profile_hash: string;
}

// === Validation Profile Types ===

export type ValidationProfilePreset = 'large_c_codebase' | 'webapp' | 'strict' | 'blank';

export interface AttackerRoleDefinition {
  can_control: string[];
  cannot_control: string[];
  inherits?: string | null;
  trust_boundary?: string | null;
  exceptions?: Record<string, string>;
}

export interface TrustBoundaryDefinition {
  untrusted_side: string[];
  trusted_side: string[];
  description?: string | null;
}

export interface CategoryEvidenceGate {
  required: string[];
  reject_if?: string[];
  verifiers?: string[];
}

export interface ValidationProfile {
  excluded_paths?: string[];
  attacker_roles?: Record<string, AttackerRoleDefinition>;
  trust_boundaries?: Record<string, TrustBoundaryDefinition>;
  evidence_gates?: Record<string, CategoryEvidenceGate>;
  enabled_verifiers?: string[];
  default_verdict?: string;
  require_shipped_reachability?: boolean;
}


export type ThreatModelProfileUpdateRequest =
  | { action: 'mark_reviewed'; expected_profile_hash: string }
  | { action: 'reset_to_preset'; preset: ThreatModelPreset; expected_profile_hash: string }
  | { action: 'save_custom'; preset: ThreatModelPreset; profile: ThreatModelProfile; expected_profile_hash: string };

export const projects = {
  async list(): Promise<Project[]> {
    return request<Project[]>('/api/projects');
  },

  async create(name: string, description: string = ''): Promise<Project> {
    return request<Project>('/api/projects', {
      method: 'POST',
      body: JSON.stringify({ name, description }),
    });
  },

  async get(projectId: string): Promise<Project> {
    return request<Project>(`/api/projects/${projectId}`);
  },

  async update(
    projectId: string,
    data: { name?: string; description?: string; threat_model?: 'A' | 'AB' | 'ABC' }
  ): Promise<Project> {
    return request<Project>(`/api/projects/${projectId}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },

  async delete(projectId: string): Promise<void> {
    await request(`/api/projects/${projectId}`, { method: 'DELETE' });
  },

  async getStatus(): Promise<ProjectStatus> {
    return request<ProjectStatus>('/api/projects/status');
  },

  async enter(projectId: string): Promise<Project> {
    return request<Project>(`/api/projects/${projectId}/enter`, { method: 'POST' });
  },

  async exit(): Promise<void> {
    await request('/api/projects/exit', { method: 'POST' });
  },

  async clone(projectId: string, url: string, branch?: string, force: boolean = false): Promise<Project> {
    return request<Project>(`/api/projects/${projectId}/clone`, {
      method: 'POST',
      body: JSON.stringify({ url, branch, force }),
    }, CLONE_TIMEOUT);
  },

  async quickClone(url: string, branch?: string, projectName?: string, force: boolean = false): Promise<Project> {
    return request<Project>('/api/projects/quick-clone', {
      method: 'POST',
      body: JSON.stringify({ url, branch, project_name: projectName, force }),
    }, CLONE_TIMEOUT);
  },

  async refresh(projectId: string): Promise<Project> {
    return request<Project>(`/api/projects/${projectId}/refresh`, { method: 'POST' });
  },

  async getThreatModelProfile(projectId: string): Promise<ThreatModelProfileResponse> {
    return request<ThreatModelProfileResponse>(`/api/projects/${projectId}/threat-model-profile`);
  },

  async updateThreatModelProfile(
    projectId: string,
    payload: ThreatModelProfileUpdateRequest
  ): Promise<ThreatModelProfileResponse> {
    return request<ThreatModelProfileResponse>(`/api/projects/${projectId}/threat-model-profile`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    });
  },

  async getValidationProfile(projectId: string): Promise<ValidationProfile> {
    return request<ValidationProfile>(`/api/projects/${projectId}/validation-profile`);
  },

  async updateValidationProfile(
    projectId: string,
    profile: ValidationProfile
  ): Promise<ValidationProfile> {
    return request<ValidationProfile>(`/api/projects/${projectId}/validation-profile`, {
      method: 'PUT',
      body: JSON.stringify(profile),
    });
  },

  async applyValidationProfilePreset(
    projectId: string,
    presetName: ValidationProfilePreset
  ): Promise<ValidationProfile> {
    return request<ValidationProfile>(`/api/projects/${projectId}/validation-profile/apply-preset`, {
      method: 'POST',
      body: JSON.stringify({ preset_name: presetName }),
    });
  },

  async autoConfigureValidationProfile(projectId: string): Promise<ValidationProfile> {
    return request<ValidationProfile>(`/api/projects/${projectId}/validation-profile/auto-configure`, {
      method: 'POST',
    }, 180000);
  },
};

// === Health ===

export async function checkHealth(): Promise<boolean> {
  try {
    await request('/api/health');
    return true;
  } catch {
    return false;
  }
}

// === Auth API Keys ===

export interface ApiKeyValidationResult {
  valid: boolean;
  provider: string;
  error?: string;
}

export const authApiKeys = {
  async save(provider: string, apiKey: string): Promise<void> {
    await request('/api/auth/api-keys', {
      method: 'PUT',
      body: JSON.stringify({ provider, api_key: apiKey }),
    });
  },

  async validate(provider: string, apiKey: string): Promise<ApiKeyValidationResult> {
    return request<ApiKeyValidationResult>('/api/auth/api-keys/validate', {
      method: 'POST',
      body: JSON.stringify({ provider, api_key: apiKey }),
    });
  },

  async get(provider: string): Promise<{ has_key: boolean; masked_key?: string }> {
    return request(`/api/auth/api-keys/${provider}`);
  },

  async delete(provider: string): Promise<void> {
    await request(`/api/auth/api-keys/${provider}`, { method: 'DELETE' });
  },
};

// === Session API ===

export const session = {
  async getSnapshotInfo(): Promise<SnapshotInfo | null> {
    try {
      return await request<SnapshotInfo | null>('/api/session/snapshot');
    } catch (err) {
      if (err instanceof APIError && err.status === 404) {
        return null;
      }
      throw err;
    }
  },

  async pause(uiState?: {
    active_view: string;
    selected_file: string | null;
    open_panels: string[];
    selected_agent_id: string | null;
  }): Promise<{
    status: string;
    snapshot_path: string;
    agents_paused: number;
    findings_saved: number;
  }> {
    return request('/api/session/pause', {
      method: 'POST',
      body: JSON.stringify(uiState ? { ui_state: uiState } : {}),
    });
  },

  async resume(): Promise<{
    status: string;
    snapshot: SessionSnapshot;
  }> {
    return request('/api/session/resume', {
      method: 'POST',
    });
  },

  async deleteSnapshot(): Promise<void> {
    await request('/api/session/snapshot', { method: 'DELETE' });
  },
};

// === Protocol Policy API ===

export const protocolPolicies = {
  async list(): Promise<ProtocolPolicy[]> {
    const response = await request<{ policies: ProtocolPolicy[] }>('/api/protocol-policies');
    return response.policies;
  },

  async get(policyId: string): Promise<ProtocolPolicy> {
    return request<ProtocolPolicy>(`/api/protocol-policies/${policyId}`);
  },

  async updateProjectProtocol(projectId: string, protocolId: string): Promise<void> {
    await request(`/api/projects/${projectId}`, {
      method: 'PATCH',
      body: JSON.stringify({ protocol_id: protocolId }),
    });
  },
};

// === Evidence Quest API ===

export const evidenceQuests = {
  async trigger(findingId: string): Promise<void> {
    await request(`/api/findings/${findingId}/quests`, {
      method: 'POST',
    });
  },

  async listForFinding(findingId: string): Promise<EvidenceQuest[]> {
    const response = await request<{ quests: EvidenceQuest[] }>(`/api/findings/${findingId}/quests`);
    return response.quests;
  },

  async get(questId: string): Promise<EvidenceQuest> {
    return request<EvidenceQuest>(`/api/quests/${questId}`);
  },
};

// === Cache API ===

export interface CacheMetrics {
  enabled: boolean;
  hits: number;
  misses: number;
  hit_rate: number;
  size: number;
  cache_count?: number;
}

export const cache = {
  async getMetrics(): Promise<CacheMetrics> {
    return request<CacheMetrics>('/api/cache/metrics');
  },
};

export { API_BASE };

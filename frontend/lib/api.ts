/**
 * API client for quick_hack backend
 */

import type {
  RepoInfo,
  RepoCloneRequest,
  FileNode,
  FileContent,
  Agent,
  AgentCreateRequest,
  AgentStatus,
  Finding,
  AgentStats,
  InvestigationFlow,
  CallTreeRoute,
  LLMInteraction,
  ToolDetail,
  InvestigationReport,
  AgentStateSnapshot,
  SnapshotInfo,
  SessionSnapshot,
  CodeGraph,
  GraphStats,
  GraphNode,
} from '@/types';

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

async function fetchWithAuth(
  url: string,
  options: RequestInit = {}
): Promise<Response> {
  const token = getAccessToken?.();
  const headers: HeadersInit = {
    ...options.headers,
  };

  if (token) {
    (headers as Record<string, string>)['Authorization'] = `Bearer ${token}`;
  }

  let response = await fetch(url, { ...options, headers });

  // If unauthorized, try to refresh token and retry
  if (response.status === 401 && refreshTokenFn) {
    const refreshed = await refreshTokenFn();
    if (refreshed) {
      const newToken = getAccessToken?.();
      if (newToken) {
        (headers as Record<string, string>)['Authorization'] = `Bearer ${newToken}`;
        response = await fetch(url, { ...options, headers });
      }
    }
  }

  return response;
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

class APIError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = 'APIError';
  }
}

// Session token management
let _sessionToken: string | null = null;
let _tokenFetchPromise: Promise<string> | null = null;

export async function initializeAuth(): Promise<string> {
  /**
   * Fetch and store the session token for authenticated requests.
   * Call this once on app startup.
   */
  if (_sessionToken) return _sessionToken;

  // Prevent multiple concurrent fetches
  if (_tokenFetchPromise) return _tokenFetchPromise;

  _tokenFetchPromise = (async (): Promise<string> => {
    try {
      const response = await fetch(`${API_BASE}/api/auth/token`);
      if (response.ok) {
        const data = await response.json();
        const token: string = data.token || '';
        _sessionToken = token;
        console.log('[Auth] Token initialized');
        return token;
      }
    } catch (err) {
      console.error('Failed to initialize auth:', err);
    } finally {
      _tokenFetchPromise = null;
    }
    return '';
  })();

  return _tokenFetchPromise;
}

export async function refreshAuth(): Promise<string> {
  /**
   * Force refresh the session token.
   * Use when WebSocket connection fails with auth error.
   */
  _sessionToken = null;
  _tokenFetchPromise = null;
  console.log('[Auth] Refreshing token...');
  return initializeAuth();
}

export function getSessionToken(): string | null {
  return _sessionToken;
}

export function isAuthInitialized(): boolean {
  return _sessionToken !== null && _sessionToken.length > 0;
}

export function clearSessionToken(): void {
  _sessionToken = null;
  _tokenFetchPromise = null;
}

async function request<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const url = `${API_BASE}${endpoint}`;

  // Include session token in headers if available
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...options.headers as Record<string, string>,
  };

  if (_sessionToken) {
    headers['X-Session-Token'] = _sessionToken;
  }

  const response = await fetchWithAuth(url, {
    ...options,
    headers,
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }));
    throw new APIError(response.status, error.detail || 'Request failed');
  }

  return response.json();
}

// === Git API ===

export const git = {
  async clone(req: RepoCloneRequest): Promise<RepoInfo> {
    return request<RepoInfo>('/api/git/clone', {
      method: 'POST',
      body: JSON.stringify(req),
    });
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
  async getTree(repoId: string, maxDepth = 10): Promise<FileNode> {
    return request<FileNode>(`/api/files/${repoId}/tree?max_depth=${maxDepth}`);
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

// === Call Tree API ===

export const calltree = {
  async listRoutes(repoId: string): Promise<CallTreeRoute[]> {
    return request<CallTreeRoute[]>(`/api/calltree/${repoId}/routes`);
  },

  async getTree(
    repoId: string,
    routeId: string,
    options?: {
      maxDepth?: number;
      maxNodes?: number;
      includeExternal?: boolean;
    }
  ): Promise<InvestigationFlow> {
    const params = new URLSearchParams();
    params.set('route_id', routeId);
    if (options?.maxDepth !== undefined) params.set('max_depth', String(options.maxDepth));
    if (options?.maxNodes !== undefined) params.set('max_nodes', String(options.maxNodes));
    if (options?.includeExternal !== undefined) {
      params.set('include_external', String(options.includeExternal));
    }
    return request<InvestigationFlow>(`/api/calltree/${repoId}/tree?${params.toString()}`);
  },
};

// === Agents API ===

export const agents = {
  async create(req: AgentCreateRequest): Promise<Agent> {
    return request<Agent>('/api/agents', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  },

  async start(agentId: string): Promise<Agent> {
    return request<Agent>(`/api/agents/${agentId}/start`, { method: 'POST' });
  },

  async pause(agentId: string): Promise<Agent> {
    return request<Agent>(`/api/agents/${agentId}/pause`, { method: 'POST' });
  },

  async resume(agentId: string): Promise<Agent> {
    return request<Agent>(`/api/agents/${agentId}/resume`, { method: 'POST' });
  },

  async cancel(agentId: string): Promise<Agent> {
    return request<Agent>(`/api/agents/${agentId}/cancel`, { method: 'POST' });
  },

  async list(repoId?: string, status?: AgentStatus): Promise<Agent[]> {
    const params = new URLSearchParams();
    if (repoId) params.set('repo_id', repoId);
    if (status) params.set('status', status);
    const query = params.toString();
    return request<Agent[]>(`/api/agents${query ? `?${query}` : ''}`);
  },

  async get(agentId: string): Promise<Agent> {
    return request<Agent>(`/api/agents/${agentId}`);
  },

  async delete(agentId: string): Promise<void> {
    await request(`/api/agents/${agentId}`, { method: 'DELETE' });
  },

  async getFindings(agentId: string): Promise<Finding[]> {
    return request<Finding[]>(`/api/agents/${agentId}/findings`);
  },

  async getAllFindings(repoId?: string): Promise<Finding[]> {
    const query = repoId ? `?repo_id=${repoId}` : '';
    return request<Finding[]>(`/api/agents/findings/all${query}`);
  },

  async getStats(): Promise<AgentStats> {
    return request<AgentStats>('/api/agents/stats');
  },

  async getModels(): Promise<Record<string, string[]>> {
    return request<Record<string, string[]>>('/api/agents/models');
  },

  async getFlow(agentId: string): Promise<InvestigationFlow> {
    return request<InvestigationFlow>(`/api/agents/${agentId}/flow`);
  },

  async getFlowStats(agentId: string): Promise<Record<string, unknown>> {
    return request(`/api/agents/${agentId}/flow/stats`);
  },

  async clearFlow(agentId: string): Promise<void> {
    await request(`/api/agents/${agentId}/flow`, { method: 'DELETE' });
  },

  async queueInvestigation(
    agentId: string,
    nodeId: string,
    notes?: string
  ): Promise<{ queued: boolean; task_id?: string; reason?: string }> {
    return request(`/api/agents/${agentId}/investigate`, {
      method: 'POST',
      body: JSON.stringify({ node_id: nodeId, notes }),
    });
  },

  async getLLMInteractions(
    agentId: string,
    limit?: number,
    offset?: number
  ): Promise<LLMInteraction[]> {
    const params = new URLSearchParams();
    if (limit) params.set('limit', String(limit));
    if (offset) params.set('offset', String(offset));
    const query = params.toString();
    return request(`/api/agents/${agentId}/llm-interactions${query ? `?${query}` : ''}`);
  },

  async getToolDetails(
    agentId: string,
    limit?: number,
    offset?: number
  ): Promise<ToolDetail[]> {
    const params = new URLSearchParams();
    if (limit) params.set('limit', String(limit));
    if (offset) params.set('offset', String(offset));
    const query = params.toString();
    return request(`/api/agents/${agentId}/tool-details${query ? `?${query}` : ''}`);
  },

  async getObservabilityStats(agentId: string): Promise<ObservabilityStats> {
    return request(`/api/agents/${agentId}/observability-stats`);
  },

  // Report endpoints
  async getReport(agentId: string, reportId?: string): Promise<InvestigationReport> {
    const query = reportId ? `?report_id=${reportId}` : '';
    return request(`/api/agents/${agentId}/report${query}`);
  },

  async downloadReport(agentId: string, format: 'md' | 'json' | 'svg'): Promise<Blob> {
    const url = `${API_BASE}/api/agents/${agentId}/report/download?format=${format}`;
    const response = await fetchWithAuth(url, {
      headers: _sessionToken ? { 'X-Session-Token': _sessionToken } : {},
    });
    if (!response.ok) {
      throw new APIError(response.status, 'Failed to download report');
    }
    return response.blob();
  },

  async listReports(agentId?: string): Promise<Array<{ id: string; agent_id: string; repo_name: string; generated_at: string; findings_count: number }>> {
    const query = agentId ? `?agent_id=${agentId}` : '';
    return request(`/api/agents/reports/all${query}`);
  },

  // State persistence endpoints
  async getState(agentId: string): Promise<AgentStateSnapshot> {
    return request(`/api/agents/${agentId}/state`);
  },

  async getStateSummary(agentId: string): Promise<Record<string, unknown>> {
    return request(`/api/agents/${agentId}/state/summary`);
  },

  async deleteState(agentId: string): Promise<void> {
    await request(`/api/agents/${agentId}/state`, { method: 'DELETE' });
  },

  async listSavedStates(): Promise<Array<Record<string, unknown>>> {
    return request('/api/agents/saved-states');
  },
};

// === Code Graph API ===

export const codeGraph = {
  async initialize(agentId: string, repoPath: string): Promise<CodeGraph> {
    return request<CodeGraph>(`/api/agents/${agentId}/graph/initialize`, {
      method: 'POST',
      body: JSON.stringify({ repo_path: repoPath }),
    });
  },

  async get(agentId: string): Promise<CodeGraph> {
    return request<CodeGraph>(`/api/agents/${agentId}/graph`);
  },

  async getStats(agentId: string): Promise<GraphStats> {
    return request<GraphStats>(`/api/agents/${agentId}/graph/stats`);
  },

  async expandNode(agentId: string, nodeId: string): Promise<{ expanded_node_id: string; new_nodes: GraphNode[] }> {
    return request(`/api/agents/${agentId}/graph/expand/${nodeId}`, {
      method: 'POST',
    });
  },

  async markVisited(agentId: string, filePath: string, durationMs?: number): Promise<{ marked: boolean; node_id?: string }> {
    return request(`/api/agents/${agentId}/graph/mark-visited`, {
      method: 'POST',
      body: JSON.stringify({ file_path: filePath, duration_ms: durationMs }),
    });
  },

  async clear(agentId: string): Promise<void> {
    return request(`/api/agents/${agentId}/graph`, { method: 'DELETE' });
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
    });
  },

  async quickClone(url: string, branch?: string, projectName?: string, force: boolean = false): Promise<Project> {
    return request<Project>('/api/projects/quick-clone', {
      method: 'POST',
      body: JSON.stringify({ url, branch, project_name: projectName, force }),
    });
  },

  async refresh(projectId: string): Promise<Project> {
    return request<Project>(`/api/projects/${projectId}/refresh`, { method: 'POST' });
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
      return await request<SnapshotInfo>('/api/session/snapshot');
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

export { APIError, API_BASE };

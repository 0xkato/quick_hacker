// === Enums ===

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type AgentStatus = 'pending' | 'running' | 'paused' | 'completed' | 'failed' | 'cancelled';
export type AgentType = 'deep_scan' | 'quick_audit' | 'custom' | 'strict_analysis' | 'ultra_strict' | 'deep_audit';
export type ProviderType = 'openai' | 'anthropic' | 'ollama';

// === Repository ===

export interface RepoInfo {
  id: string;
  url: string;
  name: string;
  branch: string;
  path: string;
  cloned_at: string;
  languages: string[];
  file_count: number;
}

export interface RepoCloneRequest {
  url: string;
  branch?: string;
}

// === File System ===

export interface FileNode {
  name: string;
  path: string;
  is_dir: boolean;
  children?: FileNode[];
  size?: number;
  extension?: string;
}

export interface FileContent {
  path: string;
  content: string;
  language?: string;
  line_count: number;
}

// === Provider ===

export interface ProviderConfig {
  provider: ProviderType;
  model: string;
  api_key?: string;
  base_url?: string;
  temperature?: number;
  max_tokens?: number;
}

// === Agent ===

export interface AgentCreateRequest {
  repo_id: string;
  agent_type: AgentType;
  provider_config: ProviderConfig;
  name?: string;
  custom_prompt?: string;
  target_files?: string[];
  focus_areas?: string[];
}

export interface Agent {
  id: string;
  repo_id: string;
  name: string;
  agent_type: AgentType;
  status: AgentStatus;
  provider_config: ProviderConfig;
  custom_prompt?: string;
  target_files?: string[];
  focus_areas?: string[];
  created_at: string;
  started_at?: string;
  completed_at?: string;
  files_analyzed: number;
  findings_count: number;
  error_message?: string;
}

// === Finding ===

export interface Finding {
  id: string;
  agent_id: string;
  repo_id: string;
  severity: Severity;
  title: string;
  description: string;
  file_path: string;
  line_start: number;
  line_end?: number;
  code_snippet?: string;
  vulnerability_type: string;
  attack_scenario?: string;
  recommended_fix?: string;
  confidence: number;
  created_at: string;
  metadata?: Record<string, unknown>;
}

// === WebSocket ===

export type WSMessageType =
  | 'agent_status'
  | 'finding'
  | 'progress'
  | 'error'
  | 'log'
  | 'pipeline_stage'
  | 'llm_request'
  | 'llm_response'
  | 'tool_detail'
  | 'state_sync'
  | 'report_ready';

export interface WSMessage {
  type: WSMessageType;
  agent_id: string;
  data: Record<string, unknown>;
  timestamp: string;
}

export interface AgentProgress {
  current: number;
  total: number;
  file?: string;
}

// === API ===

export interface APIResponse<T = unknown> {
  success: boolean;
  message?: string;
  data?: T;
}

export interface AgentStats {
  total_agents: number;
  status_counts: Record<string, number>;
  total_findings: number;
  max_concurrent: number;
}

// === UI State ===

export interface AppState {
  currentRepo: RepoInfo | null;
  currentFile: FileContent | null;
  agents: Agent[];
  findings: Finding[];
  selectedAgentId: string | null;
  isLoading: boolean;
  error: string | null;
}

// === Settings ===

export interface APISettings {
  openai_key?: string;
  anthropic_key?: string;
  ollama_url?: string;
  default_provider: ProviderType;
  default_model: string;
}

// === Flow Visualization ===

export type FlowNodeType =
  | 'user_input'
  | 'tool_call'
  | 'tool_result'
  | 'analysis'
  | 'finding'
  | 'code_read'
  | 'search'
  | 'scan';

export type FlowNodeStatus = 'pending' | 'running' | 'completed' | 'failed';

export interface FlowNode {
  id: string;
  type: FlowNodeType;
  label: string;
  status: FlowNodeStatus;
  data?: Record<string, unknown>;
  timestamp: string;
  duration_ms?: number;
}

export interface FlowEdge {
  id: string;
  source: string;
  target: string;
  label?: string;
}

export interface InvestigationFlow {
  session_id: string;
  nodes: FlowNode[];
  edges: FlowEdge[];
  current_node_id?: string;
}

// === Observability ===

export type LLMInteractionType = 'request' | 'response';

export interface LLMInteraction {
  id: string;
  agent_id: string;
  interaction_type: LLMInteractionType;
  timestamp: string;
  summary: string;
  full_content: string;
  messages?: Array<Record<string, unknown>>;
  tools_available?: string[];
  tool_calls?: Array<Record<string, unknown>>;
  prompt_tokens?: number;
  completion_tokens?: number;
  total_tokens?: number;
  duration_ms?: number;
  model?: string;
  provider?: string;
  request_id?: string;
}

export interface CodeContext {
  before: string;
  content: string;
  after: string;
  file_path: string;
  line_range: [number, number];
}

export interface ToolDetail {
  id: string;
  agent_id: string;
  timestamp: string;
  tool_name: string;
  tool_call_id: string;
  arguments: Record<string, unknown>;
  arguments_summary: string;
  result: unknown;
  result_summary: string;
  success: boolean;
  error_message?: string;
  code_context?: CodeContext;
  duration_ms: number;
  llm_reasoning?: string;
  confidence_score?: number;
}

export interface AgentStateSnapshot {
  id: string;
  agent_id: string;
  created_at: string;
  repo_id: string;
  repo_path: string;
  agent_type: string;
  provider_config: Record<string, unknown>;
  custom_prompt?: string;
  target_files?: string[];
  focus_areas?: string[];
  status: string;
  files_analyzed: number;
  total_files: number;
  current_file?: string;
  findings: Array<Record<string, unknown>>;
  conversation_history: Array<Record<string, unknown>>;
  flow_nodes: Array<Record<string, unknown>>;
  flow_edges: Array<Record<string, unknown>>;
  current_flow_node_id?: string;
  investigation_context?: Record<string, unknown>;
  total_prompt_tokens: number;
  total_completion_tokens: number;
  total_api_calls: number;
  last_error?: string;
  retry_count: number;
}

export interface FindingSummary {
  id: string;
  severity: Severity;
  title: string;
  file_path: string;
  line_start: number;
  vulnerability_type: string;
  confidence: number;
}

export interface TimelineEvent {
  timestamp: string;
  event_type: string;
  description: string;
  data?: Record<string, unknown>;
}

export interface InvestigationReport {
  id: string;
  agent_id: string;
  generated_at: string;
  executive_summary: string;
  agent_name: string;
  agent_type: string;
  repo_id: string;
  repo_name: string;
  started_at?: string;
  completed_at?: string;
  duration_seconds?: number;
  findings_summary: FindingSummary[];
  findings_by_severity: Record<string, number>;
  findings_by_type: Record<string, number>;
  total_files: number;
  files_with_findings: string[];
  timeline: TimelineEvent[];
  total_prompt_tokens: number;
  total_completion_tokens: number;
  total_api_calls: number;
  estimated_cost?: number;
  flow_json_path?: string;
  flow_svg_path?: string;
  markdown_path?: string;
}

export interface TokenUsage {
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
}

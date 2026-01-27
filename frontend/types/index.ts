// === Imports ===

import { SubmissionResult } from './protocol';

// === Enums ===

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type FindingClassification = 'security_issue' | 'bug' | 'misconfiguration' | 'hardening';
export type FixType = 'code' | 'config' | 'docs' | 'warning';
export type AgentStatus = 'pending' | 'running' | 'paused' | 'completed' | 'failed' | 'cancelled';
export type AgentType = 'quick_audit' | 'custom' | 'strict_analysis' | 'ultra_strict' | 'deep_audit';
export type ScanTier = 'quick' | 'medium' | 'advanced' | 'pro' | 'ultra' | 'evil' | 'custom';
export type ProviderType = 'openai' | 'anthropic' | 'ollama' | 'codex_cli';

// === Triage System ===

export type Disposition =
  | 'valid_security_issue'
  | 'bug'
  | 'hardening'
  | 'misconfiguration'
  | 'by_design'
  | 'speculative';

export type ChecklistStatus = 'PROVEN' | 'DISPROVEN' | 'UNKNOWN';

export interface ChecklistItem {
  value: boolean;
  status: ChecklistStatus;
  reason: string;
}

export interface ProofChecklist {
  source_controlled_input: ChecklistItem;
  sink_present: ChecklistItem;
  dataflow_evidenced: ChecklistItem;
  reachable: ChecklistItem;
  boundary_crossed: ChecklistItem;
  not_only_misconfig: ChecklistItem;
  security_control_bypassed?: ChecklistItem;
}

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
  codex_path?: string;
  temperature?: number;
  max_tokens?: number;
}

// === Dual-Model Handoff ===

export type HandoffMode = 'exploration' | 'sink_identification';

export interface FileReadRecord {
  path: string;
  relevance_score: number;
  summary?: string;
  read_at: string;
}

export interface TechStack {
  languages: string[];
  frameworks: string[];
  dependencies: string[];
}

export interface EntryPoint {
  name: string;
  file_path: string;
  line_number: number;
  method?: string;
  route?: string;
  code_snippet: string;
}

export interface Sink {
  sink_type: string;
  function_name: string;
  file_path: string;
  line_number: number;
  code_snippet: string;
  context?: string;
}

export interface ScannerHandoffState {
  repo_path: string;
  files_read: FileReadRecord[];
  tech_stack: TechStack;
  entry_points: EntryPoint[];
  dangerous_sinks: Sink[];
  file_map: Record<string, { relevance: number; summary?: string }>;
  scanner_model: string;
  scanner_tokens_used: number;
  scanner_duration_ms: number;
  handoff_reason: string;
}

export interface PhaseHandoffEvent {
  scanner_tokens: number;
  scanner_duration_ms: number;
  entry_points_found: number;
  sinks_found: number;
  files_read: number;
  handoff_reason: string;
}

// === Agent ===

export interface AgentCreateRequest {
  repo_id: string;
  agent_type: AgentType;
  provider_config?: ProviderConfig;
  scan_tier?: ScanTier | string;
  time_budget_seconds?: number;
  scanner_config?: ProviderConfig;
  analyzer_config?: ProviderConfig;
  handoff_after?: HandoffMode;
  name?: string;
  custom_prompt?: string;
  target_files?: string[];
  focus_areas?: string[];
  use_claude_sdk?: boolean;  // Use Claude Agent SDK for native tool loop (Anthropic only)
}

export interface Agent {
  id: string;
  repo_id: string;
  name: string;
  agent_type: AgentType;
  status: AgentStatus;
  provider_config: ProviderConfig;
  scan_tier?: string;
  time_budget_seconds?: number;
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

// === LLM Validation ===

/**
 * Result of LLM-based validation investigation
 */
export interface ValidationResult {
  is_valid: boolean;
  reasoning: string[];
  categories: string[];
  confidence: number | null;
  investigation_steps: string[] | null;
  timestamp: string;
}

// === Finding ===

export interface Finding {
  id: string;
  agent_id: string;
  repo_id: string;
  severity: Severity | null;  // May be null for non-reportable findings
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
  // Classification gate fields
  classification?: FindingClassification;
  config_dependent?: boolean;
  config_flag?: string | null;
  default_secure?: boolean | null;
  contradiction_present?: boolean;
  fix_type?: FixType;
  classification_reasoning?: string;
  // Triage system fields
  batch_id?: string;
  disposition?: Disposition;
  classification_confidence?: number;
  exploit_confidence?: number;
  proof_checklist?: ProofChecklist;
  reasoning?: string[];
  triage_policy_version?: string;
  triaged_at?: string;
  category?: string;
  // Protocol evaluation
  submission_result?: SubmissionResult;
  evidence_quest_id?: string;
  evidence_quest_completed?: boolean;
  // LLM validation result
  validation_result?: ValidationResult | null;
}

// === WebSocket ===

export type WSMessageType =
  | 'agent_status'
  | 'finding'
  | 'progress'
  | 'error'
  | 'log'
  | 'llm_request'
  | 'llm_response'
  | 'tool_detail'
  | 'state_sync'
  | 'report_ready'
  | 'phase_handoff'
  | 'session_pausing'
  | 'session_paused'
  | 'session_resumed'
  | 'auth_required'
  | 'auth_ok';

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
  | 'scan'
  | 'entry_point'
  | 'function'
  | 'external'
  | 'cycle';

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

// === Call Tree ===

export interface CallTreeRoute {
  id: string;
  method: string;
  path: string;
  handler: string;
  file: string;
  line?: number;
  framework?: string;
  label?: string;
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

// === Session Hibernation ===

export type SessionStatus = 'active' | 'pausing' | 'paused' | 'resuming';

export interface SessionSnapshotAgent {
  id: string;
  agent_type: string;
  status: string;
  target_files: string[];
  processed_files: string[];
  pending_files: string[];
  current_file: string | null;
  config: Record<string, unknown>;
}

export interface SessionSnapshotUIState {
  active_view: string;
  selected_file: string | null;
  open_panels: string[];
  selected_agent_id: string | null;
}

export interface SessionSnapshot {
  version: number;
  timestamp: string;
  project_id: string;
  agents: SessionSnapshotAgent[];
  findings: Record<string, unknown>[];
  llm_context: Array<{
    agent_id: string;
    messages: Record<string, unknown>[];
  }>;
  ui_state: SessionSnapshotUIState;
}

export interface SnapshotInfo {
  timestamp: string;
  agent_count: number;
  findings_count: number;
  pending_files: number;
}

// === Code Graph ===

export type GraphNodeType = 'entry_point' | 'function' | 'external' | 'cycle';
export type RelevanceLevel = 'high' | 'medium' | 'low' | 'skip';

export interface RelevanceBreakdown {
  content_score: number;
  position_score: number;
  matched_patterns: string[];
}

export interface GraphNode {
  id: string;
  type: GraphNodeType;
  label: string;
  file_path?: string;
  line_number?: number;
  module?: string;

  // Relevance
  relevance_level: RelevanceLevel;
  relevance_score: number;
  relevance_breakdown: RelevanceBreakdown;

  // Expansion
  is_expanded: boolean;
  child_count: number;
  children_loaded: boolean;

  // Agent activity
  visited: boolean;
  visited_at?: string;
  visit_duration_ms?: number;

  // Additional data
  data?: Record<string, unknown>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label?: string;
}

export interface CodeGraph {
  agent_id: string;
  repo_path: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  entry_point_ids: string[];
  created_at: string;
}

export interface GraphStats {
  total_nodes: number;
  entry_points: number;
  visited: number;
  high_relevance_unvisited: number;
  by_relevance: Record<RelevanceLevel, number>;
}

// === Imports ===

import { SubmissionResult } from './protocol';

// === Enums ===

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type FindingClassification = 'security_issue' | 'bug' | 'misconfiguration' | 'hardening';
export type FixType = 'code' | 'config' | 'docs' | 'warning';
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

export interface TriageProofChecklist {
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
  children?: FileNode[] | null;
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
  proof_checklist?: TriageProofChecklist;
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
  | 'flow_update'
  | 'bt_node_add'
  | 'bt_node_update'
  | 'bt_node_batch'
  | 'auth_required'
  | 'auth_ok';

export interface WSMessage {
  type: WSMessageType;
  agent_id: string;
  data: Record<string, unknown>;
  timestamp: string;
}

// === API ===

export interface APIResponse<T = unknown> {
  success: boolean;
  message?: string;
  data?: T;
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
  subagent?: string;  // Sub-agent that made this interaction (Overseer mode)
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
  subagent?: string;  // Sub-agent that made this call (Overseer mode)
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

// === Behavior Tree Types ===

export type BTNodeType =
  | 'session'
  | 'phase'
  | 'wave'
  | 'signal'
  | 'agent'
  | 'turn'
  | 'llm_request'
  | 'llm_response'
  | 'llm_thinking'
  | 'tool_call'
  | 'tool_result'
  | 'finding'
  | 'error';

export type BTNodeStatus = 'pending' | 'active' | 'completed' | 'failed';

export interface BTNode {
  id: string;
  agent_id: string;
  parent_id: string | null;
  node_type: BTNodeType;
  label: string;
  status: BTNodeStatus;
  timestamp: string;
  data: Record<string, unknown>;
  children_count: number;
  depth: number;
}

export interface BTNodeUpdate {
  id: string;
  agent_id: string;
  status?: BTNodeStatus;
  label?: string;
  data_merge?: Record<string, unknown>;
  children_count?: number;
}

// === Campaign Platform Types ===

export type CampaignStatus = 'created' | 'planning' | 'extracting' | 'compiling' | 'running' | 'paused' | 'completed' | 'failed' | 'cancelled';
export type CampaignPreset = 'quick' | 'medium' | 'advanced' | 'pro' | 'ultra' | 'evil';
export type TargetKind = 'api_route' | 'parser' | 'workflow' | 'browser' | 'cli' | 'message_consumer' | 'native_function';
export type LaneSpecStatus = 'planned' | 'compiled' | 'validated' | 'retired';
export type RunLaneStatus = 'queued' | 'running' | 'stalled' | 'completed' | 'failed' | 'cancelled' | 'superseded';
export type ArtifactType = 'crash' | 'hang' | 'oracle_hit' | 'differential_failure';
export type ArtifactClassification = 'issue_candidate' | 'harness_artifact' | 'flaky_unconfirmed';
export type IssueDisposition = 'confirmed_security_issue' | 'confirmed_non_security_bug' | 'hardening_observation';
export type IssueSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface CampaignCreateRequest {
  repo_id: string;
  campaign_preset?: CampaignPreset;
  lm_provider?: string;
  lm_model?: string;
  enabled_engines?: string[];
  max_parallel_lanes?: number;
  budget_seconds?: number;
  steering_interval_seconds?: number;
  target_scope?: string;
  directed_targets?: string[];
  custom_oracles?: string[];
  max_lm_jobs?: number;
  seed_sources?: string[];
  corpus_reuse_policy?: string;
  actor_profiles?: string[];
  env_profile?: Record<string, unknown>;
  methodology_overrides?: Record<string, unknown>;
  target_filters?: Record<string, unknown>;
  plateau_window_seconds?: number;
  max_compilation_failures_per_lane?: number;
  max_steering_cycles?: number;
  repro_attempts?: number;
  minimization_budget_seconds?: number;
}

export interface Campaign {
  id: string;
  repo_id: string;
  status: CampaignStatus;
  preset: CampaignPreset;
  budget_seconds: number;
  max_parallel_lanes: number;
  lm_provider?: string;
  lm_model?: string;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  error_message?: string;
}

export interface Target {
  id: string;
  campaign_id: string;
  kind: TargetKind;
  entrypoint: string;
  language?: string;
  schemas?: unknown;
  stateful: boolean;
  actors?: string[];
  reset_strategy?: string;
  priority_score?: number;
  created_at: string;
}

export interface LaneSpec {
  id: string;
  target_id: string;
  revision: number;
  structure_model: string;
  input_producer: string;
  feedback_models: string[];
  oracle_packs: string[];
  engine: string;
  budget_seconds?: number;
  seed_sources?: string[];
  status: LaneSpecStatus;
  created_at: string;
}

export interface RunLane {
  id: string;
  lane_spec_id: string;
  execution_bundle_id: string;
  status: RunLaneStatus;
  started_at?: string;
  completed_at?: string;
  cpu_limit?: string;
  memory_limit_mb?: number;
  timeout_seconds?: number;
  resource_profile?: string;
}

export interface Artifact {
  id: string;
  run_lane_id: string;
  type: ArtifactType;
  bucket_key?: string;
  artifact_classification: ArtifactClassification;
  analysis_outcome?: string;
  reproducible?: boolean;
  stability_score?: number;
  minimized?: boolean;
  replay_recipe?: Record<string, unknown>;
  evidence_refs?: string[];
  created_at: string;
}

export interface ArtifactBucket {
  id: string;
  campaign_id: string;
  bucket_key: string;
  artifact_count: number;
  first_seen_at: string;
  last_seen_at: string;
}

export interface ProofChecklist {
  target_real: boolean;
  harness_validated: boolean;
  real_code_reached: boolean;
  external_input_controlled: boolean;
  oracle_triggered_or_sanitizer_hit: boolean;
  reproduced_cleanly: boolean;
  artifact_minimization_attempted: boolean;
  not_harness_artifact: boolean;
  not_test_only: boolean;
  security_impact_confirmed: boolean;
}

export interface Issue {
  id: string;
  artifact_id: string;
  severity: IssueSeverity;
  title: string;
  description: string;
  category?: string;
  cwe_id?: string;
  disposition: IssueDisposition;
  proof: ProofChecklist;
  root_cause?: string;
  recommended_fix?: string;
  regression_test_id?: string;
  created_at: string;
}

export interface SteeringDecision {
  id: string;
  campaign_id: string;
  decision_type: string;
  triggering_metrics: Record<string, unknown>;
  recommendation: string;
  affected_lane_ids: string[];
  created_at: string;
}

export interface CoverageSummary {
  operations_hit: number;
  parameters_exercised: number;
  status_classes_seen: string[];
  sequence_depth: number;
  validity_ratio: number;
  requests_per_sec: number;
}

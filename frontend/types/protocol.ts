/**
 * Protocol-aware reportability layer types
 */

export enum SubmissionDecision {
  SUBMIT = "submit",
  DONT_SUBMIT = "dont_submit",
  NEEDS_MORE_INFO = "needs_more_info"
}

export interface SubmissionResult {
  protocol_id: string;
  decision: SubmissionDecision;
  reasons: string[];
  missing_evidence: string[];
  suggested_next_steps: string[];
  quest_run: boolean;
  quest_id?: string;
  quest_findings?: Record<string, any>;
  disposition_modified: boolean;
  disposition_reason?: string;
}

export interface ProtocolPolicy {
  id: string;
  display_name: string;
  default_threat_model_preset: string;
  min_disposition_to_submit: string[];
  require_cross_boundary_for_local_bugs: boolean;
  reject_social_engineering_only: boolean;
  require_repro_steps: boolean;
  require_impact_statement: boolean;
  require_realistic_attacker_model: boolean;
  min_checklist_proven_count: number;
  allow_unknown_in_checklist: boolean;
  category_rules: Record<string, Record<string, any>>;
  enable_evidence_quests: boolean;
  quest_categories: string[];
}

export interface EvidenceQuest {
  id: string;
  finding_id: string;
  category: string;
  quest_type: string;
  status: string;
  started_at?: string;
  completed_at?: string;
  success?: boolean;
  error_message?: string;
  evidence_found?: Record<string, any>;
}

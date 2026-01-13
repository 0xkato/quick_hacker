/**
 * Type definitions for Investigation Flow visualization
 * Matches backend Span and Edge models from reconstruction service
 */

export type SpanType = 'hypothesis' | 'hypothesis_visit' | 'critic_pass' | 'placeholder';
export type SpanState = 'open' | 'completed' | 'discarded';
export type Outcome = 'confirmed' | 'refuted' | 'inconclusive' | null;

/**
 * Span interface matching backend Python dataclass
 * Uses snake_case to match backend serialization
 */
export interface Span {
  span_id: string;
  span_type: SpanType;
  hypothesis_id: string | null;
  label: string;
  state: SpanState;
  outcome: Outcome;
  parent_span_id: string | null;
  created_turn_id: number;
  completed_at: number | null;
  focus_gap: string | null;
  focus_note: string | null;
  stage: string | null;
  event_ids: number[];
  artifact_ids: number[];
  is_collapsed: boolean;
}

/**
 * Edge interface for span relationships and evidence links
 */
export interface Edge {
  id: string;
  source: string;
  target: string;
  edge_type: 'parent_child' | 'evidence_link';
  label?: string;
  style?: 'dashed' | 'solid';
  hidden?: boolean;
}

/**
 * Props for the HypothesisNode component
 */
export interface HypothesisNodeData {
  span: Span;
  isCollapsed: boolean;
  onToggleCollapse: () => void;
}

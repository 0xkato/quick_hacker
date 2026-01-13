/**
 * HypothesisNode Component
 *
 * Visual representation of a hypothesis span in the investigation tree.
 * Features outcome-based coloring, event/artifact counts, and collapse/expand.
 */

import React from 'react';
import { Handle, Position } from 'reactflow';
import { HypothesisNodeData, Outcome, SpanState } from '../types';

interface HypothesisNodeProps {
  data: HypothesisNodeData;
}

/**
 * Get color classes based on outcome
 */
const getOutcomeColor = (outcome: Outcome): string => {
  switch (outcome) {
    case 'confirmed':
      return 'border-green-500 bg-green-50';
    case 'refuted':
      return 'border-red-500 bg-red-50';
    case 'inconclusive':
      return 'border-yellow-500 bg-yellow-50';
    default:
      return 'border-blue-500 bg-blue-50'; // Default for null outcome
  }
};

/**
 * Get color classes based on state (used when state is not 'completed')
 */
const getStateColor = (state: SpanState, outcome: Outcome): string => {
  if (state === 'completed') {
    // For completed state, use outcome color
    return getOutcomeColor(outcome);
  } else if (state === 'open') {
    return 'border-blue-500 bg-blue-50';
  } else if (state === 'discarded') {
    return 'border-gray-400 bg-gray-100';
  }
  return 'border-gray-300 bg-white';
};

/**
 * HypothesisNode Component
 *
 * Displays:
 * - Span label
 * - Event and artifact counts
 * - Outcome-based visual styling
 * - Collapse/expand button (if events exist)
 * - Focus gap (if present)
 *
 * Memoized to prevent unnecessary re-renders when parent TreeLayout re-renders.
 */
const HypothesisNode: React.FC<HypothesisNodeProps> = React.memo(({ data }) => {
  const { span, isCollapsed, onToggleCollapse } = data;

  // Determine node color based on state and outcome
  const colorClass = getStateColor(span.state, span.outcome);

  // Check if node has children (events)
  const hasEvents = span.event_ids && span.event_ids.length > 0;

  return (
    <div
      className={`px-4 py-3 rounded-lg border-2 shadow-md min-w-[200px] max-w-[300px] ${colorClass}`}
    >
      {/* Top handle for incoming edges */}
      <Handle
        type="target"
        position={Position.Top}
        className="w-3 h-3"
      />

      {/* Node header with label and collapse button */}
      <div className="flex items-start justify-between gap-2">
        <div className="flex-1">
          <div className="font-semibold text-sm text-gray-900 break-words">
            {span.label}
          </div>
        </div>

        {/* Collapse/expand button - only show if has events */}
        {hasEvents && (
          <button
            onClick={onToggleCollapse}
            className="flex-shrink-0 text-gray-600 hover:text-gray-900 focus:outline-none"
            aria-label={isCollapsed ? 'Expand' : 'Collapse'}
          >
            {isCollapsed ? '▶' : '▼'}
          </button>
        )}
      </div>

      {/* Metadata: Event and artifact counts */}
      <div className="mt-2 flex items-center gap-3 text-xs text-gray-600">
        {span.event_ids && span.event_ids.length > 0 && (
          <div className="flex items-center gap-1">
            <span className="font-medium">{span.event_ids.length}</span>
            <span>{span.event_ids.length === 1 ? 'event' : 'events'}</span>
          </div>
        )}
        {span.artifact_ids && span.artifact_ids.length > 0 && (
          <div className="flex items-center gap-1">
            <span className="font-medium">{span.artifact_ids.length}</span>
            <span>{span.artifact_ids.length === 1 ? 'artifact' : 'artifacts'}</span>
          </div>
        )}
      </div>

      {/* Focus gap indicator */}
      {span.focus_gap && (
        <div className="mt-2 text-xs text-gray-700 italic border-t border-gray-300 pt-2">
          Focus: {span.focus_gap}
        </div>
      )}

      {/* Outcome badge */}
      {span.outcome && (
        <div className="mt-2">
          <span
            className={`inline-block px-2 py-0.5 text-xs font-medium rounded-full ${
              span.outcome === 'confirmed'
                ? 'bg-green-200 text-green-800'
                : span.outcome === 'refuted'
                ? 'bg-red-200 text-red-800'
                : 'bg-yellow-200 text-yellow-800'
            }`}
          >
            {span.outcome.charAt(0).toUpperCase() + span.outcome.slice(1)}
          </span>
        </div>
      )}

      {/* Bottom handle for outgoing edges */}
      <Handle
        type="source"
        position={Position.Bottom}
        className="w-3 h-3"
      />
    </div>
  );
});

HypothesisNode.displayName = 'HypothesisNode';

export default HypothesisNode;

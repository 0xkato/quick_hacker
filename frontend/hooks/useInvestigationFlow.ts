/**
 * useInvestigationFlow Hook
 *
 * Fetches and reconstructs investigation flow from events into spans and edges.
 * Manages loading state, error handling, and cleanup for safe React integration.
 *
 * @module hooks/useInvestigationFlow
 */

import { useState, useEffect, useMemo } from 'react';
import {
  reconstructInvestigationDag,
  FlowEvent,
  ReconstructionError,
} from '@/lib/reconstructionClient';
import { Span, Edge } from '@/components/InvestigationFlow/types';

/**
 * Hook return value with reconstructed data and state.
 */
export interface UseInvestigationFlowResult {
  /** Reconstructed spans keyed by span_id. Empty object during loading or on error. */
  spans: Record<string, Span>;

  /** Reconstructed edges representing span relationships. Empty array during loading or on error. */
  edges: Edge[];

  /** Loading state: true while fetching reconstruction, false otherwise */
  isLoading: boolean;

  /** Error object if reconstruction failed, null otherwise */
  error: Error | null;

  /** Event-to-span mapping for debugging (optional) */
  eventToSpan?: Record<string, string>;
}

/**
 * Reconstruct investigation flow from flat event stream.
 *
 * Automatically reconstructs whenever agentId or events change.
 * Handles cleanup to prevent memory leaks and race conditions.
 *
 * **Loading behavior:**
 * - `isLoading: true` while reconstruction is in progress
 * - `spans` and `edges` remain empty ({} and []) during loading
 * - Previous data is cleared when starting new reconstruction
 *
 * **Error handling:**
 * - Errors are caught and stored in `error` state
 * - `isLoading` is set to false on error
 * - `spans` and `edges` remain empty on error
 * - Errors are cleared before starting new reconstruction
 *
 * **Edge cases handled:**
 * - Empty agentId: Skips reconstruction, returns empty state
 * - Empty events array: Skips reconstruction, returns empty state
 * - Rapid re-renders: Cleanup prevents stale state updates
 * - Component unmount: AbortController cancels in-flight requests
 *
 * @param agentId - Agent identifier (required, non-empty)
 * @param events - Flat list of investigation events
 * @returns Reconstructed spans, edges, loading state, and error
 *
 * @example
 * ```tsx
 * function InvestigationView({ agentId, events }: Props) {
 *   const { spans, edges, isLoading, error } = useInvestigationFlow(agentId, events);
 *
 *   if (isLoading) return <Spinner />;
 *   if (error) return <ErrorAlert message={error.message} />;
 *
 *   return <TreeLayout spans={spans} edges={edges} />;
 * }
 * ```
 *
 * @example
 * ```tsx
 * // Real-time updates: Hook automatically reconstructs when events change
 * function LiveInvestigation({ agentId }: Props) {
 *   const { events } = useWebSocket(agentId); // Events update in real-time
 *   const { spans, edges } = useInvestigationFlow(agentId, events);
 *
 *   return <TreeLayout spans={spans} edges={edges} />;
 * }
 * ```
 */
export function useInvestigationFlow(
  agentId: string,
  events: FlowEvent[]
): UseInvestigationFlowResult {
  // State management
  const [spans, setSpans] = useState<Record<string, Span>>({});
  const [edges, setEdges] = useState<Edge[]>([]);
  const [eventToSpan, setEventToSpan] = useState<Record<string, string>>({});
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  // Effect: Reconstruct investigation DAG when inputs change
  useEffect(() => {
    // Early return: Skip reconstruction if inputs are invalid or empty
    if (!agentId || agentId.trim() === '') {
      // Clear state for empty agent ID
      setSpans({});
      setEdges([]);
      setEventToSpan({});
      setIsLoading(false);
      setError(null);
      return;
    }

    if (!events || events.length === 0) {
      // Clear state for empty events
      setSpans({});
      setEdges([]);
      setEventToSpan({});
      setIsLoading(false);
      setError(null);
      return;
    }

    // Setup: AbortController for cleanup
    const abortController = new AbortController();
    let cancelled = false;

    // Async reconstruction function
    const reconstruct = async () => {
      try {
        // Set loading state and clear previous error
        if (!cancelled) {
          setIsLoading(true);
          setError(null);
          // Clear previous data while loading
          setSpans({});
          setEdges([]);
          setEventToSpan({});
        }

        // Call reconstruction API
        const result = await reconstructInvestigationDag(
          agentId,
          events,
          abortController.signal
        );

        // Update state with results (only if not cancelled)
        if (!cancelled) {
          setSpans(result.spans);
          setEdges(result.edges);
          setEventToSpan(result.event_to_span);
          setIsLoading(false);
        }
      } catch (err) {
        // Handle errors (only if not cancelled)
        if (!cancelled) {
          // Convert unknown errors to Error objects
          let errorObj: Error;

          if (err instanceof Error) {
            errorObj = err;
          } else {
            errorObj = new Error(String(err));
          }

          // Special handling for ReconstructionError
          if (err instanceof ReconstructionError) {
            console.error(
              `[useInvestigationFlow] Reconstruction failed for agent ${agentId}:`,
              err.message,
              { statusCode: err.statusCode }
            );
          } else {
            console.error(
              `[useInvestigationFlow] Unexpected error for agent ${agentId}:`,
              errorObj
            );
          }

          setError(errorObj);
          setIsLoading(false);
          // Keep data cleared on error
          setSpans({});
          setEdges([]);
          setEventToSpan({});
        }
      }
    };

    // Execute reconstruction
    reconstruct();

    // Cleanup: Prevent state updates after unmount or re-render
    return () => {
      cancelled = true;
      abortController.abort();
    };
  }, [agentId, events]); // Reconstruct when agentId or events change

  // Memoize return object to prevent unnecessary re-renders
  const result = useMemo<UseInvestigationFlowResult>(
    () => ({
      spans,
      edges,
      isLoading,
      error,
      eventToSpan,
    }),
    [spans, edges, isLoading, error, eventToSpan]
  );

  return result;
}

/**
 * Testing Strategy (framework not configured - document strategy here)
 *
 * **Unit Tests (when framework available):**
 *
 * 1. Test empty inputs:
 *    - Empty agentId should return empty state with no loading
 *    - Empty events should return empty state with no loading
 *
 * 2. Test successful reconstruction:
 *    - Mock reconstructInvestigationDag to return test data
 *    - Verify spans, edges populated correctly
 *    - Verify loading transitions: false -> true -> false
 *    - Verify error is null on success
 *
 * 3. Test error handling:
 *    - Mock reconstructInvestigationDag to throw ReconstructionError
 *    - Verify error state is set
 *    - Verify loading is false after error
 *    - Verify spans/edges are empty on error
 *    - Verify console.error is called with descriptive message
 *
 * 4. Test cleanup:
 *    - Unmount component during loading
 *    - Verify AbortController.abort() is called
 *    - Verify no state updates occur after unmount
 *
 * 5. Test race conditions:
 *    - Change agentId/events rapidly
 *    - Verify only latest result updates state
 *    - Verify previous in-flight requests are cancelled
 *
 * 6. Test memoization:
 *    - Call hook with same inputs multiple times
 *    - Verify return object reference is stable (===)
 *
 * **Integration Tests:**
 *
 * 1. Test with real WebSocket events:
 *    - Connect to WebSocket, receive events
 *    - Verify reconstruction updates in real-time
 *
 * 2. Test with TreeLayout component:
 *    - Pass hook results to TreeLayout
 *    - Verify tree renders correctly
 *    - Verify loading/error states display properly
 *
 * **Manual Testing:**
 *
 * 1. Load investigation view with real agent
 * 2. Verify spans/edges render in TreeLayout
 * 3. Trigger error (invalid agent ID)
 * 4. Verify error message displays
 * 5. Watch WebSocket events stream in
 * 6. Verify tree updates in real-time
 */

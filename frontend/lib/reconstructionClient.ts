/**
 * Reconstruction API Client
 *
 * Provides typed interface to backend reconstruction service.
 * Transforms flat event streams into structured investigation DAGs (spans + edges).
 */

import { Span, Edge } from '@/components/InvestigationFlow/types';

/**
 * Flow event from WebSocket or backend.
 * Represents a single event in the investigation trace.
 */
export interface FlowEvent {
  /** Unique event identifier */
  id: string;

  /** Event type (e.g., "turn_plan", "tool_call", "llm_request") */
  type: string;

  /** ISO timestamp when event occurred */
  timestamp?: string;

  /** Event-specific data payload (varies by type) */
  data?: any; // Intentional: event data structure varies by type

  /** Span ID this event belongs to (for pre-attributed events) */
  span_id?: string;

  /** Hypothesis ID this event relates to */
  hypothesis_id?: string;

  /** Artifact IDs produced by this event */
  output_artifact_ids?: string[];

  /** Artifact IDs consumed by this event */
  input_artifact_ids?: string[];
}

/**
 * Result from backend reconstruction service.
 */
export interface ReconstructionResult {
  /** Reconstructed spans keyed by span_id */
  spans: Record<string, Span>;

  /** Edges representing span hierarchy and evidence links */
  edges: Edge[];

  /** Mapping from event_id to span_id for debugging */
  event_to_span: Record<string, string>;
}

/**
 * API Error thrown when reconstruction request fails.
 * Includes status code and descriptive context.
 */
export class ReconstructionError extends Error {
  constructor(
    public statusCode: number,
    public agentId: string,
    message: string
  ) {
    super(message);
    this.name = 'ReconstructionError';
  }
}

/**
 * Reconstruct investigation DAG from flat event stream.
 *
 * Makes POST request to backend reconstruction service and transforms events
 * into structured spans and edges for visualization.
 *
 * @param agentId - Agent identifier
 * @param events - Flat list of investigation events
 * @param signal - Optional AbortSignal for request cancellation
 * @returns Promise resolving to reconstructed spans, edges, and event mappings
 * @throws {ReconstructionError} If request fails (network, HTTP error, or invalid JSON)
 *
 * @example
 * ```typescript
 * try {
 *   const result = await reconstructInvestigationDag(
 *     "agent_123",
 *     events,
 *     abortController.signal
 *   );
 *   console.log(`Reconstructed ${Object.keys(result.spans).length} spans`);
 * } catch (error) {
 *   if (error instanceof ReconstructionError) {
 *     console.error(`Reconstruction failed (${error.statusCode}): ${error.message}`);
 *   }
 * }
 * ```
 */
export async function reconstructInvestigationDag(
  agentId: string,
  events: FlowEvent[],
  signal?: AbortSignal
): Promise<ReconstructionResult> {
  // Defensive validation
  if (!agentId || agentId.trim() === '') {
    throw new ReconstructionError(
      0,
      agentId,
      'Agent ID is required for reconstruction'
    );
  }

  if (!Array.isArray(events)) {
    throw new ReconstructionError(
      0,
      agentId,
      'Events must be an array'
    );
  }

  // Build API URL
  const apiBase = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
  const url = `${apiBase}/api/agents/${encodeURIComponent(agentId)}/reconstruct`;

  try {
    // Make POST request with events in body
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ events }),
      signal,
    });

    // Handle non-2xx responses
    if (!response.ok) {
      let errorDetail = `HTTP ${response.status}: ${response.statusText}`;

      // Try to extract error detail from JSON response
      try {
        const errorData = await response.json();
        if (errorData.detail) {
          errorDetail = errorData.detail;
        } else if (errorData.message) {
          errorDetail = errorData.message;
        }
      } catch {
        // Ignore JSON parse errors, use status text
      }

      throw new ReconstructionError(
        response.status,
        agentId,
        `Reconstruction failed for agent ${agentId}: ${errorDetail}`
      );
    }

    // Parse JSON response
    let data: any;
    try {
      data = await response.json();
    } catch (parseError) {
      throw new ReconstructionError(
        response.status,
        agentId,
        `Failed to parse reconstruction response as JSON: ${parseError instanceof Error ? parseError.message : 'Unknown error'}`
      );
    }

    // Validate response structure
    if (!data || typeof data !== 'object') {
      throw new ReconstructionError(
        response.status,
        agentId,
        'Invalid reconstruction response: expected object'
      );
    }

    if (!data.spans || typeof data.spans !== 'object') {
      throw new ReconstructionError(
        response.status,
        agentId,
        'Invalid reconstruction response: missing or invalid spans'
      );
    }

    if (!Array.isArray(data.edges)) {
      throw new ReconstructionError(
        response.status,
        agentId,
        'Invalid reconstruction response: missing or invalid edges array'
      );
    }

    if (!data.event_to_span || typeof data.event_to_span !== 'object') {
      throw new ReconstructionError(
        response.status,
        agentId,
        'Invalid reconstruction response: missing or invalid event_to_span mapping'
      );
    }

    // Return typed result
    return {
      spans: data.spans as Record<string, Span>,
      edges: data.edges as Edge[],
      event_to_span: data.event_to_span as Record<string, string>,
    };
  } catch (error) {
    // Handle fetch errors (network, abort, etc.)
    if (error instanceof ReconstructionError) {
      throw error; // Re-throw our custom errors
    }

    if (error instanceof Error) {
      // Network error, abort, or other fetch failure
      if (error.name === 'AbortError') {
        throw new ReconstructionError(
          0,
          agentId,
          'Reconstruction request was cancelled'
        );
      }

      throw new ReconstructionError(
        0,
        agentId,
        `Network error during reconstruction: ${error.message}`
      );
    }

    // Unknown error type
    throw new ReconstructionError(
      0,
      agentId,
      `Unexpected error during reconstruction: ${String(error)}`
    );
  }
}

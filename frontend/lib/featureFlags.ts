/**
 * Feature Flag Client for gradual feature rollout.
 *
 * Provides type-safe access to feature flags with backend integration.
 * Flags are fetched from the backend and cached in-memory.
 *
 * Usage:
 *   import { featureFlags, FeatureFlag } from '@/lib/featureFlags';
 *
 *   await featureFlags.fetchFlags(userId);
 *   if (featureFlags.isEnabled(FeatureFlag.SPAN_BASED_FLOW)) {
 *     // Show new span-based UI
 *   }
 */

import { APIError, API_BASE } from './api';

/**
 * Feature flags matching backend FeatureFlag enum.
 * MUST stay in sync with backend/services/feature_flags.py
 */
export enum FeatureFlag {
  SPAN_BASED_FLOW = 'span_based_flow',
  DUAL_WRITE_MODE = 'dual_write_mode',
}

/**
 * Response from backend feature flags endpoint
 */
interface FeatureFlagsResponse {
  flags: Record<string, boolean>;
}

/**
 * Client for fetching and checking feature flags.
 *
 * Integrates with backend feature flag service to provide
 * type-safe, user-specific feature flag checks.
 */
export class FeatureFlagClient {
  private flags: Map<FeatureFlag, boolean>;
  private userId: string | null;
  private fetchPromise: Promise<void> | null;

  constructor() {
    this.flags = new Map();
    this.userId = null;
    this.fetchPromise = null;
  }

  /**
   * Fetch feature flags for a specific user from the backend.
   *
   * Flags are cached in-memory. Call this method again to refresh.
   * Uses existing auth patterns from api.ts for authentication.
   *
   * @param userId - The user ID to fetch flags for
   * @returns Promise that resolves when flags are fetched
   * @throws {APIError} If the backend request fails
   */
  async fetchFlags(userId: string): Promise<void> {
    // If already fetching for this user, return existing promise
    if (this.fetchPromise && this.userId === userId) {
      return this.fetchPromise;
    }

    this.userId = userId;
    this.fetchPromise = this._doFetch(userId);

    try {
      await this.fetchPromise;
    } finally {
      this.fetchPromise = null;
    }
  }

  /**
   * Internal method to perform the actual fetch.
   */
  private async _doFetch(userId: string): Promise<void> {
    try {
      const url = `${API_BASE}/api/feature-flags?user_id=${encodeURIComponent(userId)}`;

      // Note: Using fetch directly here rather than api.ts's request()
      // because we want to handle auth errors gracefully for feature flags.
      // Feature flags should degrade gracefully if auth fails.
      const response = await fetch(url, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        // If auth fails or endpoint doesn't exist, use safe defaults
        if (response.status === 401 || response.status === 404) {
          console.warn(
            `Feature flags endpoint returned ${response.status}, using defaults`
          );
          this._setDefaults();
          return;
        }

        const error = await response
          .json()
          .catch(() => ({ detail: 'Unknown error' }));
        throw new APIError(
          response.status,
          error.detail || 'Failed to fetch feature flags'
        );
      }

      const data: FeatureFlagsResponse = await response.json();

      // Update flags map
      this.flags.clear();
      Object.entries(data.flags).forEach(([key, value]) => {
        // Validate that key is a valid FeatureFlag
        if (Object.values(FeatureFlag).includes(key as FeatureFlag)) {
          this.flags.set(key as FeatureFlag, value);
        }
      });

      // Ensure all flags have a value (use defaults if missing)
      this._ensureDefaults();
    } catch (error) {
      // On any error, use safe defaults
      console.error('Failed to fetch feature flags:', error);
      this._setDefaults();
    }
  }

  /**
   * Check if a feature flag is enabled.
   *
   * Returns false if flags haven't been fetched yet or if flag is not set.
   * Call fetchFlags() first to load flags from backend.
   *
   * @param flag - The feature flag to check
   * @returns True if flag is enabled, false otherwise
   */
  isEnabled(flag: FeatureFlag): boolean {
    return this.flags.get(flag) ?? false;
  }

  /**
   * Set safe defaults for all flags.
   * Called when fetch fails or endpoint is unavailable.
   */
  private _setDefaults(): void {
    this.flags.clear();
    this.flags.set(FeatureFlag.SPAN_BASED_FLOW, false);
    this.flags.set(FeatureFlag.DUAL_WRITE_MODE, true);
  }

  /**
   * Ensure all flags have a value, using defaults for missing ones.
   */
  private _ensureDefaults(): void {
    if (!this.flags.has(FeatureFlag.SPAN_BASED_FLOW)) {
      this.flags.set(FeatureFlag.SPAN_BASED_FLOW, false);
    }
    if (!this.flags.has(FeatureFlag.DUAL_WRITE_MODE)) {
      this.flags.set(FeatureFlag.DUAL_WRITE_MODE, true);
    }
  }

  /**
   * Clear cached flags.
   * Useful for testing or when user changes.
   */
  clear(): void {
    this.flags.clear();
    this.userId = null;
    this.fetchPromise = null;
  }

  /**
   * Get the current user ID.
   * Returns null if fetchFlags hasn't been called yet.
   */
  getUserId(): string | null {
    return this.userId;
  }

  /**
   * Get all flags as a plain object.
   * Useful for debugging or displaying flag status.
   *
   * @returns Object with all flags and their current values
   */
  getAllFlags(): Record<FeatureFlag, boolean> {
    const result: Record<string, boolean> = {};
    Object.values(FeatureFlag).forEach((flag) => {
      result[flag] = this.isEnabled(flag);
    });
    return result as Record<FeatureFlag, boolean>;
  }
}

/**
 * Global singleton instance.
 * Use this throughout the application.
 */
export const featureFlags = new FeatureFlagClient();

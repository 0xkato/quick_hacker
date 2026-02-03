'use client';

import { useEffect, useRef, useState, useCallback } from 'react';
import type { WSMessage, Finding, AgentProgress, LLMInteraction, ToolDetail, InvestigationFlow } from '@/types';
import { useAuth } from '@/hooks/useAuth';

const WS_BASE_URL = process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:8000/ws';
const RECONNECT_DELAY = 3000;
const AUTH_RETRY_DELAY = 500;
const MAX_AUTH_RETRIES = 3;

interface UseWebSocketOptions {
  onMessage?: (message: WSMessage) => void;
  onFinding?: (finding: Finding) => void;
  onProgress?: (agentId: string, progress: AgentProgress) => void;
  onAgentStatus?: (agentId: string, status: string) => void;
  onLog?: (agentId: string, message: string) => void;
  onError?: (agentId: string, error: string) => void;
  // Observability callbacks
  onLLMRequest?: (agentId: string, interaction: LLMInteraction) => void;
  onLLMResponse?: (agentId: string, interaction: LLMInteraction) => void;
  onToolDetail?: (agentId: string, detail: ToolDetail) => void;
  onStateSync?: (agentId: string, state: Record<string, unknown>) => void;
  onReportReady?: (agentId: string, reportId: string) => void;
  onFlowUpdate?: (agentId: string, flow: InvestigationFlow) => void;
  autoReconnect?: boolean;
  enabled?: boolean; // Only connect when true (default: true)
}

export function useWebSocket(options: UseWebSocketOptions = {}) {
  const [isConnected, setIsConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout>();
  const authRetryTimeoutRef = useRef<NodeJS.Timeout>();
  const optionsRef = useRef(options);
  const mountedRef = useRef(true);
  const reconnectAttempts = useRef(0);
  const authRetryCount = useRef(0);
  const connectionIdRef = useRef(0); // Track connection attempts to prevent stale callbacks

  const { getAccessToken, refreshToken } = useAuth();

  // Keep options ref updated
  useEffect(() => {
    optionsRef.current = options;
  }, [options]);

  const connect = useCallback(() => {
    // Clear any pending auth retry
    if (authRetryTimeoutRef.current) {
      clearTimeout(authRetryTimeoutRef.current);
      authRetryTimeoutRef.current = undefined;
    }

    // Don't connect if unmounted
    if (!mountedRef.current) {
      return;
    }

    // Already connected or connecting
    if (wsRef.current?.readyState === WebSocket.OPEN ||
        wsRef.current?.readyState === WebSocket.CONNECTING) {
      return;
    }

    // Get JWT access token
    const token = getAccessToken();

    // Don't connect without a valid token - retry after delay
    if (!token) {
      console.log('[WS] Waiting for auth token...');
      const currentConnectionId = ++connectionIdRef.current;
      authRetryTimeoutRef.current = setTimeout(() => {
        // Only retry if this is still the current connection attempt
        if (mountedRef.current && connectionIdRef.current === currentConnectionId) {
          connect();
        }
      }, AUTH_RETRY_DELAY);
      return;
    }

    try {
      const wsUrl = (() => {
        try {
          const url = new URL(WS_BASE_URL);
          url.searchParams.set('token', token);
          return url.toString();
        } catch {
          const sep = WS_BASE_URL.includes('?') ? '&' : '?';
          return `${WS_BASE_URL}${sep}token=${encodeURIComponent(token)}`;
        }
      })();
      const ws = new WebSocket(wsUrl);

      const sendAuth = () => {
        try {
          ws.send(JSON.stringify({ type: 'auth', token }));
        } catch (err) {
          console.error('[WS] Failed to send auth message:', err);
        }
      };

      ws.onopen = () => {
        if (!mountedRef.current) {
          ws.close();
          return;
        }
        setIsConnected(false);
        setError(null);
        console.log('[WS] Connected');
        sendAuth();
      };

      ws.onclose = async (event) => {
        wsRef.current = null;
        setIsConnected(false);

        // Check if this was an auth failure (code 4001)
        const isAuthFailure = event.code === 4001;

        if (isAuthFailure) {
          if (authRetryCount.current >= MAX_AUTH_RETRIES) {
            setError('Authentication failed. Please login again.');
            return;
          }

          authRetryCount.current++;
          console.log(`[WS] Auth failed, refreshing token (attempt ${authRetryCount.current}/${MAX_AUTH_RETRIES})`);

          // Refresh the token and retry
          try {
            const refreshed = await refreshToken();

            if (!refreshed) {
              throw new Error('Token refresh failed');
            }
            const currentConnectionId = connectionIdRef.current;
            reconnectTimeoutRef.current = setTimeout(() => {
              if (mountedRef.current && connectionIdRef.current === currentConnectionId) {
                connect();
              }
            }, 500);
          } catch (err) {
            console.error('[WS] Failed to refresh auth:', err);
            setError('Authentication failed. Please login again.');
          }
          return;
        }

        // Only reconnect if mounted and autoReconnect is enabled
        if (mountedRef.current && optionsRef.current.autoReconnect !== false) {
          reconnectAttempts.current++;
          const delay = Math.min(RECONNECT_DELAY * reconnectAttempts.current, 30000);
          const currentConnectionId = connectionIdRef.current;
          reconnectTimeoutRef.current = setTimeout(() => {
            // Only reconnect if this is still the current connection attempt
            if (mountedRef.current && connectionIdRef.current === currentConnectionId) {
              connect();
            }
          }, delay);
        }
      };

      ws.onerror = () => {
        setError('WebSocket connection error');
      };

      ws.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data) as WSMessage;
          const opts = optionsRef.current;

          // Server may request auth after accepting the socket.
          if (message.type === 'auth_required') {
            sendAuth();
            return;
          }

          if (message.type === 'auth_ok') {
            reconnectAttempts.current = 0;
            authRetryCount.current = 0;
            setIsConnected(true);
            setError(null);
            return;
          }

          // Call general message handler
          opts.onMessage?.(message);

          // Call specific handlers based on message type
          switch (message.type) {
            case 'finding':
              opts.onFinding?.(message.data as unknown as Finding);
              break;
            case 'progress':
              opts.onProgress?.(
                message.agent_id,
                message.data as unknown as AgentProgress
              );
              break;
            case 'agent_status':
              opts.onAgentStatus?.(
                message.agent_id,
                message.data.status as string
              );
              break;
            case 'log':
              opts.onLog?.(
                message.agent_id,
                message.data.message as string
              );
              break;
            case 'error':
              opts.onError?.(
                message.agent_id,
                message.data.error as string
              );
              break;
            // Observability message types
            case 'llm_request':
              opts.onLLMRequest?.(
                message.agent_id,
                message.data as unknown as LLMInteraction
              );
              break;
            case 'llm_response':
              opts.onLLMResponse?.(
                message.agent_id,
                message.data as unknown as LLMInteraction
              );
              break;
            case 'tool_detail':
              opts.onToolDetail?.(
                message.agent_id,
                message.data as unknown as ToolDetail
              );
              break;
            case 'state_sync':
              opts.onStateSync?.(
                message.agent_id,
                message.data as Record<string, unknown>
              );
              break;
            case 'report_ready':
              opts.onReportReady?.(
                message.agent_id,
                message.data.report_id as string
              );
              break;
            case 'flow_update':
              opts.onFlowUpdate?.(
                message.agent_id,
                message.data as unknown as InvestigationFlow
              );
              break;
          }
        } catch (e) {
          console.error('[WS] Failed to parse message:', e);
        }
      };

      wsRef.current = ws;
    } catch (e) {
      setError('Failed to connect to WebSocket');
      console.error('[WS] Connection failed:', e);
    }
  }, [getAccessToken, refreshToken]);

  const disconnect = useCallback(() => {
    // Increment connection ID to invalidate any pending callbacks
    connectionIdRef.current++;

    if (authRetryTimeoutRef.current) {
      clearTimeout(authRetryTimeoutRef.current);
      authRetryTimeoutRef.current = undefined;
    }
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = undefined;
    }
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
  }, []);

  const send = useCallback((data: Record<string, unknown>) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(data));
    }
  }, []);

  const subscribe = useCallback((repoId?: string, agentId?: string) => {
    send({ type: 'subscribe', repo_id: repoId, agent_id: agentId });
  }, [send]);

  const ping = useCallback(() => {
    send({ type: 'ping' });
  }, [send]);

  // Connect when enabled, disconnect on unmount
  useEffect(() => {
    mountedRef.current = true;

    // Only connect if enabled (default: true)
    const shouldConnect = options.enabled !== false;
    if (shouldConnect) {
      connect();
    }

    return () => {
      mountedRef.current = false;
      disconnect();
    };
  }, [options.enabled]); // eslint-disable-line react-hooks/exhaustive-deps

  // Heartbeat
  useEffect(() => {
    if (!isConnected) return;

    const interval = setInterval(() => {
      ping();
    }, 30000);

    return () => clearInterval(interval);
  }, [isConnected, ping]);

  return {
    isConnected,
    error,
    connect,
    disconnect,
    send,
    subscribe,
    ping,
  };
}

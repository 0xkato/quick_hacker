# JWT-Only Authentication Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace dual-mode auth (legacy session + JWT) with JWT-only authentication requiring user login.

**Architecture:** Remove all legacy session token code. WebSocket accepts JWT via query param only. Frontend redirects to login when not authenticated.

**Tech Stack:** FastAPI, PyJWT, React Context, localStorage

---

## Task 1: Remove Legacy Session Auth from Backend

**Files:**
- Modify: `backend/middleware/auth.py`

**Step 1: Remove legacy session imports and globals**

Remove lines 3-6 (threading, secrets for sessions), lines 22-25 (legacy globals):

```python
# DELETE these lines:
import secrets
import threading
# ...
_MASTER_TOKEN_CACHE: Optional[str] = None
_LEGACY_SESSION_TOKENS: dict[str, datetime] = {}
_LEGACY_LOCK = threading.Lock()
_LEGACY_SESSION_TTL = timedelta(hours=24)
```

**Step 2: Remove is_legacy_token from AuthContext**

```python
class AuthContext(BaseModel):
    """Authentication context for requests."""
    user_id: Optional[uuid.UUID] = None
    username: Optional[str] = None
    is_authenticated: bool = False
    # REMOVE: is_legacy_token: bool = False

    class Config:
        arbitrary_types_allowed = True
```

**Step 3: Simplify get_auth_context - remove legacy fallback**

```python
async def get_auth_context(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> AuthContext:
    """Get authentication context from JWT Bearer token."""
    if not credentials:
        return AuthContext(is_authenticated=False)

    payload = auth_service.decode_token(credentials.credentials)
    if not payload or payload.get("type") != "access":
        return AuthContext(is_authenticated=False)

    user_id = uuid.UUID(payload["sub"])
    user = await auth_service.get_user_by_id(db, user_id)
    if not user or not user.is_active:
        return AuthContext(is_authenticated=False)

    return AuthContext(
        user_id=user.id,
        username=user.username,
        is_authenticated=True
    )
```

**Step 4: Delete legacy functions**

Delete these functions entirely:
- `_get_master_token()` (lines 98-107)
- `get_session_token()` (lines 110-140)
- `create_new_session()` (lines 143-149)
- `verify_session()` (lines 152-169)

**Step 5: Simplify verify_ws_token to JWT only**

```python
def verify_ws_token(token: str) -> Optional[dict]:
    """Verify JWT access token for WebSocket. Returns payload or None."""
    if not token:
        return None
    payload = auth_service.decode_token(token)
    if payload and payload.get("type") == "access":
        return payload
    return None
```

**Step 6: Update get_user_api_key_for_provider**

Remove the `is_legacy_token` check:

```python
async def get_user_api_key_for_provider(
    provider: str,
    auth_context: AuthContext,
    db: AsyncSession
) -> Optional[str]:
    """Get the decrypted API key for a user and provider."""
    provider = (provider or "").strip().lower()

    # Get per-user keys for authenticated users
    if auth_context.user_id:
        try:
            key = await auth_service.get_user_api_key(db, auth_context.user_id, provider)
            if key:
                return key
        except Exception:
            pass

    # Fall back to app-level settings
    try:
        from services.settings_service import settings_service
        app_settings = await settings_service.get_settings()
        provider_settings = app_settings.providers.get(provider)
        if provider_settings and provider_settings.api_key:
            return provider_settings.api_key
    except Exception:
        pass

    # Final fallback: environment variables
    if provider == "anthropic":
        return os.environ.get("ANTHROPIC_API_KEY")
    if provider == "openai":
        return os.environ.get("OPENAI_API_KEY")
    return None
```

**Step 7: Run tests**

```bash
cd backend && python -m pytest tests/ -v --tb=short 2>&1 | tail -20
```

**Step 8: Commit**

```bash
git add backend/middleware/auth.py
git commit -m "refactor: remove legacy session auth from middleware

- Remove session token globals and functions
- Simplify get_auth_context to JWT only
- Update verify_ws_token to return payload
- Remove is_legacy_token from AuthContext

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Task 2: Simplify WebSocket to Query Param JWT Only

**Files:**
- Modify: `backend/routers/websocket.py`

**Step 1: Update imports**

Change verify_ws_token import (it now returns Optional[dict]):

```python
from middleware.auth import verify_ws_token
```

**Step 2: Simplify websocket_endpoint**

Replace the entire endpoint (lines 121-252) with:

```python
@router.websocket("")
async def websocket_endpoint(
    websocket: WebSocket,
    token: Optional[str] = Query(None),
):
    """
    WebSocket endpoint for real-time updates.

    Authentication: Pass JWT access token as query parameter: /ws?token=<jwt>

    Receives:
    - subscribe: { repo_id?: string, agent_id?: string }
    - ping: heartbeat

    Sends:
    - agent_status, finding, progress, error, log, pong, etc.
    """
    # Get token from query param (FastAPI or fallback to Starlette)
    token = token or websocket.query_params.get("token")

    # Validate JWT immediately - reject if invalid
    payload = verify_ws_token(token)
    if not payload:
        await websocket.close(code=4001, reason="Invalid or missing token")
        return

    # Accept connection
    await websocket.accept()
    await manager.connect(websocket)

    try:
        while True:
            data = await websocket.receive_text()

            try:
                message = json.loads(data)
            except json.JSONDecodeError:
                await manager.send_personal(
                    websocket,
                    {"type": "error", "data": {"error": "Invalid JSON"}}
                )
                continue

            msg_type = message.get("type", "")

            if msg_type == "ping":
                await manager.send_personal(websocket, {"type": "pong"})

            elif msg_type == "subscribe":
                await manager.send_personal(
                    websocket,
                    {
                        "type": "subscribed",
                        "data": {
                            "repo_id": message.get("repo_id"),
                            "agent_id": message.get("agent_id"),
                        }
                    }
                )

            elif msg_type == "get_status":
                stats = await orchestrator.get_stats()
                await manager.send_personal(
                    websocket,
                    {"type": "status", "data": stats}
                )

            else:
                await manager.send_personal(
                    websocket,
                    {"type": "error", "data": {"error": f"Unknown message type: {msg_type}"}}
                )

    except WebSocketDisconnect:
        await manager.disconnect(websocket)
    except Exception as e:
        print(f"WebSocket error: {e}")
        await manager.disconnect(websocket)
```

**Step 3: Run backend to verify**

```bash
cd backend && python -c "from routers.websocket import router; print('WebSocket router OK')"
```

**Step 4: Commit**

```bash
git add backend/routers/websocket.py
git commit -m "refactor: simplify WebSocket to JWT query param only

- Remove auth handshake (no more auth_required challenge)
- Validate JWT from query param immediately
- Reject invalid connections with 4001 code
- Cleaner message handling loop

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Task 3: Fix Flow 404 - Return Empty Flow

**Files:**
- Modify: `backend/routers/agents.py`

**Step 1: Update get_agent_flow to return empty flow**

Find and replace lines 269-275:

```python
@router.get("/{agent_id}/flow")
async def get_agent_flow(agent_id: str):
    """Get investigation flow for an agent."""
    flow = flow_service.get_flow(agent_id)
    if not flow:
        # Return empty flow instead of 404
        return {
            "session_id": agent_id,
            "nodes": [],
            "edges": [],
            "current_node_id": None
        }
    return flow.to_dict()
```

**Step 2: Verify the change**

```bash
cd backend && python -c "from routers.agents import router; print('Agents router OK')"
```

**Step 3: Commit**

```bash
git add backend/routers/agents.py
git commit -m "fix: return empty flow instead of 404

Frontend expects empty flow for agents that haven't started analysis.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Task 4: Remove Legacy Session Token from Frontend API

**Files:**
- Modify: `frontend/lib/api.ts`

**Step 1: Remove session token imports and globals**

Delete lines 92-149 (session token management):

```typescript
// DELETE all of this:
// Session token management
let _sessionToken: string | null = null;
let _tokenFetchPromise: Promise<string> | null = null;

export async function initializeAuth(): Promise<string> { ... }
export async function refreshAuth(): Promise<string> { ... }
export function getSessionToken(): string | null { ... }
export function isAuthInitialized(): boolean { ... }
export function clearSessionToken(): void { ... }
```

**Step 2: Remove X-Session-Token from request function**

Update the request function (around line 151):

```typescript
async function request<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const url = `${API_BASE}${endpoint}`;

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...options.headers as Record<string, string>,
  };

  // REMOVE: X-Session-Token header logic
  // if (_sessionToken) {
  //   headers['X-Session-Token'] = _sessionToken;
  // }

  const response = await fetchWithAuth(url, {
    ...options,
    headers,
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }));
    throw new APIError(response.status, error.detail || 'Request failed');
  }

  return response.json();
}
```

**Step 3: Remove session token from downloadReport**

Update agents.downloadReport (around line 385):

```typescript
async downloadReport(agentId: string, format: 'md' | 'json' | 'svg'): Promise<Blob> {
  const url = `${API_BASE}/api/agents/${agentId}/report/download?format=${format}`;
  const response = await fetchWithAuth(url);
  if (!response.ok) {
    throw new APIError(response.status, 'Failed to download report');
  }
  return response.blob();
},
```

**Step 4: Verify build**

```bash
cd frontend && npm run build 2>&1 | tail -10
```

**Step 5: Commit**

```bash
git add frontend/lib/api.ts
git commit -m "refactor: remove legacy session token from API client

- Remove initializeAuth, refreshAuth, getSessionToken functions
- Remove X-Session-Token header from requests
- JWT auth via fetchWithAuth is now the only path

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Task 5: Update WebSocket to Use JWT Query Param

**Files:**
- Modify: `frontend/hooks/useWebSocket.ts`

**Step 1: Remove legacy imports**

```typescript
// REMOVE this import:
// import { getSessionToken, refreshAuth } from '@/lib/api';
```

**Step 2: Simplify connect function**

Update the connect callback to use JWT only and pass in URL:

```typescript
const connect = useCallback(() => {
  if (authRetryTimeoutRef.current) {
    clearTimeout(authRetryTimeoutRef.current);
    authRetryTimeoutRef.current = undefined;
  }

  if (!mountedRef.current) return;

  if (wsRef.current?.readyState === WebSocket.OPEN ||
      wsRef.current?.readyState === WebSocket.CONNECTING) {
    return;
  }

  // JWT token only - no legacy fallback
  const token = getAccessToken();

  if (!token) {
    console.log('[WS] No auth token, waiting...');
    const currentConnectionId = ++connectionIdRef.current;
    authRetryTimeoutRef.current = setTimeout(() => {
      if (mountedRef.current && connectionIdRef.current === currentConnectionId) {
        connect();
      }
    }, AUTH_RETRY_DELAY);
    return;
  }

  try {
    // Pass token in query param
    const wsUrl = `${WS_BASE_URL}?token=${encodeURIComponent(token)}`;
    const ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      if (!mountedRef.current) {
        ws.close();
        return;
      }
      reconnectAttempts.current = 0;
      authRetryCount.current = 0;
      setIsConnected(true);
      setError(null);
      console.log('[WS] Connected');
      // No auth message needed - token is in URL
    };

    ws.onclose = async (event) => {
      wsRef.current = null;
      setIsConnected(false);

      const isAuthFailure = event.code === 4001;

      if (isAuthFailure && authRetryCount.current < MAX_AUTH_RETRIES) {
        authRetryCount.current++;
        console.log(`[WS] Auth failed, refreshing token (attempt ${authRetryCount.current}/${MAX_AUTH_RETRIES})`);

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

      if (mountedRef.current && optionsRef.current.autoReconnect !== false) {
        reconnectAttempts.current++;
        const delay = Math.min(RECONNECT_DELAY * reconnectAttempts.current, 30000);
        const currentConnectionId = connectionIdRef.current;
        reconnectTimeoutRef.current = setTimeout(() => {
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

        // No more auth_required handling needed
        opts.onMessage?.(message);

        switch (message.type) {
          case 'finding':
            opts.onFinding?.(message.data as unknown as Finding);
            break;
          case 'progress':
            opts.onProgress?.(message.agent_id, message.data as unknown as AgentProgress);
            break;
          case 'agent_status':
            opts.onAgentStatus?.(message.agent_id, message.data.status as string);
            break;
          case 'log':
            opts.onLog?.(message.agent_id, message.data.message as string);
            break;
          case 'error':
            opts.onError?.(message.agent_id, message.data.error as string);
            break;
          case 'llm_request':
            opts.onLLMRequest?.(message.agent_id, message.data as unknown as LLMInteraction);
            break;
          case 'llm_response':
            opts.onLLMResponse?.(message.agent_id, message.data as unknown as LLMInteraction);
            break;
          case 'tool_detail':
            opts.onToolDetail?.(message.agent_id, message.data as unknown as ToolDetail);
            break;
          case 'state_sync':
            opts.onStateSync?.(message.agent_id, message.data as Record<string, unknown>);
            break;
          case 'report_ready':
            opts.onReportReady?.(message.agent_id, message.data.report_id as string);
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
```

**Step 3: Remove tokenKindRef**

Delete the `tokenKindRef` and any references to it.

**Step 4: Verify build**

```bash
cd frontend && npm run build 2>&1 | tail -10
```

**Step 5: Commit**

```bash
git add frontend/hooks/useWebSocket.ts
git commit -m "refactor: WebSocket uses JWT query param only

- Remove legacy session token fallback
- Pass token in URL: /ws?token=<jwt>
- Remove auth_required message handling
- Simpler connection flow

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Task 6: Add Login Redirect for Unauthenticated Users

**Files:**
- Modify: `frontend/app/page.tsx` (or main layout)

**Step 1: Check current app structure**

```bash
ls frontend/app/
```

**Step 2: Add auth check to main page**

In the main page component, add redirect logic:

```typescript
'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/hooks/useAuth';

export default function Home() {
  const { isAuthenticated, isLoading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      router.push('/login');
    }
  }, [isLoading, isAuthenticated, router]);

  if (isLoading) {
    return <div className="flex items-center justify-center h-screen">Loading...</div>;
  }

  if (!isAuthenticated) {
    return null; // Will redirect
  }

  // ... rest of the page
}
```

**Step 3: Verify build**

```bash
cd frontend && npm run build 2>&1 | tail -10
```

**Step 4: Commit**

```bash
git add frontend/app/
git commit -m "feat: redirect unauthenticated users to login

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Task 7: Run Full Test Suite and Verify

**Step 1: Run backend tests**

```bash
cd backend && python -m pytest tests/ -v --tb=short
```

**Step 2: Build frontend**

```bash
cd frontend && npm run build
```

**Step 3: Manual verification**

Start the app and verify:
1. Opening app without login redirects to /login
2. After login, WebSocket connects (check console for "[WS] Connected")
3. Agents can be created and run
4. Flow endpoint returns empty flow for new agents (no 404)

**Step 4: Final commit**

```bash
git add -A
git commit -m "chore: JWT-only auth implementation complete

- Removed all legacy session token code
- WebSocket uses JWT via query param
- Frontend redirects to login when unauthenticated
- Flow returns empty instead of 404

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

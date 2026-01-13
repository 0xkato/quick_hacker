# JWT-Only Authentication Design

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace dual-mode auth (legacy session + JWT) with JWT-only authentication requiring user login.

**Architecture:** Single JWT-based auth flow with access tokens (15 min) and refresh tokens (7 days). WebSocket accepts token via query param only, no handshake. Proactive token refresh keeps users logged in.

**Tech Stack:** FastAPI, JWT (PyJWT), React hooks, localStorage

---

## What We're Removing

- Legacy session tokens (`data/.session_token`)
- `/api/auth/token` bootstrap endpoint
- `verify_session()`, `create_session()`, `get_or_create_session_token()`
- WebSocket auth handshake (challenge/response dance)
- Dual-mode token checking everywhere

## What We're Keeping

- JWT access tokens (15 min lifetime)
- JWT refresh tokens (7 days lifetime)
- User login/register endpoints
- `auth_service.decode_token()` for JWT validation

---

## New Auth Flow

```
App Load → Check localStorage for tokens
  ├─ No tokens → Redirect to /login
  └─ Has tokens → Validate access token
       ├─ Valid → Proceed to app
       └─ Expired → Try refresh
            ├─ Success → Proceed with new tokens
            └─ Fail → Redirect to /login

WebSocket → ws://host/ws?token=<access_token>
  ├─ Valid → Connection accepted
  └─ Invalid → Connection rejected (no handshake)

Token Refresh → Proactive at 80% lifetime (~12 min)
  └─ Also triggered on 401 responses
```

---

## Backend Changes

### 1. middleware/auth.py

Remove:
- `verify_session()`
- `create_session()`
- `get_or_create_session_token()`
- `_load_master_token()`
- Session token file handling

Simplify `verify_ws_token()`:
```python
def verify_ws_token(token: str) -> Optional[dict]:
    """Verify JWT access token for WebSocket."""
    if not token:
        return None
    payload = auth_service.decode_token(token)
    if payload and payload.get("type") == "access":
        return payload
    return None
```

### 2. routers/auth.py

Remove:
- `GET /api/auth/token` endpoint (legacy session bootstrap)

Keep:
- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/refresh`
- `POST /api/auth/logout`
- `GET /api/auth/verify`
- `GET /api/auth/me`

### 3. routers/websocket.py

Simplify to:
```python
@router.websocket("")
async def websocket_endpoint(websocket: WebSocket, token: str = Query(None)):
    # Validate token immediately
    payload = verify_ws_token(token)
    if not payload:
        await websocket.close(code=4001, reason="Invalid or missing token")
        return

    # Accept and manage connection
    await websocket.accept()
    user_id = payload.get("sub")
    await manager.connect(websocket, user_id)
    # ... rest of handler
```

### 4. routers/agents.py

Fix flow 404 - return empty flow instead of 404:
```python
@router.get("/{agent_id}/flow")
async def get_agent_flow(agent_id: str):
    flow = flow_service.get_flow(agent_id)
    if not flow:
        return InvestigationFlow(session_id=agent_id, nodes=[], edges=[])
    return flow
```

---

## Frontend Changes

### 1. lib/api.ts

Remove:
- `initializeAuth()`
- `getSessionToken()` / `setSessionToken()`
- Legacy token fallback logic

Add:
- `isAuthenticated()` check
- Request interceptor for 401 handling
- Token refresh queue for concurrent requests

### 2. hooks/useWebSocket.ts

Change connection URL:
```typescript
const url = `${WS_BASE_URL}?token=${encodeURIComponent(accessToken)}`;
const ws = new WebSocket(url);
```

Remove:
- Auth handshake message sending
- `auth_required` message handling

Add:
- Pre-connection auth check
- On 4001: refresh token, reconnect

### 3. hooks/useAuth.ts (new or enhanced)

```typescript
export function useAuth() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  // Check auth on mount
  // Proactive refresh scheduling
  // Logout handler

  return { isAuthenticated, isLoading, login, logout, refreshAuth };
}
```

### 4. App routing

- Wrap protected routes with auth check
- Redirect to `/login` when not authenticated
- Redirect to app after successful login

---

## Error Handling

| Scenario | Action |
|----------|--------|
| 401 on API request | Try refresh once, retry request |
| Refresh fails | Clear tokens, redirect to login |
| WebSocket 4001 close | Refresh token, reconnect |
| WebSocket disconnect | Check token, reconnect if valid |
| Token expires in <2 min | Proactive refresh |

---

## Files Changed

**Backend (remove ~200 lines, modify ~50):**
- `middleware/auth.py` - Remove session logic
- `routers/auth.py` - Remove /token endpoint
- `routers/websocket.py` - Simplify to query param auth
- `routers/agents.py` - Fix flow 404

**Frontend (remove ~150 lines, modify ~100):**
- `lib/api.ts` - Remove legacy auth
- `hooks/useWebSocket.ts` - Query param token
- `hooks/useAuth.ts` - New/enhanced auth hook
- `app/layout.tsx` or similar - Auth provider wrapper

# Legacy Code Removal Design

**Date:** 2026-01-10
**Status:** Approved
**Estimated Removal:** ~5,000+ lines of dead code

## Overview

This document outlines the complete removal of legacy code from the Quick Hack codebase, including:
- Legacy session token authentication (replaced by JWT)
- Dead agent implementations (DeepAuditAgent, UltrathinkAgent)
- Orphaned frontend components
- Legacy prompt files
- Redundant agent type mappings

## 1. Legacy Authentication Removal

### Goal
Complete removal of legacy session token auth. JWT-only authentication going forward.

### Backend Changes

#### `backend/middleware/auth.py`
Remove:
- `_session_tokens` and `_ephemeral_sessions` caches
- `_get_master_token()` function
- `get_session_token()` function
- `create_new_session()` function
- `verify_session()` function
- `X-Session-Token` header handling in `get_auth_context()`

Update:
- `verify_ws_token()` - JWT-only validation

Keep:
- JWT auth logic
- `get_current_user()`
- `get_api_key_for_provider()`

#### `backend/main.py`
Remove:
- `GET /api/auth/token` endpoint
- `POST /api/auth/session` endpoint
- `GET /api/auth/verify` endpoint
- `X-Session-Token` from CORS allowed headers

### Frontend Changes

#### `frontend/lib/api.ts`
Remove:
- `_sessionToken` variable
- `initializeAuth()` legacy token fetch
- `refreshAuth()` legacy refresh
- `getSessionToken()`, `setSessionToken()`, `clearSessionToken()`
- `X-Session-Token` header from `request()` function

Keep:
- JWT Bearer token handling

#### `frontend/hooks/useWebSocket.ts`
Remove:
- Legacy token fallback logic
- `tokenKind` tracking for `'legacy'` type

Update:
- Simplify to JWT-only connection

### Config Changes

#### `.env.example`
Remove:
- Lines 66-69: Legacy auth comments
- `AUTH_BOOTSTRAP_ALLOW_REMOTE` variable

### Test Files to Delete
- `backend/tests/test_legacy_auth_tokens.py`
- `backend/tests/test_websocket_auth_tokens.py`

### Runtime Files
- `data/.session_token` - Will no longer be created (ensure in .gitignore)

---

## 2. Dead Agent Code Removal

### Analysis Summary

| Agent Type | Class | Behavior | Action |
|-----------|-------|----------|--------|
| `QUICK_AUDIT` | QuickAuditAgent | Pattern-based fast scan | Keep |
| `DEEP_AUDIT` | ReActSecurityAgent | 60min marathon mode | Keep |
| `STRICT_ANALYSIS` | ReActSecurityAgent | 0.9+ confidence gate | Keep |
| `ULTRA_STRICT` | ReActSecurityAgent | 0.95+ + double verification | Keep |
| `CUSTOM` | ReActSecurityAgent | Default config | Keep |
| `DEEP_SCAN` | ReActSecurityAgent | Identical to CUSTOM | **Remove** |
| `ULTRATHINK` | UltrathinkAgent | Not exposed in frontend | **Remove** |

### Files to Delete

| File/Directory | Lines | Reason |
|----------------|-------|--------|
| `backend/agents/deep_audit_agent.py` | 1,162 | Never instantiated |
| `backend/agents/ultrathink_agent.py` | ~500 | Frontend doesn't expose |
| `backend/ultrathink/` (entire directory) | ~1,000 | Cascade system unreachable |
| `backend/tests/agents/test_deep_audit_coverage_integration.py` | ~200 | Tests removed agent |

### Files to Modify

#### `backend/agents/__init__.py`
Remove:
- `DeepAuditAgent` import and export
- `UltrathinkAgent` import and export

#### `backend/services/agent_orchestrator.py`
Remove:
- Lines 151-153: `FocusedAgent` reference (fixes crash bug)
- `AgentType.DEEP_SCAN` from `AGENT_CLASSES` mapping
- `AgentType.ULTRATHINK` from `AGENT_CLASSES` mapping

#### `backend/models/schemas.py` (or AgentType enum location)
Remove:
- `DEEP_SCAN` enum value
- `ULTRATHINK` enum value

#### `frontend/types/index.ts`
Remove:
- `'deep_scan'` from AgentType union

#### `frontend/components/AgentPanel/AgentManager.tsx`
Remove:
- DEEP_SCAN option from agent selector UI

---

## 3. Prompts Consolidation

### Legacy Prompt Files to Delete

| File | Lines | Reason |
|------|-------|--------|
| `backend/prompts/system_prompts.py` | 1,063 | Only imported by dead code path in base_agent |
| `backend/prompts/audit_methodology.py` | 652 | Same - dead import path |

### Files to Modify

#### `backend/agents/base_agent.py`
Remove:
- Import of `get_system_prompt` from `system_prompts`
- Import of `get_audit_prompt` from `audit_methodology`
- Any code using these functions (dead path)

#### `backend/prompts/__init__.py`
Update:
- Remove legacy exports
- Keep v2 and layer architecture exports

### Files to Keep
- `backend/prompts/strict_prompts.py` - Actively used by react_agent
- `backend/prompts/classification_gate.py` - Actively used by react_agent
- `backend/prompts/hard_rules.py` - New layer 1
- `backend/prompts/workflow_engine.py` - New layer 2
- `backend/prompts/run_config.py` - New layer 3
- `backend/prompts/v2/` - New modular system

---

## 4. Orphaned Frontend Components

### Directories to Delete

| Directory | Files | Reason |
|-----------|-------|--------|
| `frontend/components/CodeGraphVisualization/` | CodeGraphVisualization.tsx, CodeGraphNode.tsx, index.ts | Never imported in page.tsx |
| `frontend/components/CoveragePanel/` | CoverageTree.tsx, index.ts | Never imported in page.tsx |
| `frontend/components/UltrathinkPanel/` | UltrathinkPanel.tsx, GateProgress.tsx, ThinkingTrace.tsx, index.ts | Never imported in page.tsx |

### Backend Services to KEEP
These services are used by agents even though the UI components are orphaned:
- `backend/services/code_graph_service.py` - Used by react_agent lines 795, 1317
- `backend/routers/graph.py` - API endpoints for agent graph tracking
- `backend/services/coverage_tracker.py` - Used by agents for path analysis

---

## 5. Implementation Order

### Phase 1: Safe Deletions (No Dependencies)
1. Delete orphaned frontend components
2. Delete legacy test files
3. Delete legacy prompt files

### Phase 2: Agent Cleanup
1. Delete dead agent files (deep_audit_agent, ultrathink_agent, ultrathink/)
2. Update agent __init__.py exports
3. Update agent_orchestrator.py mappings
4. Fix FocusedAgent crash bug

### Phase 3: Auth Migration
1. Update frontend api.ts - remove legacy token handling
2. Update frontend useWebSocket.ts - JWT-only
3. Update backend middleware/auth.py - remove legacy functions
4. Update backend main.py - remove legacy endpoints
5. Update .env.example - remove legacy config

### Phase 4: Type Cleanup
1. Remove DEEP_SCAN from AgentType enum
2. Remove ULTRATHINK from AgentType enum
3. Update frontend types
4. Update AgentManager UI

### Phase 5: Verification
1. Run all tests
2. Start backend and frontend
3. Test authentication flow
4. Test agent creation for remaining types
5. Verify no console errors

---

## 6. Files Summary

### Total Files to Delete: 14

**Backend:**
- `agents/deep_audit_agent.py`
- `agents/ultrathink_agent.py`
- `ultrathink/cascade.py`
- `ultrathink/gates.py`
- `ultrathink/thinking.py`
- `ultrathink/config.py`
- `ultrathink/events.py`
- `ultrathink/__init__.py`
- `prompts/system_prompts.py`
- `prompts/audit_methodology.py`
- `tests/agents/test_deep_audit_coverage_integration.py`
- `tests/test_legacy_auth_tokens.py`
- `tests/test_websocket_auth_tokens.py`

**Frontend:**
- `components/CodeGraphVisualization/` (directory)
- `components/CoveragePanel/` (directory)
- `components/UltrathinkPanel/` (directory)

### Total Files to Modify: 12

**Backend:**
- `middleware/auth.py`
- `main.py`
- `agents/__init__.py`
- `agents/base_agent.py`
- `services/agent_orchestrator.py`
- `models/schemas.py` (or enum location)
- `prompts/__init__.py`

**Frontend:**
- `lib/api.ts`
- `hooks/useWebSocket.ts`
- `types/index.ts`
- `components/AgentPanel/AgentManager.tsx`

**Config:**
- `.env.example`

---

## 7. Risk Mitigation

### Before Starting
- Create a git branch for this work
- Ensure all tests pass on main
- Have a working local dev environment

### During Implementation
- Delete files before modifying (cleaner diffs)
- Run tests after each phase
- Commit after each phase

### After Completion
- Full test suite pass
- Manual testing of auth flow
- Manual testing of agent creation
- Review for any missed references

---

## 8. Estimated Impact

**Lines Removed:** ~5,000+
- deep_audit_agent.py: 1,162
- ultrathink/: ~1,000
- system_prompts.py: 1,063
- audit_methodology.py: 652
- Legacy auth code: ~500
- Frontend components: ~700
- Tests: ~400

**Benefits:**
- Cleaner codebase
- Reduced confusion about which systems to use
- Faster onboarding for new developers
- Smaller bundle size (frontend)
- No crash bugs from undefined classes

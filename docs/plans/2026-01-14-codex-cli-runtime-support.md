# Codex CLI Runtime Support Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add first-class `provider: "codex_cli"` support that runs the local `codex` binary (not OpenAI API) with MCP tool calls into quick_hack’s existing tool boundary, orchestration loop, persistence, and WebSocket streaming.

**Architecture:** Implement a `CodexCLIProvider` that runs `codex exec --json` / `codex exec resume --json`, parses JSONL events, and forwards compatible `{type: ...}` events to the existing backend orchestrator. Codex is constrained via per-agent `CODEX_HOME` config to use only a single stdio MCP server (`quickhack`) that delegates tool execution to `ToolCore`, preserving WorkspacePolicy + ScanLimits + offline-first scanning + persistence rules.

**Tech Stack:** Python 3.11, asyncio subprocess + streaming, JSON-RPC 2.0 (MCP over stdio), existing FastAPI/WebSocket broadcast, existing `services/security_scanners/*`, `services/tool_core.py`, `services/sink_signal_service.py`, `services/findings_service.py`, and triage pipeline.

---

## Key Design Decisions

1) **Provider selection**
- Add `ProviderType.CODEX_CLI = "codex_cli"` to API schemas + frontend `ProviderType`.
- Route Codex execution in `services/agent_orchestrator.py` when `provider_config.provider == "codex_cli"` (do not route through legacy `BaseProvider` factory).

2) **Codex JSONL event mapping**
- Map Codex JSONL `item.completed` with `item.type="agent_message"` → `{type:"agent_text", text: ...}`
- Map Codex JSONL MCP items `item.type="mcp_tool_call"`:
  - `item.started` → `{type:"tool_call", id:item.id, name:"mcp__<server>__<tool>", args:item.arguments}`
  - `item.completed` → `{type:"tool_result", tool_use_id:item.id, tool_name:"mcp__<server>__<tool>", result:<content>, is_error:<bool>}`
- Map `thread.started.thread_id` → `session_id` persisted in agent state.
- Map `turn.completed` → `{type:"turn_complete", session_id, usage}`
- Map `turn.failed` / `error` events → `{type:"error", message}`

3) **Per-agent CODEX_HOME isolation**
- For each Codex agent: `data/projects/<project_id>/.codex_runtime/<agent_id>/`
- Generate `config.toml`:
  - `[features] shell_tool=false, web_search_request=false`
  - `[mcp_servers.quickhack]` points to our stdio MCP server entrypoint
  - `[mcp_servers.quickhack.env]` passes `QUICKHACK_*` runtime parameters (repo_path, project_id, agent_id, limits/cancel files)
- Copy `auth.json` from the “global” Codex home (`~/.codex/auth.json` inside the runtime env/container) into the per-agent CODEX_HOME so `codex exec` works without API keys.

4) **MCP server**
- New server `backend/mcp/quickhack_mcp_server.py` implements minimal MCP surface:
  - `initialize`
  - `tools/list`
  - `tools/call`
- Tools exposed (must be curated + safe): `read_file`, `list_directory`, `grep_semantic`, `scan_repo_for_secrets`, `dependency_audit`, `analyze_ast`, `trace_dataflow`, `upsert_sink_signal`, `report_finding`, `promote_finding`.
- The MCP server instantiates `ToolCore` and delegates calls; it enforces:
  - WorkspacePolicy path validation for reads
  - no repo writes (only state store writes via services)
  - ScanLimits from orchestrator via a shared “limits” file + cancellation flag file

5) **Turn governor loop**
- Add a Codex-specific governor in `services/agent_orchestrator.py` (or a new `services/codex_cli_orchestrator.py`) that:
  - runs multiple Codex turns until scan budget exhausted
  - enforces minimum time floors (do not complete early)
  - after each turn: load/emit new sink signals + findings; run triage and persist findings
  - streams progress via existing WS message types (LLM_REQUEST/LLM_RESPONSE/TOOL_DETAIL/PROGRESS/FINDING/ERROR)
  - supports pause/resume: on pause, interrupt Codex subprocess and persist `session_id`; on resume, continue with `codex exec resume <session_id>`

---

## Implementation Tasks

### Task 1: Add codex_cli schema + UI wiring

**Files:**
- Modify: `backend/models/schemas.py`
- Modify: `frontend/types/index.ts`
- Modify: `frontend/components/AgentPanel/AgentManager.tsx`
- Modify: `backend/services/agent_orchestrator.py` (API key resolution exemption for codex_cli)
- Modify: `backend/services/settings_service.py` (default provider listing)

**Steps:**
1. Add `ProviderType.CODEX_CLI`.
2. Extend `ProviderConfig` with optional `codex_path?: string` and optional `codex_model?: string` if needed (keep backwards compatible).
3. Add Codex CLI provider to frontend dropdown + suggested model list, and don’t require API key for it.
4. Allow orchestrator to create agents with provider `codex_cli` without API keys.

**Verification:**
- `pytest backend/tests/test_session_schemas.py -q` (or nearest schema tests)

---

### Task 2: Add MCP server (stdio) + ToolCore parity

**Files:**
- Create: `backend/mcp/__init__.py`
- Create: `backend/mcp/quickhack_mcp_server.py`
- Modify: `backend/services/tool_core.py`

**Steps:**
1. Implement JSON-RPC loop for MCP:
   - parse stdin lines → requests
   - return JSON-RPC responses on stdout
2. Implement `tools/list` returning the curated tools and JSON schemas.
3. Implement `tools/call` dispatch mapping to `ToolCore` async methods.
4. Update `ToolCore`:
   - `search_code` delegates to `security_scanners.grep.semantic_grep` (ReDoS-safe)
   - `_validate_path` calls `WorkspacePolicy.validate_path` before manual resolve
   - add `analyze_ast` + `trace_dataflow` (Python-only initial support)

**Verification:**
- `pytest backend/tests/services/test_tool_core.py -q`
- `pytest backend/tests/services/test_tool_core_validity.py -q`

---

### Task 3: Implement CodexCLIProvider

**Files:**
- Create: `backend/providers/codex_cli_provider.py`

**Steps:**
1. Create per-agent CODEX_HOME and write config.toml.
2. Copy `auth.json` into CODEX_HOME if present.
3. Implement `start_session()` and `run_turn()` using:
   - first: `codex exec --json "<prompt>"`
   - resume: `codex exec resume --json <session_id> "<prompt>"`
4. Stream-parse JSONL and emit events compatible with `AgentOrchestrator` SDK event mapping.
5. Implement `interrupt()` with SIGTERM then SIGKILL fallback.

**Verification:**
- Unit tests in `backend/tests/providers/test_codex_cli_provider.py`

---

### Task 4: Orchestrator integration + pause/resume persistence

**Files:**
- Modify: `backend/services/agent_orchestrator.py`
- Modify: `backend/agents/base_agent.py` (include codex session_id in snapshot if present)

**Steps:**
1. Route `provider=="codex_cli"` to a new `_run_codex_cli_agent()`.
2. Implement Codex audit loop:
   - generate prompts
   - update MCP scan limits file before each turn
   - map Codex events → WS messages (LLM_REQUEST/LLM_RESPONSE/TOOL_DETAIL/etc.)
   - collect findings and run triage at end
3. Ensure cancel calls `provider.interrupt()` and stops promptly.
4. Ensure pause:
   - interrupts subprocess
   - persists session_id in `AgentStateSnapshot`
   - loop waits until `resume_agent` flips status back to RUNNING, then continues with `resume` command.

**Verification:**
- `pytest backend/tests/services/test_agent_orchestrator_sdk.py -q` (plus new codex tests)

---

### Task 5: Tests (unit + integration)

**Files:**
- Create: `backend/tests/providers/test_codex_cli_provider.py`
- Create: `backend/tests/mcp/test_quickhack_mcp_server.py`
- Create: `backend/tests/services/test_codex_cli_orchestrator_integration.py` (or similar)

**Coverage:**
- parse Codex JSONL → quickhack events
- session_id persistence + resume command args
- MCP dispatch + WorkspacePolicy enforcement (symlinks/escapes/excluded dirs)
- upsert sink signal dedupe
- “integration”: create/start agent via `/api/agents` with provider `codex_cli` using a stubbed Codex provider stream; verify sink_signals.json updated; verify findings saved + triage invoked

**Verification:**
- `pytest -q`

---

### Task 6: Docs (local + docker compose)

**Files:**
- Modify: `README.md` (or add `docs/codex-cli.md` and link from README)
- Optionally modify: `docker-compose.yml` (document mount for `~/.codex/auth.json`)

**Include:**
- Host install + `codex login`
- Docker mount instructions for `auth.json` into `/home/appuser/.codex/auth.json`
- Example request payload `{ provider:"codex_cli", model:"gpt-5.2-codex", codex_path:"codex" }`


# quick_hack System Architecture (Functional)

This document describes `quick_hack` as it runs today: processes, data flows, safety boundaries, and the full backend routing inventory. It intentionally focuses on functional runtime behavior and omits product/marketing details.

## Scope, Invariants, and Guardrails

**In scope**
- Backend runtime (FastAPI), routers, WebSocket, services, agents, providers, tools, scanners, triage, persistence.
- Frontend runtime (Next.js) route(s) and how it talks to the backend.
- Storage (PostgreSQL + on-disk state stores under `data/`).

**Core invariants (security/product)**
- **Tool authority**: LLMs propose actions; `quick_hack` executes tools and enforces policy.
- **Offline-first scanning**: scanners operate on local workspace content; no web search/fetching inside scanners.
- **Workspace boundaries**: file operations must respect `WorkspacePolicy` (no path escape, no symlink traversal, excluded dirs, max file size).
- **Budget & cancellation**: long-running audits are governed by scan tiers, time budgets, and cancellation propagation.
- **Findings discipline**: “signals” (leads) are distinct from “findings” (reportable issues); triage is authoritative for classification/disposition.

## Runtime Topology (Processes + Primary Flows)

**Processes (docker compose default)**
- `frontend` (Next.js): serves UI on `:3000`.
- `backend` (FastAPI): serves REST on `:8000` and WebSocket at `/ws`.
- `postgres` (PostgreSQL): durable storage for users, API keys, findings, evidence blobs.
- `redis` (optional): cache / pubsub (used by some subsystems; backend also has in-process tool output caching).
- `ollama` (optional): local model server for the `ollama` provider.
- `codex` (optional, host binary): spawned by backend when `provider=codex_cli` is used.

**Primary data flows**
1. **UI → REST**: Next.js calls `/api/*` for projects, files, agents, settings, triage, reports.
2. **UI → WebSocket**: `/ws` for real-time agent events (status/progress/findings/observability).
3. **Agent runtime**:
   - Orchestrator selects agent implementation and provider (OpenAI/Anthropic/Ollama/Claude SDK/Codex CLI).
   - Provider drives turns; tool calls are executed by `ToolCore` (directly or via MCP server).
   - Events are recorded in `ObservabilityService` and streamed over WebSocket.
4. **Persistence**:
   - Agent state snapshots saved to `data/agent_states/<agent_id>.json`.
   - Per-project sink signals saved to `data/projects/<project_id>/sink_signals.json`.
   - Findings/evidence stored in Postgres tables (`findings`, `evidence_blobs`).

## Backend: Entry Point and Lifecycle

**FastAPI app**: `backend/main.py`
- Startup (`lifespan`):
  - Registers main asyncio loop for cross-thread WebSocket broadcasts (`routers/websocket.py:set_main_loop`).
  - Initializes database tables (`database/connection.py:init_db`).
  - Checks triage schema availability (`database/schema_checker.py:initialize_triage_availability`).
  - Initializes services (`settings_service`, `project_service`).
- CORS: configured via `config.settings.cors_origins`.

## Backend: Authentication & Authorization

**JWT auth (HTTP)**
- JWT config: `backend/config.py` (`jwt_secret_key`, access/refresh TTL).
- Auth helpers:
  - Router-level enforcement for most endpoints via `Depends(require_auth)` (see `backend/middleware/auth.py`).
  - `backend/routers/auth.py` uses `HTTPBearer` and `get_current_user` for authenticated auth endpoints (e.g., `/me`).

**WebSocket auth**
- WebSocket endpoint accepts early, then validates:
  - Query token: `/ws?token=<jwt>`
  - Or a message-based handshake: `{ "type": "auth", "token": "<jwt>" }`
- Implementation: `backend/routers/websocket.py:websocket_endpoint` + `middleware.auth.verify_ws_token`.

## Backend: Routing Inventory (Complete)

Auth column meanings:
- `Public`: no JWT required
- `Bearer`: requires JWT (either via router dependencies or `Depends(get_current_user)`)

### Root routes (`backend/main.py`)

| Method | Path | Auth | Purpose / Side effects |
|---|---|---|---|
| GET | `/` | Public | Basic status payload (app + version). |
| GET | `/health` | Public | Docker healthcheck endpoint. |
| GET | `/api/health` | Bearer | Detailed health + provider configuration status. |

### WebSocket routes (`backend/routers/websocket.py`)

| Method | Path | Auth | Purpose / Side effects |
|---|---|---|---|
| WS | `/ws` | Bearer (query or handshake) | Real-time event stream + simple client commands (`ping`, `subscribe`, `get_status`). |

Note: `backend/routers/websocket.py` mentions a legacy `/api/auth/token` flow in comments, but there is no such HTTP endpoint implemented; WebSocket auth is JWT-only (`verify_ws_token`).

### Auth routes (`backend/routers/auth.py`)

| Method | Path | Auth | Purpose / Side effects |
|---|---|---|---|
| POST | `/api/auth/register` | Public | Create user; dev-friendly fallback to login if already exists. |
| POST | `/api/auth/login` | Public | Username/email + password → JWT access/refresh. |
| POST | `/api/auth/refresh` | Public | Refresh token → new access/refresh. |
| GET | `/api/auth/me` | Bearer | Current user profile. |
| PUT | `/api/auth/api-keys` | Bearer | Persist provider API key for current user (DB). |
| GET | `/api/auth/api-keys` | Bearer | API key presence status per provider. |
| DELETE | `/api/auth/api-keys/{provider}` | Bearer | Remove provider API key (DB). |
| POST | `/api/auth/api-keys/validate` | Bearer | Validates key via provider call; special-case Anthropic OAuth-style tokens. |

### Projects routes (`backend/routers/projects.py`)

All under `/api/projects/*` (router prefix `/projects`, included at `/api`).

| Method | Path | Auth | Purpose / Side effects |
|---|---|---|---|
| GET | `/api/projects` | Bearer | List projects. |
| POST | `/api/projects` | Bearer | Create project metadata (and project dir). |
| GET | `/api/projects/status` | Bearer | Return current selected project. |
| GET | `/api/projects/{project_id}` | Bearer | Get project. |
| PUT | `/api/projects/{project_id}` | Bearer | Update project metadata incl. threat model. |
| DELETE | `/api/projects/{project_id}` | Bearer | Delete project and its on-disk workspace. |
| POST | `/api/projects/{project_id}/enter` | Bearer | Set current project (workspace selection). |
| POST | `/api/projects/exit` | Bearer | Clear current project selection. |
| POST | `/api/projects/{project_id}/clone` | Bearer | Clone repo into project dir; optional `force` bypasses “already in project” guard. |
| POST | `/api/projects/{project_id}/refresh` | Bearer | Pull latest changes in project repo. |
| GET | `/api/projects/{project_id}/sink-signals` | Bearer | List persistent sink signals (`data/projects/<id>/sink_signals.json`). |
| PUT | `/api/projects/{project_id}/sink-signals/{fingerprint}/status` | Bearer | Update sink signal lifecycle status (no downgrades). |
| POST | `/api/projects/quick-clone` | Bearer | Create project + clone + auto-enter. |

### Git routes (`backend/routers/git.py`)

All under `/api/git/*` (included at `/api/git`).

| Method | Path | Auth | Purpose / Side effects |
|---|---|---|---|
| POST | `/api/git/clone` | Bearer | Clone repo into `repos/` (legacy path) and return `RepoInfo`. |
| GET | `/api/git/repos` | Bearer | List cloned repos (legacy). |
| GET | `/api/git/repos/{repo_id}` | Bearer | Get repo metadata. |
| DELETE | `/api/git/repos/{repo_id}` | Bearer | Delete repo checkout. |
| POST | `/api/git/repos/{repo_id}/refresh` | Bearer | Pull latest changes for a repo checkout. |

### Files routes (`backend/routers/files.py`)

All under `/api/files/*` (included at `/api/files`).

| Method | Path | Auth | Purpose / Side effects |
|---|---|---|---|
| GET | `/api/files/{repo_id}/tree` | Bearer | File tree (bounded by `max_depth`). |
| GET | `/api/files/{repo_id}/content` | Bearer | Read file by `path` query (WorkspacePolicy enforced in `file_service`). |
| GET | `/api/files/{repo_id}/files` | Bearer | List files by extensions (bounded). |
| GET | `/api/files/{repo_id}/search` | Bearer | Pattern search in repo (bounded). |

### Agents routes (`backend/routers/agents.py`)

All under `/api/agents/*` (included at `/api/agents`).

| Method | Path | Auth | Purpose / Side effects |
|---|---|---|---|
| POST | `/api/agents` | Bearer | Create agent (select repo/project + configs). |
| POST | `/api/agents/{agent_id}/start` | Bearer | Start agent task. |
| POST | `/api/agents/{agent_id}/pause` | Bearer | Request pause (best-effort per agent). |
| POST | `/api/agents/{agent_id}/resume` | Bearer | Resume paused agent. |
| POST | `/api/agents/{agent_id}/cancel` | Bearer | Cancel agent + propagate to provider interrupt. |
| GET | `/api/agents` | Bearer | List agents (optionally includes persisted agents). |
| GET | `/api/agents/stats` | Bearer | Orchestrator stats + capacity. |
| GET | `/api/agents/models` | Bearer | List available models by provider. |
| GET | `/api/agents/{agent_id}` | Bearer | Get agent (in-memory or persisted). |
| POST | `/api/agents/{agent_id}/load` | Bearer | Load persisted agent state into in-memory observability/flow caches. |
| DELETE | `/api/agents/{agent_id}` | Bearer | Delete agent, state, flow, observability. |
| GET | `/api/agents/{agent_id}/findings` | Bearer | Findings for agent (in-memory or persisted). |
| GET | `/api/agents/findings/all` | Bearer | Aggregate findings across agents (in-memory + persisted). |
| GET | `/api/agents/{agent_id}/llm-interactions` | Bearer | Observability: LLM interaction log. |
| GET | `/api/agents/{agent_id}/tool-details` | Bearer | Observability: tool execution log. |
| GET | `/api/agents/{agent_id}/observability-stats` | Bearer | Observability stats (counts + token usage). |
| POST | `/api/agents/{agent_id}/investigate` | Bearer | Queue follow-up investigation for a flow node. |
| GET | `/api/agents/{agent_id}/state` | Bearer | Return persisted `AgentStateSnapshot`. |
| GET | `/api/agents/{agent_id}/state/summary` | Bearer | Persisted state metadata without full load. |
| DELETE | `/api/agents/{agent_id}/state` | Bearer | Delete persisted state file. |
| GET | `/api/agents/saved-states` | Bearer | List persisted states. |
| GET | `/api/agents/{agent_id}/report` | Bearer | Get generated report (structured). |
| GET | `/api/agents/{agent_id}/report/download` | Bearer | Download report as `md|json|svg`. |
| GET | `/api/agents/reports/all` | Bearer | List reports. |
| POST | `/api/agents/{agent_id}/triage` | Bearer | Re-run triage (requires triage DB schema). |
| GET | `/api/agents/{agent_id}/triaged-findings/batch/{batch_id}` | Bearer | Retrieve triaged findings for a batch. |

### Settings routes (`backend/routers/settings.py`)

All under `/api/settings/*` (router prefix `/settings`, included at `/api`).

| Method | Path | Auth | Purpose / Side effects |
|---|---|---|---|
| GET | `/api/settings` | Bearer | Export full settings (keys masked). |
| GET | `/api/settings/providers` | Bearer | Provider config (keys masked). |
| PUT | `/api/settings/providers/{provider}` | Bearer | Update provider config (DB/settings store). |
| POST | `/api/settings/providers/{provider}/test` | Bearer | Smoke test provider with configured credentials. |
| GET | `/api/settings/agent-defaults` | Bearer | Get default provider/model + agent flags. |
| PUT | `/api/settings/agent-defaults` | Bearer | Update agent defaults. |
| GET | `/api/settings/models` | Bearer | Return configured model list. |
| GET | `/api/settings/prompts` | Bearer | List custom prompts. |
| POST | `/api/settings/prompts` | Bearer | Create custom prompt. |
| PUT | `/api/settings/prompts/{prompt_id}` | Bearer | Update custom prompt. |
| DELETE | `/api/settings/prompts/{prompt_id}` | Bearer | Delete custom prompt. |
| GET | `/api/settings/ui` | Bearer | Get UI preferences. |
| PUT | `/api/settings/ui` | Bearer | Update UI preferences. |
| POST | `/api/settings/export` | Bearer | Export settings JSON. |
| POST | `/api/settings/import` | Bearer | Import settings JSON. |

### Chat routes (`backend/routers/chat.py`)

All under `/api/chat/*` (router prefix `/chat`, included at `/api`).

| Method | Path | Auth | Purpose / Side effects |
|---|---|---|---|
| POST | `/api/chat/stream` | Bearer | SSE stream chat response (`text/event-stream`). |
| POST | `/api/chat` | Bearer | Non-streaming chat completion. |
| GET | `/api/chat/prompts` | Bearer | Returns available chat system prompt templates (preview). |

### Flow routes (`backend/routers/flow.py`)

All under `/api/*` (router has no prefix; included at `/api`).

| Method | Path | Auth | Purpose / Side effects |
|---|---|---|---|
| GET | `/api/agents/{agent_id}/flow` | Bearer | Get flow graph; may restore from persisted snapshot. |
| GET | `/api/agents/{agent_id}/flow/stats` | Bearer | Flow summary stats; may restore then compute. |
| DELETE | `/api/agents/{agent_id}/flow` | Bearer | Clear flow graph (in-memory). |
| POST | `/api/agents/{agent_id}/reconstruct` | Bearer | Reconstruct span DAG from events for visualization. |

### Graph routes (`backend/routers/graph.py`)

All under `/api/*` (included at `/api`).

| Method | Path | Auth | Purpose / Side effects |
|---|---|---|---|
| POST | `/api/agents/{agent_id}/graph/initialize` | Bearer | Initialize code graph for agent based on repo entry points. |
| GET | `/api/agents/{agent_id}/graph` | Bearer | Return code graph (or empty). |
| GET | `/api/agents/{agent_id}/graph/stats` | Bearer | Graph summary stats (visited/unvisited). |
| POST | `/api/agents/{agent_id}/graph/expand/{node_id}` | Bearer | Expand node children. |
| POST | `/api/agents/{agent_id}/graph/mark-visited` | Bearer | Mark file visited (relevance tracking). |
| DELETE | `/api/agents/{agent_id}/graph` | Bearer | Clear code graph (in-memory). |

### Call-tree routes (`backend/routers/call_tree.py`)

All under `/api/*` (included at `/api`).

| Method | Path | Auth | Purpose / Side effects |
|---|---|---|---|
| GET | `/api/calltree/{repo_id}/routes` | Bearer | Static discovery of FastAPI routes in target repo. |
| GET | `/api/calltree/{repo_id}/tree` | Bearer | Build static call tree for a selected route (bounded). |

### Session (hibernation) routes (`backend/routers/session.py`)

All under `/api/session/*` (router prefix `/session`, included at `/api`).

| Method | Path | Auth | Purpose / Side effects |
|---|---|---|---|
| GET | `/api/session/snapshot` | Bearer | Snapshot metadata. |
| POST | `/api/session/pause` | Bearer | Pause agents + persist snapshot (project-local). |
| POST | `/api/session/resume` | Bearer | Load snapshot and return restoration payload (frontend-driven restore). |
| DELETE | `/api/session/snapshot` | Bearer | Delete snapshot. |

### Cache routes (`backend/routers/cache.py`)

All under `/api/*` (included at `/api`).

| Method | Path | Auth | Purpose / Side effects |
|---|---|---|---|
| GET | `/api/cache/metrics` | Bearer | Return aggregated tool-cache metrics. |

### Feature flag routes (`backend/routers/feature_flags.py`)

All under `/api/*` (included at `/api`).

| Method | Path | Auth | Purpose / Side effects |
|---|---|---|---|
| GET | `/api/feature-flags` | Bearer | Evaluate flags for `user_id` (deterministic rollout). |
| POST | `/api/feature-flags/{flag_name}/enable` | Bearer | Enable flag globally (in-process store). |
| POST | `/api/feature-flags/{flag_name}/disable` | Bearer | Disable flag globally. |
| POST | `/api/feature-flags/{flag_name}/rollout` | Bearer | Set rollout percentage. |

## Backend: WebSocket Event Model

**Envelope**: `models.schemas.WSMessage`
- `type`: `WSMessageType` (string enum)
- `agent_id`: agent ID (or `"session"` for session-level events)
- `data`: type-specific payload
- `timestamp`: server timestamp

**Message types (server → client)**: `models.schemas.WSMessageType`
- `agent_status`: agent status changes (`running|paused|completed|failed|cancelled`).
- `progress`: phase/budget/flow updates; includes `type` discriminator inside `data` (e.g., `flow_update`, `phase_change`, `triage_complete`).
- `finding`: finding created/updated.
- `llm_request`, `llm_response`, `tool_detail`: observability stream (LLM interactions + tool executions).
- `state_sync`: persisted state saved/deleted notifications.
- `report_ready`: report generated, ready to fetch/download.
- `error`, `log`: errors and logs for UI display.

**Client → server commands** (JSON messages)
- `ping` → server replies `pong`.
- `subscribe` → currently acknowledged but not used for filtering (broadcast remains global).
- `get_status` → server replies with orchestrator stats.
- `auth` → optional, used for handshake when query token missing/invalid.

## Backend: Core Services and Responsibilities

### AgentOrchestrator (`backend/services/agent_orchestrator.py`)

**Responsibilities**
- Agent lifecycle (create/start/pause/resume/cancel/delete).
- Provider dispatch:
  - Default in-agent `.run()` for legacy agents.
  - Claude SDK run loop (`_run_sdk_agent`) when `provider=claude_sdk` or `use_claude_sdk`.
  - Codex CLI run loop (`_run_codex_cli_agent`) when `provider=codex_cli`.
- Streaming:
  - Emits `WSMessage` events via registered callbacks (`routers/websocket.py` registers the broadcaster).
  - Logs observability via `ObservabilityService`.
- Budget governance:
  - Time-tiered budgets from `services/scan_tier_service.resolve_scan_budget`.
  - Enforces time floors per tier (see `services/claude_sdk_orchestrator.SCAN_TIER_FLOORS`).
- Persistence:
  - Saves `AgentStateSnapshot` best-effort after turns and on completion/cancel/failure.

### ProjectService (`backend/services/project_service.py`)

**Responsibilities**
- Manages project metadata and current project selection.
- Owns project workspace directories under `data/projects/<project_id>/`.
- Provides repo path resolution helpers used by files/calltree and agent creation.

### FileService (`backend/services/file_service.py`)

**Responsibilities**
- File tree generation, safe file reads, bounded searches.
- Enforces workspace/symlink/path rules (used by API and tools).

### SinkSignalService (`backend/services/sink_signal_service.py`)

**Responsibilities**
- Per-project sink signal persistence to `data/projects/<project_id>/sink_signals.json`.
- Deduplication via deterministic fingerprint.
- Status updates are monotonic (no downgrade).

### ObservabilityService (`backend/services/observability_service.py`)

**Responsibilities**
- Stores LLM requests/responses, tool call details, token usage per agent.
- Broadcasts `llm_request`, `llm_response`, `tool_detail` messages over WebSocket.

### FlowService + Reconstruction (`backend/services/flow_service.py`, `backend/services/reconstruction_service.py`)

**Responsibilities**
- Builds investigation flow graph (nodes/edges) as tools are called and hypotheses evolve.
- Supports reconstruction into spans/DAG for the span-based UI.

### Triage pipeline (`backend/services/finding_triage_service.py`)

**Responsibilities**
- Evidence gather (`EvidenceGatherer`) + deterministic classification (`StrictClassifier`).
- **Guarantee**: `triaged_count == raw_count` (no silent drops).
- Produces dispositions (`valid_security_issue`, `bug`, `hardening`, `misconfiguration`, `by_design`, `speculative`) and proof checklist.

### Service map (`backend/services/*.py`)

This is a functional index of the backend service layer. Use it as a “jump table” when you’re changing behavior.

**Agent runtime / governance**
- `backend/services/agent_orchestrator.py`: agent lifecycle, provider dispatch, WS/observability streaming, persistence hooks.
- `backend/services/claude_sdk_orchestrator.py`: turn governor for Claude SDK sessions (phase/budget/time-floor steering).
- `backend/services/scan_tier_service.py`: scan tier → (budget, floor) resolution helpers.
- `backend/services/investigation_queue_service.py`: in-memory queue for user-triggered deep investigations.
- `backend/services/coverage_tracker.py`: tracks entry-point → sink path coverage status (for coverage-driven audits).

**Tool boundary / caching / redaction**
- `backend/services/tool_core.py`: shared implementations of workspace tools (file read/list/search/scanners/persistence/flow hooks).
- `backend/services/tool_cache.py`: LRU + TTL cache for tool outputs (git-head keyed).
- `backend/services/git_head_tracker.py`: git HEAD lookup for cache invalidation.
- `backend/services/redaction_service.py`: secret redaction for tool outputs and evidence.

**Scanning + evidence**
- `backend/services/security_scanners/*`: offline-first scanners (secrets, dependency audit, semantic grep) with `WorkspacePolicy` + `ScanLimits`.
- `backend/services/attack_surface_service.py`: attack-surface discovery + conservative triage of candidate surfaces.
- `backend/services/evidence_gatherer.py`: evidence extraction for triage (symbols/routes/auth gates/snippets).

**Triage + classification**
- `backend/services/finding_triage_service.py`: batch triage orchestration + guarantees.
- `backend/services/strict_classifier.py`: deterministic rules for proof checklist + disposition.
- `backend/services/blocking_gaps.py`: category-specific “blocking gaps” for the critic loop.
- `backend/services/critic_loop.py`: evidence-gap/refuter loop to decide continue/stop/report.
- `backend/services/prompt_router.py`: modular prompt routing/composition for category+stage prompts.

**State / persistence / reporting**
- `backend/services/persistence_service.py`: on-disk agent state snapshots (`data/agent_states/`).
- `backend/services/session_service.py`: per-project UI+agent snapshot (`.quickhack/session-snapshot.json`).
- `backend/services/sink_signal_service.py`: per-project sink signal registry (`sink_signals.json`).
- `backend/services/findings_service.py`: DB persistence for findings.
- `backend/services/report_service.py`: report generation and export (md/json/svg).
- `backend/services/artifact_service.py`: investigation artifact registry (used for span DAG provenance).
- `backend/services/span_service.py`: span model + provenance attachment for investigation trace.
- `backend/services/reconstruction_service.py`: reconstructs structured span DAG from flat flow events.

**UI/observability support**
- `backend/services/observability_service.py`: LLM + tool execution logging and WS broadcast.
- `backend/services/flow_service.py`: investigation flow graph state (nodes/edges) used by UI.
- `backend/services/code_graph_service.py`: code graph initialization/expansion/mark-visited for UI.
- `backend/services/relevance_scorer.py`: relevance scoring for code graph nodes.

**Projects / files / git**
- `backend/services/project_service.py`: project/workspace lifecycle + current project selection.
- `backend/services/file_service.py`: safe repo file operations for UI endpoints.
- `backend/services/git_service.py`: clone/list/refresh/delete for legacy `repos/` checkouts.

**Settings / feature flags**
- `backend/services/settings_service.py`: persistent settings (providers/models/prompts/ui prefs).
- `backend/services/feature_flags.py`: in-process feature flags with deterministic rollout.

## LLM Providers (How “Reasoning” Runs)

Provider selection is driven by `AgentCreateRequest.provider_config.provider` (`models.schemas.ProviderType`).

### API-backed providers
- `openai` → `backend/providers/openai_provider.py` (OpenAI API).
- `anthropic` → `backend/providers/anthropic_provider.py` (Anthropic API).
- `ollama` → `backend/providers/ollama_provider.py` (local Ollama HTTP server).

### Claude SDK provider
- Uses Anthropic’s Agent SDK semantics + MCP tooling.
- Orchestrator bridges SDK events into the existing WebSocket/observability model.

### Codex CLI provider (`provider="codex_cli"`)

**What it is**
- Runs local `codex` binary (Codex CLI), **not** OpenAI API.
- Streams JSONL events from Codex and maps them into the same internal event shapes used by existing UI/observability.

**Isolation and tool restriction**
- Per agent runtime directory: `data/projects/<project_id>/.codex_runtime/<agent_id>/`
  - `HOME` is set to that directory when launching Codex so `~/.codex/config.toml` resolves inside the runtime.
  - `CODEX_HOME` is set to `<runtime>/.codex` for explicitness/forward compat.
- Generated config disables Codex built-in tools:
  - `shell_tool=false`
  - `web_search_request=false`
- Exactly one MCP server is registered: `quickhack` (stdio server implemented by `backend/mcp/quickhack_mcp_server.py`).

**Auth behavior**
- Best-effort copy of `~/.codex/auth.json` into the per-agent runtime (supports “Sign in with ChatGPT” cached credentials).
- No token scraping; failures surface as Codex auth errors.

**Control flow**
1. Orchestrator constructs prompt for phase (`scanner` → `analyzer`) and writes per-turn limits for the MCP server.
2. Provider runs:
   - First turn: `codex exec --json ... --cd <repo_path> <prompt>`
   - Resume: `codex exec resume <session_id> --json ... <prompt>`
3. Codex emits JSONL:
   - `thread.started` → captures `session_id` for resume.
   - `item.started` / `item.completed` for agent messages and MCP tool calls/results.
4. Provider converts Codex events to internal events:
   - `agent_text` chunks
   - `tool_call` / `tool_result` for MCP tools
   - `turn_complete`
5. Orchestrator consumes these events to:
   - Update flow graph nodes.
   - Persist/triage findings when `report_finding` is called.
   - Stream updates to UI via WebSocket.

## Agent Implementations (What Runs Under the Orchestrator)

Agent types are selected via `models.schemas.AgentType` and instantiated in `AgentOrchestrator.create_agent`.

- `backend/agents/quick_audit_agent.py` (`quick_audit`): fast pattern-based scan (tool-driven, short budget).
- `backend/agents/react_agent.py` (`custom`): ReAct-style targeted investigation loop.
- `backend/agents/deep_audit/supervisor.py` (`strict_analysis`, `ultra_strict`, `deep_audit`): multi-pass, coverage-oriented supervisor coordinating deep subagents and stages.

Supporting agent modules
- `backend/agents/base_agent.py`: shared agent interface (`run()`, pause/cancel hooks, snapshot export).
- `backend/agents/deep_audit/*`: deep-audit state machine, nodes, tools, filesystem guards for that agent architecture.
- `backend/agents/dual_model_config.py`: dual-model configuration wiring (scanner vs analyzer config).

## MCP Tool Server (Codex ↔ quick_hack Tool Boundary)

**Server**: `backend/mcp/quickhack_mcp_server.py`
- Protocol: MCP (JSON-RPC 2.0 over stdio).
- Tool implementation layer: `services.tool_core.ToolCore` (shared with legacy tool executor patterns).
- Scan limits and cancellation:
  - The Codex provider writes `limits.json` and a `cancel.flag` file in the agent runtime.
  - MCP server reads these per request to construct `ScanLimits(deadline=..., cancelled=...)`.

**Tool inventory (as exposed to Codex)**
- `read_file`, `list_directory`
- `grep_semantic`
- `scan_repo_for_secrets`, `dependency_audit`
- `analyze_ast`, `trace_dataflow`
- Flow graph tools: `track_file_analysis`, `track_function_discovered`, `track_call_chain`, `track_sink_identified`, `track_entry_point`
- Persistence tools: `upsert_sink_signal`, `report_finding`, `promote_finding`

## ToolCore (Shared Tool Implementations)

**Module**: `backend/services/tool_core.py`
- Async API; uses `asyncio.to_thread` for blocking I/O.
- Enforces `WorkspacePolicy` for file reads/listing/search.
- Uses ReDoS-safe semantic grep (`services.security_scanners.grep.semantic_grep`) rather than ad-hoc regex scanning.
- Redacts secrets before returning content to models (`services.redaction_service`).
- Writes:
  - Sink signals (via `services.sink_signal_service`) to `data/projects/<project_id>/sink_signals.json`.
  - Findings (via agent/orchestrator + DB service) to Postgres.

## Prompting System (How Prompts Are Built)

**Loader**: `backend/prompting_loader.py`
- Loads templates from repo-level `prompting/` directory.
- `render_prompt()` performs simple `{{placeholder}}` substitution.

**Key prompt assets**
- Agent orchestrator templates: `prompting/agents/*` (scanner/analyzer policies, time-floor steering, investigation tasks, evidence verification, etc.).
- Provider/system prompts: `prompting/providers/*`.

**Important operational note**
- Many false-positive failure modes are mitigated by these prompt templates (e.g., “vendored/test key != reportable secret” rules and “evidence-first” reporting).
- When changing the prompt strategy for a provider, ensure the orchestrator path actually uses the intended templates (Codex path builds prompts via `render_prompt()` in `_run_codex_cli_agent`).

## Persistence Model (Disk + Database)

**Database (PostgreSQL)**
- Connection: `backend/database/connection.py` (`DATABASE_URL`, async engine).
- Tables (core):
  - `users`, `user_api_keys`
  - `findings` (includes triage fields)
  - `evidence_blobs` (triage evidence snippets)
- Triage availability is gated at startup via `database/schema_checker.py` (auto-disables triage if schema missing).

**On-disk state**
- `data/agent_states/<agent_id>.json`: `AgentStateSnapshot` (findings, flow, observability, provider state such as Codex `session_id`).
- `data/projects/<project_id>/sink_signals.json`: persistent sink signals.
- `data/projects/<project_id>/.codex_runtime/<agent_id>/`: Codex runtime isolation (config/auth/limits/cancel flag).
- `repos/`: legacy repo clones (distinct from per-project clones under `data/projects/<id>/`).

## Frontend: Routes, State, and Backend Integration

**Routes (Next.js App Router)**
- `GET /` → `frontend/app/page.tsx` (main IDE view)
- Layout: `frontend/app/layout.tsx`

**Backend integration**
- REST client wrappers: `frontend/lib/api` (projects, files, agents, calltree, session, settings).
- WebSocket client: `frontend/hooks/useWebSocket`
  - Connects to `NEXT_PUBLIC_WS_URL` (defaults `ws://localhost:8000/ws`) after auth.
  - Applies minimal filtering in the client:
    - `onFinding`: only inserts findings whose `agent_id` is in the current project’s agent list.

**UI panels (functional responsibilities)**
- Explorer: file tree + file content (`/api/files/*`).
- Agents: create/start/pause/resume/cancel (`/api/agents/*`) + live status via WS.
- Findings: fetch findings (`/api/agents/findings/all` + per-agent) + triage metadata display.
- Flow: investigation flow graph (`/api/agents/{id}/flow`) + reconstruction (`/api/agents/{id}/reconstruct`).
- LLM interactions: observability (`/api/agents/{id}/llm-interactions`, `/tool-details`) + WS stream.
- Session controls: snapshot/pause/resume (`/api/session/*`).

## Codex CLI Control Flow (End-to-End)

`AgentOrchestrator → CodexCLIProvider → Codex (exec/resume) → MCP quickhack server → ToolCore → (scanners/persistence/triage) → WS stream → UI`

Key handoffs:
- Provider writes per-turn limits → MCP server enforces `ScanLimits`.
- Codex tool calls → MCP tools → `ToolCore` (policy + redaction + persistence).
- `report_finding` calls → orchestrator collects new findings → triage pipeline runs (if enabled) → UI receives both raw + triaged metadata over WS/REST.

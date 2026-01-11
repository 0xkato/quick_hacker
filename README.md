# quick_hack

Browser-based security auditing IDE powered by LLM agents.

`quick_hack` focuses on long-running, **time-budgeted** investigations that keep going past “I’m done” by steering the model toward uncovered hotspots and deeper file coverage.

## Key Concepts

### Projects

A **Project** is a single cloned repository plus its persistent state (threat model, sink signals, snapshots).

- Projects are isolated: signals/findings from one codebase do not bleed into another.
- The UI uses `project_id` as the primary identifier for file browsing + audits.

### Agents + Scan Tiers (Time Budgets)

Agents run audits against a project. For non-custom scans, the UI creates a `deep_audit` agent and supplies a `scan_tier` (time budget).

| Scan tier | Budget | What it’s for |
|----------:|-------:|---------------|
| `quick` | 5 min | Fast initial orientation + obvious hotspots |
| `medium` | 15 min | Better coverage and first-pass deep dives |
| `advanced` | 45 min | Sustained tracing + multiple leads |
| `pro` | 90 min | Broad coverage + higher-confidence verification |
| `ultra` | 4 hours | Large repos, repeated deep passes |
| `evil` | 24 hours | “All day” auditing / soak mode |
| `custom` | n/a | Send a custom prompt (no preset time tier) |

Notes:
- The backend enforces a time floor before accepting “audit complete” signals from the LLM for time-tiered scans.
- A single file may be reviewed multiple times as new context emerges.

### Sink Signals vs Findings

This system distinguishes **leads** from **reported vulnerabilities**:

- **Sink signals** are investigation leads (entry points, sinks, hotspots). They are *not* findings.
  - Persist per project at `data/projects/<project_id>/sink_signals.json`.
  - Can be queued/promoted/dismissed over time as the audit progresses.
- **Findings** are what the agent reports as potential vulnerabilities (severity, file/line, evidence, suggested fix).

## Architecture

### System Overview

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                           Frontend (Next.js / React)                         │
│                                                                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   Project   │  │    Agent    │  │  Findings   │  │    Flow Diagram     │  │
│  │  Selector   │  │   Panel     │  │   Panel     │  │ (Investigation Tree)│  │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────────────┘  │
│  ┌─────────────────────────────┐  ┌─────────────────────────────────────────┐│
│  │      Monaco Code Editor     │  │         Call Tree + Code Graph          ││
│  └─────────────────────────────┘  └─────────────────────────────────────────┘│
└───────────────────────────────────────┬──────────────────────────────────────┘
                                        │ REST `/api/*` + WebSocket `/ws`
                                        ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                               Backend (FastAPI)                              │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │                              API Layer                                  │  │
│  │  /api/auth/*     /api/projects/*    /api/agents/*    /ws (WebSocket)   │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                        │                                      │
│  ┌─────────────────────────────────────┴──────────────────────────────────┐  │
│  │                          Agent Orchestrator                             │  │
│  │                                                                         │  │
│  │   ┌─────────────┐    ┌─────────────────────────────────────────────┐   │  │
│  │   │  ReAct Loop │───▶│              Tool Executor                  │   │  │
│  │   │ (Deep Audit)│    │                                             │   │  │
│  │   └─────────────┘    │  ┌───────────────────────────────────────┐  │   │  │
│  │                      │  │         Security Scanners             │  │   │  │
│  │                      │  │  • scan_repo_for_secrets              │  │   │  │
│  │                      │  │  • dependency_audit                   │  │   │  │
│  │                      │  │  • grep_semantic                      │  │   │  │
│  │                      │  │  • generate_security_report           │  │   │  │
│  │                      │  └───────────────────────────────────────┘  │   │  │
│  │                      │  ┌───────────────────────────────────────┐  │   │  │
│  │                      │  │         Code Analysis Tools           │  │   │  │
│  │                      │  │  • read_file / search_code            │  │   │  │
│  │                      │  │  • list_files / get_file_tree         │  │   │  │
│  │                      │  │  • analyze_ast / trace_dataflow       │  │   │  │
│  │                      │  └───────────────────────────────────────┘  │   │  │
│  │                      │  ┌───────────────────────────────────────┐  │   │  │
│  │                      │  │         Execution Tools               │  │   │  │
│  │                      │  │  • run_command (sandboxed)            │  │   │  │
│  │                      │  │  • run_tests                          │  │   │  │
│  │                      │  └───────────────────────────────────────┘  │   │  │
│  │                      └─────────────────────────────────────────────┘   │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────────┐   │
│  │  Sink Signals    │  │    Findings      │  │   Flow Graph Service     │   │
│  │  (Leads/Hotspots)│  │   (Reported)     │  │  (Investigation Tree)    │   │
│  └──────────────────┘  └──────────────────┘  └──────────────────────────┘   │
└───────────────┬───────────────────────────┬───────────────────────────┬──────┘
                │                           │                           │
                ▼                           ▼                           ▼
         Postgres (users, keys)      Redis (optional cache)     LLM providers
                                                           (Anthropic / OpenAI / Ollama)
```

### Security Scanners Module

The `backend/services/security_scanners/` module provides four specialized security analysis tools:

```
security_scanners/
├── base.py          # Core types: ScanFinding, ScanResult, WorkspacePolicy, ScanLimits
├── secrets.py       # Pattern + entropy-based secret detection
├── dependencies.py  # Lockfile parsing + vulnerability database lookup
├── grep.py          # Regex code search with context lines
├── report.py        # Report generation (Markdown, JSON, SARIF)
└── data/
    └── advisory_db.json  # Bundled vulnerability database
```

| Tool | Description | Key Features |
|------|-------------|--------------|
| `scan_repo_for_secrets` | Detect hardcoded secrets | Pattern matching (AWS, GitHub, JWT), entropy analysis, fingerprint deduplication |
| `dependency_audit` | Check dependencies for CVEs | Parses npm, yarn, pnpm, pip lockfiles; checks against advisory DB |
| `grep_semantic` | Regex search with context | ReDoS protection, configurable context lines, file glob filtering |
| `generate_security_report` | Aggregate findings | Markdown (human), JSON (machine), SARIF (CI/CD integration) |

**Security Boundaries:**
- `WorkspacePolicy` enforces: path validation, excluded directories, file size limits, symlink rejection
- `ScanLimits` provides: time budgets, cancellation callbacks, resource caps (max files/matches)
- Secrets are always redacted in output using `redact_secret()` with fingerprinting for deduplication

### Agent Tool Execution Flow

```
User Request (e.g., "start medium scan")
         │
         ▼
┌─────────────────────┐
│  Agent Orchestrator │
│  (time budget: 15m) │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────────────────────────────────────────────────┐
│                        ReAct Loop                                │
│                                                                  │
│   1. Observe: Read current state, findings, coverage            │
│   2. Think: Decide next investigation step                      │
│   3. Act: Call tool (e.g., scan_repo_for_secrets)               │
│   4. Repeat until budget exhausted or audit complete            │
│                                                                  │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │                    Tool Executor                         │   │
│   │                                                          │   │
│   │   • Validates tool name + parameters                     │   │
│   │   • Creates WorkspacePolicy for repo                     │   │
│   │   • Creates ScanLimits with fraction of remaining budget │   │
│   │   • Executes tool async                                  │   │
│   │   • Accumulates findings (deduped, capped at 500)        │   │
│   │   • Returns structured ToolResult                        │   │
│   └─────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
           │
           ▼
┌─────────────────────┐
│   Findings + Report │
│   (Markdown/SARIF)  │
└─────────────────────┘
```

### Data Flow

```
                     ┌─────────────────────────────────────────┐
                     │              Repository                 │
                     │  (cloned to data/projects/<id>/repo/)   │
                     └───────────────────┬─────────────────────┘
                                         │
         ┌───────────────────────────────┼───────────────────────────────┐
         │                               │                               │
         ▼                               ▼                               ▼
┌─────────────────┐           ┌─────────────────┐           ┌─────────────────┐
│ Secrets Scanner │           │ Dependency Audit│           │  Grep Semantic  │
│                 │           │                 │           │                 │
│ • Scan all text │           │ • Find lockfiles│           │ • Pattern search│
│ • Pattern match │           │ • Parse deps    │           │ • Context lines │
│ • Entropy check │           │ • Check CVEs    │           │ • File filtering│
└────────┬────────┘           └────────┬────────┘           └────────┬────────┘
         │                             │                             │
         └─────────────────────────────┼─────────────────────────────┘
                                       │
                                       ▼
                            ┌─────────────────────┐
                            │   ScanFinding[]     │
                            │                     │
                            │ • tool, severity    │
                            │ • file_path, lines  │
                            │ • snippet, details  │
                            │ • confidence        │
                            └──────────┬──────────┘
                                       │
                    ┌──────────────────┼──────────────────┐
                    │                  │                  │
                    ▼                  ▼                  ▼
          ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
          │    Markdown     │ │      JSON       │ │      SARIF      │
          │    Report       │ │     Export      │ │  (CI/CD tools)  │
          └─────────────────┘ └─────────────────┘ └─────────────────┘
```

### Key Design Decisions

1. **Time-Budgeted Scans**: Agents operate within explicit time budgets (5m to 24h). Each tool gets a fraction of remaining budget via `ScanLimits.deadline`.

2. **Signals vs Findings**: Raw scanner output produces "signals" (leads). The agent promotes verified signals to "findings" after investigation.

3. **Finding Accumulation**: Findings are deduplicated by fingerprint and capped at 500 per session. Priority eviction keeps highest-severity findings.

4. **Async by Default**: All scanners use `asyncio.to_thread()` to avoid blocking the event loop during file I/O and regex operations.

5. **Offline-First Scanning**: Security scanners work without network access. Vulnerability databases are bundled locally.

## Quick Start

### Option A: Docker Compose (recommended)

This starts the full stack (backend + frontend + Postgres + Redis + Ollama).

```bash
cp .env.example .env
docker compose up --build
```

- Frontend: `http://localhost:3000`
- Backend: `http://localhost:8000`

### Claude Code / ACP (Claude Agent SDK)

The backend can run audits through Claude Code via `claude-agent-sdk` (which uses Agent Client Protocol internally).

- Docker: the backend image installs both `claude-agent-sdk` (Python) and `@anthropic-ai/claude-code` (Node).
- Local dev: install Python deps in `backend/` and `npm i -g @anthropic-ai/claude-code`.
- Enable per agent with `use_claude_sdk: true` (provider stays `anthropic`).

### Option B: Local Development (no Docker)

Prereqs:
- Python 3.10+
- Node.js 18+
- Postgres (required for auth)

Backend:
```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

Frontend:
```bash
cd frontend
npm ci
npm run dev
```

## Authentication

- HTTP API: `Authorization: Bearer <access_token>`
- WebSocket: `ws://localhost:8000/ws?token=<access_token>`
- Tokens are stored by the frontend in `localStorage`:
  - `quick_hack_access_token`
  - `quick_hack_refresh_token`

## API Examples

### Login (JWT)

```bash
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"you@example.com","password":"yourpassword"}'
```

### Quick-clone a repo into a new Project

```bash
curl -X POST http://localhost:8000/api/projects/quick-clone \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"url":"https://github.com/user/repo.git"}'
```

### Start a time-tiered deep audit

```bash
curl -X POST http://localhost:8000/api/agents \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "repo_id": "'"$PROJECT_ID"'",
    "agent_type": "deep_audit",
    "scan_tier": "medium",
    "use_claude_sdk": true,
    "provider_config": { "provider": "anthropic", "model": "claude-sonnet-4-20250514" }
  }'
```

Notes:
- `use_claude_sdk: true` runs the audit via Claude Code (Claude Agent SDK) using the `quickhack` in-process MCP server (`mcp__quickhack__*` tools).
- If you omit `use_claude_sdk` (or set it to `false`), the backend uses the legacy ReAct loop.

Then:
```bash
curl -X POST http://localhost:8000/api/agents/$AGENT_ID/start \
  -H "Authorization: Bearer $TOKEN"
```

### List sink signals for a project

```bash
curl http://localhost:8000/api/projects/$PROJECT_ID/sink-signals \
  -H "Authorization: Bearer $TOKEN"
```

## Repo Layout

```
quick_hack/
├── backend/
│   ├── main.py                 # FastAPI app + router wiring
│   ├── agents/
│   │   ├── react_agent.py      # ReAct-based audit agent (legacy loop)
│   │   ├── tools.py            # ToolExecutor + tool definitions
│   │   └── base_agent.py       # Shared agent base + finding helpers
│   ├── routers/                # /api/* HTTP endpoints + /ws
│   ├── services/
│   │   ├── security_scanners/  # Security analysis tools
│   │   │   ├── base.py         # Core types (ScanFinding, ScanResult, etc.)
│   │   │   ├── secrets.py      # Secret detection (patterns + entropy)
│   │   │   ├── dependencies.py # Dependency vulnerability audit
│   │   │   ├── grep.py         # Semantic code search
│   │   │   ├── report.py       # Report generation (MD/JSON/SARIF)
│   │   │   └── data/           # Bundled vulnerability database
│   │   ├── agent_orchestrator.py      # Agent lifecycle management
│   │   ├── claude_sdk_orchestrator.py # Time-tier governor (Claude SDK mode)
│   │   ├── tool_core.py               # MCP tool implementations (Claude SDK mode)
│   │   ├── sink_signal_service.py     # Lead/hotspot tracking (project-local)
│   │   └── flow_service.py            # Investigation graph service
│   ├── providers/
│   │   ├── claude_sdk_provider.py     # Claude Code / Agent SDK provider
│   │   └── mcp_tools.py               # In-process MCP server (`quickhack`)
│   ├── database/               # SQLAlchemy models + connection
│   ├── prompts/                # Prompt templates / policies
│   └── tests/
│       ├── services/security_scanners/  # Scanner unit tests (201 tests)
│       └── agents/             # Tool integration tests
├── frontend/
│   ├── app/                    # Next.js App Router
│   ├── components/             # Panels, diagrams, modals
│   ├── hooks/                  # WebSocket + UI hooks
│   ├── contexts/               # AuthContext (JWT + tokens)
│   └── lib/                    # API client
├── data/                       # Runtime state (settings, projects, sink signals)
├── repos/                      # Runtime clones (legacy git service)
└── docker-compose.yml
```

## Running Tests

```bash
cd backend
pip install -r requirements-dev.txt
pytest -q
```

## Configuration (.env)

See `.env.example` for the full list. Common knobs:

| Variable | Description |
|----------|-------------|
| `NEXT_PUBLIC_API_URL` | Backend base URL for the frontend |
| `NEXT_PUBLIC_WS_URL` | WebSocket URL (usually `ws://localhost:8000/ws`) |
| `DATABASE_URL` | Postgres connection string |
| `REDIS_URL` | Redis connection string |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` | Provider keys (fallback; UI settings override) |
| `SETTINGS_SECRET` | Used to obfuscate stored settings |
| `JWT_SECRET_KEY` | JWT signing secret (change in production) |
| `SANDBOX_ENABLED` | Enables Docker-based sandbox execution |

## Security Notes

- Do not expose this stack to untrusted networks without hardening (auth, CORS, secrets, sandboxing).
- The backend can mount `docker.sock` for sandboxed execution; treat this as production-sensitive.

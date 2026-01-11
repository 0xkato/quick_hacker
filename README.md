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

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                           Frontend (Next.js / React)                         │
│                                                                              │
│  - Project selector + repo explorer (Monaco)                                 │
│  - Agent panel (scan tiers + custom prompts)                                 │
│  - Findings panel + report viewer                                             │
│  - Flow diagram (live investigation graph)                                   │
│  - Call tree diagram + code graph                                             │
│  - Settings (per-user provider keys) + Auth UI                               │
└───────────────────────────────────────┬──────────────────────────────────────┘
                                        │ REST `/api/*` + WebSocket `/ws`
                                        ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                               Backend (FastAPI)                              │
│                                                                              │
│  Routers:                                                                     │
│  - `/api/auth/*` (JWT login/register + per-user provider keys)                │
│  - `/api/projects/*` (projects, clone/refresh, sink signals)                  │
│  - `/api/agents/*` (create/start/pause/resume, findings, reports, state)      │
│  - `/api/agents/{id}/flow` (investigation flow graph)                         │
│  - `/api/calltree/*` + `/api/agents/{id}/graph/*` (static + dynamic graphs)   │
│  - `/ws` (live updates + observability stream)                                │
│                                                                              │
│  Services:                                                                    │
│  - Agent orchestrator + ReAct-based deep audit agent                          │
│  - Attack-surface scan/triage → sink signals                                  │
│  - Observability + reports + session snapshots                                │
│  - Sandbox (optional): Docker-based execution via docker.sock                 │
└───────────────┬───────────────────────────┬───────────────────────────┬──────┘
                │                           │                           │
                ▼                           ▼                           ▼
         Postgres (users, keys)      Redis (optional cache)     LLM providers
                                                           (Anthropic / OpenAI / Ollama)
```

## Quick Start

### Option A: Docker Compose (recommended)

This starts the full stack (backend + frontend + Postgres + Redis + Ollama).

```bash
cp .env.example .env
docker compose up --build
```

- Frontend: `http://localhost:3000`
- Backend: `http://localhost:8000`

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
    "provider_config": { "provider": "anthropic", "model": "claude-sonnet-4-20250514" }
  }'
```

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
│   ├── agents/                 # Agents + tools (ReAct deep audit lives here)
│   ├── routers/                # /api/* HTTP endpoints + /ws
│   ├── services/               # Orchestrator, sink signals, flow, reports, etc.
│   ├── database/               # SQLAlchemy models + connection
│   ├── prompts/                # Prompt templates / policies
│   └── tests/                  # Pytest suite
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

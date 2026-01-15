# quick_hack

AI-powered security auditing browser IDE with evidence-based triage system.

`quick_hack` is a comprehensive platform that combines LLM agents, static code analysis, and a strict vulnerability triage system to identify and validate security issues in codebases.

## Key Features

### 🤖 Multiple Agent Types

**Three specialized agents for different audit needs:**

| Agent Type | Purpose | Speed | Depth |
|-----------|---------|-------|-------|
| **QuickAudit** | Fast pattern-based scanning | ~1-2 min | Surface-level |
| **ReAct** | Targeted investigation with reasoning loops | ~5-10 min | Deep dives |
| **DeepAudit** | Comprehensive systematic audit (LangGraph) | ~15-30 min | Multi-pass thorough |

### 🎯 Strict Triage System

**Zero false positive philosophy** with evidence-based classification:

- **Tri-State Proof Checklist:** PROVEN_TRUE / PROVEN_FALSE / UNKNOWN (not boolean flags)
- **Code-Only Evidence:** Never trusts scanner descriptions, only verifies from source code
- **Six Dispositions:**
  - `VALID_SECURITY_ISSUE` - Exploitable vulnerability (REPORT)
  - `BUG` - Security control bypassed (REPORT)
  - `HARDENING` - Risky but mitigated (Optional)
  - `MISCONFIGURATION` - Exploitable only when security disabled (Optional)
  - `BY_DESIGN` - Intentional product feature (FILTER)
  - `SPECULATIVE` - High-risk but unproven (FILTER)

**Conservative Feature Intent Detection:** Requires 2+ strong signals (path + symbol/documentation) to classify exec/eval as BY_DESIGN, dramatically reducing false positives from code execution findings.

### 🛠️ Rich Tool Ecosystem

**13 specialized tools** for comprehensive code analysis:

- **Code Analysis:** ReadFile, Ripgrep, AST parsing, symbol search
- **Execution:** Bash (Docker sandboxed), test runners
- **Code Understanding:** Call graph, data flow tracing, route discovery
- **File Operations:** List files, file tree generation
- **Security:** Auth gate detection, config analysis

### 📊 Interactive IDE

- **Monaco Editor:** VS Code-like editing with syntax highlighting
- **File Explorer:** Hierarchical tree view with search
- **Chat Interface:** Query agents about findings with streaming responses
- **Investigation Trace:** Interactive span-based tree/DAG visualization of investigation hypotheses, tool calls, and artifact provenance (feature flag-controlled, enabled by default)
- **Findings Panel:** Filter, group, and export vulnerability reports
- **Code Graph:** Interactive call graph exploration with relevance scoring

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────────┐
│                      Frontend (Next.js 14 + React 18)                    │
│                                                                          │
│  ┌───────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐ │
│  │  Monaco   │  │   File   │  │  Agent   │  │ Findings │  │  Tree   │ │
│  │  Editor   │  │ Explorer │  │ Manager  │  │  Panel   │  │ Layout  │ │
│  │           │  │          │  │          │  │          │  │ (Spans) │ │
│  └───────────┘  └──────────┘  └──────────┘  └──────────┘  └─────────┘ │
└────────────────────────────┬─────────────────────────────────────────────┘
                             │ HTTP/REST + WebSocket
┌────────────────────────────┴─────────────────────────────────────────────┐
│                      Backend (FastAPI + Python 3.11+)                    │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                      Agent Orchestrator                          │   │
│  │                                                                  │   │
│  │   ┌─────────────┐    ┌─────────────┐    ┌──────────────┐       │   │
│  │   │ QuickAudit  │    │    ReAct    │    │  DeepAudit   │       │   │
│  │   │   Agent     │    │    Agent    │    │  (LangGraph) │       │   │
│  │   └─────────────┘    └─────────────┘    └──────────────┘       │   │
│  │                                                                  │   │
│  │   ┌──────────────────────────────────────────────────────────┐  │   │
│  │   │               Tool Execution (13 tools)                  │  │   │
│  │   │  • ReadFile  • Ripgrep  • Bash (sandboxed)              │  │   │
│  │   │  • CallGraph • FindSymbol • GetRoutes                   │  │   │
│  │   └──────────────────────────────────────────────────────────┘  │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                      Triage System                               │   │
│  │                                                                  │   │
│  │   ┌─────────────────┐    ┌──────────────────────────────────┐   │   │
│  │   │   Evidence      │ ─▶ │   Strict Classifier              │   │   │
│  │   │   Gatherer      │    │   • Tri-state proof checklist    │   │   │
│  │   │                 │    │   • Disposition rules            │   │   │
│  │   │ • Code snippets │    │   • Conservative feature detect  │   │   │
│  │   │ • Route info    │    │   • Code-only evidence          │   │   │
│  │   │ • Auth gates    │    │   • Exec/eval filtering         │   │   │
│  │   └─────────────────┘    └──────────────────────────────────┘   │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  ┌────────────┐  ┌──────────────┐  ┌──────────────────┐  ┌──────────┐  │
│  │  Project   │  │  Session     │  │  Reconstruction  │  │   Code   │  │
│  │  Service   │  │  Service     │  │  Service         │  │  Graph   │  │
│  │            │  │              │  │  (Span-based     │  │ Service  │  │
│  │            │  │              │  │   DAG builder)   │  │          │  │
│  └────────────┘  └──────────────┘  └──────────────────┘  └──────────┘  │
└───────────────────────┬──────────────────────────────────────────────────┘
                        │
┌───────────────────────┴──────────────────────────────────────────────────┐
│                    PostgreSQL / SQLite Database                          │
│  Users, Projects, Sessions, Messages, Findings, Evidence                │
└──────────────────────────────────────────────────────────────────────────┘
                        │
┌───────────────────────┴──────────────────────────────────────────────────┐
│                        LLM Providers                                     │
│  • Anthropic (Claude Opus/Sonnet/Haiku)                                 │
│  • OpenAI (GPT-4/GPT-3.5)                                                │
│  • Ollama (Local models)                                                 │
│  • Claude SDK (MCP-based)                                                │
│  • Codex CLI (local `codex`, MCP tools)                                  │
└──────────────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Option A: Docker Compose (Recommended)

**Prerequisites:**
- Docker & Docker Compose
- 8GB+ RAM recommended

```bash
# Clone repository
git clone https://github.com/yourusername/quick_hack.git
cd quick_hack

# Configure environment
cp .env.example .env
# Edit .env and set at minimum:
#   - ANTHROPIC_API_KEY or OPENAI_API_KEY
#   - JWT_SECRET_KEY (change default!)

# Start all services
docker compose up --build

# Access the application
# Frontend: http://localhost:3000
# Backend API: http://localhost:8000
# API Docs: http://localhost:8000/docs
```

**Docker Services:**
- `backend` - FastAPI server (port 8000)
- `frontend` - Next.js application (port 3000)
- `db` - PostgreSQL database (port 5432)

### Option B: Local Development

**Prerequisites:**
- Python 3.11+
- Node.js 18+
- PostgreSQL (or use SQLite for development)

**Backend:**
```bash
cd backend
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Configure database
export DATABASE_URL="postgresql://user:pass@localhost/quickhack"
# Or use SQLite: export DATABASE_URL="sqlite:///./data/quickhack.db"

# Set required environment variables
export JWT_SECRET_KEY="your-secret-key-change-in-production"
export ANTHROPIC_API_KEY="sk-ant-..."  # or OPENAI_API_KEY

# Run backend
uvicorn main:app --reload --port 8000
```

**Frontend:**
```bash
cd frontend
npm install

# Configure API endpoints
export NEXT_PUBLIC_API_URL="http://localhost:8000"
export NEXT_PUBLIC_WS_URL="ws://localhost:8000/ws"

# Run frontend
npm run dev
```

## Authentication

**JWT-based authentication** with access and refresh tokens:

- **Access Token:** 24-hour lifetime, used for API requests
- **Refresh Token:** 30-day lifetime, used to obtain new access tokens
- **Storage:** Tokens stored in `localStorage` by frontend
- **WebSocket:** Authenticated via initial auth message with Bearer token

**Create Account:**
```bash
curl -X POST http://localhost:8000/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "username": "your_username",
    "password": "secure_password"
  }'
```

**Login:**
```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "secure_password"
  }'
```

## API Examples

### Create Project

```bash
curl -X POST http://localhost:8000/api/projects \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Project",
    "repo_url": "https://github.com/user/repo.git"
  }'
```

### Start Agent Audit

```bash
# Start QuickAudit (fast scan)
curl -X POST http://localhost:8000/api/agents/execute \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "project_id": "project-id-here",
    "agent_type": "QUICK_AUDIT",
    "prompt": "Perform security audit"
  }'

# Start DeepAudit (comprehensive)
curl -X POST http://localhost:8000/api/agents/execute \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "project_id": "project-id-here",
    "agent_type": "DEEP_AUDIT",
    "prompt": "Comprehensive security analysis"
  }'
```

### Get Findings

```bash
# Get all findings for a project
curl http://localhost:8000/api/findings/$PROJECT_ID \
  -H "Authorization: Bearer $ACCESS_TOKEN"

# Get only reportable findings
curl "http://localhost:8000/api/findings/$PROJECT_ID?disposition=VALID_SECURITY_ISSUE,BUG" \
  -H "Authorization: Bearer $ACCESS_TOKEN"

# Filter by category
curl "http://localhost:8000/api/findings/$PROJECT_ID?category=CODE_INJECTION" \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

## Configuration

Key environment variables (see `.env.example` for complete list):

### Application
```bash
APP_NAME=quick_hack
DEBUG=false  # Set true for development
```

### Authentication
```bash
JWT_SECRET_KEY=your-secret-key-64-chars-minimum  # REQUIRED - CHANGE IN PRODUCTION
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=1440  # 24 hours
JWT_REFRESH_TOKEN_EXPIRE_DAYS=30
```

### Database
```bash
# PostgreSQL (production)
DATABASE_URL=postgresql+asyncpg://user:pass@localhost:5432/quickhack

# SQLite (development)
DATABASE_URL=sqlite+aiosqlite:///./data/quickhack.db
```

### LLM Providers
```bash
# Anthropic (recommended for best results)
ANTHROPIC_API_KEY=sk-ant-...

# OpenAI
OPENAI_API_KEY=sk-...

# Ollama (local models)
OLLAMA_BASE_URL=http://localhost:11434

# Claude SDK
ANTHROPIC_AUTH_TOKEN=...  # OAuth token for Claude SDK

# Codex CLI (local; no API key by default)
# `codex login` stores credentials at ~/.codex/auth.json
CODEX_GLOBAL_HOME=~/.codex  # optional override; defaults to ~/.codex
```

## Codex CLI (Local Provider)

quick_hack supports a local `codex` binary as a first-class provider: `provider: "codex_cli"`.

- Runs `codex exec --json` / `codex exec resume ... --json` and streams JSONL events to the existing WebSocket UI.
- Disables Codex built-in shell + web search and exposes only quick_hack tools via an MCP stdio server.

### Host Setup (recommended)

```bash
codex --version
codex login
ls ~/.codex/auth.json
```

### Use In quick_hack

Example `provider_config`:

```json
{
  "provider": "codex_cli",
  "model": "gpt-5.2-codex",
  "codex_path": "codex"
}
```

### Docker Compose Notes

- The backend container must have a `codex` binary available in `PATH` (install it in `backend/Dockerfile` or mount it into the container).
- Mount Codex auth into the backend container so `auth.json` is readable:
  - `~/.codex:/home/appuser/.codex:ro`
  - quick_hack runs `codex` with an isolated HOME per agent at `data/projects/<project_id>/.codex_runtime/<agent_id>/`, so Codex reads:
    - `data/projects/<project_id>/.codex_runtime/<agent_id>/.codex/config.toml`
    - `data/projects/<project_id>/.codex_runtime/<agent_id>/.codex/auth.json`

### Agent Settings
```bash
MAX_CONCURRENT_AGENTS=10     # Max parallel agent executions
AGENT_TIMEOUT_SECONDS=300    # 5 minutes (increase for DeepAudit)
MAX_CONTEXT_TOKENS=128000    # Context window size
```

### Triage System
```bash
TRIAGE_ENABLED=true
TRIAGE_BATCH_BUDGET_MS=15000          # 15 seconds total
TRIAGE_PER_FINDING_BUDGET_MS=300      # 300ms per finding
TRIAGE_ENABLE_REDACTION=true          # Redact secrets in evidence
TRIAGE_SHOW_FILTERED_BY_DEFAULT=false # Hide non-reportable findings
```

### Sandbox (Security)
```bash
SANDBOX_ENABLED=true              # Enable Docker sandboxing
SANDBOX_TIMEOUT_SECONDS=30        # Command timeout
SANDBOX_MEMORY_LIMIT=256m         # Memory limit
SANDBOX_NETWORK_DISABLED=true     # Disable network in sandbox
```

### CORS
```bash
CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
```

## Project Structure

```
quick_hack/
├── backend/
│   ├── main.py                      # FastAPI application entry point
│   ├── config.py                    # Centralized configuration
│   ├── agents/
│   │   ├── base_agent.py            # Abstract agent base class
│   │   ├── quick_audit_agent.py     # Fast pattern-based scanning
│   │   ├── react_agent.py           # ReAct reasoning loop
│   │   ├── deep_audit_agent.py      # LangGraph state machine
│   │   ├── orchestrator.py          # Agent lifecycle management
│   │   ├── claude_sdk_orchestrator.py  # Time-governed execution
│   │   ├── tools/                   # 13 tool implementations
│   │   └── validity_checklists/     # Per-vulnerability-type checklists
│   ├── routers/                     # 13 API endpoint modules
│   │   ├── agents.py                # Agent execution endpoints
│   │   ├── auth.py                  # Authentication (signup/login/refresh)
│   │   ├── projects.py              # Project management
│   │   ├── files.py                 # File operations
│   │   ├── findings.py              # Findings CRUD
│   │   ├── websocket.py             # Real-time updates
│   │   └── ... (7 more routers)
│   ├── services/                    # Business logic (31 files)
│   │   ├── agent_service.py         # Agent management
│   │   ├── evidence_gatherer.py     # Triage evidence collection
│   │   ├── strict_classifier.py     # Vulnerability classification
│   │   ├── code_graph_service.py    # Call graph construction
│   │   ├── flow_tracker.py          # Agent execution tracking
│   │   ├── reconstruction_service.py # Span-based DAG reconstruction
│   │   ├── feature_flags.py         # Feature flag service
│   │   └── ... (24 more services)
│   ├── database/                    # SQLAlchemy models
│   │   ├── models.py                # 6 core models (User, Project, Finding, etc.)
│   │   ├── connection.py            # Async engine setup
│   │   └── schema_checker.py        # Schema validation
│   ├── providers/                   # LLM provider integrations
│   │   ├── anthropic_provider.py    # Claude integration
│   │   ├── openai_provider.py       # GPT integration
│   │   ├── ollama_provider.py       # Local models
│   │   └── claude_sdk_provider.py   # Claude SDK/MCP
│   ├── middleware/
│   │   └── auth.py                  # JWT validation
│   └── tests/                       # Pytest test suite
│       └── services/
│           └── test_strict_classifier.py  # 41 triage tests
├── frontend/
│   ├── app/                         # Next.js App Router pages
│   │   ├── page.tsx                 # Landing page
│   │   ├── login/                   # Auth pages
│   │   ├── projects/                # Project workspace
│   │   └── layout.tsx               # Root layout with providers
│   ├── components/                  # React components
│   │   ├── Editor/                  # Monaco editor wrapper
│   │   ├── FileExplorer/            # File tree browser
│   │   ├── Agent/                   # Agent manager
│   │   ├── Chat/                    # Chat interface
│   │   ├── Findings/                # Findings panel
│   │   ├── InvestigationFlow/       # Span-based tree visualization (TreeLayout)
│   │   ├── Flow/                    # Legacy flow visualization
│   │   └── ... (14 component dirs)
│   ├── contexts/                    # React Context providers
│   │   └── AuthContext.tsx          # Global auth state
│   ├── hooks/                       # Custom React hooks
│   │   ├── useAuth.ts
│   │   ├── useWebSocket.ts
│   │   ├── useInvestigationFlow.ts  # Span reconstruction hook
│   │   └── ... (10+ hooks)
│   └── lib/
│       ├── api.ts                   # API client with auth
│       └── types.ts                 # TypeScript interfaces
├── docs/
│   ├── triage-system.md             # Triage documentation
│   └── plans/                       # Design documents
│       ├── 2026-01-12-architecture-reference.md       # Complete architecture
│       ├── 2026-01-12-strict-exec-eval-filtering-design.md
│       └── 2026-01-12-strict-exec-eval-filtering-implementation.md
├── docker-compose.yml               # Docker services definition
├── .env.example                     # Environment variables template
└── README.md                        # This file
```

## Testing

```bash
cd backend

# Install test dependencies
pip install -r requirements-dev.txt

# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific test file
pytest tests/services/test_strict_classifier.py -v

# Run tests matching pattern
pytest -k "test_exec" -v
```

**Test Coverage:**
- Triage system: 41 tests (exec/eval filtering, disposition rules, evidence gathering)
- Total backend tests: 100+ tests

## Key Architectural Decisions

### 1. Tri-State Proof Checklist
Uses PROVEN_TRUE / PROVEN_FALSE / UNKNOWN instead of booleans to distinguish "proven safe" from "insufficient evidence", dramatically reducing false negatives.

### 2. Code-Only Evidence Analysis
Triage classifier never trusts finding descriptions from scanners, only verifies from actual source code to prevent manipulation.

### 3. Conservative Feature Intent Detection
Requires 2+ strong signals (path + symbol/doc) to classify exec/eval as BY_DESIGN, preventing false positives from legitimate code execution features.

### 4. LangGraph for Complex Workflows
DeepAudit uses state machine for deterministic multi-step workflow with clear progress tracking and pause/resume capability.

### 5. Sandboxed Tool Execution
Bash commands run in Docker containers with read-only filesystem, no network, and resource limits for security.

### 6. WebSocket for Real-Time Updates
Agents broadcast progress via WebSocket instead of polling for low-latency user feedback.

### 7. Provider Abstraction Layer
Unified interface for 4 LLM providers enables easy switching and cost optimization.

### 8. Disposition-First Triage
Six nuanced dispositions (not binary "vulnerable/safe") provide clear audit trail and different actions per classification.

### 9. Span-Based Investigation Visualization
Reconstruction algorithm transforms flat event streams into structured DAG with hypothesis spans, tool call nesting, and artifact provenance. Feature flag-controlled with TreeLayout as default renderer, showing branching investigations with collapse/expand and outcome-based coloring.

See [docs/plans/2026-01-12-architecture-reference.md](docs/plans/2026-01-12-architecture-reference.md) for complete architectural documentation (4,300+ lines covering every major component).

## Security Considerations

### Production Deployment Checklist

- [ ] **Change JWT_SECRET_KEY** - Use 64+ random characters
- [ ] **Enable HTTPS** - Use reverse proxy (nginx/caddy) with TLS
- [ ] **Restrict CORS_ORIGINS** - Only allow your frontend domain
- [ ] **Enable SANDBOX_ENABLED** - Always sandbox bash commands
- [ ] **Disable DEBUG mode** - Set `DEBUG=false`
- [ ] **Use PostgreSQL** - SQLite not recommended for production
- [ ] **Secure API keys** - Store provider keys in environment variables
- [ ] **Set AUTH_BOOTSTRAP_ALLOW_REMOTE=false** - Restrict signup to localhost
- [ ] **Review file permissions** - Ensure repos_dir and data_dir are secure
- [ ] **Enable rate limiting** - Add rate limiting middleware
- [ ] **Monitor logs** - Setup logging aggregation and alerting

### Sandbox Security

When `SANDBOX_ENABLED=true`, bash commands execute in isolated Docker containers:
- **Read-only filesystem** - Project files mounted as read-only
- **No network access** - Network disabled unless explicitly needed
- **Resource limits** - Memory and CPU caps enforced
- **Timeout enforcement** - Commands killed after timeout

**Never disable sandboxing** when auditing untrusted repositories.

## Common Issues & Solutions

### "Database connection failed"
- **Solution:** Ensure PostgreSQL is running and `DATABASE_URL` is correct
- **Dev:** Use SQLite with `DATABASE_URL=sqlite+aiosqlite:///./data/quickhack.db`

### "Unauthorized" on API requests
- **Solution:** Login to get access token, include in `Authorization: Bearer <token>` header
- **Frontend:** Token stored automatically in localStorage after login

### "Agent execution timeout"
- **Solution:** Increase `AGENT_TIMEOUT_SECONDS` for DeepAudit (default: 300s)
- **Recommendation:** 600s (10 min) for DeepAudit, 1200s (20 min) for large repos

### "WebSocket connection failed"
- **Solution:** Check `NEXT_PUBLIC_WS_URL` is set correctly
- **CORS:** Ensure WebSocket URL is in `CORS_ORIGINS`

### "Docker sandbox not available"
- **Solution:** Ensure Docker daemon is running
- **Disable:** Set `SANDBOX_ENABLED=false` (dev only, not for production)

### "LLM API key invalid"
- **Solution:** Verify API key is correct and has sufficient credits
- **Per-user keys:** Can also configure API keys per user in Settings UI

## Documentation

- **[Architecture Reference](docs/plans/2026-01-12-architecture-reference.md)** - Complete system documentation (4,300+ lines)
- **[Triage System](docs/triage-system.md)** - Evidence-based classification guide
- **[API Documentation](http://localhost:8000/docs)** - Interactive Swagger UI (when backend running)

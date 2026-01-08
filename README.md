# Quick Hack

AI-powered security vulnerability research platform with Ultrathink hierarchical verification cascade.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Frontend (Next.js)                             │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐  │
│  │  Editor  │ │ Findings │ │  Agents  │ │   Chat   │ │  Ultrathink      │  │
│  │ (Monaco) │ │  Panel   │ │  Panel   │ │  Panel   │ │  Visualization   │  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │ WebSocket + REST
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                             Backend (FastAPI)                               │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                           Security Agents                             │  │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌────────────────┐  │  │
│  │  │ Quick Audit │ │  Deep Scan  │ │   Custom    │ │  Ultrathink    │  │  │
│  │  └─────────────┘ └─────────────┘ └─────────────┘ └────────────────┘  │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                         LLM Providers                                 │  │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐                     │  │
│  │  │  Anthropic  │ │   OpenAI    │ │   Ollama    │                     │  │
│  │  │ (Claude)    │ │  (GPT-4)    │ │  (Local)    │                     │  │
│  │  └─────────────┘ └─────────────┘ └─────────────┘                     │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Ultrathink: Hierarchical Verification Cascade

Ultrathink maximizes AI cognitive depth for security research. Instead of ~500ms inference, it provides **60+ seconds of reasoning** through a 5-gate adversarial cascade:

```
Finding → Triage → Deep Analysis → Devil's Advocate → Proof Generator → Final Gate → Report
            │           │                │                 │              │
          FAST      THOROUGH        ADVERSARIAL        CONCRETE       REPUTATION
          (5s)       (180s)           (120s)            (90s)           (60s)
```

**Gates:**
1. **Triage** - Quick filter for obvious non-issues
2. **Deep Analysis** - Source-to-sink verification with full trace
3. **Devil's Advocate** - Actively argues AGAINST the finding
4. **Proof Generator** - Must produce concrete exploit or admit inability
5. **Final Gate** - "Would you stake your reputation on this?"

**Thinking Modes:**
- **Native** (Claude) - Uses built-in extended thinking blocks
- **Simulated** (GPT-4) - Chain-of-thought prompting
- **Structured** (Open Source) - Highly structured reasoning prompts

## Quick Start

### Prerequisites

- Python 3.10+
- Node.js 18+
- API key for at least one provider (Anthropic, OpenAI, or Ollama running locally)

### 1. Clone and Setup

```bash
git clone https://github.com/0xkato/quick-hack.git
cd quick-hack

# Copy environment template
cp .env.example .env
```

### 2. Configure API Keys

Edit `.env` and add your API keys:

```bash
# Required: At least one of these
ANTHROPIC_API_KEY=sk-ant-...  # For Claude (recommended for Ultrathink)
OPENAI_API_KEY=sk-...         # For GPT-4

# Optional: Local models
OLLAMA_BASE_URL=http://localhost:11434
```

### 3. Start Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Run the server
python main.py
```

Backend runs at `http://localhost:8000`

### 4. Start Frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend runs at `http://localhost:3000`

### 5. Get Auth Token

The API requires authentication. Get your session token:

```bash
curl http://localhost:8000/api/auth/token
```

Use this token in the `X-Session-Token` header for API requests.

## Docker Compose (Alternative)

```bash
docker-compose up -d
```

This starts:
- Backend on port 8000
- Frontend on port 3000
- Redis for caching
- Ollama for local models (optional)

## Usage

### Web Interface

1. Open `http://localhost:3000`
2. Clone a repository or select an existing project
3. Choose an agent type:
   - **Quick Audit** - Fast surface-level scan
   - **Deep Scan** - Thorough analysis with data flow tracing
   - **Ultrathink** - Maximum verification with hierarchical cascade

### API Examples

```bash
# Clone a repo
curl -X POST http://localhost:8000/api/projects/clone \
  -H "Content-Type: application/json" \
  -H "X-Session-Token: YOUR_TOKEN" \
  -d '{"url": "https://github.com/user/repo"}'

# Start Ultrathink agent
curl -X POST http://localhost:8000/api/agents/create \
  -H "Content-Type: application/json" \
  -H "X-Session-Token: YOUR_TOKEN" \
  -d '{
    "repo_id": "repo-id",
    "agent_type": "ultrathink",
    "provider_config": {
      "provider": "anthropic",
      "model": "claude-opus-4-5-20251101"
    }
  }'
```

### WebSocket Events

Connect to `ws://localhost:8000/ws?token=YOUR_TOKEN` for real-time updates:

```javascript
// Ultrathink cascade events
ultrathink_cascade_start   // Cascade begins
ultrathink_gate_start      // Gate evaluation starts
ultrathink_thinking_update // Real-time thinking stream
ultrathink_gate_complete   // Gate pass/fail with reasoning
ultrathink_cascade_complete // Final verdict
```

## Project Structure

```
quick-hack/
├── backend/
│   ├── main.py              # FastAPI application
│   ├── config.py            # Configuration
│   ├── agents/              # Security agents
│   │   ├── base_agent.py
│   │   ├── quick_audit_agent.py
│   │   ├── deep_scan_agent.py
│   │   └── ultrathink_agent.py
│   ├── ultrathink/          # Hierarchical cascade
│   │   ├── config.py        # Gate configurations
│   │   ├── thinking.py      # Extended thinking engine
│   │   ├── gates.py         # 5 verification gates
│   │   ├── cascade.py       # Orchestrator
│   │   └── events.py        # WebSocket emitter
│   ├── providers/           # LLM integrations
│   │   ├── anthropic_provider.py
│   │   ├── openai_provider.py
│   │   └── ollama_provider.py
│   ├── routers/             # API endpoints
│   └── models/              # Pydantic schemas
│
├── frontend/
│   ├── app/                 # Next.js app router
│   ├── components/
│   │   ├── Editor/          # Monaco code editor
│   │   ├── FindingsPanel/   # Vulnerability list
│   │   ├── AgentPanel/      # Agent controls
│   │   ├── ChatPanel/       # LLM chat interface
│   │   └── UltrathinkPanel/ # Cascade visualization
│   ├── hooks/               # React hooks (WebSocket)
│   └── lib/                 # API client
│
└── docs/
    └── ultrathink.md        # Detailed cascade docs
```

## Running Tests

```bash
cd backend
pip install pytest pytest-asyncio

# All tests
python -m pytest tests/ -v

# Ultrathink tests only
python -m pytest tests/ultrathink/ -v

# Integration tests
python -m pytest tests/integration/ -v
```

## Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | - | Anthropic API key for Claude |
| `OPENAI_API_KEY` | - | OpenAI API key for GPT-4 |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama server URL |
| `DEBUG` | `false` | Enable debug mode |
| `MAX_CONCURRENT_AGENTS` | `5` | Max parallel agents |
| `SANDBOX_ENABLED` | `true` | Docker sandbox for execution |
| `SETTINGS_SECRET` | - | Encryption key for stored settings |

## Recommended Models for Ultrathink

| Provider | Model | Native Thinking | Notes |
|----------|-------|-----------------|-------|
| Anthropic | `claude-opus-4-5-20251101` | Yes | Best for Ultrathink |
| Anthropic | `claude-sonnet-4-20250514` | Yes | Good balance |
| OpenAI | `gpt-4o` | Simulated | Strong reasoning |
| Ollama | `llama3.3:70b` | Structured | Local, no API key |

## License

MIT

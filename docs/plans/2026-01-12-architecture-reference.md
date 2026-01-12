# quick_hack Architecture Reference

**Version:** 1.0.0
**Date:** 2026-01-12
**Purpose:** Comprehensive architectural documentation covering every major component, framework, and code path in the quick_hack system.

---

## Table of Contents

1. [System Overview](#system-overview)
2. [Core Architecture](#core-architecture)
3. [Backend Framework & Services](#backend-framework--services)
4. [Agent System](#agent-system)
5. [Tool System](#tool-system)
6. [Triage System](#triage-system)
7. [Database Layer](#database-layer)
8. [Frontend Architecture](#frontend-architecture)
9. [Authentication & Authorization](#authentication--authorization)
10. [Real-time Communication](#real-time-communication)
11. [Provider System](#provider-system)
12. [Code Analysis Services](#code-analysis-services)
13. [Data Flow Patterns](#data-flow-patterns)
14. [Configuration System](#configuration-system)
15. [Key Architectural Decisions](#key-architectural-decisions)

---

## System Overview

**quick_hack** is an AI-powered security auditing browser IDE that combines automated vulnerability detection with human expertise. The system uses multiple AI agent types to analyze codebases, identify potential security issues, and provide detailed evidence-based triage reports.

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Frontend (Next.js)                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Monaco     │  │  Chat UI     │  │   Project    │      │
│  │   Editor     │  │              │  │   Browser    │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└────────────────────────┬────────────────────────────────────┘
                         │ HTTP/REST + WebSocket
┌────────────────────────┴────────────────────────────────────┐
│                  Backend (FastAPI)                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Routers    │  │   Services   │  │  Middleware  │      │
│  │  (13 modules)│  │  (31 files)  │  │    (Auth)    │      │
│  └──────┬───────┘  └──────┬───────┘  └──────────────┘      │
│         │                  │                                 │
│  ┌──────┴──────────────────┴───────┐                        │
│  │       Agent Orchestration       │                        │
│  │  ┌───────────┐  ┌────────────┐  │                        │
│  │  │  Quick    │  │   React    │  │                        │
│  │  │  Audit    │  │   Agent    │  │                        │
│  │  └───────────┘  └────────────┘  │                        │
│  │  ┌────────────────────────────┐ │                        │
│  │  │   Deep Audit (LangGraph)   │ │                        │
│  │  └────────────────────────────┘ │                        │
│  └─────────────────────────────────┘                        │
│                     │                                        │
│  ┌──────────────────┴───────────────────┐                   │
│  │        Triage System                 │                   │
│  │  Evidence Gatherer → Strict Filter   │                   │
│  └──────────────────────────────────────┘                   │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────┴────────────────────────────────────┐
│              Database (PostgreSQL/SQLite)                    │
│  Users, Sessions, Projects, Findings, Evidence              │
└─────────────────────────────────────────────────────────────┘
```

### Technology Stack

**Backend:**
- **Framework:** FastAPI 0.104+ (async Python 3.11+)
- **ORM:** SQLAlchemy 2.0+ with async support
- **Validation:** Pydantic 2.0+
- **Database:** PostgreSQL (production) / SQLite (development)
- **WebSocket:** FastAPI native WebSocket support
- **HTTP Client:** aiohttp for async HTTP requests

**Frontend:**
- **Framework:** Next.js 14+ (App Router)
- **UI Library:** React 18+
- **Language:** TypeScript 5+
- **Editor:** Monaco Editor (VS Code editor component)
- **State:** React Context + local state
- **Styling:** Tailwind CSS
- **HTTP Client:** Fetch API with custom wrapper

**AI/LLM:**
- **Providers:** Anthropic (Claude), OpenAI (GPT), Ollama (local), Claude SDK
- **Orchestration:** LangGraph for complex workflows
- **Streaming:** Server-Sent Events (SSE) via streaming responses

**Development Tools:**
- **Code Analysis:** AST parsing, ripgrep, tree-sitter
- **Sandboxing:** Docker-based execution isolation
- **Testing:** pytest (backend), Jest/React Testing Library (frontend)

---

## Core Architecture

### Request Flow Overview

```
User Action (Frontend)
    ↓
API Request (HTTP/WebSocket)
    ↓
Router (FastAPI endpoint)
    ↓
Authentication Middleware (JWT validation)
    ↓
Service Layer (business logic)
    ↓
┌───────────────────────────────┐
│ If Agent Request:             │
│   AgentOrchestrator           │
│     → Agent Execution         │
│     → Tool Calls              │
│     → WebSocket Updates       │
└───────────────────────────────┘
    ↓
┌───────────────────────────────┐
│ If Triage Request:            │
│   EvidenceGatherer            │
│     → StrictClassifier        │
│     → Disposition Rules       │
└───────────────────────────────┘
    ↓
Database Operations (async SQLAlchemy)
    ↓
Response (JSON/SSE/WebSocket)
    ↓
Frontend Update (React state)
```

### Directory Structure

```
quick_hack/
├── backend/
│   ├── agents/                   # Agent implementations (13 files)
│   │   ├── __init__.py
│   │   ├── base_agent.py         # Abstract base for all agents
│   │   ├── quick_audit_agent.py  # Fast scan agent
│   │   ├── react_agent.py        # ReAct pattern agent
│   │   ├── deep_audit_agent.py   # LangGraph-based thorough audit
│   │   ├── orchestrator.py       # Agent lifecycle management
│   │   ├── claude_sdk_orchestrator.py  # Time-governed execution
│   │   ├── tools/                # Tool implementations
│   │   │   ├── base.py           # ToolCore base class
│   │   │   ├── bash.py           # Sandboxed shell execution
│   │   │   ├── read_file.py      # File reading tool
│   │   │   ├── ripgrep.py        # Code search tool
│   │   │   ├── list_files.py     # Directory listing
│   │   │   └── ... (13 tools total)
│   │   └── validity_checklists/  # Per-vulnerability-type checklists
│   │       ├── sql_injection.md
│   │       ├── xss.md
│   │       └── ... (12 checklists)
│   ├── routers/                  # API endpoints (16 files)
│   │   ├── agents.py             # Agent CRUD and execution
│   │   ├── auth.py               # Authentication endpoints
│   │   ├── call_tree.py          # Call graph analysis
│   │   ├── chat.py               # Chat interface
│   │   ├── files.py              # File operations
│   │   ├── flow.py               # Flow tracking
│   │   ├── git.py                # Git operations
│   │   ├── graph.py              # Code graph endpoints
│   │   ├── projects.py           # Project management
│   │   ├── session.py            # Session management
│   │   ├── settings.py           # Settings CRUD
│   │   └── websocket.py          # WebSocket handler
│   ├── services/                 # Business logic (31 files)
│   │   ├── agent_service.py      # Agent management
│   │   ├── auth_service.py       # Auth logic
│   │   ├── code_graph_service.py # Code analysis graph
│   │   ├── evidence_gatherer.py  # Triage evidence collection
│   │   ├── file_service.py       # File operations
│   │   ├── flow_tracker.py       # Agent flow tracking
│   │   ├── git_service.py        # Git operations
│   │   ├── project_service.py    # Project lifecycle
│   │   ├── session_service.py    # Session management
│   │   ├── settings_service.py   # Settings persistence
│   │   ├── strict_classifier.py  # Triage classification
│   │   └── ... (20+ more services)
│   ├── database/                 # Database layer
│   │   ├── connection.py         # Async engine setup
│   │   ├── models.py             # SQLAlchemy models
│   │   └── schema_checker.py     # Schema validation
│   ├── models/                   # Pydantic schemas
│   │   ├── schemas.py            # Core data models
│   │   └── enums.py              # Enumerations
│   ├── middleware/               # HTTP middleware
│   │   └── auth.py               # JWT validation
│   ├── providers/                # LLM provider integrations
│   │   ├── anthropic_provider.py
│   │   ├── openai_provider.py
│   │   ├── ollama_provider.py
│   │   └── claude_sdk_provider.py
│   ├── config.py                 # Configuration management
│   ├── main.py                   # FastAPI application entry
│   └── tests/                    # Backend tests
├── frontend/
│   ├── app/                      # Next.js pages (App Router)
│   │   ├── page.tsx              # Home/landing
│   │   ├── login/
│   │   ├── projects/
│   │   └── layout.tsx
│   ├── components/               # React components
│   │   ├── agent/                # Agent-related UI
│   │   ├── chat/                 # Chat interface
│   │   ├── editor/               # Monaco editor wrapper
│   │   ├── project/              # Project browser
│   │   ├── triage/               # Triage UI
│   │   └── ... (15 subdirectories)
│   ├── contexts/                 # React Context providers
│   │   └── AuthContext.tsx       # Auth state
│   ├── hooks/                    # Custom React hooks
│   │   ├── useAuth.ts
│   │   ├── useWebSocket.ts
│   │   └── ... (10+ hooks)
│   └── lib/                      # Utilities
│       ├── api.ts                # API client
│       └── types.ts              # TypeScript types
├── docs/                         # Documentation
│   ├── triage-system.md          # Triage documentation
│   └── plans/                    # Design documents
└── docker-compose.yml            # Development environment
```

---

## Backend Framework & Services

### FastAPI Application Structure

**File:** `backend/main.py` (179 lines)

The FastAPI application uses a lifespan context manager for startup/shutdown hooks:

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    set_main_loop(asyncio.get_running_loop())  # For WebSocket broadcasts
    await init_db()                             # Database initialization
    await initialize_triage_availability()      # Schema compatibility check
    await settings_service.initialize()         # Load settings
    await project_service.initialize()          # Load projects

    yield

    # Shutdown
    # (cleanup happens automatically)

app = FastAPI(
    title="quick_hack",
    description="Security Auditing Browser IDE",
    version="0.1.0",
    lifespan=lifespan,
)
```

**Router Registration:**

```python
# All routers require authentication except auth and websocket
app.include_router(projects.router, dependencies=[Depends(require_auth)])
app.include_router(git.router, dependencies=[Depends(require_auth)])
app.include_router(files.router, dependencies=[Depends(require_auth)])
app.include_router(agents.router, dependencies=[Depends(require_auth)])
app.include_router(settings_router.router)  # No auth for settings read
app.include_router(chat_router.router, dependencies=[Depends(require_auth)])
app.include_router(flow.router, dependencies=[Depends(require_auth)])
app.include_router(call_tree.router, dependencies=[Depends(require_auth)])
app.include_router(graph_router.router, dependencies=[Depends(require_auth)])
app.include_router(websocket.router)  # WebSocket has separate auth
app.include_router(auth.router)  # Login/signup endpoints
app.include_router(session_router.router, dependencies=[Depends(require_auth)])
```

### Service Layer Pattern

All business logic is encapsulated in service classes located in `backend/services/`. Services follow a consistent pattern:

**Service Initialization:**
```python
class ServiceName:
    def __init__(self):
        self._state = None

    async def initialize(self):
        """Called during app startup."""
        self._state = await self._load_from_db()

    async def get_or_create(self, identifier: str):
        """Lazy loading for on-demand resources."""
        if identifier not in self._cache:
            self._cache[identifier] = await self._create(identifier)
        return self._cache[identifier]
```

**Key Services:**

1. **`project_service.py`** - Project lifecycle management
   - Repository cloning
   - Directory scanning
   - File tree generation
   - Project metadata persistence

2. **`session_service.py`** - Chat session management
   - Session creation and retrieval
   - Message history persistence
   - Session-project association

3. **`agent_service.py`** - Agent execution orchestration
   - Agent type selection (QuickAudit, ReAct, DeepAudit)
   - Execution state management
   - Result aggregation

4. **`code_graph_service.py`** - Static code analysis
   - AST parsing for Python/JS/TS
   - Symbol extraction (functions, classes, imports)
   - Call graph construction
   - Cross-file reference resolution

5. **`flow_tracker.py`** - Agent execution flow tracking
   - Tool call logging
   - Finding discovery tracking
   - Execution timeline reconstruction

6. **`evidence_gatherer.py`** - Triage evidence collection
   - File content extraction
   - Code snippet capture
   - Route/handler identification
   - Auth gate detection

7. **`strict_classifier.py`** - Vulnerability classification
   - Tri-state proof checklist evaluation
   - Disposition rule application
   - Evidence-based reasoning generation

8. **`settings_service.py`** - Configuration persistence
   - Provider API keys (encrypted)
   - Model preferences
   - System settings

9. **`git_service.py`** - Git operations
   - Repository status
   - Branch operations
   - Commit/diff retrieval
   - File history

10. **`file_service.py`** - File system operations
    - Safe path resolution (prevents path traversal)
    - File reading with encoding detection
    - Directory traversal
    - File writing (within project boundaries)

### Dependency Injection Pattern

FastAPI's dependency injection is used extensively for:

**Authentication:**
```python
async def require_auth(authorization: str = Header(None)) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401)
    token = authorization[7:]
    payload = jwt.decode(token, settings.secret_key, algorithms=["HS256"])
    return payload["sub"]  # user_id
```

**Database Sessions:**
```python
async def get_db() -> AsyncSession:
    async with async_session_maker() as session:
        yield session
```

**Service Access:**
```python
# Services are singleton instances imported directly
from services.project_service import project_service
from services.session_service import session_service
```

---

## Agent System

The agent system is the core of quick_hack's intelligence. It provides three agent types with different trade-offs between speed, depth, and cost.

### Agent Types

#### 1. QuickAudit Agent

**File:** `backend/agents/quick_audit_agent.py`

**Purpose:** Fast, pattern-based vulnerability scanning for initial triage.

**Characteristics:**
- **Speed:** ~30-60 seconds for medium codebase
- **Cost:** Low (uses smaller models like Claude Sonnet)
- **Depth:** Surface-level pattern matching
- **Tools:** Read, Ripgrep, ListFiles (no code execution)

**Algorithm:**
```python
1. Scan repository for high-risk patterns
2. For each match:
   a. Extract surrounding code context
   b. Classify using pattern rules
   c. Gather minimal evidence
3. Return findings list
```

**Use Cases:**
- Initial security assessment
- Pre-commit hooks
- CI/CD integration
- Quick sanity checks

#### 2. ReAct Agent

**File:** `backend/agents/react_agent.py`

**Purpose:** Reasoning and acting in cycles for targeted investigation.

**Characteristics:**
- **Speed:** ~2-5 minutes per finding
- **Cost:** Medium (uses Claude Sonnet/Opus)
- **Depth:** Can follow code paths, validate findings
- **Tools:** Full tool suite (Read, Bash, Ripgrep, WriteFile, etc.)

**Algorithm (ReAct Pattern):**
```python
loop:
    thought = llm("What should I investigate next?")
    action = llm("What tool/action should I take?")
    observation = execute_action(action)

    if observation indicates vulnerability confirmed:
        gather_evidence()
        break
    elif observation indicates false positive:
        mark_filtered()
        break
    elif max_iterations_reached:
        mark_speculative()
        break
```

**Use Cases:**
- Validating QuickAudit findings
- Investigating specific vulnerability reports
- Exploring complex code paths
- Reproducing security issues

#### 3. DeepAudit Agent (LangGraph)

**File:** `backend/agents/deep_audit_agent.py`

**Purpose:** Comprehensive, systematic security audit using state machine workflow.

**Characteristics:**
- **Speed:** ~15-30 minutes for medium codebase
- **Cost:** High (uses Claude Opus, many tool calls)
- **Depth:** Systematic coverage, multi-pass analysis
- **Tools:** Full suite + custom audit tools

**State Machine (LangGraph):**
```
START
  ↓
[1. ANALYZE_ARCHITECTURE]
  - Read main files
  - Identify frameworks
  - Map auth/authz
  ↓
[2. IDENTIFY_ENTRY_POINTS]
  - Find routes/handlers
  - Map user input sources
  ↓
[3. TRACE_DATA_FLOWS]
  - Follow variables
  - Track transformations
  ↓
[4. IDENTIFY_SINKS]
  - Find dangerous operations
  - Check for protections
  ↓
[5. VALIDATE_FINDINGS]
  - Confirm exploitability
  - Gather evidence
  ↓
[6. TRIAGE]
  - Apply strict classifier
  - Generate reports
  ↓
[7. GENERATE_REPORT]
  - Format findings
  - Add recommendations
  ↓
[8. END]
```

**State Transitions:**
```python
workflow = StateGraph(AuditState)
workflow.add_node("analyze_architecture", analyze_architecture_node)
workflow.add_node("identify_entry_points", identify_entry_points_node)
workflow.add_node("trace_data_flows", trace_data_flows_node)
workflow.add_node("identify_sinks", identify_sinks_node)
workflow.add_node("validate_findings", validate_findings_node)
workflow.add_node("triage", triage_node)
workflow.add_node("generate_report", generate_report_node)

workflow.set_entry_point("analyze_architecture")
workflow.add_edge("analyze_architecture", "identify_entry_points")
workflow.add_edge("identify_entry_points", "trace_data_flows")
workflow.add_edge("trace_data_flows", "identify_sinks")
workflow.add_edge("identify_sinks", "validate_findings")
workflow.add_edge("validate_findings", "triage")
workflow.add_edge("triage", "generate_report")
workflow.add_edge("generate_report", END)

app = workflow.compile()
```

**Use Cases:**
- Comprehensive security audits
- Pre-release security reviews
- Compliance requirements (SOC2, PCI-DSS)
- High-value target assessment

### Agent Orchestration

#### AgentOrchestrator

**File:** `backend/agents/orchestrator.py`

**Responsibilities:**
- Agent lifecycle management (start, stop, pause, resume)
- Concurrent agent execution (up to `max_concurrent_agents`)
- Tool call execution and sandboxing
- Progress tracking via WebSocket
- Error handling and recovery

**Key Methods:**

```python
async def execute_agent(
    agent_id: str,
    agent_type: AgentType,
    project_id: str,
    session_id: str,
    user_id: str,
    prompt: str,
) -> AgentExecution:
    """
    Main entry point for agent execution.

    Flow:
    1. Validate inputs and check concurrency limits
    2. Create agent instance based on type
    3. Setup tool environment
    4. Execute agent loop:
       a. Get next action from LLM
       b. Execute tool call (sandboxed if needed)
       c. Send progress update via WebSocket
       d. Feed observation back to LLM
    5. Process results (findings, evidence)
    6. Persist to database
    7. Send completion message via WebSocket
    """
```

**Concurrency Control:**
```python
_active_agents: Dict[str, AgentExecution] = {}
_agent_semaphore: Optional[asyncio.Semaphore] = None

async def _acquire_slot(self) -> None:
    if len(self._active_agents) >= settings.max_concurrent_agents:
        raise HTTPException(
            status_code=429,
            detail=f"Maximum {settings.max_concurrent_agents} agents already running"
        )
    await self._agent_semaphore.acquire()

async def _release_slot(self, agent_id: str) -> None:
    del self._active_agents[agent_id]
    self._agent_semaphore.release()
```

#### ClaudeSDKOrchestrator

**File:** `backend/agents/claude_sdk_orchestrator.py`

**Purpose:** Time-governed agent execution using Claude SDK's native tool system.

**Key Features:**
- **Time budgets:** Enforces max execution time per agent run
- **Token budgets:** Tracks context usage, prevents runaway loops
- **MCP integration:** Uses Model Context Protocol for tool definitions
- **Streaming:** Real-time tool call and result streaming

**Time Governance:**
```python
class TimeGoverned ExecutionConfig:
    max_execution_time: timedelta  # e.g., 5 minutes
    max_turns: int                 # e.g., 20 agentic turns
    max_context_tokens: int        # e.g., 100k tokens

async def execute_with_governance(
    agent: Agent,
    prompt: str,
    config: TimeGovernedExecutionConfig,
) -> ExecutionResult:
    start_time = datetime.now()
    turns = 0
    context_tokens = 0

    while True:
        if datetime.now() - start_time > config.max_execution_time:
            raise TimeoutError("Execution exceeded time budget")
        if turns >= config.max_turns:
            raise MaxTurnsExceeded("Agent exceeded turn limit")
        if context_tokens >= config.max_context_tokens:
            raise ContextLimitExceeded("Context size exceeded budget")

        # Execute one turn
        response = await agent.step()
        turns += 1
        context_tokens += response.usage.total_tokens

        if response.stop_reason == "end_turn":
            break

    return ExecutionResult(...)
```

---

## Tool System

Tools are the primitives that agents use to interact with code, file systems, and external systems. All tools inherit from `ToolCore` base class.

### Tool Architecture

**File:** `backend/agents/tools/base.py`

```python
class ToolCore(ABC):
    """Base class for all agent tools."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique tool identifier."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable tool description for LLM."""
        pass

    @property
    @abstractmethod
    def parameters_schema(self) -> Dict[str, Any]:
        """JSON Schema for tool parameters."""
        pass

    @abstractmethod
    async def execute(self, **kwargs) -> ToolResult:
        """Execute tool with given parameters."""
        pass

    def to_mcp_tool(self) -> MCPTool:
        """Convert to Model Context Protocol tool definition."""
        return MCPTool(
            name=self.name,
            description=self.description,
            inputSchema=self.parameters_schema,
        )
```

### Available Tools

#### 1. **ReadFileTool**

**File:** `backend/agents/tools/read_file.py`

**Purpose:** Read file contents with safety checks.

**Parameters:**
- `file_path: str` - Path relative to project root
- `line_start: Optional[int]` - Start line for partial reads
- `line_end: Optional[int]` - End line for partial reads

**Safety Features:**
- Path traversal prevention (rejects `../`)
- Binary file detection (returns error for non-text files)
- Size limits (max 10MB per read)
- Encoding detection (tries UTF-8, falls back to chardet)

**Example:**
```python
result = await read_file.execute(
    file_path="backend/services/auth.py",
    line_start=10,
    line_end=50,
)
# Returns: ToolResult(output="...", success=True)
```

#### 2. **RipgrepTool**

**File:** `backend/agents/tools/ripgrep.py`

**Purpose:** Fast code search using ripgrep.

**Parameters:**
- `pattern: str` - Regex pattern to search
- `file_pattern: Optional[str]` - Glob pattern for files (e.g., "*.py")
- `case_sensitive: bool` - Case sensitivity flag

**Features:**
- Respects .gitignore
- Multi-threaded search
- Context lines (before/after match)
- JSON output parsing

**Example:**
```python
result = await ripgrep.execute(
    pattern=r"exec\s*\(",
    file_pattern="**/*.py",
    case_sensitive=True,
)
# Returns: List of matches with file, line, column
```

#### 3. **BashTool**

**File:** `backend/agents/tools/bash.py`

**Purpose:** Execute shell commands (sandboxed if enabled).

**Parameters:**
- `command: str` - Shell command to execute
- `timeout: int` - Max execution time in seconds

**Sandboxing (when enabled):**
```python
docker_cmd = [
    "docker", "run",
    "--rm",  # Auto-remove container
    "--network", "none",  # No network access
    "--memory", settings.sandbox_memory_limit,
    "--cpus", str(settings.sandbox_cpu_limit),
    "-v", f"{project_path}:/workspace:ro",  # Read-only mount
    "quickhack-sandbox",
    "bash", "-c", command,
]
```

**Security:**
- Read-only file system access
- No network access
- Memory/CPU limits
- Timeout enforcement

**Example:**
```python
result = await bash.execute(
    command="pytest tests/test_auth.py -v",
    timeout=30,
)
```

#### 4. **WriteFileTool**

**File:** `backend/agents/tools/write_file.py`

**Purpose:** Write or modify files (requires explicit user permission).

**Parameters:**
- `file_path: str` - Path relative to project root
- `content: str` - File contents to write
- `create_backup: bool` - Create .bak file before overwriting

**Safety Features:**
- Path traversal prevention
- Backup creation option
- Size limits (max 5MB per write)
- Directory creation if needed

**Example:**
```python
result = await write_file.execute(
    file_path="backend/config.py",
    content="# Updated config\n...",
    create_backup=True,
)
```

#### 5. **ListFilesTool**

**File:** `backend/agents/tools/list_files.py`

**Purpose:** List directory contents with filtering.

**Parameters:**
- `directory: str` - Directory path relative to project root
- `pattern: Optional[str]` - Glob pattern (e.g., "*.py")
- `max_depth: int` - Max recursion depth

**Features:**
- Respects .gitignore
- File size and type information
- Sorted output (directories first, then files alphabetically)

**Example:**
```python
result = await list_files.execute(
    directory="backend/services",
    pattern="*.py",
    max_depth=2,
)
```

#### 6. **CallGraphTool**

**File:** `backend/agents/tools/call_graph.py`

**Purpose:** Generate function call graph for code analysis.

**Parameters:**
- `function_name: str` - Target function to analyze
- `max_depth: int` - Call chain depth limit

**Algorithm:**
```python
1. Parse AST for target function definition
2. Extract all function calls within body
3. For each called function:
   a. Find definition in same file or imports
   b. Recurse to depth limit
4. Build directed graph: caller → callee
5. Return as adjacency list with line numbers
```

**Example:**
```python
result = await call_graph.execute(
    function_name="process_user_input",
    max_depth=3,
)
# Returns: {"process_user_input": ["sanitize", "validate"], "sanitize": [...]}
```

#### 7. **FindSymbolTool**

**File:** `backend/agents/tools/find_symbol.py`

**Purpose:** Locate function/class definitions across codebase.

**Parameters:**
- `symbol_name: str` - Function or class name
- `symbol_type: str` - "function" or "class"

**Uses:**
- AST parsing for exact matches
- Ripgrep fallback for dynamic code

**Example:**
```python
result = await find_symbol.execute(
    symbol_name="authenticate_user",
    symbol_type="function",
)
# Returns: {"file": "auth.py", "line": 42, "signature": "def authenticate_user(...)"}
```

#### Additional Tools (8-13)

8. **GetDiffTool** - Git diff retrieval
9. **GetCommitHistoryTool** - Git log with filters
10. **SearchImportsTool** - Find import statements
11. **GetRoutesTool** - Extract API routes (framework-aware)
12. **GetAuthGatesTool** - Identify auth decorators/middleware
13. **GetConfigTool** - Parse configuration files

### Tool Execution Flow

```
Agent requests tool call
    ↓
Orchestrator receives tool name + parameters
    ↓
Validate parameters against JSON schema
    ↓
Check if tool requires sandboxing
    ↓
┌─────────────────────────────┐
│ If Sandbox Required:        │
│   Create Docker container   │
│   Mount project (read-only) │
│   Execute command           │
│   Capture output            │
│   Destroy container         │
└─────────────────────────────┘
    ↓
┌─────────────────────────────┐
│ If No Sandbox:              │
│   Execute directly          │
│   Apply timeouts            │
│   Capture output            │
└─────────────────────────────┘
    ↓
Parse output as ToolResult
    ↓
Log tool call + result (FlowTracker)
    ↓
Send progress update via WebSocket
    ↓
Return observation to agent
```

---

## Triage System

The triage system is quick_hack's most critical component for reducing false positives. It implements a strict, evidence-based classification workflow that challenges every finding.

### Philosophy

**"Unknown ≠ Safe, Unknown = Unproven"**

- Don't mislabel unknowns as "expected" (BY_DESIGN)
- If we can't prove it's a product feature AND can't prove exploitation → SPECULATIVE
- SPECULATIVE findings are filtered (non-reportable) but correctly labeled as "needs more evidence"
- Prefer false negatives over false positives (harsh but honest)

### Architecture

```
Raw Finding (from agent/scanner)
    ↓
EvidenceGatherer
  - Extract file content
  - Capture code snippets
  - Find route registration
  - Identify auth gates
  - Search for security controls
    ↓
Finding + Evidence Bundle
    ↓
StrictClassifier
  - Build ProofChecklist (tri-state)
  - Apply disposition rules
  - Generate reasoning
    ↓
Classified Finding (with disposition)
    ↓
┌────────────────────────────────┐
│ REPORTABLE:                    │
│  - VALID_SECURITY_ISSUE        │
│  - BUG                         │
├────────────────────────────────┤
│ FILTERED:                      │
│  - BY_DESIGN                   │
│  - HARDENING                   │
│  - MISCONFIGURATION            │
│  - SPECULATIVE                 │
└────────────────────────────────┘
```

### Tri-State Proof Checklist

**File:** `backend/models/schemas.py` (lines 215-270)

Every finding must satisfy a checklist before being marked VALID_SECURITY_ISSUE:

```python
class ChecklistStatus(str, Enum):
    PROVEN_TRUE = "PROVEN_TRUE"      # Evidence confirms
    PROVEN_FALSE = "PROVEN_FALSE"    # Evidence contradicts
    UNKNOWN = "UNKNOWN"              # Insufficient evidence

class ChecklistItem(BaseModel):
    value: bool                      # True/False claim
    status: ChecklistStatus          # Proof level
    reason: str                      # Evidence justification

class ProofChecklist(BaseModel):
    """All items must be PROVEN_TRUE for VALID_SECURITY_ISSUE."""

    source_controlled_input: ChecklistItem
    # Evidence: HTTP param, JSON body, WebSocket message, file upload, etc.

    sink_present: ChecklistItem
    # Evidence: exec(), os.system(), cursor.execute(), etc.

    dataflow_evidenced: ChecklistItem
    # Evidence: Variable tracing, call chain, transformation steps

    reachable: ChecklistItem
    # Evidence: Route registration, handler mapping, exposed endpoint

    boundary_crossed: ChecklistItem
    # Evidence: Unauth→auth, viewer→admin, user→server, etc.

    not_only_misconfig: ChecklistItem
    # Evidence: Exploitable even with security enabled

    security_control_bypassed: Optional[ChecklistItem]
    # Evidence: Read-only flag ignored, RBAC check skipped, etc.

    # Exec/eval specific reasoning (added by strict exec filter)
    exec_sink_reason: Optional[str] = None
    feature_intent_reason: Optional[str] = None
    auth_bypass_reason: Optional[str] = None
```

### Disposition Types

**File:** `backend/models/enums.py`

```python
class Disposition(str, Enum):
    VALID_SECURITY_ISSUE = "VALID_SECURITY_ISSUE"
    # All checklist items PROVEN_TRUE
    # Real exploitable vulnerability
    # Example: Unauthenticated RCE via exec()

    BUG = "BUG"
    # Security control explicitly bypassed/contradicted
    # Example: Read-only mode flag exists but ignored

    HARDENING = "HARDENING"
    # Risky pattern but credible defenses reduce exploitability
    # Example: SQL injection but numeric coercion prevents it

    MISCONFIGURATION = "MISCONFIGURATION"
    # Only exploitable when security disabled
    # Example: Auth can be turned off via config

    BY_DESIGN = "BY_DESIGN"
    # Intentional product feature, proven with 2+ signals
    # Example: Pipeline executor runs user code (path + symbol + doc)

    SPECULATIVE = "SPECULATIVE"
    # High-risk pattern but unproven
    # Example: exec() exists but auth/reachability unknown
```

### EvidenceGatherer

**File:** `backend/services/evidence_gatherer.py`

**Purpose:** Collect all relevant code evidence for a finding before classification.

**Inputs:**
- `Finding` - Raw finding from agent/scanner
- `project_id` - Repository to search

**Outputs:**
- `Evidence` - Bundle of code snippets and metadata

**Evidence Collection Process:**

```python
async def gather_evidence(finding: Finding, project_id: str) -> Evidence:
    evidence = Evidence(finding_id=finding.id)

    # 1. Extract handler code (±30 lines around finding location)
    if finding.file_path and finding.line_number:
        evidence.handler_snippet = await self._extract_snippet(
            file_path=finding.file_path,
            line=finding.line_number,
            context_lines=30,
        )

        # Parse AST for symbol info
        evidence.ast_tree = ast.parse(evidence.handler_snippet)
        evidence.symbol_info = self._extract_symbol_info(
            ast_tree=evidence.ast_tree,
            target_line=finding.line_number,
        )

    # 2. Find route registration
    if finding.endpoint_path:
        evidence.route_registration = await self._find_route_registration(
            endpoint=finding.endpoint_path,
            project_id=project_id,
        )

    # 3. Identify auth gates
    evidence.auth_gates = await self._find_auth_decorators(
        file_path=finding.file_path,
        function_name=evidence.symbol_info.name,
        project_id=project_id,
    )

    # 4. Search for security controls
    if finding.category == VulnerabilityCategory.CODE_INJECTION:
        evidence.security_controls = await self._search_security_controls(
            keywords=["read_only", "disable_exec", "safe_mode"],
            file_path=finding.file_path,
            project_id=project_id,
        )

    return evidence
```

**Key Methods:**

1. **`_extract_snippet`** - File content extraction with line ranges
2. **`_find_route_registration`** - Searches for `@app.route()`, `@router.post()`, etc.
3. **`_find_auth_decorators`** - Searches for `@require_auth`, `@login_required`, etc.
4. **`_search_security_controls`** - Ripgrep for security-related flags/checks

### StrictClassifier

**File:** `backend/services/strict_classifier.py` (752 lines)

**Purpose:** Apply disposition rules based on evidence to classify findings.

**Core Method:**

```python
async def classify(
    finding: Finding,
    evidence: Evidence,
) -> ClassificationResult:
    """
    Main classification entry point.

    Flow:
    1. Build proof checklist from evidence
    2. Apply disposition rules (order matters!)
    3. Generate reasoning bullets
    4. Return classification with confidence scores
    """

    # Build checklist (tri-state evaluation)
    checklist = self._build_proof_checklist(finding, evidence)

    # Apply rules (returns on first match)
    disposition = self._apply_rules(finding, evidence, checklist)

    # Generate auditable reasoning
    reasoning = self._generate_reasoning(checklist, disposition)

    # Calculate confidence scores
    classification_confidence = self._calculate_classification_confidence(checklist)
    exploit_confidence = self._calculate_exploit_confidence(checklist) if disposition in [Disposition.VALID_SECURITY_ISSUE, Disposition.BUG] else None

    return ClassificationResult(
        disposition=disposition,
        classification_confidence=classification_confidence,
        exploit_confidence=exploit_confidence,
        reasoning=reasoning,
        checklist=checklist,
    )
```

### Disposition Rules (Application Order)

**File:** `backend/services/strict_classifier.py:_apply_rules()` (lines 350-450)

Rules are applied in strict order, returning on first match:

```python
def _apply_rules(
    self,
    finding: Finding,
    evidence: Evidence,
    checklist: ProofChecklist,
) -> Disposition:

    # RULE 1: Security control bypassed → BUG
    if checklist.security_control_bypassed:
        if checklist.security_control_bypassed.status == ChecklistStatus.PROVEN_TRUE:
            if checklist.reachable.status == ChecklistStatus.PROVEN_TRUE:
                return Disposition.BUG

    # RULE 2: Misconfig-only → MISCONFIGURATION
    if checklist.not_only_misconfig.status == ChecklistStatus.PROVEN_FALSE:
        return Disposition.MISCONFIGURATION

    # RULE 3: Strict exec/eval filtering (if applicable)
    is_exec_sink, exec_reason = self._is_code_exec_sink(finding, evidence)
    if is_exec_sink:
        checklist.exec_sink_reason = exec_reason
        checklist.sink_present = ChecklistItem(
            value=True,
            status=ChecklistStatus.PROVEN_TRUE,
            reason=exec_reason,
        )

        # Sub-rule 3a: Feature intent proven → BY_DESIGN
        feature_proven, feature_reason = self._feature_intent_proven(finding, evidence)
        checklist.feature_intent_reason = feature_reason
        if feature_proven:
            return Disposition.BY_DESIGN

        # Sub-rule 3b: Full proof chain → VALID or SPECULATIVE
        if (checklist.source_controlled_input.status == ChecklistStatus.PROVEN_TRUE and
            checklist.reachable.status == ChecklistStatus.PROVEN_TRUE and
            checklist.dataflow_evidenced.status == ChecklistStatus.PROVEN_TRUE):

            bypass_proven, bypass_reason = self._auth_bypass_explicitly_proven(finding, evidence)
            checklist.auth_bypass_reason = bypass_reason

            if bypass_proven or checklist.boundary_crossed.status == ChecklistStatus.PROVEN_TRUE:
                return Disposition.VALID_SECURITY_ISSUE

            return Disposition.SPECULATIVE  # Auth unknown

        # Sub-rule 3c: Default → SPECULATIVE
        return Disposition.SPECULATIVE

    # RULE 4: Full proof chain → VALID_SECURITY_ISSUE
    if (checklist.source_controlled_input.status == ChecklistStatus.PROVEN_TRUE and
        checklist.sink_present.status == ChecklistStatus.PROVEN_TRUE and
        checklist.dataflow_evidenced.status == ChecklistStatus.PROVEN_TRUE and
        checklist.reachable.status == ChecklistStatus.PROVEN_TRUE and
        checklist.boundary_crossed.status == ChecklistStatus.PROVEN_TRUE and
        checklist.not_only_misconfig.status == ChecklistStatus.PROVEN_TRUE):
        return Disposition.VALID_SECURITY_ISSUE

    # RULE 5: Pattern downgrades (category-specific)
    disposition = self._apply_pattern_downgrades(finding, evidence, checklist)
    if disposition:
        return disposition

    # RULE 6: Default → SPECULATIVE
    return Disposition.SPECULATIVE
```

### Strict Exec/Eval Filtering

**Design Document:** `docs/plans/2026-01-12-strict-exec-eval-filtering-design.md`

**Purpose:** Dramatically reduce false positives from code execution findings.

**Implementation:** Added in Phase 1 (Tasks 1-10), fully tested with 24 new tests.

**Key Components:**

#### 1. AST-Based Sink Detection

**Method:** `_is_code_exec_sink(finding, evidence) -> (bool, str)`

**Detects:**
- Direct calls: `exec()`, `eval()`, `compile()`
- Attribute calls: `kernel.execute()`, `runner.eval()`
- Obfuscated: `getattr(__builtins__, "exec")`, `__builtins__["exec"]`

**Critical Features:**
- **Scoped to symbol range** - Only checks AST nodes within `symbol_info.line_start` to `line_end`
- **Avoids comment/string false positives** - Uses AST parsing, ignores string literals
- **Handles async functions** - Checks both `ast.FunctionDef` and `ast.AsyncFunctionDef`
- **Regex fallback** - If AST fails, uses regex with line-number prefix stripping

**Code:** `backend/services/strict_classifier.py:425-515`

#### 2. Conservative Feature Intent Detection

**Method:** `_feature_intent_proven(finding, evidence) -> (bool, str)`

**Requires TWO+ strong signals:**

**Signal A - Path Match:**
- `/pipelines/`, `/executor/`, `/kernel/`, `/etl/`, `/workflow/`, `/dag/`, `/notebooks/`

**Signal B - Symbol Match:**
- Class names: `PipelineExecutor`, `KernelRunner`, `BlockExecutor`
- Function names: `execute_pipeline()`, `run_kernel()`, `eval_block()`

**Signal C - Documentation Match:**
- Comments: "block execution", "pipeline runtime", "notebook kernel"
- Docstrings: "Execute user code", "Run pipeline block"

**Logic:**
```python
if (path_match + symbol_match) OR (path_match + doc_match):
    return (True, f"Feature intent PROVEN: {signals}")
else:
    return (False, "Feature intent UNKNOWN: insufficient signals")
```

**Code:** `backend/services/strict_classifier.py:517-577`

#### 3. Explicit Auth Bypass Detection

**Method:** `_auth_bypass_explicitly_proven(finding, evidence) -> (bool, str)`

**CRITICAL:** Only searches code evidence, NOT `finding.description` (prevents scanner manipulation)

**Code-only search space:**
- Handler snippet
- Route registration snippets
- Auth gate snippets

**Explicit markers:**

**Parameters (auth-specific):**
- `bypass_auth=True`, `require_auth=False`, `public=True`, `skip_auth=True`

**Function calls:**
- `bypass_oauth_check()`, `skip_permission_check()`, `bypass_auth()`

**Decorators:**
- `@public_endpoint`, `@no_auth_required`, `@unauthenticated`, `@allow_anonymous`

**Comments (in code):**
- `# no auth required`, `# public endpoint`, `# bypass authentication`

**Code:** `backend/services/strict_classifier.py:579-623`

### Pattern Downgrades

**Method:** `_apply_pattern_downgrades(finding, evidence, checklist) -> Optional[Disposition]`

**Purpose:** Category-specific rules that can ONLY downgrade (never upgrade to VALID/BUG).

**Categories Handled:**

1. **SSRF (Server-Side Request Forgery)**
   - If URL is constant or admin-configured → BY_DESIGN
   - If BASE_URL from config → HARDENING (unless user controls scheme/host)

2. **CSRF/WebSocket Origin**
   - If `check_origin=True` without ambient credentials → HARDENING
   - If ambient credentials (cookies/session) + CORS misconfigured → VALID

3. **SQL Injection**
   - Identifier interpolation (table/schema names) → HARDENING
   - Developer-controlled parameters → BY_DESIGN
   - User input in WHERE/INSERT/UPDATE without parameterization → VALID

4. **Hardcoded Secrets**
   - Example/test/docker-compose defaults → HARDENING
   - Real active secrets with access → VALID

**Code:** `backend/services/strict_classifier.py:650-720`

### Category-Specific Checklists

**Directory:** `backend/agents/validity_checklists/`

Each vulnerability type has a markdown checklist that agents use for validation:

**Files:**
- `sql_injection.md` - Parameterization, ORM behavior, dataflow
- `xss.md` - Context, escaping, content-type
- `rce.md` - Shell injection, code execution, dataflow
- `ssrf.md` - URL control, allowlists, internal network access
- `path_traversal.md` - Path normalization, chroot, symlinks
- `auth_bypass.md` - Auth gates, session management, RBAC
- `idor.md` - Authorization checks, object ownership
- `xxe.md` - XML parsing, external entities, DTD
- `deserialization.md` - Pickle/YAML/JSON, type checking
- `crypto.md` - Algorithm strength, key management, IV
- `dos.md` - Resource limits, rate limiting, recursion
- `csrf.md` - Token validation, SameSite cookies, origin checks

**Example:** `backend/agents/validity_checklists/sql_injection.md`

```markdown
# SQL Injection Validity Checklist

## Required Conditions

### 1. Attacker Data Reaches SQL Sink
- [ ] Attacker-controlled data flows into a SQL query construction point
- [ ] The data is interpreted as SQL syntax (not just data values)
- [ ] Examples: String concatenation, string interpolation, or dynamic query building

### 2. No Effective Parameterization
- [ ] Query is not using parameterized statements (prepared statements, query builders)
- [ ] OR parameterization is incomplete (e.g., table/column names are concatenated)
- [ ] Attacker can inject SQL syntax metacharacters (quotes, semicolons, comments, etc.)

### 3. Reachability
- [ ] Code path is reachable (routing/auth/config analysis confirms)
- [ ] Not dead code, disabled feature, or admin-only with strong auth

## Common False Positive Traps

DISPROVE the vulnerability if any of these apply:

- **Parameterized Queries**: Properly used prepared statements or parameterized queries prevent SQL injection.
  - Example: `cursor.execute("SELECT * FROM users WHERE id = ?", [user_id])` is safe

- **ORM with Safe Query Builders**: ORMs like Django ORM, SQLAlchemy, ActiveRecord properly parameterize when used correctly.
  - Example: `User.objects.filter(username=user_input)` is safe in Django

...
```

Agents reference these checklists during validation to ensure systematic evaluation.

---

This completes Part 1 of the architecture reference. The document covers:
- System overview and technology stack
- Core architecture and request flow
- Backend framework structure with 13 routers, 31 services
- Agent system (3 types: QuickAudit, ReAct, DeepAudit)
- Tool system (13 tools with sandboxing)
- Triage system (evidence gathering, strict classification, disposition rules)

---

## Database Layer

### Database Architecture

**Files:**
- `backend/database/connection.py` - Async engine and session factory
- `backend/database/models.py` - SQLAlchemy ORM models
- `backend/database/schema_checker.py` - Schema validation

**Supported Databases:**
- **PostgreSQL** (production) - Async via asyncpg driver
- **SQLite** (development) - Async via aiosqlite driver

**Connection Setup:**

```python
# backend/database/connection.py

from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

# Connection string from config
# PostgreSQL: postgresql+asyncpg://user:pass@host:5432/dbname
# SQLite: sqlite+aiosqlite:///./data/quickhack.db

engine = create_async_engine(
    settings.database_url,
    echo=settings.debug,  # SQL logging
    pool_size=20,         # Connection pool
    max_overflow=10,      # Max extra connections
)

async_session_maker = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,  # Keep objects usable after commit
)

async def init_db():
    """Create all tables if they don't exist."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
```

### Data Models

**File:** `backend/database/models.py`

#### 1. User Model

```python
class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    email: Mapped[str] = mapped_column(String, unique=True, index=True)
    username: Mapped[str] = mapped_column(String, unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    # Relationships
    api_keys: Mapped[List["UserAPIKey"]] = relationship(back_populates="user")
    projects: Mapped[List["Project"]] = relationship(back_populates="owner")
    sessions: Mapped[List["ChatSession"]] = relationship(back_populates="user")
```

**Indexes:**
- `email` - Unique, for login lookup
- `username` - Unique, for display and lookup

**Password Hashing:**
```python
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)
```

#### 2. UserAPIKey Model

```python
class UserAPIKey(Base):
    __tablename__ = "user_api_keys"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    user_id: Mapped[str] = mapped_column(String, ForeignKey("users.id"))
    provider: Mapped[str] = mapped_column(String)  # "anthropic", "openai", etc.
    encrypted_key: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Relationships
    user: Mapped["User"] = relationship(back_populates="api_keys")
```

**Encryption:**
```python
from cryptography.fernet import Fernet

# Key derived from settings.secret_key
cipher = Fernet(settings.encryption_key)

def encrypt_api_key(plain_key: str) -> str:
    return cipher.encrypt(plain_key.encode()).decode()

def decrypt_api_key(encrypted_key: str) -> str:
    return cipher.decrypt(encrypted_key.encode()).decode()
```

#### 3. Project Model

```python
class Project(Base):
    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, index=True)
    repo_path: Mapped[str] = mapped_column(String)  # Path in repos_dir
    repo_url: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    owner_id: Mapped[str] = mapped_column(String, ForeignKey("users.id"))

    # Relationships
    owner: Mapped["User"] = relationship(back_populates="projects")
    sessions: Mapped[List["ChatSession"]] = relationship(back_populates="project")
    findings: Mapped[List["Finding"]] = relationship(back_populates="project")
```

#### 4. ChatSession Model

```python
class ChatSession(Base):
    __tablename__ = "chat_sessions"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    user_id: Mapped[str] = mapped_column(String, ForeignKey("users.id"))
    project_id: Mapped[str] = mapped_column(String, ForeignKey("projects.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user: Mapped["User"] = relationship(back_populates="sessions")
    project: Mapped["Project"] = relationship(back_populates="sessions")
    messages: Mapped[List["ChatMessage"]] = relationship(back_populates="session")
```

#### 5. ChatMessage Model

```python
class ChatMessage(Base):
    __tablename__ = "chat_messages"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    session_id: Mapped[str] = mapped_column(String, ForeignKey("chat_sessions.id"))
    role: Mapped[str] = mapped_column(String)  # "user", "assistant", "system"
    content: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Relationships
    session: Mapped["ChatSession"] = relationship(back_populates="messages")
```

#### 6. Finding Model

```python
class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    project_id: Mapped[str] = mapped_column(String, ForeignKey("projects.id"))
    agent_execution_id: Mapped[str] = mapped_column(String)
    category: Mapped[str] = mapped_column(String, index=True)  # VulnerabilityCategory
    severity: Mapped[str] = mapped_column(String)  # Severity enum
    disposition: Mapped[str] = mapped_column(String, index=True)  # Disposition enum
    title: Mapped[str] = mapped_column(String)
    description: Mapped[str] = mapped_column(Text)
    file_path: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    line_number: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    endpoint_path: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # JSON fields (stored as text, parsed by Pydantic)
    checklist_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    reasoning_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    project: Mapped["Project"] = relationship(back_populates="findings")
```

**Indexes:**
- `category` - For filtering by vulnerability type
- `disposition` - For filtering REPORTABLE vs FILTERED

### Schema Validation

**File:** `backend/database/schema_checker.py`

**Purpose:** Check if database schema supports triage system fields.

```python
async def initialize_triage_availability(engine: AsyncEngine) -> None:
    """
    Check if 'findings' table has triage-related columns.
    Sets global flag for conditional triage features.
    """
    global triage_system_available

    async with engine.connect() as conn:
        # Check if findings table exists
        result = await conn.execute(text(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='findings'"
        ))
        if not result.fetchone():
            triage_system_available = False
            return

        # Check for triage columns
        result = await conn.execute(text("PRAGMA table_info(findings)"))
        columns = {row[1] for row in result.fetchall()}

        required_columns = {"disposition", "checklist_json", "reasoning_json"}
        triage_system_available = required_columns.issubset(columns)
```

This allows graceful degradation if running against an older database schema.

---

## Authentication & Authorization

### JWT-Based Authentication

**File:** `backend/middleware/auth.py`

**Token Types:**
- **Access Token** - Short-lived (24 hours), used for API requests
- **Refresh Token** - Long-lived (30 days), used to obtain new access tokens

**Token Structure:**

```python
# Access Token Payload
{
    "sub": "user_id",           # Subject (user identifier)
    "email": "user@example.com",
    "username": "alice",
    "type": "access",
    "exp": 1704153600,          # Expiration timestamp
    "iat": 1704067200,          # Issued at timestamp
}

# Refresh Token Payload
{
    "sub": "user_id",
    "type": "refresh",
    "exp": 1706659200,
    "iat": 1704067200,
}
```

**Token Generation:**

```python
from jose import jwt
from datetime import datetime, timedelta

def create_access_token(user: User) -> str:
    payload = {
        "sub": user.id,
        "email": user.email,
        "username": user.username,
        "type": "access",
        "exp": datetime.utcnow() + timedelta(hours=24),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, settings.secret_key, algorithm="HS256")

def create_refresh_token(user: User) -> str:
    payload = {
        "sub": user.id,
        "type": "refresh",
        "exp": datetime.utcnow() + timedelta(days=30),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, settings.secret_key, algorithm="HS256")
```

**Token Validation:**

```python
async def require_auth(authorization: str = Header(None)) -> str:
    """
    FastAPI dependency that validates JWT and returns user_id.

    Raises:
        HTTPException(401): If token is missing, invalid, or expired
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid authorization header"
        )

    token = authorization[7:]  # Strip "Bearer "

    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=["HS256"]
        )

        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")

        return payload["sub"]  # Return user_id

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
```

### Authentication Endpoints

**File:** `backend/routers/auth.py`

#### 1. Signup

```python
@router.post("/auth/signup")
async def signup(
    email: str,
    username: str,
    password: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Create new user account.

    Validations:
    - Email format
    - Email uniqueness
    - Username uniqueness
    - Password strength (min 8 chars)
    """

    # Check if email exists
    result = await db.execute(select(User).where(User.email == email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")

    # Check if username exists
    result = await db.execute(select(User).where(User.username == username))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Username already taken")

    # Create user
    user = User(
        id=str(uuid.uuid4()),
        email=email,
        username=username,
        hashed_password=hash_password(password),
    )
    db.add(user)
    await db.commit()

    # Generate tokens
    access_token = create_access_token(user)
    refresh_token = create_refresh_token(user)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": {
            "id": user.id,
            "email": user.email,
            "username": user.username,
        },
    }
```

#### 2. Login

```python
@router.post("/auth/login")
async def login(
    email: str,
    password: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Authenticate user and return tokens.

    Credentials:
    - Email + password
    """

    # Find user
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user.is_active:
        raise HTTPException(status_code=401, detail="Account disabled")

    # Generate tokens
    access_token = create_access_token(user)
    refresh_token = create_refresh_token(user)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": {
            "id": user.id,
            "email": user.email,
            "username": user.username,
        },
    }
```

#### 3. Token Refresh

```python
@router.post("/auth/refresh")
async def refresh(
    refresh_token: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Exchange refresh token for new access token.

    This allows maintaining sessions without storing access tokens.
    """

    try:
        payload = jwt.decode(
            refresh_token,
            settings.secret_key,
            algorithms=["HS256"]
        )

        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")

        user_id = payload["sub"]

        # Verify user still exists and is active
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()

        if not user or not user.is_active:
            raise HTTPException(status_code=401, detail="User not found or disabled")

        # Generate new access token
        access_token = create_access_token(user)

        return {"access_token": access_token}

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
```

### Authorization Patterns

**Resource Ownership:**

```python
@router.get("/api/projects/{project_id}")
async def get_project(
    project_id: str,
    user_id: str = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
):
    """Only project owner can access."""

    result = await db.execute(
        select(Project).where(
            Project.id == project_id,
            Project.owner_id == user_id,  # Ownership check
        )
    )
    project = result.scalar_one_or_none()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    return project
```

**No RBAC:** Current system uses simple ownership model (user owns projects/sessions). No role-based access control yet.

---

## Real-time Communication

### WebSocket Architecture

**File:** `backend/routers/websocket.py`

**Purpose:** Bi-directional real-time communication between frontend and backend for agent progress updates.

**Connection Flow:**

```
Client connects to ws://host/ws
    ↓
Server accepts connection
    ↓
Client sends authentication message:
    {"type": "auth", "token": "Bearer eyJ..."}
    ↓
Server validates JWT token
    ↓
┌──────────────────────────────┐
│ If valid:                    │
│   Store connection in        │
│   _active_connections[user_id]│
└──────────────────────────────┘
    ↓
┌──────────────────────────────┐
│ If invalid:                  │
│   Close connection with 4001 │
└──────────────────────────────┘
    ↓
Server → Client: {"type": "auth_success"}
    ↓
[Bidirectional messaging]
    ↓
Agent executes, sends progress updates
    ↓
Server broadcasts to client
    ↓
Client renders updates in UI
```

**WebSocket Handler:**

```python
from fastapi import WebSocket, WebSocketDisconnect

# Store active connections
_active_connections: Dict[str, WebSocket] = {}
_main_loop: Optional[asyncio.AbstractEventLoop] = None

def set_main_loop(loop: asyncio.AbstractEventLoop):
    """Called during app startup to enable broadcasts from agents."""
    global _main_loop
    _main_loop = loop

@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket connection handler.

    Authentication:
    1. Client connects
    2. Client sends: {"type": "auth", "token": "Bearer ..."}
    3. Server validates JWT
    4. Connection stored for user_id
    """

    await websocket.accept()

    try:
        # Wait for auth message (timeout 10s)
        auth_msg = await asyncio.wait_for(
            websocket.receive_json(),
            timeout=10.0
        )

        if auth_msg.get("type") != "auth":
            await websocket.close(code=4000, reason="Expected auth message")
            return

        # Validate token
        token = auth_msg.get("token", "")
        if not token.startswith("Bearer "):
            await websocket.close(code=4001, reason="Invalid token format")
            return

        payload = jwt.decode(
            token[7:],
            settings.secret_key,
            algorithms=["HS256"]
        )
        user_id = payload["sub"]

        # Store connection
        _active_connections[user_id] = websocket

        # Send success
        await websocket.send_json({"type": "auth_success"})

        # Keep connection alive
        while True:
            # Receive messages from client (heartbeat, etc.)
            message = await websocket.receive_json()
            # Handle client messages if needed

    except asyncio.TimeoutError:
        await websocket.close(code=4002, reason="Auth timeout")
    except WebSocketDisconnect:
        # Client disconnected
        if user_id in _active_connections:
            del _active_connections[user_id]
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        await websocket.close(code=1011, reason="Internal error")
```

**Broadcasting from Agents:**

Agents run in background tasks (not in WebSocket handler). To send messages to WebSocket clients, agents use `_broadcast_to_user()`:

```python
async def _broadcast_to_user(user_id: str, message: dict):
    """
    Send message to user's WebSocket connection from agent context.

    Challenge: Agent runs in background task, WebSocket runs in main loop.
    Solution: Use asyncio.run_coroutine_threadsafe to schedule on main loop.
    """

    if user_id not in _active_connections:
        return  # User disconnected

    websocket = _active_connections[user_id]

    # Schedule send on main event loop
    future = asyncio.run_coroutine_threadsafe(
        websocket.send_json(message),
        _main_loop,  # Main loop stored during startup
    )

    try:
        future.result(timeout=5.0)  # Wait for send to complete
    except Exception as e:
        logger.error(f"Failed to send WebSocket message: {e}")
        # Remove stale connection
        del _active_connections[user_id]
```

**Agent Integration:**

```python
# In AgentOrchestrator.execute_agent()

async def _send_progress(step: str, data: dict):
    """Send progress update during agent execution."""
    await _broadcast_to_user(user_id, {
        "type": "agent_progress",
        "agent_id": agent_id,
        "step": step,
        "data": data,
    })

# During execution
await _send_progress("tool_call", {"tool": "ripgrep", "args": {...}})
await _send_progress("tool_result", {"output": "..."})
await _send_progress("finding_discovered", {"finding": {...}})
await _send_progress("agent_complete", {"findings_count": 5})
```

### Message Types

**Client → Server:**

1. **Auth:**
```json
{"type": "auth", "token": "Bearer eyJ..."}
```

2. **Heartbeat:**
```json
{"type": "ping"}
```

**Server → Client:**

1. **Auth Success:**
```json
{"type": "auth_success"}
```

2. **Agent Progress:**
```json
{
  "type": "agent_progress",
  "agent_id": "abc123",
  "step": "tool_call",
  "data": {
    "tool": "ripgrep",
    "args": {"pattern": "exec\\(", "file_pattern": "**/*.py"}
  }
}
```

3. **Tool Result:**
```json
{
  "type": "agent_progress",
  "agent_id": "abc123",
  "step": "tool_result",
  "data": {
    "tool": "ripgrep",
    "output": "backend/services/executor.py:42: exec(code)",
    "success": true
  }
}
```

4. **Finding Discovered:**
```json
{
  "type": "agent_progress",
  "agent_id": "abc123",
  "step": "finding_discovered",
  "data": {
    "finding": {
      "id": "finding123",
      "category": "CODE_INJECTION",
      "severity": "CRITICAL",
      "title": "Arbitrary Code Execution",
      "file_path": "backend/services/executor.py",
      "line_number": 42
    }
  }
}
```

5. **Agent Complete:**
```json
{
  "type": "agent_progress",
  "agent_id": "abc123",
  "step": "agent_complete",
  "data": {
    "findings_count": 5,
    "reportable_count": 2,
    "filtered_count": 3
  }
}
```

### Frontend Integration

**File:** `frontend/hooks/useWebSocket.ts`

```typescript
export function useWebSocket(token: string | null) {
  const [socket, setSocket] = useState<WebSocket | null>(null);
  const [messages, setMessages] = useState<WSMessage[]>([]);

  useEffect(() => {
    if (!token) return;

    // Connect to WebSocket
    const ws = new WebSocket(`ws://localhost:8000/ws`);

    ws.onopen = () => {
      // Send auth message
      ws.send(JSON.stringify({
        type: "auth",
        token: `Bearer ${token}`,
      }));
    };

    ws.onmessage = (event) => {
      const message = JSON.parse(event.data);
      setMessages(prev => [...prev, message]);

      // Handle different message types
      if (message.type === "agent_progress") {
        // Update agent progress UI
        updateAgentProgress(message.agent_id, message.step, message.data);
      }
    };

    ws.onerror = (error) => {
      console.error("WebSocket error:", error);
    };

    ws.onclose = () => {
      console.log("WebSocket closed");
      // Attempt reconnect after 5s
      setTimeout(() => {
        // ... reconnect logic ...
      }, 5000);
    };

    setSocket(ws);

    return () => {
      ws.close();
    };
  }, [token]);

  return { socket, messages };
}
```

---

## Provider System

The provider system abstracts LLM API integrations, allowing quick_hack to support multiple AI providers with a unified interface.

### Provider Architecture

**Abstract Base:** `backend/providers/base_provider.py`

```python
class BaseProvider(ABC):
    """Base class for all LLM providers."""

    @abstractmethod
    async def create_completion(
        self,
        messages: List[Message],
        model: str,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        tools: Optional[List[Tool]] = None,
        stream: bool = False,
    ) -> CompletionResponse:
        """
        Generate completion from messages.

        Args:
            messages: Conversation history
            model: Model identifier
            temperature: Sampling temperature (0-1)
            max_tokens: Max tokens to generate
            tools: Available tools for function calling
            stream: Enable streaming responses

        Returns:
            CompletionResponse with content and metadata
        """
        pass

    @abstractmethod
    async def create_streaming_completion(
        self,
        messages: List[Message],
        model: str,
        **kwargs,
    ) -> AsyncIterator[CompletionChunk]:
        """Stream completion chunks."""
        pass

    @abstractmethod
    def supports_tools(self) -> bool:
        """Whether provider supports function/tool calling."""
        pass

    @abstractmethod
    def get_available_models(self) -> List[str]:
        """List of model identifiers supported by provider."""
        pass
```

### Supported Providers

#### 1. Anthropic (Claude)

**File:** `backend/providers/anthropic_provider.py`

**Models:**
- `claude-opus-4-5` - Most capable, highest cost
- `claude-sonnet-4-5` - Balanced intelligence and speed (default)
- `claude-haiku-3-5` - Fast, low cost

**Features:**
- Tool calling (function calling)
- Streaming responses
- Vision (image input support)
- 200K context window

**Implementation:**

```python
from anthropic import AsyncAnthropic

class AnthropicProvider(BaseProvider):
    def __init__(self, api_key: str):
        self.client = AsyncAnthropic(api_key=api_key)

    async def create_completion(
        self,
        messages: List[Message],
        model: str,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        tools: Optional[List[Tool]] = None,
        stream: bool = False,
    ) -> CompletionResponse:

        # Convert tools to Anthropic format
        anthropic_tools = [self._convert_tool(t) for t in tools] if tools else None

        # Create completion
        response = await self.client.messages.create(
            model=model,
            messages=[self._convert_message(m) for m in messages],
            temperature=temperature,
            max_tokens=max_tokens or 4096,
            tools=anthropic_tools,
        )

        # Parse tool calls if present
        tool_calls = []
        if response.stop_reason == "tool_use":
            for block in response.content:
                if block.type == "tool_use":
                    tool_calls.append(ToolCall(
                        id=block.id,
                        name=block.name,
                        arguments=block.input,
                    ))

        return CompletionResponse(
            content=self._extract_text(response.content),
            tool_calls=tool_calls,
            stop_reason=response.stop_reason,
            usage=Usage(
                input_tokens=response.usage.input_tokens,
                output_tokens=response.usage.output_tokens,
            ),
        )

    def supports_tools(self) -> bool:
        return True

    def get_available_models(self) -> List[str]:
        return [
            "claude-opus-4-5",
            "claude-sonnet-4-5",
            "claude-haiku-3-5",
        ]
```

#### 2. OpenAI (GPT)

**File:** `backend/providers/openai_provider.py`

**Models:**
- `gpt-4-turbo` - Most capable GPT-4 variant
- `gpt-4` - Standard GPT-4
- `gpt-3.5-turbo` - Fast, low cost

**Features:**
- Function calling
- Streaming responses
- Vision (gpt-4-vision)
- 128K context window (turbo)

**Implementation:**

```python
from openai import AsyncOpenAI

class OpenAIProvider(BaseProvider):
    def __init__(self, api_key: str):
        self.client = AsyncOpenAI(api_key=api_key)

    async def create_completion(
        self,
        messages: List[Message],
        model: str,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        tools: Optional[List[Tool]] = None,
        stream: bool = False,
    ) -> CompletionResponse:

        # Convert tools to OpenAI format
        openai_tools = [self._convert_tool(t) for t in tools] if tools else None

        # Create completion
        response = await self.client.chat.completions.create(
            model=model,
            messages=[self._convert_message(m) for m in messages],
            temperature=temperature,
            max_tokens=max_tokens,
            tools=openai_tools,
        )

        message = response.choices[0].message

        # Parse tool calls
        tool_calls = []
        if message.tool_calls:
            for tc in message.tool_calls:
                tool_calls.append(ToolCall(
                    id=tc.id,
                    name=tc.function.name,
                    arguments=json.loads(tc.function.arguments),
                ))

        return CompletionResponse(
            content=message.content or "",
            tool_calls=tool_calls,
            stop_reason=response.choices[0].finish_reason,
            usage=Usage(
                input_tokens=response.usage.prompt_tokens,
                output_tokens=response.usage.completion_tokens,
            ),
        )

    def supports_tools(self) -> bool:
        return True

    def get_available_models(self) -> List[str]:
        return ["gpt-4-turbo", "gpt-4", "gpt-3.5-turbo"]
```

#### 3. Ollama (Local)

**File:** `backend/providers/ollama_provider.py`

**Models:**
- User-configurable (whatever is installed locally)
- Common: `llama2`, `codellama`, `mistral`

**Features:**
- Local inference (no API key needed)
- Privacy (no data sent to external servers)
- Cost-free
- Limited tool calling support (varies by model)

**Implementation:**

```python
import aiohttp

class OllamaProvider(BaseProvider):
    def __init__(self, base_url: str = "http://localhost:11434"):
        self.base_url = base_url

    async def create_completion(
        self,
        messages: List[Message],
        model: str,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        tools: Optional[List[Tool]] = None,
        stream: bool = False,
    ) -> CompletionResponse:

        # Ollama uses simpler message format
        prompt = self._messages_to_prompt(messages)

        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": model,
                    "prompt": prompt,
                    "temperature": temperature,
                    "options": {
                        "num_predict": max_tokens or -1,
                    },
                },
            ) as resp:
                data = await resp.json()

                return CompletionResponse(
                    content=data["response"],
                    tool_calls=[],  # Limited tool support
                    stop_reason="stop",
                    usage=Usage(
                        input_tokens=data.get("prompt_eval_count", 0),
                        output_tokens=data.get("eval_count", 0),
                    ),
                )

    def supports_tools(self) -> bool:
        return False  # Most Ollama models don't support tools

    def get_available_models(self) -> List[str]:
        # Would query Ollama API for installed models
        return ["llama2", "codellama", "mistral"]
```

#### 4. Claude SDK

**File:** `backend/providers/claude_sdk_provider.py`

**Purpose:** Use Anthropic's Claude SDK with MCP (Model Context Protocol) for more powerful agentic workflows.

**Differences from Anthropic Provider:**
- Native MCP tool integration
- Time-governed execution
- Better streaming support
- Enhanced observability

**Implementation:**

```python
from anthropic import Anthropic

class ClaudeSDKProvider(BaseProvider):
    def __init__(self, api_key: str):
        self.client = Anthropic(api_key=api_key)

    async def create_completion(
        self,
        messages: List[Message],
        model: str,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        tools: Optional[List[MCPTool]] = None,  # MCP tools, not generic
        stream: bool = False,
    ) -> CompletionResponse:

        # MCP tools are passed directly
        response = await self.client.messages.create(
            model=model,
            messages=[self._convert_message(m) for m in messages],
            temperature=temperature,
            max_tokens=max_tokens or 4096,
            tools=tools,  # Already in MCP format
        )

        # Rest similar to AnthropicProvider
        ...

    def supports_tools(self) -> bool:
        return True

    def get_available_models(self) -> List[str]:
        return ["claude-opus-4-5", "claude-sonnet-4-5"]
```

### Provider Selection Logic

**File:** `backend/services/agent_service.py`

```python
def _get_provider(agent_type: AgentType, user_settings: UserSettings) -> BaseProvider:
    """
    Select provider based on agent type and user preferences.

    Default mapping:
    - QuickAudit → Claude Sonnet (fast, accurate)
    - ReAct → Claude Sonnet or Opus (depending on setting)
    - DeepAudit → Claude Opus (most capable)

    Falls back to user's default provider if model not available.
    """

    if agent_type == AgentType.QUICK_AUDIT:
        preferred = "anthropic/claude-sonnet-4-5"
    elif agent_type == AgentType.REACT:
        preferred = user_settings.get("react_model", "anthropic/claude-sonnet-4-5")
    elif agent_type == AgentType.DEEP_AUDIT:
        preferred = "anthropic/claude-opus-4-5"
    else:
        preferred = user_settings.default_model

    # Parse provider/model
    provider_name, model_name = preferred.split("/")

    # Get API key
    api_key = user_settings.providers[provider_name].api_key

    # Instantiate provider
    if provider_name == "anthropic":
        return AnthropicProvider(api_key)
    elif provider_name == "openai":
        return OpenAIProvider(api_key)
    elif provider_name == "ollama":
        return OllamaProvider()
    elif provider_name == "claude_sdk":
        return ClaudeSDKProvider(api_key)
    else:
        raise ValueError(f"Unknown provider: {provider_name}")
```

---

This completes Part 2 of the architecture reference, covering:
- Database layer with 6 core models (User, UserAPIKey, Project, ChatSession, ChatMessage, Finding)
- Authentication & Authorization (JWT-based, token types, endpoints)
- Real-time Communication (WebSocket architecture, broadcasting, message types)
- Provider System (4 providers: Anthropic, OpenAI, Ollama, Claude SDK)

Continuing with Part 3...

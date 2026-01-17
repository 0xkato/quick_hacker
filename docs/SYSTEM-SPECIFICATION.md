# QuickHack System Specification
**Version:** 2.0.0
**Last Updated:** 2026-01-17
**Status:** Current (integrate-phase3-phase4 branch)

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [System Architecture](#system-architecture)
3. [Provider System](#provider-system)
4. [Specialized Prompting System](#specialized-prompting-system)
5. [Threat Modeling System](#threat-modeling-system)
6. [Triage & Classification](#triage--classification)
7. [Security Issue vs Bug Classification](#security-issue-vs-bug-classification)
8. [Protocol-Aware Reportability Layer](#protocol-aware-reportability-layer)
9. [Data Models](#data-models)
10. [API Reference](#api-reference)
11. [Testing Strategy](#testing-strategy)
12. [Deployment](#deployment)

---

## Executive Summary

QuickHack is an AI-powered security vulnerability scanner that uses large language models to analyze codebases for security issues. The system distinguishes between security vulnerabilities, functional bugs, and hardening opportunities through evidence-based classification with per-project threat modeling.

### Key Features

- **Dual Provider System:** Claude SDK (native) + Codex CLI (external process)
- **MCP Integration:** Model Context Protocol for tool standardization
- **Specialized Prompting:** Category-specific validity checklists for 9 vulnerability types
- **Threat Modeling:** Per-project threat profiles with capability-based gating
- **Evidence-Based Classification:** Tri-state proof checklist with 2-signal minimum
- **Input Channel Inference:** Conservative, deterministic channel detection
- **Real-Time UI:** React frontend with WebSocket updates
- **Flow Visualization:** Interactive call graph and tool execution trees

### Technology Stack

**Backend:**
- Python 3.11+
- FastAPI (async web framework)
- SQLite (database)
- Pydantic (data validation)
- Anthropic SDK (Claude models)

**Frontend:**
- Next.js 14 (React framework)
- TypeScript
- TailwindCSS
- Recharts (visualization)

**Infrastructure:**
- Docker + Docker Compose
- Nginx (reverse proxy)
- WebSocket (real-time updates)

---

## System Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Frontend (Next.js)                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │ Projects │  │ Agents   │  │ Findings │  │ Settings │       │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘       │
└────────────────────────────┬────────────────────────────────────┘
                             │ HTTP/WebSocket
                             ↓
┌─────────────────────────────────────────────────────────────────┐
│                      Backend (FastAPI)                          │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                  Agent Orchestrator                       │  │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐         │  │
│  │  │  Provider  │  │  Triage    │  │  Tool      │         │  │
│  │  │  Manager   │  │  Service   │  │  Core      │         │  │
│  │  └────────────┘  └────────────┘  └────────────┘         │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│  │   Claude    │  │   Codex     │  │    MCP      │            │
│  │   SDK       │  │   CLI       │  │   Server    │            │
│  └─────────────┘  └─────────────┘  └─────────────┘            │
└──────────────────────────┬───────────────────────────────────────┘
                           │
                           ↓
                    ┌──────────────┐
                    │   SQLite     │
                    │   Database   │
                    └──────────────┘
```

### Request Flow

1. **User Action:** User creates analysis session via frontend
2. **API Call:** Frontend sends POST to `/sessions/{session_id}/run`
3. **Orchestrator:** Agent Orchestrator selects provider (Claude SDK or Codex CLI)
4. **Analysis:** Provider executes agent loop with MCP tools
5. **Tool Calls:** Agent calls tools (read_file, search_symbol, track_* flow tools)
6. **Findings:** Provider emits findings via event stream
7. **Triage:** Findings passed through FindingTriageService
8. **Classification:** StrictClassifier applies rules with threat model gating
9. **Storage:** Findings stored in SQLite with evidence JSON
10. **WebSocket:** UI receives real-time updates
11. **Display:** Frontend renders findings with proof checklists

### Directory Structure

```
quick_hack/
├── backend/
│   ├── agents/                    # Agent implementations
│   │   ├── base_agent.py
│   │   ├── react_agent.py
│   │   └── tools/
│   │       └── context.py         # ToolExecutionContext
│   ├── models/                    # Data models
│   │   ├── schemas.py             # Pydantic schemas
│   │   └── threat_model_profile.py
│   ├── providers/                 # LLM provider implementations
│   │   ├── anthropic_provider.py
│   │   ├── claude_sdk_provider.py # Native SDK provider
│   │   ├── codex_cli_provider.py  # External process provider
│   │   ├── openai_provider.py
│   │   └── ollama_provider.py
│   ├── quickhack_mcp/             # MCP server (renamed from mcp/)
│   │   └── quickhack_mcp_server.py
│   ├── routers/                   # FastAPI routers
│   │   ├── projects.py            # Project & threat model APIs
│   │   └── sessions.py            # Session APIs
│   ├── services/                  # Business logic
│   │   ├── agent_orchestrator.py  # Main orchestration
│   │   ├── finding_triage_service.py
│   │   ├── strict_classifier.py
│   │   ├── evidence_gatherer.py
│   │   ├── input_channel_inference.py  # Phase 3
│   │   ├── threat_model_gating.py      # Phase 3
│   │   ├── threat_model_prompt_block.py
│   │   ├── file_origin.py              # Phase 4
│   │   ├── tool_budget_manager.py      # Phase 4
│   │   └── tool_core.py
│   ├── tests/                     # Test suite
│   └── main.py                    # FastAPI app entry point
├── frontend/
│   ├── app/                       # Next.js app router
│   ├── components/                # React components
│   │   ├── ThreatModel/
│   │   │   └── ThreatModelModal.tsx
│   │   ├── FindingsPanel/
│   │   ├── AgentPanel/
│   │   └── FlowVisualization/
│   ├── lib/                       # Utilities
│   └── types/                     # TypeScript types
├── prompting/                     # System prompts
│   ├── base/
│   │   └── base_prompt.md
│   └── agents/
│       ├── profile_strict_mode.md
│       ├── profile_deep_audit_mode.md
│       └── profile_ultra_strict_mode.md
├── docs/
│   └── SYSTEM-SPECIFICATION.md    # This file
└── docker-compose.yml
```

---

## Provider System

### Overview

QuickHack supports two execution modes via a dual provider architecture:

1. **Claude SDK Provider:** Native Python SDK with agentic loop
2. **Codex CLI Provider:** External process via Model Context Protocol (MCP)

### Provider Selection

```python
# In agent_orchestrator.py
def _create_provider(self, session: Session) -> BaseProvider:
    """Select provider based on feature flags."""
    if feature_flags.codex_cli_enabled(session.project_id):
        return CodexCLIProvider(
            repo_path=self.repo_root,
            project_id=session.project_id,
            agent_id=session.agent_id
        )
    else:
        return ClaudeSDKProvider(
            api_key=settings.ANTHROPIC_API_KEY,
            model="claude-sonnet-4-5-20250929"
        )
```

### Claude SDK Provider

**File:** `backend/providers/claude_sdk_provider.py`

**Features:**
- Native agentic loop using Anthropic Python SDK
- Direct tool call handling
- State management in Python
- Lower latency for tool calls

**Architecture:**
```python
class ClaudeSDKProvider(BaseProvider):
    def run_agent(self, prompt: str, tools: list[dict]) -> AsyncIterator[dict]:
        messages = [{"role": "user", "content": prompt}]

        while not done:
            response = anthropic.messages.create(
                model=self.model,
                messages=messages,
                tools=tools,
                max_tokens=4096
            )

            # Handle stop_reason
            if response.stop_reason == "tool_use":
                # Execute tools
                for block in response.content:
                    if block.type == "tool_use":
                        result = await self._execute_tool(block)
                        messages.append(tool_result_message)

            elif response.stop_reason == "end_turn":
                break

            # Emit events
            yield {"type": "finding", "data": {...}}
```

**SDK Availability Check:**
```python
try:
    import anthropic
    SDK_AVAILABLE = True
except ImportError:
    SDK_AVAILABLE = False
    # Falls back to other providers
```

### Codex CLI Provider

**File:** `backend/providers/codex_cli_provider.py`

**Features:**
- External process execution via `codex` CLI binary
- MCP-based tool integration
- Process isolation and sandboxing
- Automatic config generation

**Architecture:**
```python
class CodexCLIProvider(BaseProvider):
    def __init__(self, repo_path: str, project_id: str, agent_id: str):
        self.repo_path = repo_path
        self.project_id = project_id
        self.agent_id = agent_id
        self._write_config_toml()  # Generate ~/.config/codex/config.toml

    def run_agent(self, prompt: str, tools: list[dict]) -> AsyncIterator[dict]:
        # Write prompt to temp file
        prompt_file = self._write_prompt_file(prompt)

        # Start codex process
        proc = subprocess.Popen(
            ["codex", "run", "--file", str(prompt_file)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self._build_env()
        )

        # Parse output for findings
        for line in iter(proc.stdout.readline, b''):
            event = self._parse_codex_output(line)
            if event:
                yield event
```

**Config Generation:**
```toml
[features]
auth = true

[mcp.servers.quickhack]
command = "python"
args = ["/path/to/quickhack_mcp_server.py"]
env.QUICKHACK_REPO_PATH = "/repo/path"
env.QUICKHACK_PROJECT_ID = "proj_123"
env.QUICKHACK_AGENT_ID = "agent_456"
env.QUICKHACK_LIMITS_PATH = "/tmp/limits.json"
env.QUICKHACK_CANCEL_PATH = "/tmp/cancel.flag"
```

### MCP Server

**File:** `backend/quickhack_mcp/quickhack_mcp_server.py`

**Purpose:** Exposes QuickHack tools via Model Context Protocol for Codex CLI

**Protocol:** JSON-RPC 2.0 over stdin/stdout

**Exposed Tools:**
- `read_file` - Read file with security boundaries
- `list_directory` - List directory contents
- `search_symbol` - AST-based symbol search
- `find_references` - Symbol reference search
- `get_call_graph` - Function call graph extraction
- `track_file_analysis` - Flow tracking (Phase 2)
- `track_function_discovered` - Flow tracking
- `track_call_chain` - Flow tracking
- `track_sink_identified` - Flow tracking
- `track_entry_point` - Flow tracking

**Security Boundaries:**
```python
def _validate_path(self, path: str) -> Path:
    """Validate path is within repo and not excluded."""
    resolved = (self.repo_root / path).resolve()

    # Check repo boundary
    if not str(resolved).startswith(str(self.repo_root)):
        raise ValueError("Path outside repo")

    # Check excluded directories
    excluded = {"node_modules", ".git", ".venv", "__pycache__"}
    for part in resolved.parts:
        if part in excluded:
            raise ValueError(f"Path in excluded directory: {part}")

    # Check symlink escape
    if resolved.is_symlink():
        target = resolved.readlink()
        if not str(target).startswith(str(self.repo_root)):
            raise ValueError("Symlink escape attempt")

    return resolved
```

**Test Coverage:**
- `test_mcp_tools_list_includes_read_file` ✓
- `test_mcp_read_file_rejects_symlink_escape` ✓
- `test_mcp_read_file_rejects_excluded_directory` ✓
- `test_mcp_read_file_rejects_path_traversal` ✓
- `test_mcp_server_starts_as_script_and_lists_tools` ✓

---

## Specialized Prompting System

### Overview

QuickHack uses a modular prompting system that dynamically composes specialized prompts based on vulnerability category, analysis stage, and detected framework. This ensures agents receive category-specific guidance for finding and validating vulnerabilities.

### Architecture

```
BASE_PROMPT + VALIDITY_CHECKLIST + STAGE_MODULE + CONTEXT_MODULE + TASK
     ↓               ↓                    ↓               ↓            ↓
  Always          Category            DeepAudit       Framework    User task
  included        specific            stage           specific
                  (SQL, XSS,         (identify,       (Django,
                   memory)            trace)          FastAPI)
```

### Prompt Router

**File:** `backend/services/prompt_router.py`

The PromptRouter dynamically selects and assembles prompts based on context:

```python
class PromptRouter:
    """Routes to appropriate prompt modules based on context."""

    # Vulnerability category → validity checklist mapping
    VALIDITY_CHECKLIST_MAP = {
        "SQL_INJECTION": "validity_checklists/sql_injection.md",
        "COMMAND_INJECTION": "validity_checklists/command_injection.md",
        "XSS": "validity_checklists/xss.md",
        "MEMORY_SAFETY": "validity_checklists/memory_safety.md",
        "SSRF": "validity_checklists/ssrf.md",
        "CODE_INJECTION": "validity_checklists/code_injection.md",
        "DESERIALIZATION": "validity_checklists/deserialization.md",
        "PATH_TRAVERSAL": "validity_checklists/path_traversal.md",
        "AUTH_BYPASS": "validity_checklists/auth_idor.md",
        "IDOR": "validity_checklists/auth_idor.md",
    }

    # DeepAudit stage → stage module mapping
    STAGE_MODULE_MAP = {
        "identify_entrypoints": "stages/identify_entrypoints.md",
        "trace_dataflow": "stages/trace_dataflow.md",
        "validate_exploitability": "stages/validate_exploitability.md",
        "triage": "stages/triage.md",
    }

    # Framework → context module mapping
    CONTEXT_MODULE_MAP = {
        "django": "contexts/django.md",
        "fastapi": "contexts/fastapi.md",
        "flask": "contexts/flask.md",
        "express": "contexts/express.md",
    }
```

**Usage:**
```python
router = PromptRouter()

# Route based on vulnerability category
modules = router.route(
    category="SQL_INJECTION",
    stage="trace_dataflow",
    framework="django",
    framework_confidence=0.9
)

# Assemble final prompt
final_prompt = router.assemble_from_paths(modules, task="Find SQL injection")
```

### Validity Checklists (Specialized by Category)

**Location:** `prompting/validity_checklists/`

Each vulnerability category has a specialized checklist that guides evidence gathering:

#### 1. SQL Injection (`sql_injection.md`)

**Key Patterns:**
- **Sink:** `execute()`, `executemany()`, `cursor.execute()`, `db.query()`
- **Safe Pattern:** Parameterized queries (`execute("SELECT * FROM users WHERE id = ?", [user_id])`)
- **Unsafe Pattern:** String concatenation (`execute(f"SELECT * FROM users WHERE id = {user_id}")`)

**Checklist Guidance:**
```markdown
## 3. Trace Data Flow (dataflow_evidenced)

**Safe Patterns (Parameterized Queries):**
If you see `execute("SELECT * FROM users WHERE id = ?", [user_id])`:
- This IS parameterized (safe)
- `dataflow_evidenced = PROVEN_FALSE` (data flow is blocked by parameterization)

**Unsafe Patterns (String Concatenation):**
If you see `execute(f"SELECT * FROM users WHERE id = {user_id}")`:
- This is NOT parameterized (unsafe)
- `dataflow_evidenced = PROVEN_TRUE` if you can trace user_id to request input
```

#### 2. Command Injection (`command_injection.md`)

**Key Patterns:**
- **Sink:** `os.system()`, `subprocess.call()` with `shell=True`, `child_process.exec()`
- **Safe Pattern:** Argv arrays without shell (`subprocess.run(['git', 'log', user_input], shell=False)`)
- **Unsafe Pattern:** Shell involvement (`os.system(f"convert {user_file} output.png")`)

**Shell Metacharacters:**
```markdown
Evidence that user input can inject shell commands:
- `;` - Command separator
- `|` - Pipe to another command
- `&` - Background execution
- `$()` or backticks - Command substitution
- `>`, `>>`, `<` - Redirection
- `&&`, `||` - Conditional execution
```

#### 3. Memory Safety (`memory_safety.md`)

**CRITICAL: ANALYSIS ONLY - NO EXPLOITATION INSTRUCTIONS**

**Key Patterns (C/C++):**
- **Unsafe Functions:** `strcpy()`, `strcat()`, `sprintf()`, `gets()` (unbounded)
- **Safe Alternatives:** `strncpy()`, `snprintf()`, bounds checking

**Key Patterns (Rust):**
- **Unsafe:** `unsafe { }` blocks, `.get_unchecked()`, raw pointer dereferences
- **Safe:** `.get()` (returns Option), ownership system prevents UAF

**Remediation Guidance (Defensive):**
```markdown
**For Buffer Overflows:**
- Replace `strcpy()` with `strncpy()` or `strlcpy()`
- Replace `sprintf()` with `snprintf()`
- Always validate buffer sizes before writes

**For Use-After-Free:**
- Set pointers to NULL after `free()`
- Use smart pointers (C++ `std::unique_ptr`, `std::shared_ptr`)
- Use Rust ownership system (borrow checker prevents UAF)
```

#### 4. XSS (`xss.md`)

**Key Patterns:**
- **Sink:** `innerHTML`, `document.write()`, `dangerouslySetInnerHTML`, template rendering
- **Safe Pattern:** Auto-escaping (`<div>{userName}</div>` in React, `{{ userName }}` in Jinja2)
- **Unsafe Pattern:** No escaping (`innerHTML = userInput`, `dangerouslySetInnerHTML={{__html: userInput}}`)

#### 5. Path Traversal (`path_traversal.md`)

**Key Patterns:**
- **Sink:** `open()`, `Path()`, file system operations
- **Safe Pattern:** Allowlist validation, path normalization, jail directory
- **Unsafe Pattern:** Direct concatenation (`open(f"/var/data/{user_file}")`)

#### 6. SSRF (`ssrf.md`)

**Key Patterns:**
- **Sink:** `requests.get()`, `urllib.request.urlopen()`, `fetch()`
- **Safe Pattern:** URL allowlist, scheme validation, private IP blocking
- **Unsafe Pattern:** User-controlled URL (`requests.get(user_url)`)

#### 7. Deserialization (`deserialization.md`)

**Key Patterns:**
- **Sink:** `pickle.load()`, `yaml.load()`, `json.loads()` with object hooks
- **Safe Pattern:** `yaml.safe_load()`, schema validation
- **Unsafe Pattern:** `pickle.load(user_data)`, `yaml.load()` without SafeLoader

#### 8. Code Injection (`code_injection.md`)

**Key Patterns:**
- **Sink:** `eval()`, `exec()`, `Function()` constructor, `setTimeout()` with string
- **Safe Pattern:** No dynamic code execution, sandboxing, AST parsing
- **Unsafe Pattern:** `eval(user_input)`, `exec(user_code)`

#### 9. Auth/IDOR (`auth_idor.md`)

**Key Patterns:**
- **Sink:** Direct object access without authorization check
- **Safe Pattern:** Authorization checks before every access
- **Unsafe Pattern:** `User.objects.get(id=user_provided_id)` without ownership check

### Base Prompt

**File:** `prompting/base/base_prompt.md`

**Key Principles:**
- **Untrusted Data Handling:** All repo content is untrusted (prompt-injection safety)
- **Evidence Integrity:** Never invent evidence, always cite sources
- **Tri-State Logic:** PROVEN_TRUE | PROVEN_FALSE | UNKNOWN
- **StrictClassifier Alignment:** Follow disposition rules

**Proof Checklist (Universal):**
```markdown
- **source_controlled_input**: PROVEN_TRUE | PROVEN_FALSE | UNKNOWN
- **sink_present**: PROVEN_TRUE | PROVEN_FALSE | UNKNOWN
- **dataflow_evidenced**: PROVEN_TRUE | PROVEN_FALSE | UNKNOWN
- **reachable**: PROVEN_TRUE | PROVEN_FALSE | UNKNOWN
- **boundary_crossed**: PROVEN_TRUE | PROVEN_FALSE | UNKNOWN
- **not_only_misconfig**: PROVEN_TRUE | PROVEN_FALSE | UNKNOWN
- **security_control_bypassed**: PROVEN_TRUE | PROVEN_FALSE | UNKNOWN
```

### Stage Modules (DeepAudit Workflow)

**Location:** `prompting/stages/`

Stage-specific guidance for multi-phase analysis:

1. **`identify_entrypoints.md`** - Find HTTP routes, CLI commands, message handlers
2. **`trace_dataflow.md`** - Follow data from entrypoint to sink
3. **`validate_exploitability.md`** - Verify exploitability conditions
4. **`triage.md`** - Determine final disposition

### Framework Context Modules

**Location:** `prompting/contexts/`

Framework-specific patterns and idioms:

1. **`django.md`** - Django ORM, request patterns, middleware
2. **`fastapi.md`** - Dependency injection, Pydantic validation
3. **`flask.md`** - Blueprints, request object, Jinja2 templates
4. **`express.md`** - Middleware, route params, template engines

**Confidence Gating:** Context modules only loaded if framework detection confidence ≥ 0.8

### Prompt Composition Example

```python
# Detect vulnerability in Django app
category = "SQL_INJECTION"
stage = "trace_dataflow"
framework = "django"
framework_confidence = 0.9

# Route to appropriate modules
router = PromptRouter()
modules = router.route(category, stage, framework, framework_confidence)

# Assemble final prompt
final_prompt = router.assemble_from_paths(modules, task="""
Analyze app/views.py for SQL injection vulnerabilities.
Focus on the user_search() function.
""")

# Result:
# BASE_PROMPT (evidence rules, checklist)
# + sql_injection.md (parameterized vs concatenated queries)
# + trace_dataflow.md (follow data from source to sink)
# + django.md (Django ORM patterns, query construction)
# + TASK (specific analysis target)
```

### Benefits of Specialized Prompting

1. **Reduced False Positives:**
   - Category-specific safe pattern detection
   - Framework-aware validation
   - Example: Knows Django ORM parameterizes by default

2. **Higher Quality Evidence:**
   - Structured evidence gathering plans
   - Tool call examples for each category
   - Citation format standards

3. **Consistent Classification:**
   - All categories align with StrictClassifier rules
   - Tri-state logic enforced
   - Disposition mapping clear

4. **Scalability:**
   - Easy to add new vulnerability categories
   - Modular composition reduces prompt bloat
   - Framework detection enables targeted guidance

### Test Coverage

**File:** `backend/tests/services/test_prompt_router.py`

```python
def test_route_sql_injection():
    """Test routing for SQL injection category."""
    router = PromptRouter()
    modules = router.route(category="SQL_INJECTION")
    assert modules.validity_checklist == "validity_checklists/sql_injection.md"

def test_route_with_framework_context():
    """Test routing with high-confidence framework detection."""
    modules = router.route(
        category="SQL_INJECTION",
        framework="django",
        framework_confidence=0.85  # Above 0.8 threshold
    )
    assert modules.context_module == "contexts/django.md"

def test_all_vulnerability_categories():
    """Test routing for all supported vulnerability categories."""
    categories = ["SQL_INJECTION", "SSRF", "CODE_INJECTION",
                  "COMMAND_INJECTION", "MEMORY_SAFETY"]
    for category in categories:
        modules = router.route(category=category)
        assert modules.validity_checklist is not None
```

**All routing tests passing ✓**

---

## Threat Modeling System

### Overview

QuickHack uses per-project threat modeling to gate attacker-controlled input detection. Threat profiles define:
- **Execution contexts:** Where the code runs
- **Attacker capabilities:** What the attacker can do
- **Assets:** What needs protection

### Data Model

**File:** `backend/models/threat_model_profile.py`

```python
class ThreatModelProfile(BaseModel):
    """Per-project threat model profile."""
    execution_contexts: list[str]      # e.g., ["product_runtime", "server_runtime"]
    attacker_capabilities: list[str]   # e.g., ["remote_network", "untrusted_file_input"]
    assets: list[str]                  # e.g., ["user_data", "api_keys"]

    def to_canonical_dict(self) -> dict:
        """Canonical representation for hashing."""
        return {
            "execution_contexts": sorted(self.execution_contexts),
            "attacker_capabilities": sorted(self.attacker_capabilities),
            "assets": sorted(self.assets),
        }

    def canonical_hash(self) -> str:
        """SHA256 hash for optimistic concurrency control."""
        canonical = json.dumps(self.to_canonical_dict(), sort_keys=True)
        return hashlib.sha256(canonical.encode()).hexdigest()
```

### Preset System

**File:** `backend/models/threat_model_profile.py`

```python
class ThreatModelPreset(str, Enum):
    A = "A"      # Minimal: Remote network only
    AB = "AB"    # Standard: Network + file input
    ABC = "ABC"  # Maximum: All attack surfaces

def preset_to_profile(preset: ThreatModelPreset) -> ThreatModelProfile:
    """Convert preset to full profile."""
    if preset == ThreatModelPreset.A:
        return ThreatModelProfile(
            execution_contexts=["product_runtime", "server_runtime"],
            attacker_capabilities=["remote_network"],
            assets=["user_data", "api_keys"],
        )

    elif preset == ThreatModelPreset.AB:
        return ThreatModelProfile(
            execution_contexts=["product_runtime", "server_runtime", "dev_tooling"],
            attacker_capabilities=["remote_network", "untrusted_file_input"],
            assets=["user_data", "api_keys", "source_code"],
        )

    elif preset == ThreatModelPreset.ABC:
        return ThreatModelProfile(
            execution_contexts=["product_runtime", "server_runtime", "dev_tooling", "ci_pipeline"],
            attacker_capabilities=[
                "remote_network",
                "untrusted_file_input",
                "remote_web_content",
                "untrusted_repo_content",
                "untrusted_ci_artifact",
            ],
            assets=["user_data", "api_keys", "source_code", "infrastructure"],
        )
```

### Capability → Channel Mapping

**File:** `backend/services/threat_model_gating.py`

```python
def derive_allowed_input_channels(
    threat_model_profile: dict | None
) -> set[InputChannel]:
    """
    Canonical mapping: attacker capability → input channels

    Args:
        threat_model_profile: Profile dict with 'attacker_capabilities' list

    Returns:
        Set of allowed InputChannel enums. If no profile, returns all channels
        (no gating, preserve legacy behavior).
    """
    if not threat_model_profile:
        return set(InputChannel)  # No gating

    caps = set(threat_model_profile.get("attacker_capabilities", []))

    cap_to_channels: dict[str, set[InputChannel]] = {
        "remote_network": {InputChannel.network},
        "untrusted_file_input": {InputChannel.file_input},
        "remote_web_content": {InputChannel.web_content},
        "untrusted_repo_content": {InputChannel.repo_checkout},
        "untrusted_ci_artifact": {InputChannel.ci_artifact},
        "local_unprivileged_user": {InputChannel.local_unprivileged},
    }

    allowed: set[InputChannel] = set()
    for cap in caps:
        allowed |= cap_to_channels.get(cap, set())

    # Always allow unknown (non-deterministic won't gate anyway)
    allowed.add(InputChannel.unknown)

    return allowed
```

### Database Schema

**Table:** `projects`

```sql
CREATE TABLE projects (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    repo_path TEXT NOT NULL,
    -- ... other fields ...
    threat_model_profile_json TEXT,  -- JSON serialized ThreatModelProfile
    profile_hash TEXT                -- SHA256 for optimistic concurrency
);
```

### API Endpoints

**GET /projects/{project_id}/threat-model-profile**

Returns current threat model profile with hash for optimistic concurrency control.

```json
{
  "profile": {
    "execution_contexts": ["product_runtime", "server_runtime"],
    "attacker_capabilities": ["remote_network"],
    "assets": ["user_data", "api_keys"]
  },
  "profile_hash": "a1b2c3d4..."
}
```

**PUT /projects/{project_id}/threat-model-profile**

Updates threat model profile with hash validation.

```json
{
  "profile": {
    "execution_contexts": ["product_runtime", "server_runtime", "dev_tooling"],
    "attacker_capabilities": ["remote_network", "untrusted_file_input"],
    "assets": ["user_data", "api_keys", "source_code"]
  },
  "profile_hash": "a1b2c3d4..."  // Must match current hash
}
```

**Response (409 Conflict if hash mismatch):**
```json
{
  "detail": {
    "error": "profile_hash_mismatch",
    "message": "Profile was modified by another session",
    "current_hash": "e5f6g7h8...",
    "provided_hash": "a1b2c3d4..."
  }
}
```

### Frontend UI

**Component:** `frontend/components/ThreatModel/ThreatModelModal.tsx`

**Features:**
- Per-project threat model editor
- Preset selection (A/AB/ABC)
- Custom profile editing
- Optimistic concurrency with hash validation
- Visual capability mapping

**Usage Flow:**
1. User opens project settings
2. Clicks "Edit Threat Model"
3. Modal opens with current profile
4. User selects preset or customizes
5. On save, sends PUT with profile_hash
6. If conflict (409), shows merge dialog
7. Updates local state on success

### Prompt Injection

**File:** `backend/services/threat_model_prompt_block.py`

```python
def build_threat_model_prompt_block(threat_model_profile: dict | None) -> str:
    """
    Build authoritative threat model prompt block for agent system prompt.

    Injected into agent prompts to inform classification decisions.
    """
    if not threat_model_profile:
        return ""

    caps = threat_model_profile.get("attacker_capabilities", [])
    contexts = threat_model_profile.get("execution_contexts", [])
    assets = threat_model_profile.get("assets", [])

    return f"""
# Project Threat Model (Authoritative)

The following threat model defines this project's attack surface.
Use this to determine whether input channels represent attacker-controlled sources.

## Execution Contexts
{chr(10).join(f"- {ctx}" for ctx in contexts)}

## Attacker Capabilities (Enabled Input Channels)
{chr(10).join(f"- {cap}" for cap in caps)}

## Protected Assets
{chr(10).join(f"- {asset}" for asset in assets)}

## Input Channel Gating
- If an input channel is NOT listed in attacker capabilities, findings from that channel should be classified as HARDENING (not VALID_SECURITY_ISSUE).
- This gating is enforced by the triage system automatically.
"""
```

**Injection Point:** `backend/services/agent_orchestrator.py`

```python
def _build_system_prompt(self, session: Session) -> str:
    """Build system prompt with threat model block."""
    base_prompt = self._load_base_prompt()

    # Get threat model profile
    profile = project_service.get_threat_model_profile(session.project_id)

    # Inject threat model block
    threat_model_block = build_threat_model_prompt_block(profile)

    return f"{base_prompt}\n\n{threat_model_block}"
```

---

## Triage & Classification

### Overview

The triage system orchestrates evidence gathering and classification with threat model gating. It guarantees that all findings are processed (no drops) and applies strict disposition rules.

### Workflow

```
Finding → Evidence Gatherer → Input Channel Inference → Strict Classifier → Triaged Finding
   ↓                ↓                    ↓                        ↓
Raw data      Gather evidence      Infer channel        Apply rules + gating
              (code snippets,      (2-signal min)       (tri-state checklist)
               symbols, routes)
```

### FindingTriageService

**File:** `backend/services/finding_triage_service.py`

**Responsibilities:**
- Batch processing with timeout
- Coordinate gatherer + classifier
- Generate batch_id
- Guarantee: triaged_count == raw_count (never drops findings)

```python
class FindingTriageService:
    def triage_findings(
        self,
        repo_root: str,
        findings: list[Finding],
        policy_version: str = "1.0.0",
        budgets: Optional[BudgetConfig] = None,
        threat_model_profile: Optional[dict] = None,
    ) -> TriageResult:
        """
        Triage a batch of findings.

        GUARANTEE: len(triaged_findings) == len(findings)
        """
        batch_id = self._generate_batch_id()
        gatherer = EvidenceGatherer(repo_root, budgets)
        classifier = StrictClassifier()

        triaged = []
        reportable = []

        for finding in findings:
            # Gather evidence (includes input channel inference)
            evidence = gatherer.gather(finding)

            # Classify (gating happens inside classifier)
            classification = classifier.classify(
                finding=finding,
                evidence=evidence,
                threat_model_profile=threat_model_profile,
            )

            # Attach triage metadata
            triaged_finding = self._attach_triage_metadata(
                finding, classification, batch_id, policy_version
            )
            triaged.append(triaged_finding)

            # Track reportable
            if classification.disposition in [
                Disposition.VALID_SECURITY_ISSUE,
                Disposition.BUG
            ]:
                reportable.append(triaged_finding)

        # Verify guarantee
        assert len(triaged) == len(findings)

        return TriageResult(
            triaged_findings=triaged,
            reportable_findings=reportable,
            metrics=self._build_metrics(...),
            batch_id=batch_id
        )
```

### Input Channel Inference

**File:** `backend/services/input_channel_inference.py` (376 lines)

**Purpose:** Infer input channel from evidence using 2-signal minimum

**Policy:**
- Requires BOTH entrypoint detection AND source read detection
- Conservative: defaults to `unknown` unless deterministic
- Precedence order: WebSocket → HTTP → File → Web Content → Repo/CI

**Example (HTTP):**

```python
def infer_input_channel(*, finding: Finding, evidence: Evidence) -> None:
    """Infer input channel (mutates evidence in-place)."""

    # 1) Check WebSocket signals
    signals = _collect_websocket_signals(evidence)
    if {"websocket_registration", "websocket_message_read"} <= set(signals):
        evidence.input_channel = InputChannel.network
        evidence.input_channel_deterministic = True
        evidence.input_channel_signals = signals
        evidence.input_channel_reason = "ws registration + message read"
        return

    # 2) Check HTTP signals
    signals = _collect_http_signals(evidence)
    if "route_registration" in signals and (
        "request_data_read" in signals or "framework_param_binding" in signals
    ):
        evidence.input_channel = InputChannel.network
        evidence.input_channel_deterministic = True
        evidence.input_channel_signals = signals
        evidence.input_channel_reason = "route + request/binding"
        return

    # ... other channels ...

    # Default: unknown
    evidence.input_channel = InputChannel.unknown
    evidence.input_channel_deterministic = False
```

**Signal Detection Examples:**

```python
def _collect_http_signals(evidence: Evidence) -> list[str]:
    """Collect HTTP/REST signals."""
    signals = []

    # Signal 1: Route registration
    if _has_route_registration(evidence):
        signals.append("route_registration")

    # Signal 2a: Request data read
    if _has_request_data_read(evidence):
        signals.append("request_data_read")

    # Signal 2b: Framework param binding
    if _has_framework_param_binding(evidence):
        signals.append("framework_param_binding")

    return signals

def _has_route_registration(evidence: Evidence) -> bool:
    """Check for route registration patterns."""
    snippet = (evidence.snippet or "") + (evidence.handler_snippet or "")

    route_patterns = [
        r'@app\.(get|post|put|delete|patch)\(',  # FastAPI
        r'@router\.(get|post|put|delete|patch)\(',
        r'@app\.route\(',                         # Flask
        r'@bp\.route\(',
        r'path\(["\']',                           # Django
    ]

    return any(re.search(p, snippet, re.IGNORECASE) for p in route_patterns)

def _has_framework_param_binding(evidence: Evidence) -> bool:
    """
    Check if framework binds route params to handler args.

    Uses route template params ∩ handler args intersection.
    """
    if evidence.symbol_info and evidence.route_registration:
        route_params = _extract_route_params(evidence.route_registration)
        handler_args = _extract_handler_args(evidence.symbol_info)

        # If intersection non-empty, binding detected
        if route_params & handler_args:
            return True

    return False
```

### StrictClassifier

**File:** `backend/services/strict_classifier.py`

**Responsibilities:**
- Evaluate A-G checklist items (PROVEN/DISPROVEN/UNKNOWN)
- Apply disposition rules in priority order
- Integrate threat model gating
- Return disposition + confidence + reasoning

```python
class StrictClassifier:
    def classify(
        self,
        finding: Finding,
        evidence: Evidence,
        threat_model_profile: dict | None = None,
    ) -> ClassificationResult:
        """
        Classify a finding based on evidence with threat model gating.
        """
        # Build tri-state checklist
        checklist = self._build_checklist(finding, evidence, threat_model_profile)

        # Apply strict disposition rules
        disposition = self._apply_rules(checklist, finding, evidence)

        # Apply pattern downgrades (ONLY downgrades)
        disposition = self._apply_pattern_downgrades(...)

        # Compute confidence
        classification_confidence = self._compute_classification_confidence(...)
        exploit_confidence = self._compute_exploit_confidence(...) if VALID/BUG else None

        # Generate reasoning
        reasoning = self._generate_reasoning(...)

        return ClassificationResult(
            disposition=disposition,
            classification_confidence=classification_confidence,
            exploit_confidence=exploit_confidence,
            proof_checklist=checklist,
            reasoning=reasoning,
            category=category
        )
```

**Threat Model Gating Integration:**

```python
def _build_checklist(
    self,
    finding: Finding,
    evidence: Evidence,
    threat_model_profile: dict | None
) -> ProofChecklist:
    """Build tri-state checklist with threat model gating."""

    # Build base checklist
    checklist = ProofChecklist(
        source_controlled_input=self._evaluate_attacker_control(finding, evidence),
        sink_present=self._evaluate_sink(finding, evidence),
        # ... other items ...
    )

    # Apply threat model gating
    if threat_model_profile:
        allowed_channels = derive_allowed_input_channels(threat_model_profile)

        # If input channel is deterministic AND not allowed
        if evidence.input_channel_deterministic:
            if evidence.input_channel not in allowed_channels:
                # Force DISPROVEN
                checklist.source_controlled_input = ChecklistItem(
                    value=False,
                    status=ChecklistStatus.DISPROVEN,
                    reason=f"disabled_by_profile: input_channel={evidence.input_channel.value} not enabled by ThreatModelProfile",
                    reason_code="disabled_by_profile"
                )

    return checklist
```

**Disposition Rules:**

```python
def _apply_rules(
    self,
    checklist: ProofChecklist,
    finding: Finding,
    evidence: Evidence
) -> Disposition:
    """Apply disposition rules in priority order."""

    # RULE 0: Threat-model gated input → HARDENING
    if checklist.source_controlled_input.reason_code == "disabled_by_profile":
        return Disposition.HARDENING

    # RULE 1: All PROVEN → VALID
    if all(item.status == ChecklistStatus.PROVEN for item in checklist.all_items()):
        return Disposition.VALID_SECURITY_ISSUE

    # RULE 2: Only config DISPROVEN → MISCONFIGURATION
    if (
        checklist.not_only_misconfig.status == ChecklistStatus.DISPROVEN
        and all(
            item.status == ChecklistStatus.PROVEN
            for item in checklist.all_items()
            if item != checklist.not_only_misconfig
        )
    ):
        return Disposition.MISCONFIGURATION

    # RULE 3: Attacker control DISPROVEN → HARDENING or BY_DESIGN
    if checklist.source_controlled_input.status == ChecklistStatus.DISPROVEN:
        # Check if explicitly marked as intended behavior
        if "by_design" in checklist.source_controlled_input.reason.lower():
            return Disposition.BY_DESIGN
        return Disposition.HARDENING

    # RULE 4: Sink DISPROVEN → BUG
    if checklist.sink_present.status == ChecklistStatus.DISPROVEN:
        return Disposition.BUG

    # RULE 5: Dataflow DISPROVEN → BUG
    if checklist.dataflow_evidenced.status == ChecklistStatus.DISPROVEN:
        return Disposition.BUG

    # RULE 6: Reachability DISPROVEN → HARDENING
    if checklist.reachable.status == ChecklistStatus.DISPROVEN:
        return Disposition.HARDENING

    # Default: SPECULATIVE
    return Disposition.SPECULATIVE
```

---

## Security Issue vs Bug Classification

### Overview

QuickHack distinguishes between security vulnerabilities, functional bugs, and hardening opportunities through evidence-based classification.

### Disposition Taxonomy

```python
class Disposition(str, Enum):
    VALID_SECURITY_ISSUE = "valid_security_issue"  # Exploitable vulnerability
    BUG = "bug"                                     # Functional bug, not security
    HARDENING = "hardening"                         # Defense-in-depth improvement
    BY_DESIGN = "by_design"                         # Expected behavior
    MISCONFIGURATION = "misconfiguration"           # Config issue, not code
    SPECULATIVE = "speculative"                     # Insufficient evidence
```

### Classification Criteria

#### Security Issue (ALL must be true):

1. **A. Attacker-Controlled Input:**
   - Input comes from untrusted source (network, file, web content, repo, CI)
   - Input channel is enabled by threat model profile
   - Deterministically classified (2-signal minimum)

2. **B. Dangerous Sink Present:**
   - SQL query execution (SQLi)
   - Command execution (command injection)
   - File system operations (path traversal)
   - Code evaluation (code injection)
   - Memory unsafe operations (buffer overflow)
   - Deserialization (insecure deserialization)
   - Authentication/authorization bypass

3. **C. Dataflow Evidenced:**
   - Static analysis or dynamic tracing shows flow
   - Input reaches sink without sanitization
   - No effective security control in path

4. **D. Reachable:**
   - Code path is actually executed
   - Not dead code or disabled feature
   - Accessible via public API/route

5. **E. Boundary Crossed:**
   - Trust boundary violation (external → internal)
   - Privilege boundary crossing
   - Security context switch

6. **F. Not Only Misconfiguration:**
   - Code-level issue, not just config
   - Requires code change to fix

7. **G. Security Control Bypassed:**
   - Bypasses authentication/authorization/validation

#### Bug (ANY can be true):

1. **No Attacker Control:**
   - Input source is trusted (internal only)
   - OR input channel disabled by threat model

2. **No Security Sink:**
   - Functional operation only (logging, display, calculation)

3. **No Dataflow:**
   - Input and sink exist but no path between them
   - Effective sanitization prevents flow

4. **Functional Defect:**
   - Null pointer dereference
   - Logic error
   - Type error
   - Performance issue

### Decision Tree

```
Is input attacker-controlled? (A)
├─ NO → Functional defect? → YES: BUG, NO: BY_DESIGN/HARDENING
└─ YES → Input channel enabled by threat model?
         ├─ NO → HARDENING (out of scope, still useful)
         └─ YES → Dangerous sink? (B)
                  ├─ NO → BUG
                  └─ YES → Dataflow evidenced? (C)
                           ├─ NO → BUG or HARDENING
                           └─ YES → Reachable? (D)
                                    ├─ NO → HARDENING
                                    └─ YES → Crosses security boundary? (E)
                                             ├─ NO → BY_DESIGN or HARDENING
                                             └─ YES → Only config issue? (F)
                                                      ├─ YES → MISCONFIGURATION
                                                      └─ NO → Bypasses control? (G)
                                                               └─ YES: VALID_SECURITY_ISSUE
                                                                  NO: VALID_SECURITY_ISSUE or HARDENING
```

### Examples

#### Example 1: SQL Injection (Security Issue)

```python
@app.get("/user/{user_id}")
def get_user(user_id: str):
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    db.execute(query)
```

**Classification:**
- ✓ A: Attacker-controlled (HTTP route param, network enabled)
- ✓ B: Sink (SQL query execution)
- ✓ C: Dataflow (user_id → query)
- ✓ D: Reachable (public route)
- ✓ E: Boundary crossed (external → database)
- ✓ F: Not config (code flaw)
- ✓ G: Bypasses parameterization

**Disposition:** VALID_SECURITY_ISSUE

#### Example 2: Null Pointer (Bug)

```python
def calculate_total(items):
    return sum(item.price for item in items)

calculate_total(None)  # AttributeError
```

**Classification:**
- ✗ A: No attacker control (internal call)
- ✗ B: No security sink (math operation)

**Disposition:** BUG

#### Example 3: Hardening (Out of Threat Model)

```python
@app.get("/admin/logs")
def get_logs():
    with open("/var/log/app.log") as f:
        return f.read()
```

**Threat Model:** Preset A (remote_network only)

**Classification:**
- ✗ A: No attacker-controlled input (hardcoded path)
- Input channel: unknown (no user input to path)
- Gating: Not applicable

**Disposition:** HARDENING (add auth, rate limiting)

---

## Protocol-Aware Reportability Layer

### Overview

The protocol layer sits between the triage pipeline and final report generation. It evaluates whether findings are worth submitting to specific disclosure channels (bug bounties, VRPs, internal reporting).

### Architecture

```
Finding → Evidence → Classification → Protocol Evaluation → Storage
                          ↓              ↓
                    Disposition    SubmissionResult
                                        ↓
                                  Evidence Quest? → Re-triage
```

### Key Components

**ProtocolEvaluator:** Applies protocol-specific quality gates to determine submit/dont_submit/needs_more_info

**ProtocolPolicy:** Configuration defining quality requirements per protocol (osvrp_strict, hackerone_strict, etc.)

**EvidenceQuestOrchestrator:** Manages autonomous LLM agents that gather missing evidence for high-signal findings

**Quest Playbooks:** Category-specific evidence gathering strategies (CommandInjectionQuest, SQLInjectionQuest, etc.)

### Data Models

**SubmissionResult:**
- decision: submit | dont_submit | needs_more_info
- reasons: Human-readable explanations
- missing_evidence: Specific gaps (for NMI)
- quest_run: Whether evidence quest was triggered
- disposition_modified: If protocol changed disposition

**ProtocolPolicy:**
- min_disposition_to_submit: Set of dispositions that meet threshold
- require_cross_boundary_for_local_bugs: Gate for CLI/local bugs
- category_rules: Per-category validation (e.g., command injection requires shell)
- enable_evidence_quests: Whether to run autonomous evidence gathering

### Evaluation Flow

1. **Gate 1 - Disposition:** Check if disposition meets protocol threshold
2. **Gate 2 - Checklist:** Verify sufficient PROVEN items
3. **Gate 3 - Attacker Model:** Reject social engineering if policy requires
4. **Gate 4 - Category Rules:** Apply vulnerability-specific validation
5. **Gate 5 - Local Boundary:** Check automation for local bugs

If any gate fails: Either reject (dont_submit) or request more info (needs_more_info)

If all gates pass: Accept for submission (submit)

### Disposition Override

ProtocolEvaluator can modify Finding.disposition based on protocol rules:
- VALID → HARDENING (insufficient proof)
- VALID → HARDENING (local-only without automation)
- VALID → HARDENING (social engineering dependency)

No audit trail is preserved (simplified approach).

### Evidence Quests

When needs_more_info with quest_run=True:
1. Create EvidenceQuest in database
2. Instantiate category-specific playbook (CommandInjectionQuest, etc.)
3. Playbook uses LLM with tools to gather missing evidence
4. If quest succeeds: Update Evidence → Re-run Classifier → Re-run ProtocolEvaluator
5. Store quest results in database for audit

Quest playbooks have access to:
- read_file: Read source code
- grep: Search codebase
- parse_ast: Parse Python AST
- (Future: More sophisticated analysis tools)

### Database Schema

**protocol_policies table:**
- Stores policy configurations as JSON
- Seeded with 5 defaults on first run

**evidence_quests table:**
- Tracks quest execution lifecycle
- Stores evidence_found and new_checklist_items

**findings.submission_result:**
- JSON field storing SubmissionResult
- Indexed on decision for filtering

### API Endpoints

- GET /protocol-policies (list all)
- GET /protocol-policies/:id (get specific)
- PATCH /projects/:id (update project protocol)
- POST /findings/:id/quests (trigger quest)
- GET /findings/:id/quests (list quests)
- GET /quests/:id (quest details)
- GET /findings (with submission_decision filter)

### UI Components

- ProtocolPolicySelector: Choose protocol in project settings
- SubmissionBadge: Visual indicator (✓ / ✗ / ?) in findings list
- SubmissionPanel: Full details in finding drawer
- Quest status display: Show when quest ran and what it found

---

## Data Models

### Core Schemas

**File:** `backend/models/schemas.py`

#### InputChannel

```python
class InputChannel(str, Enum):
    """Input channels represent where attacker-controlled data originates."""
    network = "network"                    # HTTP, WebSocket, gRPC
    file_input = "file_input"              # File uploads, user-provided files
    web_content = "web_content"            # Browser-side (DOM sources)
    repo_checkout = "repo_checkout"        # Repository content (CI/CD)
    ci_artifact = "ci_artifact"            # Build artifacts
    local_unprivileged = "local_unprivileged"  # Local user input
    unknown = "unknown"                    # Cannot determine
```

#### Evidence

```python
class Evidence(BaseModel):
    """Evidence bundle for triage classification."""

    # Core evidence
    finding_id: str
    snippet: str | None = None
    handler_snippet: str | None = None
    symbol_info: dict | None = None
    route_registration: str | None = None
    auth_gates: list[str] = Field(default_factory=list)
    dataflow_snippet: str | None = None

    # Input channel inference (Phase 3)
    input_channel: InputChannel = InputChannel.unknown
    input_channel_deterministic: bool = False
    input_channel_signals: list[str] = Field(default_factory=list)
    input_channel_reason: str = ""

    # Budget tracking (Phase 4)
    timed_out: bool = False
    tools_executed: int = 0
```

#### ChecklistItem

```python
class ChecklistStatus(str, Enum):
    PROVEN = "PROVEN"              # Evidence confirms condition
    DISPROVEN = "DISPROVEN"        # Evidence refutes condition
    UNKNOWN = "UNKNOWN"            # Insufficient evidence

class ChecklistItem(BaseModel):
    """Tri-state checklist item with auditable reasoning."""
    value: bool                           # Semantic value (True = condition holds)
    status: ChecklistStatus               # PROVEN/DISPROVEN/UNKNOWN
    reason: str                           # Human-readable explanation
    tool_calls: list[str] = Field(default_factory=list)  # Evidence tool calls
    reason_code: str | None = None        # Machine-readable code (e.g., "disabled_by_profile")
```

#### ProofChecklist

```python
class ProofChecklist(BaseModel):
    """Tri-state proof checklist for security issue validation."""

    # A. Is the input attacker-controlled?
    source_controlled_input: ChecklistItem

    # B. Is there a dangerous operation (sink)?
    sink_present: ChecklistItem

    # C. Is dataflow from source to sink evidenced?
    dataflow_evidenced: ChecklistItem

    # D. Is the vulnerable code reachable?
    reachable: ChecklistItem

    # E. Does execution cross a trust boundary?
    boundary_crossed: ChecklistItem

    # F. Is it more than just a misconfiguration?
    not_only_misconfig: ChecklistItem

    # G. Does it bypass a security control?
    security_control_bypassed: ChecklistItem
```

#### Finding

```python
class Finding(BaseModel):
    """Security finding with triage metadata."""

    # Core finding
    id: str
    session_id: str
    title: str
    description: str
    file_path: str
    line_number: int | None = None
    severity: str
    category: VulnerabilityCategory
    cwe_id: str | None = None

    # Triage metadata
    batch_id: str | None = None
    disposition: Disposition | None = None
    classification: FindingClassification = FindingClassification.SECURITY_ISSUE
    classification_confidence: int | None = None  # 0-100
    exploit_confidence: int | None = None         # 0-100
    proof_checklist: ProofChecklist | None = None
    reasoning: list[str] = Field(default_factory=list)
    triage_policy_version: str | None = None
    triaged_at: datetime | None = None

    # Metadata
    metadata: dict = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)
```

---

## API Reference

### Projects

**GET /projects**
- List all projects
- Returns: `list[Project]`

**POST /projects**
- Create new project
- Body: `{name: string, repo_path: string}`
- Returns: `Project`

**GET /projects/{project_id}**
- Get project details
- Returns: `Project`

**GET /projects/{project_id}/threat-model-profile**
- Get threat model profile with hash
- Returns: `{profile: ThreatModelProfile, profile_hash: string}`

**PUT /projects/{project_id}/threat-model-profile**
- Update threat model profile with optimistic concurrency
- Body: `{profile: ThreatModelProfile, profile_hash: string}`
- Returns: `{profile: ThreatModelProfile, profile_hash: string}`
- Errors: `409 Conflict` if hash mismatch

### Sessions

**POST /sessions**
- Create analysis session
- Body: `{project_id: string, agent_type: string, profile: string}`
- Returns: `Session`

**POST /sessions/{session_id}/run**
- Start analysis (async)
- Returns: `202 Accepted`
- WebSocket: Stream events to `/ws/sessions/{session_id}`

**GET /sessions/{session_id}/findings**
- Get findings for session
- Query: `?disposition=valid_security_issue&limit=50&offset=0`
- Returns: `{findings: list[Finding], total: int}`

**GET /sessions/{session_id}/metrics**
- Get triage metrics
- Returns: `TriageMetrics`

---

## Testing Strategy

### Test Coverage

**Total:** 24 tests passing ✓

**Categories:**
- Unit tests: Models, services, classification logic
- Integration tests: API endpoints, triage workflow, MCP server
- Security tests: Path traversal, symlink escape, directory exclusion

### Key Test Files

1. **`test_threat_model_gating.py`** (98 lines)
   - Capability→channel mapping
   - Preset profiles
   - Edge cases (empty profile, unknown capabilities)

2. **`test_quickhack_mcp_server.py`** (150 lines)
   - MCP tools list
   - Security boundaries (symlink, traversal, exclusions)
   - Subprocess execution

3. **`test_strict_classifier.py`**
   - Disposition rules
   - Threat model gating integration
   - Checklist evaluation

4. **`test_finding_triage_service.py`**
   - Batch processing
   - Timeout handling
   - Evidence gathering integration

### Running Tests

```bash
# All tests
pytest backend/tests/

# Specific category
pytest backend/tests/services/test_threat_model_gating.py

# With coverage
pytest --cov=backend --cov-report=html
```

---

## Deployment

### Docker Compose

```yaml
version: '3.8'

services:
  backend:
    build: ./backend
    ports:
      - "8000:8000"
    environment:
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
      - DATABASE_URL=sqlite:///./quickhack.db
    volumes:
      - ./data:/app/data
      - ./repos:/repos

  frontend:
    build: ./frontend
    ports:
      - "3000:3000"
    environment:
      - NEXT_PUBLIC_API_URL=http://backend:8000
    depends_on:
      - backend
```

### Environment Variables

**Backend:**
```bash
ANTHROPIC_API_KEY=sk-ant-...
DATABASE_URL=sqlite:///./quickhack.db
CODEX_CLI_PATH=/usr/local/bin/codex
ENABLE_CODEX_CLI=false
```

**Frontend:**
```bash
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_WS_URL=ws://localhost:8000
```

### Deployment Checklist

1. Set `ANTHROPIC_API_KEY`
2. Initialize database: `alembic upgrade head`
3. Build Docker images: `docker-compose build`
4. Start services: `docker-compose up -d`
5. Verify health: `curl http://localhost:8000/health`
6. Check logs: `docker-compose logs -f`

---

## Version History

**v2.0.0 (2026-01-17)** - Phase 3 & 4 Implementation
- Evidence model migration to Pydantic
- Input channel inference with 2-signal minimum
- Centralized threat model gating
- Enhanced test coverage
- Bug fixes (MCP directory rename, SDK availability)

**v1.0.0 (2026-01-16)** - Threat Modeling System
- Per-project threat profiles
- Preset system (A/AB/ABC)
- Threat model prompt injection
- Frontend UI (ThreatModelModal)
- Optimistic concurrency control

---

## Appendices

### A. Capability→Channel Mapping Reference

| Attacker Capability | Enabled Input Channels |
|---------------------|------------------------|
| `remote_network` | `network` |
| `untrusted_file_input` | `file_input` |
| `remote_web_content` | `web_content` |
| `untrusted_repo_content` | `repo_checkout` |
| `untrusted_ci_artifact` | `ci_artifact` |
| `local_unprivileged_user` | `local_unprivileged` |

### B. Signal Detection Patterns

**HTTP Signals:**
- `route_registration`: `@app.get(`, `@router.post(`, `@app.route(`
- `request_data_read`: `request.json()`, `request.form()`, `request.POST`
- `framework_param_binding`: Route params ∩ handler args

**WebSocket Signals:**
- `websocket_registration`: `@app.websocket(`, `WebSocket(`
- `websocket_message_read`: `.receive()`, `.recv()`, `message.data`

**File Signals:**
- `file_upload_api`: `UploadFile`, `request.files`
- `external_file_read`: `open(`, `.read(`, `Path(`
- `file_parse_operation`: `json.load`, `yaml.load`, `pickle.load`

### C. Disposition Rule Priority

0. Threat-model gated → HARDENING
1. All PROVEN → VALID_SECURITY_ISSUE
2. Only config DISPROVEN → MISCONFIGURATION
3. Attacker control DISPROVEN → HARDENING or BY_DESIGN
4. Sink DISPROVEN → BUG
5. Dataflow DISPROVEN → BUG
6. Reachability DISPROVEN → HARDENING
7. Default → SPECULATIVE

---

**End of Specification**

For questions or contributions, see `/docs/CONTRIBUTING.md`

# Claude Agent SDK Integration Design

## Goal

Add Claude Agent SDK as a new provider option (`provider: "claude_sdk"`) that replaces the custom ReAct loop with Claude's native agent loop, while keeping quick_hack as the governor (budget, steering, finding validation).

**Key principle:** Claude SDK is an additional provider, not a replacement for the entire system. OpenAI/Ollama/Anthropic-API providers continue to use the existing ReAct loop.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            AgentOrchestrator                                │
│                     (budget, steering, finding validation)                  │
└─────────────────────────────────┬───────────────────────────────────────────┘
                                  │
        ┌─────────────────────────┴─────────────────────────┐
        │                                                   │
        ▼                                                   ▼
┌───────────────────────┐                     ┌───────────────────────┐
│  ClaudeSDKProvider    │                     │  LegacyReActProvider  │
│  (provider: claude_sdk)│                    │  (anthropic/openai/   │
│                       │                     │   ollama)             │
│  - ClaudeSDKClient    │                     │  - ReActSecurityAgent │
│  - MCP tool server    │                     │  - ToolExecutor       │
│  - Native agent loop  │                     │  - Custom ReAct loop  │
└───────────┬───────────┘                     └───────────┬───────────┘
            │                                             │
            └──────────────────┬──────────────────────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │   Shared ToolCore   │
                    │                     │
                    │  - read_file()      │
                    │  - search_code()    │
                    │  - scan_secrets()   │
                    │  - report_finding() │
                    │  - ... (all tools)  │
                    └─────────────────────┘
```

---

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Tool access | Full MCP lockdown | All quick_hack tools as MCP, no Claude Code built-ins |
| Finding validation | Governor validates | Claude reports freely, orchestrator validates after each turn |
| Dual-mode | Two Claude sessions | Scanner session → handoff → analyzer session (cost optimization) |
| Pause/resume | Full state reconstruction | Persist session_id, resume via SDK's `resume` option |
| Provider support | Additional option | Keep legacy ReAct for OpenAI/Ollama |
| Provider selection | Explicit `claude_sdk` | No auto-detection, user opts in |

---

## Component Design

### 1. MCP Tool Server

Tools exposed via Claude Agent SDK's `@tool()` decorator:

```python
from claude_agent_sdk import tool, create_sdk_mcp_server

@tool(
    "read_file",
    "Read file contents with optional line range",
    {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "File path relative to repo root"},
            "start_line": {"type": "integer", "description": "Starting line (1-indexed)"},
            "end_line": {"type": "integer", "description": "Ending line (inclusive)"},
        },
        "required": ["path"]
    }
)
async def read_file(args: dict[str, Any]) -> dict[str, Any]:
    text = await tool_core.read_file(
        args["path"],
        args.get("start_line"),
        args.get("end_line")
    )
    return {"content": [{"type": "text", "text": truncate(text)}]}
```

**Tools to expose:**
- File operations: `read_file`, `list_directory`, `search_code`
- Security scanners: `scan_repo_for_secrets`, `dependency_audit`, `grep_semantic`
- Findings: `report_finding`, `list_sink_signals`, `upsert_sink_signal`
- Report: `generate_security_report`

**Key patterns:**
- Full JSON Schema with `"type": "object"`, `"properties"`, `"required"`
- Handler signature: `async def handler(args: dict) -> dict`
- Return format: `{"content": [{"type": "text", "text": ...}]}`
- Output truncation for large results (50k chars max)

### 2. ClaudeSDKProvider

```python
from claude_agent_sdk import ClaudeSDKClient, ClaudeAgentOptions
from claude_agent_sdk import (
    AssistantMessage, SystemMessage, ResultMessage,
    TextBlock, ToolUseBlock, ToolResultBlock,
)

class ClaudeSDKProvider:
    def __init__(
        self,
        repo_path: str,
        project_id: str,
        tool_core: ToolCore,
        config: ProviderConfig,
    ):
        self.repo_path = repo_path
        self.project_id = project_id
        self.tool_core = tool_core
        self.config = config
        self.client: ClaudeSDKClient | None = None
        self.session_id: str | None = None

    async def start_session(self, audit_policy: str, resume_session_id: str | None = None):
        mcp_server, tools = create_quickhack_mcp_server(...)

        alias = "quickhack"
        allowed_tools = [f"mcp__{alias}__{t.name}" for t in tools]

        options = ClaudeAgentOptions(
            cwd=self.repo_path,
            system_prompt={
                "type": "preset",
                "preset": "claude_code",
                "append": audit_policy,
            },
            mcp_servers={alias: mcp_server},
            allowed_tools=allowed_tools,
            include_partial_messages=True,
            resume=resume_session_id,
        )

        self.client = ClaudeSDKClient(options=options)
        await self.client.connect()

    async def run_turn(self, prompt: str, on_event: Callable) -> ResultMessage:
        await self.client.query(prompt)

        result: ResultMessage | None = None
        async for msg in self.client.receive_response():
            for event in self._to_ws_events(msg):
                await on_event(event)

            if isinstance(msg, ResultMessage):
                result = msg
                self.session_id = msg.session_id

        return result

    async def interrupt(self):
        if self.client:
            await self.client.interrupt()

    async def close(self):
        if self.client:
            await self.client.disconnect()

    def _to_ws_events(self, msg) -> list[dict]:
        if isinstance(msg, SystemMessage):
            return [{"type": "system", "subtype": msg.subtype, "data": msg.data}]

        if isinstance(msg, ResultMessage):
            return [{
                "type": "turn_complete",
                "session_id": msg.session_id,
                "duration_ms": msg.duration_ms,
                "total_cost_usd": msg.total_cost_usd,
            }]

        if isinstance(msg, AssistantMessage):
            events = []
            for block in msg.content:
                if isinstance(block, TextBlock):
                    events.append({"type": "agent_text", "text": block.text})
                elif isinstance(block, ToolUseBlock):
                    events.append({"type": "tool_call", "id": block.id, "name": block.name, "args": block.input})
                elif isinstance(block, ToolResultBlock):
                    events.append({"type": "tool_result", "tool_use_id": block.tool_use_id, "result": block.content})
            return events

        return [{"type": "unknown", "raw": repr(msg)}]
```

### 3. Shared ToolCore

Shared implementation used by both MCP tools and legacy ToolExecutor:

```python
class ToolCore:
    def __init__(
        self,
        repo_path: str,
        project_id: str,
        get_scan_limits: Callable[[], ScanLimits] = None,
    ):
        self.repo_path = Path(repo_path).resolve()
        self.project_id = project_id
        self.workspace_policy = WorkspacePolicy(root_path=self.repo_path)
        self._get_scan_limits = get_scan_limits or (lambda: ScanLimits())

        # Persistence services
        self._sink_signal_service = SinkSignalService(project_id)
        self._finding_service = FindingService(project_id)
```

**Key patterns:**
- Path validation via `WorkspacePolicy.validate_path()` BEFORE resolving
- All blocking I/O wrapped with `asyncio.to_thread()`
- `search_code()` delegates to `semantic_grep()` (ReDoS protection)
- All scanners receive `limits=self._get_scan_limits()` for budget/cancel
- Findings and signals persist via services (not just in-memory)

### 4. Turn-Based Orchestrator (Governor)

```python
class ClaudeSDKOrchestrator:
    def __init__(self, scan_tier: str, on_ws_event: Callable):
        self.scan_tier = scan_tier
        self.on_ws_event = on_ws_event
        self.budget_s = SCAN_TIER_BUDGETS[scan_tier]
        self.time_floor_s = SCAN_TIER_FLOORS.get(scan_tier, 0)
        self.start_time = time.monotonic()
        self.phase = "scanner"  # or "analyzer"

    async def run_audit(self, initial_prompt: str, resume_session_id: str = None):
        await self.provider.start_session(
            audit_policy=SCANNER_POLICY,
            resume_session_id=resume_session_id,
        )

        prompt = initial_prompt

        while self.remaining_s() > 0:
            result = await self.provider.run_turn(prompt, self.on_ws_event)

            # Governor validates findings
            await self._validate_findings()

            # Check for handoff signal
            if self._should_handoff():
                await self._do_handoff()
                prompt = self._build_analyzer_prompt()
                continue

            # Check if Claude thinks it's done
            if self._claude_says_done(result):
                if not self.time_floor_satisfied():
                    prompt = self._build_continue_prompt()
                    continue
                else:
                    break

            # Steer toward uncovered areas
            prompt = self._build_steering_prompt()

        await self.provider.close()

    def make_fresh_limits(self) -> ScanLimits:
        """Create fresh ScanLimits with current remaining budget."""
        remaining = self.remaining_s()
        deadline = time.monotonic() + min(remaining, remaining * 0.25)
        return ScanLimits(deadline=deadline, cancelled=lambda: self._cancelled)
```

**Governor responsibilities:**
- Multiple `run_turn()` calls within budget
- Validate findings after each turn (confidence, required fields)
- Steer Claude toward uncovered directories/signals
- Enforce time floor ("don't stop early")
- Handle dual-mode scanner→analyzer handoff

### 5. Provider Routing

```python
# In AgentOrchestrator

async def start_agent(self, agent_id: str):
    agent = self._agents[agent_id]
    config = agent.provider_config

    if config.provider.lower() == "claude_sdk":
        task = asyncio.create_task(self._run_sdk_agent(agent))
    else:
        task = asyncio.create_task(self._run_react_agent(agent))

async def cancel_agent(self, agent_id: str):
    # Interrupt SDK provider first (stops Claude promptly)
    if agent_id in self._sdk_providers:
        await self._sdk_providers[agent_id].interrupt()

    # Then cancel the task
    if agent_id in self._agent_tasks:
        self._agent_tasks[agent_id].cancel()
```

---

## Data Flow

```
User: POST /agents {provider: "claude_sdk", scan_tier: "medium"}
                    │
                    ▼
┌─────────────────────────────────────────────────────────────┐
│                    AgentOrchestrator                         │
│                                                              │
│  1. Create ToolCore (with limits factory)                   │
│  2. Create ClaudeSDKProvider                                │
│  3. Create ClaudeSDKOrchestrator (governor)                 │
│  4. Load saved session_id (if resuming)                     │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                  ClaudeSDKOrchestrator                       │
│                                                              │
│  while budget > 0:                                          │
│    ┌─────────────────────────────────────────────────────┐  │
│    │  provider.run_turn(prompt)                          │  │
│    │    → client.query(prompt)                           │  │
│    │    → async for msg in client.receive_response()     │  │
│    │    → emit WS events (agent_text, tool_call, etc.)   │  │
│    │    → return ResultMessage with session_id           │  │
│    └─────────────────────────────────────────────────────┘  │
│                          │                                   │
│    ┌─────────────────────▼─────────────────────────────┐    │
│    │  Governor logic:                                   │    │
│    │  - Validate pending findings                       │    │
│    │  - Check for handoff signal                        │    │
│    │  - Check time floor                                │    │
│    │  - Build steering prompt                           │    │
│    └────────────────────────────────────────────────────┘    │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                      Persistence                             │
│                                                              │
│  - Findings → FindingService                                │
│  - Sink signals → SinkSignalService                         │
│  - session_id → Agent state                                  │
└─────────────────────────────────────────────────────────────┘
```

---

## File Structure

```
backend/
├── providers/
│   ├── __init__.py
│   ├── claude_sdk_provider.py    # NEW: ClaudeSDKProvider
│   ├── mcp_tools.py              # NEW: MCP tool definitions
│   ├── anthropic_provider.py     # Existing
│   ├── openai_provider.py        # Existing
│   └── ollama_provider.py        # Existing
├── services/
│   ├── tool_core.py              # NEW: Shared tool implementations
│   ├── claude_sdk_orchestrator.py # NEW: Turn-based governor
│   ├── agent_orchestrator.py     # MODIFIED: Add SDK routing
│   └── ...
└── agents/
    ├── react_agent.py            # Existing (unchanged)
    └── tools.py                  # MODIFIED: Use ToolCore
```

---

## API Changes

### Provider Config

```json
{
  "provider": "claude_sdk",
  "model": "claude-sonnet-4-20250514"
}
```

### No frontend changes required

- Same `/api/agents` endpoints
- Same WebSocket event format
- Same scan tier options

---

## Implementation Notes

1. **allowed_tools format**: `mcp__{server_key}__{tool_name}` where `server_key` matches the key in `mcp_servers` dict

2. **Session resume**: Persist `ResultMessage.session_id`, pass to `ClaudeAgentOptions(resume=session_id)`

3. **Output truncation**: Large tool outputs should be truncated to ~50k chars to avoid flooding Claude's context

4. **Fresh ScanLimits**: `get_scan_limits()` must return fresh limits each call (deadline based on remaining budget)

5. **Interrupt vs Cancel**: Call `provider.interrupt()` before task cancel for prompt Claude stop

---

## Testing Strategy

1. **Unit tests**: ToolCore methods, path validation, line slicing
2. **Integration tests**: MCP tool server with mock ClaudeSDKClient
3. **E2E tests**: Full audit flow with real SDK (requires API key)
4. **Comparison tests**: Same repo, SDK vs legacy ReAct, compare findings

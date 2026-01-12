# Anthropic Agentic Integration Design

**Date:** 2026-01-12
**Status:** Approved for Implementation
**Approach:** Anthropic SDK with Native Tool Use

---

## Overview

This design enables quick_hack to use Claude's native tool calling capabilities via the Anthropic SDK, giving the system autonomous agent-like behavior for security auditing without the complexity of ACP protocol integration.

**Key Decision:** Use Anthropic SDK directly instead of Claude Code ACP integration. This simplifies architecture while providing powerful agentic capabilities.

---

## Architecture

### High-Level Components

```
Browser UI
    ↓ (REST/WS)
quick_hack Backend
    ↓
AnthropicAgenticProvider
    ↓ (HTTP API calls)
Anthropic API (api.anthropic.com)
    ↓
Claude with Tool Use
```

### Component Responsibilities

**1. AnthropicAgenticProvider**
- Uses official `anthropic` Python SDK
- Implements automatic tool execution loop
- Handles streaming responses
- Manages conversation context across tool calls
- Yields events (text, tool calls, findings) to agent

**2. ToolAdapter**
- Converts CASS tools to Anthropic tool schema format
- Executes tool calls with WorkspacePolicy enforcement
- Handles errors and timeouts
- Returns JSON-formatted results
- Tracks tool call counts for scan limits

**3. AgenticAuditAgent**
- New agent type for autonomous security auditing
- Manages outer iteration loop (time budget enforcement)
- Processes events from provider
- Extracts and persists findings
- Streams progress to frontend via WebSocket

---

## Key Design Decisions

### Why Anthropic SDK over ACP?

**Advantages:**
- ✅ Much simpler implementation (no stdio subprocess management)
- ✅ Battle-tested SDK with excellent documentation
- ✅ Standard HTTP API (easier debugging, monitoring, logging)
- ✅ No filesystem visibility constraints (repos can stay in container)
- ✅ No host service required
- ✅ Works with existing infrastructure

**Trade-offs:**
- ❌ Requires API key and costs money (vs free Claude Code subscription)
- ❌ Standard API features (vs Claude Code's enhanced runtime)
- ⚠️ Network dependency (vs local Claude Code)

**Decision:** The simplicity and reliability gains outweigh the cost trade-off for production use.

---

## Tool Use Loop Design

### Provider Loop (Inner)

```python
async def run_agentic_loop(prompt, tools, max_iterations=25):
    messages = [{"role": "user", "content": prompt}]

    for iteration in range(max_iterations):
        # Call Claude with tools
        response = await client.messages.create(
            model=model,
            messages=messages,
            tools=tools,
            max_tokens=4096,
        )

        # Yield text content
        for block in response.content:
            if block.type == "text":
                yield TextEvent(content=block.text)

        # Handle tool use
        if response.stop_reason == "tool_use":
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    result = await execute_tool(block.name, block.input)
                    yield ToolCallEvent(tool_name=block.name, result=result)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result,
                    })

            # Continue conversation
            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user", "content": tool_results})
        else:
            # Claude finished
            break
```

### Agent Loop (Outer)

```python
async def analyze():
    start_time = time.time()
    outer_iteration = 0

    while outer_iteration < max_outer_iterations:
        # Run provider's inner loop
        async for event in provider.run_agentic_loop(prompt, tools):
            await handle_event(event)  # Extract findings, emit progress

        # Check time budget
        elapsed = time.time() - start_time
        if elapsed >= min_time_budget and should_complete():
            break  # Audit complete

        # Continue exploring
        prompt = "Continue audit, focus on unexplored areas..."
        outer_iteration += 1
```

**Key behaviors:**
- Inner loop: automatic tool execution until Claude completes thought
- Outer loop: time budget enforcement + continued exploration
- Both loops respect cancellation signals

---

## Tool Mapping

### Anthropic Tool Schema Format

```python
{
    "name": "read_file",
    "description": "Read file contents from the repository",
    "input_schema": {
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "File path relative to repository root"
            },
            "start_line": {"type": "integer"},
            "end_line": {"type": "integer"}
        },
        "required": ["path"]
    }
}
```

### Available Tools

**File Operations:**
- `read_file` - Read file contents (with optional line range)
- `search_code` - Regex search across codebase
- `list_directory` - List directory contents

**Security Detection:**
- `detect_sql_injection` - Analyze file for SQL injection patterns
- `detect_xss` - Analyze for XSS vulnerabilities
- `detect_command_injection` - Check for command injection
- `detect_path_traversal` - Identify path traversal risks

**Code Analysis:**
- `build_call_tree` - Build call graph from entry point
- `query_graph` - Query code graph database
- `analyze_data_flow` - Trace data flow for taint analysis

**Tool Execution:**
```python
async def execute_tool(tool_name: str, tool_input: dict) -> str:
    # 1. Validate workspace policy
    if not workspace_policy.is_allowed(tool_input.get("path")):
        return json.dumps({"error": "Access denied"})

    # 2. Check scan limits
    if tool_call_count >= max_tool_calls:
        return json.dumps({"error": "Tool call limit exceeded"})

    # 3. Execute with timeout
    try:
        result = await asyncio.wait_for(
            execute_tool_impl(tool_name, tool_input),
            timeout=30
        )
        return json.dumps({"success": True, "result": result})
    except Exception as e:
        return json.dumps({"error": str(e)})
```

---

## Security & Policy Enforcement

### WorkspacePolicy

Enforces path containment and access control:

```python
class WorkspacePolicy:
    def __init__(self, repo_path: Path, config: dict):
        self.repo_path = repo_path.resolve()
        self.excluded_dirs = [".git", "node_modules", "__pycache__", ".venv"]
        self.max_file_size = 1_000_000  # 1MB
        self.allow_symlinks = False

    def is_allowed(self, path: str) -> bool:
        full_path = (self.repo_path / path).resolve()

        # Path containment
        if not full_path.is_relative_to(self.repo_path):
            return False

        # Excluded directories
        for excluded in self.excluded_dirs:
            if excluded in full_path.parts:
                return False

        # Symlink rejection
        if not self.allow_symlinks and full_path.is_symlink():
            return False

        # File size limit
        if full_path.is_file() and full_path.stat().st_size > self.max_file_size:
            return False

        return True
```

### ScanLimits by Tier

```python
SCAN_LIMITS = {
    "quick": {
        "max_tool_calls": 50,
        "max_files": 100,
        "min_time_budget": 60,  # seconds
    },
    "standard": {
        "max_tool_calls": 200,
        "max_files": 500,
        "min_time_budget": 300,
    },
    "deep": {
        "max_tool_calls": 1000,
        "max_files": 2000,
        "min_time_budget": 900,
    }
}
```

### Offline-First Enforcement

**Allowed operations:**
- ✅ Local file system access (within workspace)
- ✅ Local code analysis and parsing
- ✅ Local graph database queries
- ✅ Pattern matching and regex search

**Explicitly prohibited:**
- ❌ Network requests to external services
- ❌ Fetching remote resources
- ❌ API calls to third-party services
- ❌ Package installation or downloads

No network-based tools are exposed to Claude.

---

## Message Flows

### Flow 1: Start Agentic Audit

```
Browser → Backend → Agent → Provider → Anthropic API
   │          │        │         │            │
   │─POST────>│        │         │            │
   │ /api/agents/start │         │            │
   │ {type: "agentic_audit"}     │            │
   │          │        │         │            │
   │          │─create─>│        │            │
   │          │   AgenticAuditAgent           │
   │          │        │         │            │
   │          │        │─init───>│            │
   │          │        │  ToolAdapter          │
   │          │        │         │            │
   │<─WS event─────────│         │            │
   │  {type: "agent_started"}    │            │
   │          │        │         │            │
   │          │        │─────────>│           │
   │          │        │  run_agentic_loop()  │
   │          │        │         │            │
   │          │        │         │───POST────>│
   │          │        │         │ /v1/messages
   │          │        │         │ {tools: [...]}
```

### Flow 2: Tool Execution Loop

```
Anthropic API → Provider → ToolAdapter → CASS Tools
      │             │           │              │
      │<────────────│ response  │              │
      │  stop_reason: "tool_use"│              │
      │  content: [{type: "tool_use",          │
      │            name: "read_file"}]         │
      │             │           │              │
      │             │─execute──>│              │
      │             │           │──validate──> │
      │             │           │ WorkspacePolicy
      │             │           │              │
      │             │           │──call──────> │
      │             │           │ FileTools.read_file()
      │             │           │<─result─────│
      │             │<──result──│              │
      │             │           │              │
      │─────────────>│          │              │
      │ POST /v1/messages        │              │
      │ {role: "user",           │              │
      │  content: [{type: "tool_result"}]}     │
```

### Flow 3: Streaming Progress to Frontend

```
Provider → Agent → Orchestrator → WebSocket → Browser
   │         │          │             │          │
   │─event──>│          │             │          │
   │ TextEvent          │             │          │
   │         │──────────>│            │          │
   │         │  emit_log()            │          │
   │         │          │─broadcast──>│          │
   │         │          │             │─────────>│
   │         │          │             │  {type: "log",
   │         │          │             │   content: "..."}
   │         │          │             │          │
   │─event──>│          │             │          │
   │ ToolCallEvent      │             │          │
   │         │──────────>│            │          │
   │         │  emit_progress()       │          │
   │         │          │─broadcast──>│─────────>│
   │         │          │             │  {type: "progress",
   │         │          │             │   tool: "read_file"}
   │         │          │             │          │
   │─event──>│          │             │          │
   │ FindingEvent       │             │          │
   │         │──────────>│            │          │
   │         │  emit_finding()        │          │
   │         │          │─broadcast──>│─────────>│
   │         │          │             │  {type: "finding",
   │         │          │             │   severity: "HIGH"}
```

### Flow 4: Time Budget Enforcement

```
Agent                    Provider
  │                         │
  │───run_agentic_loop()──>│
  │                         │
  │<──events (25 iters)────│
  │                         │
  │─check time budget       │
  │  elapsed: 45s           │
  │  min_time: 300s         │
  │  → continue             │
  │                         │
  │───run_agentic_loop()──>│
  │  prompt: "Continue..."  │
  │                         │
  │<──events────────────────│
  │                         │
  │─check time budget       │
  │  elapsed: 310s          │
  │  min_time: 300s         │
  │  → complete ✓           │
```

---

## Implementation Plan

### File Structure

**New Files:**
```
backend/
├── providers/
│   └── anthropic_agentic_provider.py    # Enhanced provider with tool loop
├── agents/
│   ├── tool_adapter.py                   # CASS → Anthropic tool mapping
│   └── agentic_audit_agent.py           # New agent type
├── models/
│   └── agent_events.py                   # Event types (TextEvent, etc.)
└── tests/
    ├── providers/
    │   └── test_anthropic_agentic.py
    └── agents/
        └── test_agentic_audit.py
```

**Modified Files:**
```
backend/
├── models/schemas.py                     # Add AgentType.AGENTIC_AUDIT
├── services/agent_orchestrator.py       # Register new agent type
├── routers/agents.py                    # Add endpoint to start agentic audit
└── config.py                             # Ensure ANTHROPIC_API_KEY loaded
```

### Dependencies

```txt
# requirements.txt
anthropic>=0.18.0    # Official Anthropic Python SDK
```

### Configuration

```bash
# .env
ANTHROPIC_API_KEY=sk-ant-...

# Optional: tune agentic behavior
AGENTIC_MAX_ITERATIONS=25
AGENTIC_TOOL_TIMEOUT_SEC=30
```

### Implementation Phases

**Phase 1: Core Provider (MVP)**
- Implement `AnthropicAgenticProvider` with basic tool loop
- Implement `ToolAdapter` with 3-4 core tools (read_file, search_code, list_directory)
- Basic event streaming (TextEvent, ToolCallEvent)
- Unit tests for tool execution and policy enforcement

**Phase 2: Agent Integration**
- Implement `AgenticAuditAgent` with outer loop
- Time budget enforcement
- Finding extraction from events
- WebSocket progress streaming
- Integration tests with real Anthropic API

**Phase 3: Enhanced Tools**
- Add security detection tools (detect_sql_injection, etc.)
- Add graph query tools
- Add call tree builder integration
- Performance optimization (caching, parallel tool calls)

**Phase 4: Production Hardening**
- Rate limiting and retry logic
- Comprehensive error handling
- Cost tracking and budget alerts
- Monitoring and observability
- Documentation and runbooks

---

## API Endpoints

### Start Agentic Audit

```http
POST /api/agents/start
Content-Type: application/json

{
  "agent_type": "agentic_audit",
  "repo_id": "uuid",
  "scan_tier": "standard",
  "provider": "anthropic",
  "model": "claude-opus-4-5-20251101",
  "focus_areas": ["authentication", "api_endpoints"]
}

Response:
{
  "agent_id": "uuid",
  "status": "running",
  "estimated_duration": 300
}
```

### WebSocket Events

```javascript
// Connection
ws://localhost:8000/ws/agents/{agent_id}

// Events
{
  "type": "log",
  "content": "Analyzing authentication flows..."
}

{
  "type": "progress",
  "current": 42,
  "total": 500,
  "message": "Tool: read_file (auth.py)"
}

{
  "type": "finding",
  "finding": {
    "severity": "HIGH",
    "title": "SQL Injection in User Login",
    "file_path": "app/auth.py",
    "line_start": 45,
    "code_snippet": "query = f\"SELECT * FROM users WHERE username='{username}'\"",
    "description": "...",
    "attack_scenario": "...",
    "recommended_fix": "..."
  }
}

{
  "type": "agent_complete",
  "stats": {
    "duration": 312,
    "files_analyzed": 487,
    "tool_calls": 156,
    "findings": 12
  }
}
```

---

## Testing Strategy

### Unit Tests

**Provider Tests:**
- Tool loop execution with mock Anthropic API
- Tool result injection into conversation
- Iteration limit enforcement
- Error handling and retry logic

**ToolAdapter Tests:**
- Tool schema generation
- WorkspacePolicy enforcement
- Tool execution with valid/invalid paths
- Timeout and error handling

**Agent Tests:**
- Time budget enforcement
- Outer loop continuation logic
- Finding extraction from events
- Cancellation and pause/resume

### Integration Tests

**End-to-End Flow:**
1. Start agentic audit on test repository
2. Verify tool calls are made correctly
3. Verify findings are extracted and persisted
4. Verify WebSocket events stream correctly
5. Verify time budget is enforced
6. Verify scan completes successfully

**Test Repository:**
- Small codebase with known vulnerabilities
- Covers multiple vulnerability types (SQLi, XSS, etc.)
- Expected findings documented
- Reproducible results

### Cost Management for Tests

```python
# Use cheaper model for tests
TEST_MODEL = "claude-haiku-3-5-20241022"

# Limit iterations in tests
TEST_MAX_ITERATIONS = 5

# Mock Anthropic API for unit tests
@pytest.fixture
def mock_anthropic_client():
    with patch("anthropic.AsyncAnthropic") as mock:
        # Return canned responses
        yield mock
```

---

## Prompting Strategy

### System Prompt

```
You are an expert security auditor with deep knowledge of:
- OWASP Top 10 vulnerabilities
- Secure coding practices across multiple languages
- Attack vectors and exploitation techniques
- Data flow analysis and taint tracking

When you find a vulnerability, structure your response as:
**FINDING: [Title]**
Severity: [CRITICAL|HIGH|MEDIUM|LOW]
Location: [file:line]
Description: [What is the issue]
Attack Scenario: [How could this be exploited]
Recommendation: [How to fix it]

Be thorough but precise. Report only legitimate security issues.
```

### Initial Prompt Template

```python
f"""You are a security auditor analyzing this codebase for vulnerabilities.

Repository: {repo_name}
Scan tier: {scan_tier}
Focus areas: {focus_areas or "all areas"}

Your objectives:
1. Explore the codebase structure and identify entry points
2. Analyze authentication, authorization, and session management
3. Identify potential vulnerabilities (SQLi, XSS, injection, etc.)
4. Build call trees for suspicious data flows
5. Report findings with severity, location, and remediation

You have access to tools for reading files, searching code, detecting patterns,
and building call graphs.

Begin your security audit."""
```

### Continuation Prompt

```python
f"""Continue your security audit.

So far you've found {len(findings)} potential issues.
Elapsed time: {elapsed:.0f}s / {min_time}s required.

Focus on areas you haven't explored yet:
- Uncovered authentication flows
- Data validation and sanitization
- API endpoints and their handlers
- Third-party integrations
- Configuration files

What else can you find?"""
```

---

## Cost Estimation

### Pricing (Anthropic API - January 2026)

**Claude Opus 4.5:**
- Input: $15 / 1M tokens
- Output: $75 / 1M tokens

**Claude Sonnet 4.5:**
- Input: $3 / 1M tokens
- Output: $15 / 1M tokens

### Estimated Cost per Audit

**Standard Scan (300s, ~200 tool calls):**
- Input: ~500K tokens (prompts + tool results)
- Output: ~50K tokens (responses + findings)
- **Opus: ~$11.25 per scan**
- **Sonnet: ~$2.25 per scan**

**Deep Scan (900s, ~1000 tool calls):**
- Input: ~2M tokens
- Output: ~200K tokens
- **Opus: ~$45 per scan**
- **Sonnet: ~$9 per scan**

**Recommendation:** Use Sonnet 4.5 for most scans, reserve Opus for complex/critical audits.

### Cost Controls

```python
# Budget alerts
if estimated_cost > budget_limit:
    raise BudgetExceededError()

# Track costs per project
cost_tracker.record(
    project_id=project_id,
    tokens_in=input_tokens,
    tokens_out=output_tokens,
    cost=calculated_cost
)

# Dashboard metrics
- Total spend per day/week/month
- Cost per finding
- Average scan cost by tier
```

---

## Monitoring & Observability

### Metrics to Track

**Performance:**
- Scan duration
- Tool calls per scan
- Tokens consumed (input/output)
- Findings per scan
- Time to first finding

**Quality:**
- False positive rate
- Finding severity distribution
- Tool execution errors
- Policy violations caught

**Cost:**
- Total API spend
- Cost per scan
- Cost per finding
- Budget utilization

### Logging Strategy

```python
logger.info(
    "agentic_scan_started",
    extra={
        "agent_id": agent_id,
        "repo_id": repo_id,
        "scan_tier": scan_tier,
        "model": model,
    }
)

logger.info(
    "tool_executed",
    extra={
        "tool_name": tool_name,
        "execution_time_ms": elapsed_ms,
        "result_size_bytes": len(result),
    }
)

logger.info(
    "agentic_scan_complete",
    extra={
        "agent_id": agent_id,
        "duration_sec": duration,
        "tool_calls": tool_call_count,
        "findings": len(findings),
        "tokens_in": input_tokens,
        "tokens_out": output_tokens,
        "cost_usd": cost,
    }
)
```

---

## Future Enhancements

### Phase 2 Features

**Multi-Agent Collaboration:**
- Spawn specialized agents for different vulnerability classes
- Aggregate findings from multiple agents
- Parallel exploration of different code paths

**Learning & Feedback:**
- Track false positives/negatives
- Fine-tune prompts based on feedback
- Build vulnerability pattern library

**Interactive Mode:**
- User can steer audit mid-execution
- Ask questions about findings
- Request deeper analysis of specific areas

**Advanced Tools:**
- Symbolic execution integration
- Dynamic analysis (sandboxed execution)
- Differential analysis (compare versions)

### Phase 3 Optimizations

**Caching:**
- Cache file contents
- Cache tool results for unchanged files
- Prompt caching for system prompts

**Parallelization:**
- Parallel tool execution where safe
- Batch tool calls in single API request
- Multiple agent instances for large codebases

**Smart Exploration:**
- Coverage-guided exploration
- Risk-based prioritization
- Learn from previous scans

---

## Migration Path

### From Existing Agents

**Quick Audit Agent:**
- Keep for fast pattern-based scans
- Use as pre-filter for agentic audit
- Complement, don't replace

**Deep Audit Agent:**
- Gradually migrate to agentic approach
- Compare results side-by-side
- Validate finding quality before full migration

### Rollout Strategy

1. **Alpha (Internal Testing)**
   - Test on known vulnerable codebases
   - Validate finding quality
   - Tune prompts and tool set

2. **Beta (Limited Release)**
   - Opt-in for power users
   - Gather feedback on UX
   - Monitor costs and performance

3. **General Availability**
   - Default for standard/deep scans
   - Documentation and tutorials
   - Cost visibility and controls

---

## Success Criteria

### Technical Metrics

- ✅ Scan completes successfully for 95%+ of repositories
- ✅ Average scan duration within tier budget ±20%
- ✅ Tool execution success rate >98%
- ✅ Zero policy violations in production

### Quality Metrics

- ✅ False positive rate <20%
- ✅ Finds 80%+ of known test vulnerabilities
- ✅ Severity classification accuracy >85%
- ✅ Actionable remediation advice for >90% of findings

### Cost Metrics

- ✅ Average cost per scan <$3 for standard tier
- ✅ Cost per true positive finding <$5
- ✅ Monthly budget overruns <5%

### User Experience

- ✅ Real-time progress visibility
- ✅ Clear finding explanations
- ✅ No silent failures or hangs
- ✅ Ability to pause/resume/cancel

---

## Conclusion

This design provides a production-ready path to integrate Claude's agentic capabilities into quick_hack using the Anthropic SDK. The approach is:

- **Simple:** No ACP complexity, standard HTTP API
- **Secure:** WorkspacePolicy enforcement, offline-first, no network tools
- **Scalable:** Supports quick→deep scan tiers with appropriate budgets
- **Observable:** Comprehensive logging, metrics, cost tracking
- **Incremental:** Phases allow validation before full rollout

The key insight is that the Anthropic SDK's native tool use provides 80% of the value of a full ACP integration with 20% of the complexity.

---

## Ready for Implementation

This design is approved and ready for implementation in an isolated git worktree. Next steps:

1. Create feature branch: `feature/anthropic-agentic-integration`
2. Implement Phase 1 (MVP provider and tools)
3. Add tests
4. Validate with test repository
5. Iterate based on results

---

**Design Approved By:** [User]
**Date:** 2026-01-12
**Next Review:** After Phase 1 implementation

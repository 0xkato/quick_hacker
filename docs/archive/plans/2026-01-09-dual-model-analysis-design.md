# Dual-Model Security Analysis Design

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:writing-plans to create an implementation plan from this design.

**Goal:** Enable ReActSecurityAgent to use a cheap/fast model for scanning and context gathering, then hand off to an expensive/capable model for security analysis and finding generation.

**Architecture:** Two-phase agent with structured handoff state. Scanner collects entry points, sinks, and code snippets. Analyzer receives this state (not conversation history) and performs data flow tracing and validation.

**Tech Stack:** Python dataclasses for handoff state, existing provider infrastructure, WebSocket events for phase transitions.

---

## Core Concept

The ReActSecurityAgent will support two-phase analysis using different models:

1. **Scanner Phase** (cheap/fast model): Handles exploration, attack surface mapping, and sink identification. Reads files, searches code, builds understanding of the codebase structure. All tool calls (read_file, grep_search, pattern_scan) happen here.

2. **Analyzer Phase** (expensive/capable model): Takes a structured handoff state and performs data flow tracing, validation, and finding generation. No file reading needed - works from the context the scanner prepared.

**Handoff Control:**
- `handoff_after: "sink_identification"` (default) - Scanner does phases 1-3, maximum cost savings
- `handoff_after: "exploration"` - Scanner does only phase 1, analyzer gets more control

**Model Configuration:**
- `scanner_config`: ProviderConfig for the cheap model
- `analyzer_config`: ProviderConfig for the expensive model
- Backwards compatible: existing `provider_config` alone = single-model mode

---

## Handoff State Object

The scanner builds a structured state that gets passed to the analyzer. This replaces conversation history - the analyzer starts fresh with just this context.

### ScannerHandoffState Structure

```python
@dataclass
class ScannerHandoffState:
    # What was scanned
    repo_path: str
    files_read: list[FileReadRecord]  # path, relevance_score, summary

    # Tech context
    tech_stack: TechStack  # languages, frameworks, dependencies

    # Attack surface (always populated)
    entry_points: list[EntryPoint]  # route/handler, file:line, method, code_snippet

    # Sinks (populated if handoff_after="sink_identification")
    dangerous_sinks: list[Sink]  # type (sql/exec/eval/etc), file:line, code_snippet, context

    # Scanner's observations
    file_map: dict[str, FileInfo]  # path → {relevance, summary, read_at}

    # Metadata
    scanner_model: str
    scanner_tokens_used: int
    scanner_duration_ms: int
    handoff_reason: str  # "exploration_complete" or "sink_identification_complete"
```

Code snippets include ~20 lines around each entry point/sink so the analyzer has immediate context without re-reading files.

---

## Configuration & API Changes

### Updated AgentCreateRequest Schema

```python
class AgentCreateRequest(BaseModel):
    repo_path: str
    agent_type: AgentType

    # Existing (backwards compatible)
    provider_config: Optional[ProviderConfig] = None

    # New dual-model config
    scanner_config: Optional[ProviderConfig] = None
    analyzer_config: Optional[ProviderConfig] = None
    handoff_after: Literal["exploration", "sink_identification"] = "sink_identification"
```

### Resolution Logic

1. If `provider_config` only → single-model mode (current behavior)
2. If `analyzer_config` only → auto-select scanner:
   - Anthropic analyzer → `claude-3-5-haiku` scanner
   - OpenAI analyzer → `gpt-4o-mini` scanner
   - Ollama analyzer → same model (no cheap tier)
3. If both `scanner_config` + `analyzer_config` → use as specified
4. If `scanner_config` only → error (doesn't make sense without analyzer)

### New WebSocket Events

- `PHASE_HANDOFF` - Emitted when scanner completes and analyzer takes over
- Includes: `scanner_tokens`, `scanner_duration`, `sinks_found`, `entry_points_found`

---

## Agent Flow Changes

### Modified ReActSecurityAgent.run() Flow

```
1. INITIALIZATION
   ├─ Resolve scanner_config and analyzer_config
   ├─ Create scanner provider instance
   ├─ Create analyzer provider instance (lazy - not used until handoff)
   └─ Initialize empty ScannerHandoffState

2. SCANNER PHASE (using scanner provider)
   ├─ Exploration: Map codebase, identify tech stack
   ├─ IF handoff_after == "exploration": GOTO HANDOFF
   ├─ Attack Surface Mapping: Find entry points, collect code snippets
   ├─ Sink Identification: Find dangerous functions, collect code snippets
   └─ GOTO HANDOFF

3. HANDOFF
   ├─ Finalize ScannerHandoffState with all collected data
   ├─ Emit PHASE_HANDOFF WebSocket event
   ├─ Log scanner metrics (tokens, duration, findings)
   └─ Switch active provider to analyzer

4. ANALYZER PHASE (using analyzer provider)
   ├─ Inject handoff state as system context (not conversation history)
   ├─ Data Flow Tracing: Trace inputs from entry points to sinks
   ├─ Validation: Verify exploitability
   └─ Reporting: Generate findings with evidence

5. COMPLETION
   └─ Aggregate metrics from both phases
```

The analyzer gets a fresh conversation with the handoff state injected as a structured system prompt, not as prior messages. This keeps token usage minimal.

---

## Scanner vs Analyzer Behavior

### Scanner Phase Prompt Focus

The scanner gets a modified system prompt optimized for fast context gathering:

- "Your job is to MAP the codebase, not analyze vulnerabilities yet"
- "Find all entry points and dangerous sinks"
- "Collect code snippets around interesting locations"
- "Be thorough but fast - another model will do deep analysis"
- No finding generation - just data collection

**Scanner tools:** All current tools (read_file, grep_search, pattern_scan, list_files, etc.)

### Analyzer Phase Prompt Focus

The analyzer gets a different prompt optimized for security reasoning:

- "You have a complete map of the codebase" (handoff state injected)
- "Entry points, sinks, and code snippets are provided - don't re-read files"
- "Trace data flows from user input to dangerous sinks"
- "Only report HIGH confidence findings with full evidence"

**Analyzer tools:** Limited set - maybe just `read_file` for edge cases where more context needed, but discouraged. The goal is zero tool calls in ideal case.

---

## Error Handling & Edge Cases

### What if scanner finds nothing?

- If no entry points found after exploration → log warning, continue to analyzer anyway (might be a library/utility codebase)
- If no sinks found after sink identification → handoff with empty sinks list, analyzer can still look for logic bugs

### What if scanner hits token/iteration limit?

- Handoff immediately with partial state
- Mark `handoff_reason: "limit_reached"` so analyzer knows context may be incomplete
- Analyzer can request additional file reads if critical context missing

### What if analyzer needs a file not in handoff state?

- Keep `read_file` tool available but log when used (indicates scanner missed something)
- Track "analyzer_extra_reads" metric to tune scanner behavior over time

### Rate limiting / API errors

- Each provider has independent retry logic
- If scanner provider fails permanently → fall back to analyzer-only mode with no handoff state
- If analyzer provider fails → standard error handling, no special recovery

### Cost tracking

- Track separately: `scanner_cost`, `analyzer_cost`, `total_cost`
- Emit in final metrics so users can see the split

---

## Files Changed

| File | Action |
|------|--------|
| `backend/models/schemas.py` | Add ScannerHandoffState, update AgentCreateRequest |
| `backend/agents/react_agent.py` | Implement dual-phase flow, handoff logic |
| `backend/agents/prompts/scanner_prompt.py` | New scanner-specific system prompt |
| `backend/agents/prompts/analyzer_prompt.py` | New analyzer-specific system prompt |
| `backend/services/agent_orchestrator.py` | Handle new config resolution logic |
| `backend/routers/websocket.py` | Add PHASE_HANDOFF event type |
| `frontend/types/index.ts` | Add handoff state types |
| `frontend/components/` | Display phase transition in UI (optional) |

---

## Expected Benefits

- **60-80% cost reduction** on exploration phases (cheap model reads files instead of expensive one)
- **Faster scanning** with lightweight models (lower latency per API call)
- **Better analysis quality** (expensive model focuses purely on security reasoning, not file reading)
- **Flexibility** (mix providers - e.g., GPT-4o-mini scanning + Claude Opus analysis)

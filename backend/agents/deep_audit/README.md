# Deep Audit System

A multi-agent orchestration system for automated security vulnerability auditing. The system spawns specialized sub-agents using Claude CLI to perform parallel code analysis, leveraging the "Gas Town" approach where agents authenticate through the user's Claude Code subscription rather than API keys.

## Architecture Overview

```
                                    +-------------------+
                                    |     Overseer      |
                                    | (Orchestrator)    |
                                    +--------+----------+
                                             |
                     +-----------------------+-----------------------+
                     |                       |                       |
                     v                       v                       v
          +----------+-------+    +----------+---------+   +---------+---------+
          |  Foundation      |    |     Hunting        |   |   Signal Routing  |
          |  Phase           |    |     Phase          |   |   Pipeline        |
          +------------------+    +--------------------+   +-------------------+
          | - RepoProfiler   |    | - SinkHunter (8)   |   | - Pre-screen      |
          | - ScopeMapper    |    | - EntrypointHunter |   | - Decider         |
          | - ThreatModeler  |    | - InvariantHunter  |   | - DataflowTracer  |
          +------------------+    | - TrustBoundary    |   | - Coordinator     |
                                  |   GapHunter        |   | - Specialist (64) |
                                  +--------------------+   | - Devil's Advocate|
                                                           | - Triager         |
                                                           +-------------------+
                                             |
                                    +--------v----------+
                                    |  WaveDispatcher   |
                                    | (Parallel spawn)  |
                                    +--------+----------+
                                             |
                         +-------------------+-------------------+
                         |                   |                   |
                    Claude CLI          Claude CLI          Claude CLI
                    (Sub-agent)         (Sub-agent)         (Sub-agent)
```

## Signal Routing Pipeline

Every signal discovered by hunters passes through a 7-stage routing pipeline. Each stage adds to the signal's context — never overwrites.

```
Signal from Hunter
       |
       v
  [Pre-screen] -----> Confidence adjustment (guards, language mismatch)
       |
       v
  [Pre-check] ------> Skip if previously dismissed (fingerprint cache)
       |
       v
  [Stage 1: Decider] -> Should we investigate? (dismiss or proceed)
       |
       v
  [Stage 1.5: DataflowTracer] -> Build verified source-to-sink trace
       |                           Produces TraceStep[] and GuardInfo[]
       |                           System computes trace_quality (0.0-1.0)
       v
  [Stage 2: FamilyCoordinator] -> Which specialist? What context?
       |                           Uses verified trace for routing
       v
  [Stage 3: Specialist] --------> Technical vulnerability verification
       |                           Builds on verified trace (not from scratch)
       v
  [Stage 4: Devil's Advocate] --> Challenge quick dismissals (optional)
       |                           High-severity + fast dismiss = re-examine
       v
  [Stage 5: Triager] -----------> Final classification
                                   Enforces trace quality gates
                                   SECURITY_VULNERABILITY | BUG | HARDENING |
                                   MISCONFIGURATION | BY_DESIGN | SPECULATIVE
```

### Trace Quality Enforcement

The system (not the LLM) computes a trace quality score for each signal:

| Component | Score | Condition |
|-----------|-------|-----------|
| Has source step | +0.3 | `role: "source"` in trace_steps |
| Has sink step | +0.3 | `role: "sink"` in trace_steps |
| Steps have file:line | +0.2 | All steps have valid file_path + line_number |
| Guards have code evidence | +0.1 | At least one guard has non-empty code_snippet |
| Multi-step trace | +0.1 | 3+ trace steps (not just source+sink) |

**Quality gates:**
- `>= 0.8` — High quality. Specialists and triager can rely on the trace.
- `0.5 - 0.8` — Partial trace. Specialists warned to verify independently.
- `< 0.5` — Incomplete. Triager MUST read code before confirming.

### Structured Trace Schema

**TraceStep** — A single verified step in a source-to-sink data flow trace:
```python
@dataclass
class TraceStep:
    file_path: str        # Exact file path
    line_number: int      # Exact line number
    function_name: str    # Function/method containing this step
    code_snippet: str     # Actual code from tool reads
    role: str             # "source" | "propagation" | "transform" | "guard" | "sink"
    variable: str         # Variable carrying tainted data
    note: str             # Optional explanation
```

**GuardInfo** — A guard/sanitization found along the trace path:
```python
@dataclass
class GuardInfo:
    file_path: str
    line_number: int
    guard_type: str       # "validation" | "sanitization" | "authorization" | "bounds_check" | "type_check"
    code_snippet: str     # Actual guard code
    description: str
    effectiveness: str    # "effective" | "partial" | "bypassable"
    bypass_reason: str    # Why it can be bypassed, if applicable
```

## Core Components

### 1. Overseer (`overseer.py`)

The **Overseer** is the main orchestrator that runs the entire audit campaign. It:

- Initializes the campaign state and time budget based on scan tier
- Runs the audit in phases: Foundation -> Hunting -> Signal Routing -> Finalize
- Dispatches sub-agents in parallel "waves"
- Routes every signal through the 7-stage pipeline
- Collects findings and generates the final report

**Key Features:**
- Time budget management with scan tiers
- 7-stage signal routing pipeline with trace enforcement
- SignalFlowTracker for pipeline health reporting
- Specialist confidence calibration
- Flow visualization via the flow_service for UI updates
- Always uses Claude Opus 4.6 for all agents

**Execution Flow:**
```
1. Phase 1: FOUNDATION
   - dispatch_foundation_phase() -> runs RepoProfiler, ScopeMapper, ThreatModeler in parallel
   - Builds FoundationContext for downstream agents

2. Phase 2: HUNTING
   - Dispatch 11 specialized hunters (rotating through vulnerability focus areas)
   - Collect SuspiciousSignal objects with best-effort trace_steps

3. Phase 3: SIGNAL ROUTING (per signal)
   - Pre-screen: Adjust confidence based on structured guards
   - Decider: Should we investigate?
   - DataflowTracer: Build verified source-to-sink trace
   - FamilyCoordinator: Select specialist + gather context
   - Specialist: Technical verification (builds on verified trace)
   - Devil's Advocate: Challenge quick dismissals of high-severity
   - Triager: Final classification with trace quality enforcement

4. Phase 4: FINALIZE
   - Generate final report with pipeline health stats
   - Process confirmed findings
   - Print SignalFlowTracker report
```

**Scan Tier Budgets:**
```python
SCAN_TIER_BUDGETS = {
    "quick": 300,           # 5 minutes
    "medium": 900,          # 15 minutes
    "standard": 900,        # 15 minutes (alias)
    "advanced": 2700,       # 45 minutes
    "deep": 2700,           # 45 minutes (alias)
    "pro": 5400,            # 90 minutes
    "exhaustive": 5400,     # 90 minutes (alias)
    "ultra": 14400,         # 4 hours
    "evil": 86400,          # 24 hours
}
```

### 2. Dispatcher (`dispatcher.py`)

The **WaveDispatcher** handles spawning sub-agents in parallel using Claude CLI.

**The Gas Town Approach:**
- Uses `claude -p` (print mode) to spawn non-interactive Claude CLI processes
- Authenticates through the user's Claude Code subscription (no API keys needed)
- Each sub-agent runs as a separate process with its own tool subset
- Foundation context injected via `--append-system-prompt` (subprocesses cannot access parent's ContextVars or virtual filesystem)

**Key Methods:**
```python
# Dispatch a wave of parallel tasks
await dispatcher.dispatch_wave(wave_plan, foundation_context)

# Dispatch a single task
await dispatcher.dispatch_single(task, foundation_context)

# Run Foundation Phase (RepoProfiler, ScopeMapper, ThreatModeler)
result, context = await dispatcher.dispatch_foundation_phase()
```

**CLI Command Built:**
```bash
claude -p \
  --model claude-opus-4-6 \
  --permission-mode bypassPermissions \
  --tools Read,Glob,Grep,Bash \
  --append-system-prompt "..." \
  --output-format stream-json \
  --no-session-persistence \
  --verbose \
  "Execute this task: ..."
```

**Tool Subsets by Agent Type:**
```python
AGENT_TOOL_SUBSETS = {
    "RepoProfiler": ["read_file", "list_directory", "search_code", "get_repo_tree"],
    "ScopeMapper": ["read_file", "list_directory", "search_code", "get_file_structure"],
    "SinkHunter": ["read_file", "search_code", "grep_semantic", "get_file_structure"],
    "DataflowTracer": ["read_file", "get_file_structure", "trace_data_flow", "find_usages"],
    "EntrypointHunter": ["read_file", "search_code", "grep_semantic", "get_entry_points"],
    # ... etc
}
```

### 3. State Management (`state.py`)

**CampaignState** tracks the entire audit lifecycle:

- **Project context:** project_id, scan_tier, deadline, started_at
- **Foundation Context:** repo_profile, scope_map, threat_model
- **Tracking:** hypotheses, signals (with SignalState), scopes, entrypoints
- **Results:** confirmed_findings (with dedup fingerprints), dismissed
- **Waves:** current_wave, wave_history, coverage_map

**Campaign Phases:**
```python
class CampaignPhase(str, Enum):
    FOUNDATION = "foundation"   # Building context
    HUNTING = "hunting"         # Finding signals
    ROUTING = "routing"         # Assigning to specialists
    VERIFICATION = "verification"  # Specialists analyzing
    RESOLUTION = "resolution"   # Final triage
```

**Signal Status Lifecycle:**
```
NEW -> ROUTED -> ASSIGNED -> ANALYZING -> VERIFIED/DISMISSED/DISPUTED -> TRIAGED
```

### 4. Virtual Filesystem (`filesystem.py`)

**MemoriesFilesystem** provides a virtual filesystem with two namespaces:

- `/repo/*` - Read-only access to the repository being scanned
- `/memories/*` - Writable access to agent artifacts

**Security:**
- Path traversal protection using `resolve().relative_to()` validation
- Namespace validation (must start with `/repo/` or `/memories/`)

**Standard Directories in /memories/:**
```
/memories/
  overseer/           # Wave syntheses, campaign state
  scopes/             # Per-scope summaries and signals
  traces/             # DataflowTracer outputs (per-signal trace JSON)
  triage/             # Triage verdicts
  audits/             # Auditor outputs
  findings/           # Confirmed findings
  foundation/         # Foundation phase outputs
  signals/            # Hunter outputs
  waves/              # Per-wave outputs
  calibration/        # Specialist calibration data
```

### 5. Foundation Context (`foundation.py`)

Built during the Foundation Phase and injected into all downstream agents.

**RepoProfile:**
- Languages, frameworks, build system
- Entry point files
- Total files/lines

**ScopeMap:**
- Security-critical paths (auth, crypto, API handlers)
- Test code patterns (to exclude)
- Vendor/generated code patterns (to exclude)

**ThreatModel:**
- Trust boundaries (internet -> app -> database)
- Attacker capabilities (network_access, unauthenticated, authenticated, admin)
- In-scope and out-of-scope paths with reasons

**SuspiciousSignal** — Core schema for signals passing through the pipeline:
```python
@dataclass
class SuspiciousSignal:
    signal_id: str
    title: str
    category: SignalCategory    # sql_injection, xss, command_injection, etc.
    severity: SignalSeverity    # critical, high, medium, low, info
    confidence: float           # 0.0-1.0
    file_path: str
    line_start: int
    # ... existing fields ...

    # Structured trace fields (new)
    trace_steps: list[dict]     # List of TraceStep.to_dict()
    guards: list[dict]          # List of GuardInfo.to_dict()
    trace_verified: bool        # True after DataflowTracer runs
    trace_quality: float        # 0.0-1.0, system-computed
```

### 6. Signal Flow Tracker (`signal_flow_tracker.py`)

Instruments every decision point in the routing pipeline and produces a clear end-of-scan health report showing where signals were dropped and why.

**Pipeline Health Report Example:**
```
=======================================================
  PIPELINE HEALTH REPORT
=======================================================
  Signals Entered:      47
  |-- Pre-check Skip:    3  (previously dismissed)
  |-- Routed:           44
  |
  Routing Outcomes:
  |-- Decider Dismiss:  12
  |-- Dataflow Drop:     5
  |-- Coordinator Skip:  2
  |-- Specialist Rej:    8
  |-- Triager Dismiss:   4
  |-- Verified:         13
  |   |-- BUG: 3
  |   |-- HARDENING: 2
  |   |-- SECURITY_VULNERABILITY: 8
  |
  Triager Parse Health:
  |-- JSON OK:          13
  |-- Markdown Fallback: 0
  |-- Parse Failure:     0
  |
  Persistence:
  |-- Saved to DB:      13
  |-- UNVERIFIED Block:  0
  |-- Dedup Caught:      2
  |-- DB Error:          0
=======================================================
```

### 7. Calibration System (`calibration.py`)

Tracks specialist accuracy over time and uses historical performance to weight verdicts.

**SpecialistStats** tracks per-specialist:
- Accuracy, precision, recall
- Dismissal rate, quick dismissal rate
- False negative rate
- Average analysis time and confidence

**Trust Weight Adjustments:**
- High accuracy (>80%) → +0.2 bonus
- Low accuracy (<60%) → -0.3 penalty
- High dismissal rate (>80%) → -0.2 penalty
- Result: trust weight range 0.5 to 1.5

**Calibration Alerts:**
- `high_dismissal_rate` — Specialist dismissing >80% of signals
- `low_accuracy` — Specialist accuracy below 60%
- `quick_dismissal_rate` — >50% of dismissals happen in under 30 seconds

## Sub-Agent Types

### Foundation Phase

| Agent | Purpose | Output |
|-------|---------|--------|
| **RepoProfiler** | Maps repository structure, languages, frameworks | `/memories/foundation/repo_profile.json` |
| **ScopeMapper** | Identifies security-critical vs test/vendor code | `/memories/foundation/scope_map.json` |
| **ThreatModeler** | Builds threat model with trust boundaries | `/memories/foundation/threat_model.json` |

### Hunting Phase (11 Hunter Types)

| Agent | Purpose | Focus |
|-------|---------|-------|
| **SinkHunter** | Generic dangerous sink detection | SQL, exec, file ops, eval |
| **MemorySinkHunter** | Memory safety vulnerabilities | Buffer overflow, use-after-free, integer overflow |
| **InjectionSinkHunter** | Injection vulnerabilities | SQL, command, template, LDAP injection |
| **WebSinkHunter** | Web application vulnerabilities | SSRF, request smuggling, open redirect |
| **CryptoSinkHunter** | Cryptographic vulnerabilities | Weak algorithms, key management, randomness |
| **AuthLogicHunter** | Authentication/authorization flaws | Auth bypass, privilege escalation, IDOR |
| **DeserializationSinkHunter** | Unsafe deserialization | Pickle, YAML, XML, JSON deserialization |
| **RaceConditionHunter** | Concurrency vulnerabilities | TOCTOU, race conditions, resource exhaustion |
| **InvariantViolationHunter** | Invariant violations | State corruption, logic errors |
| **TrustBoundaryGapHunter** | Trust boundary issues | Missing auth checks, privilege boundaries |
| **EntrypointHunter** | Entry point detection | HTTP routes, CLI handlers, message consumers |

All hunters output structured `trace_steps` and `guards` fields (best-effort). The DataflowTracer verifies and completes these traces.

### Routing Pipeline Agents

| Agent | Purpose | Output |
|-------|---------|--------|
| **Decider** | Decide whether to investigate a signal | `investigate` or `dismiss` |
| **DataflowTracer** | Build verified source-to-sink trace | TraceStep[] + GuardInfo[] |
| **FamilyCoordinator** | Select specialist family + gather context | Specialist assignment + context |
| **Specialist** (64 types) | Verify specific vulnerability category | `vulnerable` / `not_vulnerable` verdict |
| **Devil's Advocate** | Challenge quick dismissals | Re-examination verdict |
| **Triager** | Final classification | SECURITY_VULNERABILITY / BUG / HARDENING / etc. |

### Resolution Phase

| Agent | Purpose | Output |
|-------|---------|--------|
| **Arbiter** | Resolves specialist disagreements | Final verdict on disputed signals |
| **Auditor** | Deep-dive verification of specific signals | Case-by-case verdicts |

## Specialist Families

The system has **14 specialist families** with **64 total specialists**:

| Family | Specialists | Signal Types |
|--------|-------------|--------------|
| Memory Safety | 8 | buffer_overflow, use_after_free, integer_overflow, format_string |
| Injection | 10 | sql_injection, command_injection, template_injection, ldap_injection |
| Web Edge Cases | 4 | ssrf, request_smuggling, cache_poisoning |
| Browser/Client | 4 | xss, prototype_pollution, clickjacking |
| Deserialization | 6 | unsafe_deserialization, xxe, zip_slip, redos |
| File System | 4 | path_traversal, file_upload, symlink attacks |
| AuthN/Session | 5 | auth_bypass, session_fixation, csrf, oauth, jwt |
| AuthZ/Business Logic | 5 | idor, privilege_escalation, workflow_bypass |
| Crypto/Secrets | 4 | crypto_misuse, weak_randomness, secrets_exposure |
| Infrastructure | 4 | container security, kubernetes, ci/cd |
| Supply Chain | 3 | dependency confusion, plugin security |
| Concurrency | 2 | race_condition, resource_exhaustion |
| Data Exposure | 2 | sensitive_data_exposure, token_in_url |
| API Design | 3 | mass_assignment, parameter_pollution, graphql |

## Devil's Advocate System

The pipeline includes a **Devil's Advocate** challenge mechanism for high-severity signals that get dismissed too quickly:

```python
# Automatic challenge for quick dismissals
should_challenge, challenge_type = dispatcher.should_challenge_result(
    result, analysis_time_seconds, signal_severity
)

# Dispatch with potential challenge
final_result, challenges = await dispatcher.dispatch_with_challenge(
    task, foundation_context, signal_severity="HIGH"
)
```

Challenge types:
- `quick_dismissal`: Specialist dismissed too fast
- `incomplete_analysis`: Missing entry points or paths
- `missing_context`: Didn't consider system context
- `weak_confirmation`: DA challenges weak confirmations — if specialist says "vulnerable" but with low confidence or weak evidence, DA verifies the claim

## Tools

### Dispatch Tools (`tools/dispatch.py`)

```python
# Run Foundation Phase (MUST be called first)
DISPATCH_FOUNDATION_PHASE_TOOL
result = await dispatch_foundation_phase()

# Dispatch a wave of parallel tasks
DISPATCH_WAVE_TOOL
result = await dispatch_wave(wave_plan_json)

# Dispatch a single agent
DISPATCH_AGENT_TOOL
result = await dispatch_agent(agent_type, objective, scope, deliverable)
```

### Memory Tools (`tools/memories.py`)

```python
# Read an artifact
READ_MEMORIES_TOOL
content = read_memories("/memories/signals/sinks.json")

# List directory contents
LIST_MEMORIES_TOOL
contents = list_memories("/memories/overseer/")

# Write wave synthesis
WRITE_SYNTHESIS_TOOL
write_synthesis(wave_id=1, synthesis_content="...")

# Write arbitrary artifact
WRITE_ARTIFACT_TOOL
write_artifact("/memories/threat_model.md", content)
```

### Finalize Tools (`tools/finalize.py`)

```python
# Update campaign state
UPDATE_CAMPAIGN_STATE_TOOL
update_campaign_state(state_update_json)

# Generate final report
FINALIZE_REPORT_TOOL
finalize_report("Additional notes...")
```

## Data Flow

```
1. User starts scan with scan_tier and repo_path
        |
        v
2. Overseer initializes:
   - CampaignState (with deadline based on tier)
   - MemoriesFilesystem
   - WaveDispatcher
   - SignalFlowTracker
   - CalibrationStore
        |
        v
3. Foundation Phase (parallel):
   RepoProfiler -> /memories/foundation/repo_profile.json
   ScopeMapper  -> /memories/foundation/scope_map.json
   ThreatModeler -> /memories/foundation/threat_model.json
        |
        v
4. Build FoundationContext from outputs
   (injected into all subsequent agents via --append-system-prompt)
        |
        v
5. Hunting Phase (parallel, rotating focus areas):
   11 hunter types -> SuspiciousSignal objects with trace_steps/guards
        |
        v
6. Signal Routing Pipeline (per signal):
   Pre-screen -> Decider -> DataflowTracer -> FamilyCoordinator
   -> Specialist -> Devil's Advocate -> Triager
   Each stage tracked by SignalFlowTracker
        |
        v
7. Persistence:
   - Deduplicate against existing findings (fingerprint: file_path + line_start + category)
   - Block UNVERIFIED signals from persistence
   - Save to database via findings_service
        |
        v
8. Finalize:
   - Generate /memories/overseer/final_report.md
   - Print pipeline health report
   - Flush calibration data
   - Emit findings to frontend
```

## How to Extend

### Adding a New Agent Type

1. **Define the prompt** in `subagents.py`:
```python
NEW_AGENT_PROMPT = """You are a NewAgent subagent for security audit.

{{FOUNDATION_CONTEXT}}

## Task
Your specific task description...

## Output
When done, output ONLY the following JSON:
```json
{
  "results": [...]
}
```
"""

# Add to AGENT_PROMPTS dict
AGENT_PROMPTS["NewAgent"] = NEW_AGENT_PROMPT
```

2. **Define tool subset** in `dispatcher.py`:
```python
AGENT_TOOL_SUBSETS = {
    # ... existing agents
    "NewAgent": ["read_file", "search_code", "grep_semantic"],
}
```

3. **Use the agent** from Overseer:
```python
task = DispatchTask(
    agent_type="NewAgent",
    objective="Do something specific",
    scope=self.repo_path_str,
    deliverable="/memories/new_agent_output.json",
    time_budget=300,
)
result = await self.dispatcher.dispatch_single(task)
```

### Adding a New Specialist

1. **Add to registry** in `specialists/registry.py`:
```python
SpecialistInfo(
    id="new_vulnerability_auditor",
    name="New Vulnerability Auditor",
    family=SpecialistFamily.INJECTION,  # Or appropriate family
    triggers=[SignalCategory.NEW_CATEGORY],
    proficiency="Expert at detecting new vulnerability type...",
),
```

2. **Add signal category** in `foundation.py` if needed:
```python
class SignalCategory(Enum):
    # ... existing categories
    NEW_CATEGORY = "new_category"
```

3. **Map category to family** in `specialists/registry.py`:
```python
CATEGORY_TO_FAMILY: dict[SignalCategory, SpecialistFamily] = {
    # ... existing mappings
    SignalCategory.NEW_CATEGORY: SpecialistFamily.INJECTION,
}
```

### Adding a New Scan Tier

In `overseer.py`:
```python
SCAN_TIER_BUDGETS = {
    # ... existing tiers
    "new_tier": 7200,  # 2 hours
}
```

## WebSocket Events

The Overseer emits events for UI visibility:

| Event Type | Data |
|------------|------|
| `PROGRESS` (wave_progress) | wave, status, tasks_count, hypotheses_count, findings_count, time_remaining |
| `PROGRESS` (subagent_start) | wave, task_id, agent_type |
| `PROGRESS` (subagent_complete) | wave, task_id, agent_type, status |
| `AGENT_STATUS` | agent_id, name, agent_type, status, objective, error |
| `FINDING` | Finding object with title, severity, file_path, etc. |

## Configuration

The Overseer uses:
- **Model:** `claude-opus-4-6` (Opus for all agents)
- **Auth:** Claude Code subscription (Gas Town approach, no API keys)
- **Permission mode:** `bypassPermissions`
- **Session persistence:** Disabled (`--no-session-persistence`)
- **Output format:** `stream-json` with `--verbose`

## File Structure

```
agents/deep_audit/
  __init__.py               # Package exports
  overseer.py               # Main orchestrator + signal routing pipeline
  dispatcher.py             # Wave dispatcher (Claude CLI spawning)
  state.py                  # Campaign state management
  filesystem.py             # Virtual filesystem (/repo/, /memories/)
  foundation.py             # FoundationContext + TraceStep + GuardInfo + SuspiciousSignal
  subagents.py              # Sub-agent prompt templates (11 hunters, specialists, triager)
  calibration.py            # Specialist confidence calibration system
  signal_flow_tracker.py    # Pipeline health reporting
  specialists/
    __init__.py
    registry.py             # 64 specialists in 14 families
  tools/
    __init__.py
    dispatch.py             # Dispatch tools for Overseer
    memories.py             # Memory read/write tools
    finalize.py             # Report generation tools
  utils/
    json_extractor.py       # JSON extraction from LLM output
```

## Testing

Tests are in `tests/agents/deep_audit/` (154+ tests):
- `test_campaign_state.py` - CampaignState functionality
- `test_filesystem.py` - MemoriesFilesystem security and operations
- `test_foundation.py` - FoundationContext building + TraceStep/GuardInfo
- `test_specialist_registry.py` - Specialist routing
- `test_overseer_tools.py` - Tool execution
- `test_pipeline_integration.py` - End-to-end flow
- `test_calibration.py` - Specialist calibration system
- `test_signal_flow_tracker.py` - Pipeline health reporting
- `test_overseer_pipeline.py` - Signal routing pipeline stages

## Known Issues

- **Behavior Tree Persistence**: The LLM Behavior Tree (behavior_tree_service.py) is stored entirely in-memory. When navigating away from a session, tree data is lost. Fix requires: DB table, write-through persistence, load-from-DB on cache miss.

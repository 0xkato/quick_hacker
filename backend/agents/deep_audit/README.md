# Deep Audit System

A multi-agent orchestration system for automated security vulnerability auditing. The system spawns specialized sub-agents using Claude CLI to perform parallel code analysis, leveraging the "Gas Town" approach where agents authenticate through the user's Claude Code subscription rather than API keys.

## Architecture Overview

```
                                    +-------------------+
                                    |     Overseer      |
                                    | (Orchestrator)    |
                                    +--------+----------+
                                             |
                         +-------------------+-------------------+
                         |                   |                   |
                         v                   v                   v
              +----------+-------+  +--------+---------+  +------+----------+
              |  Foundation      |  |    Hunting       |  |  Verification   |
              |  Phase           |  |    Phase         |  |  Phase          |
              +------------------+  +------------------+  +-----------------+
              | - RepoProfiler   |  | - SinkHunter     |  | - DataflowTracer|
              | - ScopeMapper    |  | - EntrypointHunter| | - Specialists   |
              | - ThreatModeler  |  +------------------+  | - Arbiter       |
              +------------------+                        +-----------------+
                         |                   |                   |
                         +-------------------+-------------------+
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

## Core Components

### 1. Overseer (`overseer.py`)

The **Overseer** is the main orchestrator that runs the entire audit campaign. It:

- Initializes the campaign state and time budget based on scan tier
- Runs the audit in phases: Foundation -> Hunting -> Verification -> Finalize
- Dispatches sub-agents in parallel "waves"
- Collects findings and generates the final report

**Key Features:**
- Time budget management with scan tiers (quick: 5min, medium: 15min, advanced: 30min, pro: 1hr, ultra: 4hr, evil: 24hr)
- Flow visualization via the flow_service for UI updates
- Always uses Claude Opus 4.5 for all agents (configured in `provider_config`)

**Execution Flow:**
```
1. Phase 1: FOUNDATION
   - dispatch_foundation_phase() -> runs RepoProfiler, ScopeMapper, ThreatModeler in parallel
   - Builds FoundationContext for downstream agents

2. Phase 2: HUNTING
   - Dispatch SinkHunter + EntrypointHunter
   - Find dangerous sinks and entry points

3. Phase 3: WAVE LOOP
   - Continue dispatching waves until time budget exhausted
   - Rotate through vulnerability focus areas (injection, network, auth, crypto, etc.)
   - Every other wave runs DataflowTracer to verify signals

4. Phase 4: FINALIZE
   - Generate final report
   - Process confirmed findings
```

### 2. Dispatcher (`dispatcher.py`)

The **WaveDispatcher** handles spawning sub-agents in parallel using Claude CLI.

**The Gas Town Approach:**
- Uses `claude -p` (print mode) to spawn non-interactive Claude CLI processes
- Authenticates through the user's Claude Code subscription (no API keys needed)
- Each sub-agent runs as a separate process with its own tool subset

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
  --model claude-opus-4-5-20251101 \
  --permission-mode bypassPermissions \
  --tools Read,Glob,Grep,Bash \
  --system-prompt "..." \
  --output-format text \
  --no-session-persistence \
  "Execute this task: ..."
```

**Tool Subsets by Agent Type:**
```python
AGENT_TOOL_SUBSETS = {
    "RepoProfiler": ["read_file", "list_directory", "search_code", "get_repo_tree"],
    "SinkHunter": ["read_file", "search_code", "grep_semantic", "get_file_structure"],
    "DataflowTracer": ["read_file", "get_file_structure", "trace_data_flow", "find_usages"],
    # ... etc
}
```

### 3. State Management (`state.py`)

**CampaignState** tracks the entire audit lifecycle:

- **Project context:** project_id, scan_tier, deadline, started_at
- **Foundation Context:** repo_profile, scope_map, threat_model
- **Tracking:** hypotheses, signals, scopes, entrypoints
- **Results:** confirmed_findings, dismissed
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
  traces/             # Dataflow trace outputs
  triage/             # Triage verdicts
  audits/             # Auditor outputs
  findings/           # Confirmed findings
  foundation/         # Foundation phase outputs
  signals/            # Hunter outputs
  waves/              # Per-wave outputs
```

### 5. Foundation Context (`foundation.py`)

Built during the Foundation Phase and injected into all downstream agents:

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

**Usage:**
```python
# Check if a path is in scope for analysis
if foundation_context.is_in_scope("src/api/users.py"):
    # Analyze this file

# Check if path is security-critical (prioritize)
if foundation_context.is_security_critical("src/auth/jwt.py"):
    # Higher priority

# Serialize for agent prompt injection
context_text = foundation_context.to_prompt_context()
```

## Sub-Agent Types

### Foundation Phase

| Agent | Purpose | Output |
|-------|---------|--------|
| **RepoProfiler** | Maps repository structure, languages, frameworks | `/memories/foundation/repo_profile.json` |
| **ScopeMapper** | Identifies security-critical vs test/vendor code | `/memories/foundation/scope_map.json` |
| **ThreatModeler** | Builds threat model with trust boundaries | `/memories/foundation/threat_model.json` |

### Hunting Phase

| Agent | Purpose | Output |
|-------|---------|--------|
| **SinkHunter** | Finds dangerous sinks (SQL, exec, file ops) | `/memories/signals/sinks.json` |
| **EntrypointHunter** | Finds entry points (HTTP routes, CLI, etc.) | `/memories/signals/entrypoints.json` |

### Verification Phase

| Agent | Purpose | Output |
|-------|---------|--------|
| **DataflowTracer** | Traces data flow from source to sink | `/memories/waves/wave_N/dataflow_trace.json` |
| **AuthBoundaryMapper** | Maps authentication boundaries | `/memories/waves/wave_N/auth_boundaries.json` |
| **Specialists (64 types)** | Verify specific vulnerability categories | Per-signal verdicts |
| **Arbiter** | Resolves specialist disagreements | Final verdict on disputed signals |

### Resolution Phase

| Agent | Purpose | Output |
|-------|---------|--------|
| **Triager** | Final classification of verified signals | Finding severity/classification |
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

## Data Flow

```
1. User starts scan with scan_tier and repo_path
        |
        v
2. Overseer initializes:
   - CampaignState (with deadline based on tier)
   - MemoriesFilesystem
   - WaveDispatcher
        |
        v
3. Foundation Phase (parallel):
   RepoProfiler -> /memories/foundation/repo_profile.json
   ScopeMapper  -> /memories/foundation/scope_map.json
   ThreatModeler -> /memories/foundation/threat_model.json
        |
        v
4. Build FoundationContext from outputs
   (injected into all subsequent agents)
        |
        v
5. Hunting Phase (parallel):
   SinkHunter -> /memories/signals/sinks.json
   EntrypointHunter -> /memories/signals/entrypoints.json
        |
        v
6. Wave Loop (until time exhausted):
   - Dispatch focused SinkHunter waves (rotating vulnerability types)
   - Dispatch DataflowTracer to verify signals
   - Collect findings from wave outputs
        |
        v
7. Finalize:
   - Generate /memories/overseer/final_report.md
   - Convert confirmed_findings to Finding objects
   - Emit findings to frontend
```

## Devil's Advocate System

The dispatcher includes a **Devil's Advocate** challenge mechanism for high-severity signals that get dismissed too quickly:

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

The Overseer always uses:
- **Model:** `claude-opus-4-5-20251101` (Opus for all agents)
- **Auth:** Claude Code subscription (Gas Town approach, no API keys)
- **Permission mode:** `bypassPermissions`
- **Session persistence:** Disabled (`--no-session-persistence`)

## File Structure

```
agents/deep_audit/
  __init__.py           # Package exports
  overseer.py           # Main orchestrator
  dispatcher.py         # Wave dispatcher (Claude CLI spawning)
  state.py              # Campaign state management
  filesystem.py         # Virtual filesystem (/repo/, /memories/)
  foundation.py         # FoundationContext schema
  subagents.py          # Sub-agent prompt templates
  specialists/
    __init__.py
    registry.py         # 64 specialists in 14 families
  tools/
    __init__.py
    dispatch.py         # Dispatch tools for Overseer
    memories.py         # Memory read/write tools
    finalize.py         # Report generation tools
```

## Testing

Tests are in `tests/agents/deep_audit/`:
- `test_campaign_state.py` - CampaignState functionality
- `test_filesystem.py` - MemoriesFilesystem security and operations
- `test_foundation.py` - FoundationContext building
- `test_specialist_registry.py` - Specialist routing
- `test_overseer_tools.py` - Tool execution
- `test_pipeline_integration.py` - End-to-end flow

# Deep Agents Architecture Design

**Date:** 2026-02-02
**Status:** Approved
**Author:** mayor + Claude

## Overview

Build a hierarchical multi-agent system where an Overseer agent orchestrates specialized sub-agents to perform thorough security audits. The system must use all allocated time productively, going deeper rather than finishing early.

### Core Principles

1. **No laziness** - Time budget is a commitment, not a ceiling
2. **Full picture** - Overseer waits for complete wave results before deciding
3. **Deep synthesis** - Overseer produces cumulative investigation state after each wave
4. **Reuse existing infrastructure** - Sub-agents are ReactAgent instances with specialized prompts

### High-Level Flow

```
User starts scan with time budget (e.g., 4 hours)
    ↓
Overseer initializes, dispatches Wave 1 (Recon)
    ↓
[RepoProfiler, ScopeMapper×N, EntrypointHunter] run in parallel
    ↓
All complete → Overseer synthesizes investigation state
    ↓
Overseer decides Wave 2 based on findings (e.g., Hunting)
    ↓
[SinkHunter×N, AuthBoundaryMapper, ThreatModeler] run in parallel
    ↓
... continues until time budget exhausted ...
    ↓
Final synthesis → Findings report
```

---

## Sub-Agent Roster

11 agent types, each a ReactAgent instance with specialized prompt and tools:

| Agent Type | Purpose | Tools Available | Output Location |
|------------|---------|-----------------|-----------------|
| **Overseer** | Orchestrates waves, synthesizes state, enforces depth | `dispatch_wave()`, `read_memories()`, `write_synthesis()`, `finalize_report()` | `/memories/overseer/` |
| **RepoProfiler** | Map tech stack, frameworks, build system, project layout | `read_file`, `ls`, `glob`, `write_file` | `/memories/repo_profile.json` |
| **ScopeMapper** | Summarize a scope's purpose, key files, security relevance | `read_file`, `ls`, `glob`, `write_file` | `/memories/scopes/{scope_id}/summary.md` |
| **EntrypointHunter** | Find HTTP routes, CLI handlers, message consumers, GraphQL | `read_file`, `grep`, `glob`, `write_file` | `/memories/scopes/{scope_id}/entrypoints.json` |
| **SinkHunter** | Find dangerous sinks (SQL, exec, file, SSRF, deserialize) | `read_file`, `grep`, `glob`, `analyze_ast`, `write_file` | `/memories/scopes/{scope_id}/signals.json` |
| **DataflowTracer** | Trace data from user input to dangerous sink | `read_file`, `analyze_ast`, `trace_dataflow`, `write_file` | `/memories/traces/{signal_id}/dataflow.md` |
| **ThreatModeler** | Analyze attacker capabilities and attack surface | `read_file`, `read_memories`, `write_file` | `/memories/threat_model.md` |
| **AuthBoundaryMapper** | Map authn/authz flows, roles, tenant boundaries, enforcement | `read_file`, `grep`, `glob`, `write_file` | `/memories/authz_map.json`, `/memories/boundary_notes.md` |
| **Triager** | Verify a specific signal - confirm or dismiss with evidence | `read_file`, `analyze_ast`, `trace_dataflow`, `write_file` | `/memories/triage/{signal_id}/verdict.json` |
| **Auditor** | Deep-dive on triaged signal, build full proof case | `read_file`, `analyze_ast`, `trace_dataflow`, `promote_finding` | Finding object or `/memories/audits/{signal_id}/dismissed.md` |
| **Reproducer** | Produce repro steps and regression test outline | `read_file`, `read_memories`, `write_file` | `/memories/findings/{finding_id}/repro_steps.md` |

Tool subsets are intentional - each agent only gets tools relevant to its job.

---

## Filesystem Structure

All agent communication happens through `/memories/` - a virtual filesystem scoped to the scan.

```
/memories/
├── overseer/
│   ├── wave_1_dispatch.json      # What agents were sent, why
│   ├── wave_1_synthesis.md       # Deep analysis after wave 1
│   ├── wave_2_dispatch.json
│   ├── wave_2_synthesis.md
│   ├── ...
│   ├── investigation_state.json  # Cumulative state (updated each wave)
│   └── final_report.md           # Final synthesis
│
├── repo_profile.json             # RepoProfiler output
├── threat_model.md               # ThreatModeler output
├── authz_map.json                # AuthBoundaryMapper output
├── boundary_notes.md             # AuthBoundaryMapper notes
│
├── scopes/
│   ├── {scope_id}/
│   │   ├── summary.md            # ScopeMapper output
│   │   ├── entrypoints.json      # EntrypointHunter output
│   │   └── signals.json          # SinkHunter output
│   └── ...
│
├── traces/
│   └── {signal_id}/
│       └── dataflow.md           # DataflowTracer output
│
├── triage/
│   └── {signal_id}/
│       └── verdict.json          # Triager output (confirmed/dismissed + evidence)
│
├── audits/
│   └── {signal_id}/
│       ├── case.md               # Full audit case
│       └── dismissed.md          # Or dismissal with reasoning
│
└── findings/
    └── {finding_id}/
        ├── finding.json          # Promoted finding
        └── repro_steps.md        # Reproducer output
```

**Key properties:**
- Every agent writes to a predictable location
- Overseer can read any agent's output
- Human-inspectable at any point (all markdown/JSON)
- Persists across waves for cumulative learning

---

## Wave Execution Flow

### The Overseer Loop

```
┌─────────────────────────────────────────────────────────────────┐
│                         WAVE N                                  │
├─────────────────────────────────────────────────────────────────┤
│  1. INGEST                                                      │
│     └─ Read all /memories/ artifacts from previous wave         │
│                                                                 │
│  2. SYNTHESIZE                                                  │
│     └─ Update campaign_state.json                               │
│     └─ Write wave_N_synthesis.md                                │
│     └─ Update hypothesis statuses                               │
│                                                                 │
│  3. CHECK BUDGET                                                │
│     └─ Time remaining? Coverage gaps? Unresolved signals?       │
│     └─ If exhausted → FINALIZE                                  │
│                                                                 │
│  4. PLAN                                                        │
│     └─ Decide next wave objectives                              │
│     └─ Write wave_N+1_plan.json (dispatch tasks)                │
│                                                                 │
│  5. DISPATCH                                                    │
│     └─ Spawn sub-agents in parallel (one ReactAgent each)       │
│     └─ Each writes to /memories/{agent_type}/{task_id}/         │
│                                                                 │
│  6. WAIT                                                        │
│     └─ Block until all sub-agents complete                      │
│                                                                 │
│  7. LOOP → Wave N+1                                             │
└─────────────────────────────────────────────────────────────────┘
```

### Hypothesis Lifecycle

```
NEW → TRIAGED → TRACING → AUDITING → CONFIRMED/DISMISSED
 │        │         │          │              │
 │        │         │          │              └─ Final state
 │        │         │          └─ Auditor deep-dive
 │        │         └─ DataflowTracer working
 │        └─ Triager evaluated, worth pursuing
 └─ SinkHunter found a signal
```

---

## No-Laziness Enforcement

### Time-Driven Model

```
PRIMARY RULE: Use all allocated time productively.

The only valid reasons to finalize early:
1. Time budget exhausted
2. Codebase is trivially small AND fully audited (rare)

Coverage is an OUTPUT of time spent, not a gate.
```

### Strategy by Time Budget

| Tier | Time | Strategy |
|------|------|----------|
| Quick (5m) | Sprint | Profile → Hunt high-risk scopes only → Triage top 3-5 signals |
| Medium (15m) | Focused | Profile → Map key scopes → Hunt → Trace top signals |
| Advanced (45m) | Thorough | Full recon → Systematic hunting → Trace + Audit top signals |
| Pro (90m) | Deep | Above + AuthBoundaryMapper + ThreatModeler + Revisits |
| Ultra (4h) | Exhaustive | Multiple passes, lower thresholds, Reproducer for confirmed |
| Evil (24h) | Relentless | Everything, multiple lenses, revisit with fresh hypotheses |

### Enforcement Logic

```python
def can_finalize(state):
    # Time is the only hard gate
    if now() < deadline:
        return False  # Keep working

    return True  # Time's up, wrap it up
```

### Quality Gate

If sub-agent output lacks file paths, clear reasoning, or next steps, Overseer re-dispatches with targeted clarification.

### Fail-Safe (< 10% time remaining)

- Stop expanding scope
- Focus on upgrading best hypotheses to CONFIRMED or DISMISSED
- Produce final synthesis emphasizing unresolved HIGH/CRITICAL items

---

## Implementation Architecture

### Directory Structure

```
backend/agents/deep_audit/
├── __init__.py
├── overseer.py          # Overseer agent (replaces supervisor.py)
├── state.py             # CampaignState model (replaces SupervisorState)
├── dispatcher.py        # Wave dispatch + parallel execution
├── filesystem.py        # /memories/ virtual filesystem (exists, needs extension)
├── subagents.py         # Prompt templates (exists, extend with new agents)
├── enforcement.py       # No-laziness checks, quality gates
└── tools/
    ├── __init__.py
    ├── dispatch.py      # dispatch_wave(), dispatch_agent() tools for Overseer
    ├── memories.py      # read_memories(), write_synthesis() tools
    └── finalize.py      # finalize_report() tool
```

### Key Classes

```python
# state.py
class CampaignState(BaseModel):
    """Cumulative state across all waves."""
    project_id: str
    scan_tier: str
    deadline: float

    # From repo profiling
    repo_profile: Optional[dict] = None

    # Tracking
    scopes: dict[str, ScopeStatus] = {}
    entrypoints: list[Entrypoint] = []

    # Hypotheses (the core tracking structure)
    hypotheses: list[Hypothesis] = []

    # Results
    confirmed_findings: list[Finding] = []
    dismissed: list[Dismissal] = []

    # Wave tracking
    current_wave: int = 0
    wave_history: list[WaveRecord] = []

class Hypothesis(BaseModel):
    """A candidate vulnerability being investigated."""
    id: str
    signal_type: str
    status: Literal["NEW", "TRIAGED", "TRACING", "AUDITING", "CONFIRMED", "DISMISSED"]
    confidence: float
    severity: Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    location: str
    evidence_paths: list[str] = []
    assigned_agent: Optional[str] = None
    notes: str = ""
```

### Overseer as ReactAgent

```python
# overseer.py
class Overseer:
    """Campaign orchestrator - runs as a ReactAgent with orchestration tools."""

    def __init__(self, request: AgentCreateRequest, repo_path: str):
        self.state = CampaignState(...)
        self.filesystem = MemoriesFilesystem(repo_path)

        self.agent = ReactAgent(
            prompt=load_prompt("agents/overseer_system_prompt.md"),
            tools=[
                dispatch_wave,
                read_memories,
                write_synthesis,
                update_state,
                finalize_report,
            ]
        )

    async def run(self):
        while not self.time_exhausted():
            await self.agent.step()
        return self.state.confirmed_findings
```

### Wave Dispatcher

```python
# dispatcher.py
class WaveDispatcher:
    async def dispatch_wave(self, wave_plan: WavePlan) -> WaveResult:
        tasks = [self._spawn_subagent(task) for task in wave_plan.tasks]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return WaveResult(...)

    async def _spawn_subagent(self, task: DispatchTask) -> SubagentResult:
        prompt = get_subagent_prompt(task.agent_type, ...)
        tools = AGENT_TOOL_SUBSETS[task.agent_type]
        agent = ReactAgent(prompt=prompt, tools=tools, ...)
        await agent.run()
        return SubagentResult(...)
```

### Tool Subsets by Agent Type

```python
AGENT_TOOL_SUBSETS = {
    "RepoProfiler": ["read_file", "ls", "glob", "write_file"],
    "ScopeMapper": ["read_file", "ls", "glob", "write_file"],
    "EntrypointHunter": ["read_file", "grep", "glob", "get_entry_points", "write_file"],
    "SinkHunter": ["read_file", "grep", "glob", "analyze_ast", "write_file"],
    "DataflowTracer": ["read_file", "analyze_ast", "trace_dataflow", "write_file"],
    "ThreatModeler": ["read_file", "read_memories", "write_file"],
    "AuthBoundaryMapper": ["read_file", "grep", "glob", "write_file"],
    "Triager": ["read_file", "analyze_ast", "trace_dataflow", "write_file"],
    "Auditor": ["read_file", "analyze_ast", "trace_dataflow", "promote_finding", "write_file"],
    "Reproducer": ["read_file", "read_memories", "write_file"],
}
```

---

## Prompt Organization

```
prompting/
├── agents/
│   ├── overseer_system_prompt.md      # NEW
│   └── ... (existing)
│
├── subagents/                          # NEW directory
│   ├── repo_profiler.md
│   ├── scope_mapper.md
│   ├── entrypoint_hunter.md
│   ├── sink_hunter.md
│   ├── dataflow_tracer.md
│   ├── threat_modeler.md              # NEW
│   ├── auth_boundary_mapper.md        # NEW
│   ├── triager.md
│   ├── auditor.md
│   └── reproducer.md                  # NEW
│
├── validity_checklists/               # Existing
└── contexts/                          # Existing
```

---

## Prompts

### Overseer (Campaign Orchestrator)

```markdown
ROLE: Overseer (Campaign Orchestrator)

You orchestrate an iterative vulnerability research campaign over an open-source codebase by dispatching specialized sub-agents, synthesizing their outputs, and planning the next investigation wave. You are responsible for global context, prioritization, deduplication, and "no-laziness" enforcement across the system.

PRIMARY OBJECTIVE
Run a loop of: (1) ingest sub-agent artifacts → (2) synthesize new understanding → (3) plan the next wave → (4) dispatch tasks.
Each wave should increase coverage and depth, converging toward confirmed, well-evidenced security findings (or confident dismissals), within a time budget.

YOU DO NOT DIRECTLY AUDIT EVERY LINE.
You coordinate. You may do light verification when helpful, but you should primarily: prioritize, assign, cross-link artifacts, and enforce evidence standards.

INPUTS YOU MAY RECEIVE (examples)
- repo_profile.json (RepoProfiler)
- summary.md per scope (ScopeMapper)
- entrypoints.json (EntrypointHunter)
- signals.json (SinkHunter / SignalMiner)
- triage_queue.json (SignalTriage) [if implemented]
- dataflow_report.md (DataflowTracer)
- threat_model.md (ThreatModeler)
- authz_map.json / boundary_notes.md (AuthBoundaryMapper)
- finding writeups or dismissals (Auditor)
- config_findings.json / secrets_report.md (ConfigSecretsAuditor) [if implemented]
- dependency_risks.json / sbom.json (DependencyAuditor) [if implemented]

CORE RESPONSIBILITIES

1) Campaign State Management
Maintain a structured campaign state containing:
- Known tech stack + key frameworks + runtime assumptions
- Enumerated entrypoints (routes/handlers/jobs/consumers)
- High-risk sinks and suspicious patterns ("signals")
- Hypotheses (candidate vulnerabilities) with status:
  - NEW → TRIAGED → TRACING → AUDITING → CONFIRMED/DISMISSED
- Confirmed findings list and dismissed list with rationale
- Coverage map: which modules/scopes were analyzed and at what depth
- Open questions that block confirmation

2) Wave Planning (Iteration Strategy)
For each wave:
- Select a limited set of high-value objectives based on risk and coverage gaps.
- Dispatch the minimal set of sub-agent tasks needed to reduce uncertainty or confirm impact.
- Assign budgets (effort/time) and success criteria for each task.
- Avoid redundant work: deduplicate tasks already done or in progress.

Default wave strategy (adapt as needed):
- Wave 0: RepoProfiler + EntrypointHunter + broad ScopeMapper on top-level dirs
- Wave 1: SinkHunter on high-risk scopes + ThreatModeler baseline
- Wave 2: DataflowTracer on top signals + AuthBoundaryMapper on auth/tenant code
- Wave 3+: Auditor deep-dives highest-confidence paths; Reproducer for confirmed issues
You may loop and refine based on findings.

3) No-Laziness Enforcement (Critical)
Enforce these standards:
- Every claimed issue must include: precise location(s), path to reachability, and impact framing.
- Every dismissal must include: why it's not exploitable (guard, sanitizer, unreachable, false positive).
- If a sub-agent output is vague (no file paths, no reasoning, no next steps), send it back with a targeted re-task.
- Always push toward resolution: confirm or dismiss, not "maybe" forever.

4) Prioritization & Triage Logic
Rank hypotheses/signals using a consistent rubric:
- Impact (RCE > auth bypass > data exfil > DoS > info leak)
- Reachability (public unauth route > auth required > internal-only)
- Exploit complexity (low vs high)
- Prevalence (pattern repeats across codebase)
- Confidence (grounded evidence vs speculative)

5) Synthesis & Reporting
Produce crisp, structured synthesis each wave:
- What changed since last wave (new entrypoints, new sinks, new hypotheses)
- Top 3–10 hypotheses with status and next action
- Confirmed findings (if any) + where evidence lives
- Key unknowns and how to resolve them next wave

DISPATCH FORMAT (what you send to sub-agents)
For each task you dispatch, specify:
- agent_type: (RepoProfiler / ScopeMapper / EntrypointHunter / SinkHunter / DataflowTracer / ThreatModeler / AuthBoundaryMapper / Auditor / Reproducer / etc.)
- objective: what to accomplish and why
- scope: directories/modules/files to focus on
- inputs: which artifacts to use
- deliverable: expected output file name + required sections
- success_criteria: how we know it's done
- constraints: time/effort budget, avoid redoing X, focus on Y

OUTPUT REQUIREMENTS (what YOU produce each wave)
Produce 3 artifacts:

(1) wave_synthesis.md
Required sections:
- Summary (what we learned)
- Updated Mental Model (architecture + trust boundaries)
- New Signals & Hypotheses (with links to evidence)
- Confirmed Findings (if any)
- Dismissals (if any)
- Coverage & Gaps
- Next Wave Goals

(2) wave_plan.json
A machine-readable list of tasks to dispatch, using the dispatch format above.

(3) campaign_state.json
A structured state snapshot including:
- repo_profile refs
- entrypoints
- hypotheses list with statuses, owners, evidence pointers, confidence/severity
- confirmed findings + dismissals
- coverage map
- open questions

CONFIDENCE & SEVERITY SCALE
- Confidence: LOW / MEDIUM / HIGH
- Severity: INFO / LOW / MEDIUM / HIGH / CRITICAL
Explain any CRITICAL/HIGH with impact + reachability.

FAIL-SAFE BEHAVIOR
If time is nearly exhausted:
- Stop expanding scope.
- Focus on upgrading the best hypotheses to CONFIRMED or confidently DISMISSED.
- Produce a final synthesis emphasizing highest-risk unresolved items and what evidence is missing.
```

### ThreatModeler

```markdown
ROLE: ThreatModeler

You create a practical threat model for the audited repository to guide vulnerability discovery and prioritization. You identify attacker types, trust boundaries, assets, and high-risk attack paths, grounded in the codebase's actual entrypoints and architecture.

PRIMARY OBJECTIVE
Produce a threat model that:
- Enumerates the attack surface (entrypoints, components, external integrations)
- Defines attacker capabilities and trust boundaries
- Highlights prioritized attack scenarios to guide sub-agent work
- Connects architecture → likely vuln classes → where to look next

INPUTS (use what is available; do not assume all exist)
- repo_profile.json
- entrypoints.json
- scope summaries (summary.md per directory/module)
- config/security-relevant settings if available
- (optional) authz_map.json / boundary_notes.md
- (optional) dependency_risks.json

METHOD

1) Build the System Picture (grounded)
- Identify system type: web app/API, CLI tool, service, library, agent, etc.
- Identify major components: API layer, background workers, plugins, parsers, storage adapters, auth module, etc.
- Identify data stores and external services: SQL/NoSQL, caches, message brokers, object storage, HTTP clients, LLM calls, etc.
- Identify security-sensitive boundaries: network-facing interfaces, plugin boundaries, sandbox assumptions, privileged operations.

2) Define Assets & Security Goals
List assets such as:
- credentials/keys, tokens, PII, tenant data, secrets, filesystem, command execution, internal network access
Define primary security goals:
- confidentiality, integrity, availability, tenant isolation, authorization correctness

3) Attacker Models (capabilities)
Define at least these attacker profiles (adapt to repo):
- Unauthenticated internet user
- Authenticated low-priv user
- Malicious tenant user (multi-tenant)
- Insider / operator (has config access)
- Supply-chain attacker (dependency compromise)
- Adjacent service attacker (SSRF pivot target)
For each: what they can control (inputs, headers, files, configs, plugins, payloads).

4) Trust Boundaries
Explicitly define:
- where untrusted input enters
- where it is supposed to become trusted (if ever)
- boundary enforcement mechanisms (middleware, validators, auth checks)
- cross-tenant boundaries and identity propagation

5) Prioritized Attack Scenarios
Create a ranked list of "attack paths" of the form:
Entry point → boundary crossed → sink/asset → impact
For each scenario:
- likely vuln classes (e.g., SQLi, SSRF, deserialization, template injection, authz bypass, path traversal)
- where in code to focus (modules / patterns / key functions)
- what evidence to gather next (which sub-agent to dispatch)

OUTPUT
Write threat_model.md with these required sections:

1. Architecture Snapshot
2. Attack Surface Inventory
3. Assets & Security Objectives
4. Attacker Profiles & Capabilities
5. Trust Boundaries
6. Top Attack Scenarios (ranked)
7. Assumptions & Unknowns

QUALITY BAR
- Ground claims in evidence (file paths, entrypoints, configs) when available.
- Prefer fewer, higher-quality scenarios over a long generic list.
- Avoid abstract textbook threat modeling that doesn't map back to code.
```

### AuthBoundaryMapper

```markdown
ROLE: AuthBoundaryMapper

You map authentication and authorization flows, role/permission models, and tenant isolation boundaries in the codebase. Your output should make it easy to answer: "Who can do what to which resources, and where is that enforced?"

PRIMARY OBJECTIVE
Produce an evidence-based map of:
- AuthN mechanisms (sessions, JWT, OAuth, API keys, mTLS, etc.)
- Identity derivation (where user/tenant comes from)
- AuthZ enforcement points (middleware, decorators, policy checks)
- Role/permission resolution logic
- Tenant isolation controls (row-level filters, scoping queries, tenant IDs)
- Common bypass risks (missing checks, inconsistent middleware, IDOR patterns)

OUTPUTS
(1) authz_map.json - structured schema with authentication methods, identity sources, enforcement points, tenant isolation, hotspots
(2) boundary_notes.md - AuthN Summary, AuthZ Summary, Tenant Isolation Summary, Top 5 Hotspots, Open Questions

QUALITY BAR
- Do not just list "there is auth." Explain how it's enforced and where it can fail.
- Highlight inconsistencies (some routes guarded, others not).
- If you can't determine something, write exactly what to inspect next.
```

### Reproducer

```markdown
ROLE: Reproducer

You generate safe, minimal reproduction steps and a regression test outline for a vulnerability that has been CONFIRMED by an Auditor. Your output should help maintainers verify the issue and confirm a fix, without enabling weaponized exploitation.

PRIMARY OBJECTIVE
Given a confirmed finding, produce:
1) A safe reproduction guide that works in a local/dev environment
2) A regression test outline (unit/integration) to prevent reintroduction

SAFETY CONSTRAINTS (non-negotiable)
- Keep the reproduction local or in a controlled test environment.
- Use benign payloads. Do not include weaponized exploit chains.
- If demonstrating impact would require harmful behavior, demonstrate a safe proxy and explain the risk conceptually.

OUTPUTS
- repro_steps.md (Summary, Preconditions, Setup, Repro Steps, Impact Demonstration, Mitigation Hint)
- regression_test_plan.md (Test Type, Test Location, Test Plan, Negative & Edge Cases, Fix Verified When)

QUALITY BAR
- Steps must be reproducible by a maintainer.
- Keep it minimal: the shortest path that proves the issue.
- Never require external targets or real internal addresses/services.
```

---

## Implementation Plan

### Phase 1: Foundation (Core Infrastructure)
1. Create `CampaignState` model in `state.py`
2. Create `MemoriesFilesystem` extension for virtual filesystem
3. Create `WaveDispatcher` for parallel sub-agent execution
4. Create Overseer tools: `dispatch_wave`, `read_memories`, `write_synthesis`, `finalize_report`

### Phase 2: Prompts (Move to .md files)
5. Create `prompting/agents/overseer_system_prompt.md`
6. Create `prompting/subagents/` directory with all 10 sub-agent prompts
7. Move existing Python string prompts from `subagents.py` to .md files
8. Create new prompts: threat_modeler.md, auth_boundary_mapper.md, reproducer.md

### Phase 3: Overseer Agent
9. Create `Overseer` class that wraps ReactAgent with orchestration tools
10. Implement wave planning logic
11. Implement synthesis output (wave_synthesis.md, campaign_state.json)
12. Implement no-laziness enforcement (time-based)

### Phase 4: Integration
13. Wire Overseer into existing `DeepAuditSupervisor` entry point
14. Update API to support new scan flow
15. Add WebSocket updates for wave progress

### Phase 5: Testing
16. Unit tests for dispatcher, state management
17. Integration test: full scan with mocked sub-agents
18. End-to-end test: real scan on small test repo

---

## Summary

| Component | Description |
|-----------|-------------|
| **Overseer** | ReactAgent with orchestration tools, drives the campaign |
| **11 Sub-agent Types** | Specialized ReactAgents with focused prompts and tool subsets |
| **Wave Execution** | Parallel dispatch → wait for all → synthesize → plan next |
| **Communication** | Filesystem-based via `/memories/` directory |
| **No-Laziness** | Time is king - use all allocated budget productively |
| **Hypothesis Tracking** | NEW → TRIAGED → TRACING → AUDITING → CONFIRMED/DISMISSED |
| **Outputs** | wave_synthesis.md, campaign_state.json, confirmed findings |

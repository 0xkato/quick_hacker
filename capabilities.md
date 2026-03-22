# Quick Hacker — System Capabilities & Architecture

## What Is Quick Hacker?

Quick Hacker is an AI-powered security auditing IDE that automatically scans source code repositories to identify and verify security vulnerabilities. It combines a multi-agent LLM pipeline with a browser-based IDE for real-time scan monitoring, finding triage, and code navigation.

**Zero false positive philosophy** — findings must be proven from source code with verified dataflow traces. Every finding passes through a multi-stage verification pipeline before being reported.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.12, FastAPI, SQLAlchemy (async), PostgreSQL/SQLite |
| Frontend | Next.js 14, React 18, TypeScript, Tailwind CSS, Monaco Editor, ReactFlow |
| LLM Integration | Claude CLI (subscription auth), Anthropic SDK, Codex CLI |
| Real-time | WebSocket with auto-reconnect, event batching |
| Auth | JWT (access + refresh tokens), per-user encrypted API keys |

---

## Architecture Overview

```
┌─── Browser IDE ──────────────────────────────────────────────────────────┐
│  Activity Bar │ Sidebar (view-dependent) │ Main Content │ Chat Panel    │
│  - Files      │ File tree / Agents /     │ Monaco editor│ AI assistant  │
│  - Agents     │ Findings / Flow /        │ Flow diagram │ with context  │
│  - Findings   │ LLM interactions /       │ Behavior tree│               │
│  - Flow       │ Behavior tree            │              │               │
│  - LLM        │                          │              │               │
│  - Behavior   │                          │              │               │
└───────────────┴──────────────────────────┴──────────────┴───────────────┘
        │ HTTP + WebSocket                              │
┌───────▼──────────────────────────────────────────────────────────────────┐
│  FastAPI Backend (15 routers, JWT auth, async)                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  Overseer (Deep Audit Engine)                                    │   │
│  │  ┌─────────┐ ┌──────────┐ ┌─────────┐ ┌────────────┐ ┌───────┐│   │
│  │  │Foundation│→│ Hunting  │→│ Routing │→│Verification│→│Finalize││   │
│  │  │(10%)    │ │(30%)     │ │         │ │(20%)       │ │(5%)   ││   │
│  │  └─────────┘ └──────────┘ └─────────┘ └────────────┘ └───────┘│   │
│  │       │            │            │             │                 │   │
│  │  ┌────▼────────────▼────────────▼─────────────▼────────────┐   │   │
│  │  │  WaveDispatcher (spawns Claude CLI / Codex subprocesses)│   │   │
│  │  │  Up to 8 concurrent sub-agents per wave                 │   │   │
│  │  └─────────────────────────────────────────────────────────┘   │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  Services: findings, triage, behavior_tree, flow, project, scan,       │
│            observability, persistence, report, tool_cache, tool_core    │
│                                                                         │
│  Database: Users, Findings, Scans, EvidenceBlobs, BehaviorTreeNodes,   │
│            LLMInteractions, ToolDetails, ProtocolPolicies, Quests      │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## The Deep Audit Pipeline

The core of Quick Hacker is a 5-phase orchestration pipeline controlled by the **Overseer**, which dispatches specialized sub-agents as separate Claude CLI processes running in parallel.

### Phase 1: Foundation (10% of time budget)

Three sub-agents run in parallel to build context shared with all downstream agents:

| Agent | Output | Purpose |
|-------|--------|---------|
| **RepoProfiler** | `repo_profile.json` | Languages, frameworks, build system, entry points, file metrics |
| **ScopeMapper** | `scope_map.json` | Security-critical paths vs test/vendor/generated code |
| **ThreatModeler** | `threat_model.json` | Trust boundaries, attacker capabilities, in-scope attack surface |

The combined output becomes the **FoundationContext**, which is injected directly into the system prompt of every subsequent sub-agent (since sub-agents are separate processes with no shared memory).

### Phase 2: Understanding (35% of time budget, skipped for "quick" tier)

Builds a deeper security map of the codebase:

| Agent | Purpose |
|-------|---------|
| **ModuleAnalyzer** | Module structure and dependencies |
| **TrustBoundaryMapper** | Trust boundary transitions and privilege contexts |
| **DataFlowMapper** | Cross-module data flow patterns |
| **InvariantExtractor** | Business logic invariants and constraints |

### Phase 3: Hunting (30% of time budget)

Discovers suspicious signals by scanning for dangerous patterns:

| Agent | What it finds |
|-------|---------------|
| **SinkHunter** (8 variants) | Dangerous functions — SQL execution, command execution, file operations, crypto operations, deserialization, network requests |
| **EntrypointHunter** | HTTP routes, WebSocket handlers, CLI commands, message consumers |
| **InvariantViolationHunter** | Invariant violations (if Security Map available) |
| **TrustBoundaryGapHunter** | Trust boundary gaps (if Security Map available) |

Each signal includes: file path, line number, category, severity estimate, and hunter notes.

### Phase 4: Verification (20% of time budget)

Every signal passes through a multi-stage verification pipeline:

```
Signal → Decider → FamilyCoordinator → Specialist(s) → Arbiter → Triager
```

1. **Decider** — Routes signal to one of 14 specialist families based on category
2. **FamilyCoordinator** — Assigns one or more specialists within the family. Acts as devil's advocate, pushing specialists to investigate deeper
3. **Specialist** (64 types) — Domain expert that traces dataflow, identifies protections, and attempts to break them. Mindset: "assume this IS exploitable until proven otherwise"
4. **Arbiter** — Resolves disagreements between specialists. Expands search before rendering verdict
5. **Triager** — Final classification using evidence checklist

### Phase 5: Finalize (5% of time budget)

Generate the final report, emit all confirmed findings, and update the campaign state.

---

## The 14 Specialist Families (64 Specialists)

| Family | Count | Vulnerability Types |
|--------|-------|-------------------|
| **INJECTION** | 10 | SQL, NoSQL, command, template, expression, LDAP, XPath, CRLF, log, email |
| **MEMORY_SAFETY** | 8 | Buffer overflow, use-after-free, double-free, integer overflow, format string, type confusion, uninitialized memory, unsafe FFI |
| **DESERIALIZATION_PARSING** | 6 | Unsafe deserialization, XXE, zip slip, ReDoS, file parser, parser differential |
| **AUTHN_SESSION** | 5 | Auth bypass, session fixation, CSRF, OAuth, JWT |
| **AUTHZ_BUSINESS_LOGIC** | 5 | IDOR, privilege escalation, multi-tenant isolation, workflow bypass, rate limiting |
| **WEB_EDGE_CASES** | 4 | SSRF, request smuggling, cache poisoning, host header injection |
| **BROWSER_CLIENT** | 4 | XSS, prototype pollution, clickjacking, CSP bypass |
| **FILE_SYSTEM** | 4 | Path traversal, file upload, symlink/TOCTOU, temp file handling |
| **CRYPTO_SECRETS** | 4 | Crypto misuse, weak randomness, secrets exposure, TLS misconfiguration |
| **INFRASTRUCTURE** | 4 | Container security, Kubernetes, CI/CD, insecure configuration |
| **SUPPLY_CHAIN** | 3 | Dependency risk, dependency confusion, plugin security |
| **API_DESIGN** | 3 | Mass assignment, parameter pollution, GraphQL issues |
| **CONCURRENCY** | 2 | Race conditions, resource exhaustion/DoS |
| **DATA_EXPOSURE** | 2 | Sensitive data exposure, tokens in URLs |

Each specialist is powered by a detailed prompt containing:
- Domain expertise (attack patterns, bypass techniques, framework-specific knowledge)
- Detection methodology (what to search for, how to verify)
- Analysis checklist (proof requirements for each verdict)
- Output format (standardized finding structure)

These prompts live in `prompting/specialists/` and are compiled into Claude Code plugin SKILL.md files by `generate_specialist_skills.py`.

---

## Disposition Model

Every finding receives one of 6 dispositions after triage:

| Disposition | Meaning | Action |
|-------------|---------|--------|
| **VALID_SECURITY_ISSUE** | Exploitable, in scope, meaningful impact, no effective mitigations | Report |
| **BUG** | Causes incorrect behavior but not a security vulnerability | Report (lower priority) |
| **HARDENING** | Real issue but mitigations exist — defense-in-depth recommendation | Optional report |
| **MISCONFIGURATION** | Only exploitable when security is explicitly disabled | Optional report |
| **BY_DESIGN** | Intentional product behavior, threat model explicitly accepts | Filter |
| **SPECULATIVE** | Requires unproven assumptions to be exploitable | Filter |

### Proof Checklist

Each finding is verified against a tri-state checklist (PROVEN / DISPROVEN / UNKNOWN):

| Check | Question |
|-------|----------|
| `source_controlled_input` | Does attacker-controlled input reach this code? |
| `sink_present` | Is there a dangerous function/operation? |
| `dataflow_evidenced` | Is there an unsanitized flow from source to sink? |
| `reachable` | Is this code reachable from a registered route? |
| `boundary_crossed` | Does external input cross a trust boundary? |
| `not_only_misconfig` | Is the code vulnerable by design, not just by configuration? |

All PROVEN → VALID_SECURITY_ISSUE. Any DISPROVEN → downgrade. Any UNKNOWN → SPECULATIVE.

---

## Scan Tiers

| Tier | Time Budget | Phase 2 | Typical Use |
|------|-------------|---------|-------------|
| **quick** | 5 min | Skipped | Fast validation, single-focus |
| **medium** | 15 min | Included | Standard audit |
| **advanced** | 45 min | Included | Deep analysis |
| **pro** | 90 min | Included | Comprehensive coverage |
| **ultra** | 4 hours | Included | Exhaustive scan |
| **evil** | 24 hours | Included | Maximum coverage |

Higher tiers automatically enable the Overseer sub-agent system. Each sub-agent gets a proportional time budget (20-90 minutes depending on tier).

---

## Sub-Agent Execution

Sub-agents run as separate processes, not in-process function calls:

### Claude CLI Mode (default)
```bash
claude -p \
  --model claude-opus-4-6 \
  --permission-mode bypassPermissions \
  --tools Read,Glob,Grep,Bash \
  --append-system-prompt "<FOUNDATION_CONTEXT + AGENT_PROMPT>" \
  --output-format stream-json
```

Uses the user's Claude Code subscription — no API keys needed.

### Codex CLI Mode
```bash
codex --model gpt-5.4-codex ...
```

Same subprocess architecture but using OpenAI's Codex CLI.

### Concurrency
- Up to 8 concurrent sub-agents per wave (semaphore-limited)
- Waves execute sequentially (Phase 1 → Phase 2 → Phase 3 → Phase 4 → Phase 5)
- Within each wave, all tasks run in parallel

### Tool Subsets

Each agent type gets a specific set of tools:

| Agent Type | Tools |
|-----------|-------|
| Foundation agents | read_file, list_directory, search_code, get_repo_tree |
| Hunters | read_file, search_code, grep_semantic, get_file_structure |
| Specialists | read_file, search_code, find_usages, trace_data_flow, use_skill |
| Triagers | read_file, search_code, get_file_structure, trace_data_flow |

---

## Finding Schema

Each finding contains:

```
Core:           id, severity, title, description
Location:       file_path, line_start, line_end, code_snippet, vulnerable_code
Classification: vulnerability_type, cwe_id, category
Analysis:       attack_scenario, proof_of_concept, recommended_fix, confidence (0-1.0)
Dataflow:       source_trace (source-to-sink steps)
Triage:         disposition, proof_checklist, classification_confidence, exploit_confidence
Protocol:       submission_result (VRP/HackerOne reportability), evidence_quest tracking
```

### Severity Levels

| Level | Color | Meaning |
|-------|-------|---------|
| **critical** | Red (#ff5f5f) | Remote code execution, auth bypass, full data access |
| **high** | Orange (#f0b429) | Significant data exposure, privilege escalation |
| **medium** | Yellow (#ffd700) | Limited impact, requires specific conditions |
| **low** | Blue (#60a5fa) | Informational, defense-in-depth |
| **info** | Gray | Observation, no direct security impact |

---

## Frontend IDE

### Layout

```
┌─── Header ────────────────────────────────────────────────────────────┐
│ Project Name │ Threat Model Badge │ User │ Settings │ Exit Project    │
└───────────────────────────────────────────────────────────────────────┘
┌─ Activity ┬─ Sidebar ──────────┬─ Main Content ──────┬─ Chat Panel ──┐
│ Bar (48px)│ (varies by view)   │ (flex-1)            │ (resizable)   │
│           │                    │                     │               │
│ [Files]   │ File tree with     │ Monaco editor with  │ AI assistant  │
│ [Agents]  │ lazy loading       │ finding decorations │ with file +   │
│ [Findings]│                    │                     │ finding +     │
│ [Flow]    │ Agent creation +   │ ReactFlow graph     │ flow context  │
│ [LLM]     │ status cards       │ visualization       │               │
│ [Behavior]│                    │                     │ Resizable via │
│           │ Finding cards with │ Behavior tree with  │ drag handle   │
│ [Chat]    │ severity badges +  │ expandable nodes    │               │
│ [Settings]│ triage status      │                     │               │
└───────────┴────────────────────┴─────────────────────┴───────────────┘
```

### 7 Activity Views

| View | What it shows |
|------|---------------|
| **Explorer** | File tree browser with lazy loading (depth-first, 200 children per level). Click file → Monaco editor with syntax highlighting |
| **Agents** | Agent creation form (tier, provider, model, sub-agents toggle). Running agent cards with progress bars. Start/pause/cancel controls |
| **Findings** | Finding cards grouped by severity. Filter by severity/disposition. Click → detail drawer with proof checklist, code snippet, attack scenario. Triage button → LLM-powered classification |
| **Flow** | ReactFlow graph of investigation nodes (entrypoints, dataflow, hypotheses, findings). Click node → popover with details. "Open Chat" seeds chat with context |
| **LLM** | Chronological log of every LLM request/response. Token counts, model info, subagent labels. Expand for full prompt/response text |
| **Behavior** | Hierarchical tree of agent actions: Session → Phases → Waves → Signals → Tool calls. Auto-expanding. Click node for details |
| **Chat** | AI assistant sidebar. Context-aware (current file, findings, flow selection). Streaming responses. Seeds from flow node clicks |

### Real-Time Updates (WebSocket)

| Event | Throttling | Purpose |
|-------|-----------|---------|
| `agent_status` | None | Agent lifecycle changes |
| `finding` | Deduplicated | New finding discovered |
| `progress` | 200ms per agent | Scan progress updates |
| `flow_update` | None | Investigation flow changes |
| `bt_node_add/update/batch` | None | Behavior tree updates |
| `llm_request/response` | Batched 150ms | LLM interaction log |
| `tool_detail` | Batched 150ms | Tool execution log |
| `report_ready` | None | Scan report available |

WebSocket auto-reconnects with exponential backoff (max 30s). Falls back to HTTP polling (10s interval) when disconnected.

---

## API Endpoints (Key Operations)

### Scan Lifecycle

| Operation | Endpoint | What happens |
|-----------|----------|-------------|
| Create agent | `POST /api/agents` | Validates config, resolves scan budget, instantiates Overseer, saves to DB |
| Start scan | `POST /api/agents/{id}/start` | Spawns background task, transitions to RUNNING, begins Phase 1 |
| Pause scan | `POST /api/agents/{id}/pause` | Sets pause flag, saves state snapshot |
| Resume scan | `POST /api/agents/{id}/resume` | Restores from snapshot, continues |
| Cancel scan | `POST /api/agents/{id}/cancel` | Kills sub-agent processes, transitions to CANCELLED |
| Get status | `GET /api/agents/{id}` | Returns agent state (3-tier: memory → DB → JSON snapshot) |

### Finding Management

| Operation | Endpoint | What happens |
|-----------|----------|-------------|
| Get findings | `GET /api/agents/{id}/findings` | Returns findings (3-tier fallback: memory → DB → snapshot) |
| Get all for repo | `GET /api/agents/findings/all?repo_id=X` | Aggregates from all sources |
| Triage | `POST /api/agents/findings/triage?repo_id=X` | LLM evaluates findings, assigns dispositions |
| Export report | `GET /api/reports/findings/export?agent_id=X&format=md` | Generates markdown/HTML/JSON report |

### Project Management

| Operation | Endpoint |
|-----------|----------|
| Create project | `POST /api/projects` |
| Clone repo | `POST /api/projects/{id}/clone` or `POST /api/projects/quick-clone` |
| Enter project | `POST /api/projects/{id}/enter` |
| Set threat model | `PUT /api/projects/{id}/threat-model-profile` |

### Chat

| Operation | Endpoint |
|-----------|----------|
| Streaming chat | `POST /chat/stream` (SSE) |
| Context includes: current file, findings, flow selection, selected text |

---

## Data Persistence (3-Tier)

| Tier | Storage | Use Case | Speed |
|------|---------|----------|-------|
| **In-memory** | `orchestrator._agents` dict | Active scans, real-time access | Fastest |
| **Database** | PostgreSQL/SQLite | Completed scans, findings, LLM logs | Fast |
| **JSON snapshots** | `.quickhack/agents/{id}.json` | Offline availability, session restore | Slow |

All finding retrieval endpoints use 3-tier fallback: memory → DB → snapshot.

---

## Database Tables

| Table | Purpose | Key Fields |
|-------|---------|-----------|
| `users` | Authentication | id, username, email, password_hash |
| `user_api_keys` | Per-user provider API keys (encrypted) | user_id, provider, api_key_encrypted |
| `scans` | Agent/scan persistence | id, repo_id, status, scan_tier, provider_config |
| `findings` | Security findings | id, agent_id, severity, file_path, disposition, proof_checklist |
| `evidence_blobs` | Finding evidence attachments | finding_id, evidence_type, snippet |
| `llm_interactions` | LLM request/response log | agent_id, model, tokens, duration |
| `tool_details` | Tool execution log | agent_id, tool_name, input, output, duration |
| `bt_nodes` | Behavior tree (write-through) | agent_id, parent_id, node_type, status |
| `protocol_policies` | VRP/triage policy configs | id, config (JSONB) |
| `evidence_quests` | Evidence gathering quests | finding_id, status, missing_items |

---

## Configuration

### Agent Creation Parameters

| Parameter | Type | Default | Purpose |
|-----------|------|---------|---------|
| `repo_id` | string | required | Target repository |
| `agent_type` | enum | DEEP_AUDIT | Agent type |
| `scan_tier` | string | "quick" | Time budget tier |
| `provider` | string | "anthropic" | LLM provider |
| `model` | string | "claude-opus-4-6" | Model ID |
| `use_overseer` | bool | false | Enable parallel sub-agents |
| `use_claude_code_auth` | bool | false | CLI subscription vs API key |
| `use_claude_sdk` | bool | false | Native Agent SDK |
| `focus_areas` | list | null | Specific vuln types to focus on |
| `custom_prompt` | string | null | Custom system prompt addition |
| `target_files` | list | null | Specific files to analyze (null = all) |

### Application Settings

| Setting | Default | Purpose |
|---------|---------|---------|
| `max_concurrent_agents` | 10 | Concurrent scan limit |
| `tool_cache_ttl_seconds` | 3600 | Tool output cache lifetime |
| `triage_batch_budget_ms` | 15000 | Triage time budget |
| `file_read_max_bytes` | 100KB | Max file read size |
| `max_call_depth` | 3 | Max call tree depth |
| `sandbox_enabled` | true | Sandbox for tool execution |

---

## Prompting Architecture

### Directory Structure

```
prompting/
├── specialists/        # 64 specialist prompts across 14 families
│   ├── injection/      # sql_injection.md, command_injection.md, ...
│   ├── memory_safety/  # use_after_free.md, integer_overflow.md, ...
│   └── ...
├── subagents/          # 12 orchestration agent prompts
│   ├── repo_profiler.md, scope_mapper.md, threat_modeler.md
│   ├── sink_hunter.md, entrypoint_hunter.md
│   ├── dataflow_tracer.md, decider.md, family_coordinator.md
│   ├── specialist_base.md, triager.md, auditor.md, arbiter.md
│   └── reproducer.md
├── stages/             # Pipeline stage definitions
├── contexts/           # Framework-specific guidance (FastAPI, Django, Flask, Express)
├── validity_checklists/# Per-vulnerability proof requirements
├── agents/             # Agent mode prompts
├── chat/               # Chat variant prompts
└── providers/          # Provider-specific configs
```

### Specialist Prompt Structure

Each specialist prompt contains:
1. **Domain Expertise** — attack patterns, bypass techniques, framework quirks
2. **Detection Methodology** — what to grep for, what code patterns indicate vulns
3. **Analysis Checklist** — proof requirements for each verdict
4. **Common Bypasses** — how protections fail in practice
5. **Output Format** — standardized finding structure

These are compiled into Claude Code plugin SKILL.md files:
```
specialist_plugin/skills/sql-injection-audit/SKILL.md
specialist_plugin/skills/xss-audit/SKILL.md
... (64 total)
```

### Runtime Loading

`prompting_loader.py` loads prompts with `{{placeholder}}` template rendering:
```python
render_prompt("subagents/sink_hunter.md",
    FOUNDATION_CONTEXT=foundation_context.to_prompt(),
    objective="Find dangerous sinks in routes/",
    scope="routes/"
)
```

---

## Signal Flow (End-to-End)

```
1. FOUNDATION
   RepoProfiler + ScopeMapper + ThreatModeler
   → FoundationContext (embedded in all downstream prompts)

2. HUNTING
   SinkHunter (8 variants) + EntrypointHunter
   → Suspicious Signals (file_path, line, category, severity)

3. ROUTING
   Decider → maps signal category to specialist family
   FamilyCoordinator → assigns specialists within family

4. ANALYSIS
   Specialist(s) → trace dataflow, check protections, attempt to break
   → VULNERABLE / NOT_VULNERABLE / NEEDS_ARBITER

5. RESOLUTION
   Arbiter (if disagreement) → expand search, render final verdict
   Triager → apply proof checklist → disposition

6. OUTPUT
   Finding emitted with: title, description, severity, CWE, file location,
   code snippet, attack scenario, PoC, recommended fix, proof checklist,
   disposition, confidence scores
```

---

## Observability

### Behavior Tree
Real-time hierarchical visualization of agent actions:
```
Session
└── Phase: Foundation
    └── Wave 1
        ├── Agent: RepoProfiler (completed, 12s)
        ├── Agent: ScopeMapper (completed, 8s)
        └── Agent: ThreatModeler (completed, 15s)
└── Phase: Hunting
    └── Wave 2
        ├── Agent: SinkHunter-Injection (running)
        │   ├── Turn 1: search_code("execute.*query")
        │   └── Turn 2: read_file("routes/users.py")
        └── Agent: EntrypointHunter (completed, 20s)
```

Write-through persistence to database for survival across restarts.

### LLM Interaction Log
Every request and response logged with:
- Model, provider, subagent label
- Prompt/completion token counts
- Duration, tool calls
- Full prompt and response text (expandable in UI)

### Investigation Flow
Directed graph of investigation nodes:
- Entry points, dataflow traces, hypotheses, findings
- Color-coded by confidence score
- Interactive: click to open chat with context

---

## Security Features

- **JWT authentication** with access + refresh tokens
- **Per-user encrypted API keys** for LLM providers
- **Sandbox execution** for tool operations (configurable timeout, memory limit, network disabled)
- **CORS enforcement** with explicit origin allowlist
- **Request ID middleware** for log correlation
- **File read limits** (100KB max per file)
- **Excluded directories** (node_modules, .git, __pycache__, etc.)
- **Finding deduplication** (same file + vuln type + overlapping line range = skip)

---

## Development Setup

```bash
# Start everything (Docker Redis+PostgreSQL, backend, frontend)
./run-local.sh

# Backend: http://localhost:8000
# Frontend: http://localhost:3000
```

### Key Entry Points
| What | Path |
|------|------|
| Backend main | `backend/main.py` |
| Overseer | `backend/agents/deep_audit/overseer.py` |
| Dispatcher | `backend/agents/deep_audit/dispatcher.py` |
| Campaign state | `backend/agents/deep_audit/state.py` |
| Specialist registry | `backend/agents/deep_audit/specialists/registry.py` |
| Specialist prompts | `prompting/specialists/` |
| Subagent prompts | `prompting/subagents/` |
| Frontend main page | `frontend/app/page.tsx` |
| API client | `frontend/lib/api.ts` |
| WebSocket hook | `frontend/hooks/useWebSocket.ts` |

# DeepAudit v2: Understand-First Architecture

**Date:** 2026-02-06
**Status:** Draft — awaiting Mayor approval
**Author:** Mayor + Claude
**Supersedes:** 2026-02-02-deep-agents-architecture-design.md (v1)

## Problem Statement

DeepAudit v1 finds sinks first, then tries to verify them. This is backwards. The agents pattern-match for dangerous function calls (SQL queries, exec, file ops) and then ask "is this reachable?" — but they lack the holistic understanding to answer that question well. The result:

- **High false positive rate**: Raw sinks reported as findings before verification
- **Shallow understanding**: Agents don't know what the system *does*, only what functions it *calls*
- **No context for severity**: A SQL query in a test helper vs. a SQL query behind an unauthenticated route are treated the same
- **Missing vulnerability classes**: Trust boundary violations, state invariant breaks, and logic bugs are invisible to sink-pattern-matching

The core insight: **you must understand the system deeply before you can find its vulnerabilities.** The approach is inspired by professional security audit methodology — build context in phases (orientation, granular analysis, global understanding) before any hunting begins.

## Design Principles

1. **Understand first, hunt second.** Build a deep mental model of the codebase before looking for bugs. A vulnerability is a violation of an invariant — you can't find violations if you don't know the invariants.

2. **Depth over breadth.** More time = deeper understanding of the same code, not broader coverage of more code. Go deep everywhere, let agents decide *where* to go deepest.

3. **Skills are training packets.** Each specialist subagent receives a structured skill file containing methodology, decision trees, and real-world CVE examples with code snippets. This is how domain expertise is injected.

4. **Security map as artifact.** The understanding phase produces a structured security map: trust boundaries, state invariants, critical data flows, privilege transitions. This map is the foundation for all hunting.

5. **Progressive summarization.** Agents write understanding to `/memories/` as they work. Later agents build on earlier agents' summaries. Nothing is lost to context window limits.

6. **Time scales depth, not breadth.** A 5-minute scan and a 4-hour scan look at the same code. The difference is how deeply each component is understood and how many verification passes each finding gets.

---

## Architecture Overview

### Phase Pipeline (Sequential)

```
PHASE 1: ORIENTATION          (10-15% of budget)
  Build the system picture. What is this? What does it do?
    ↓
PHASE 2: DEEP UNDERSTANDING   (30-45% of budget)
  Ultra-granular analysis of security-critical components.
  Produce the Security Map artifact.
    ↓
PHASE 3: TARGETED HUNTING     (25-35% of budget)
  Hunt for vulnerabilities guided by the Security Map.
  Skills/training packets drive specialist methodology.
    ↓
PHASE 4: VERIFICATION         (15-20% of budget)
  Multi-stage verification pipeline (existing v1 routing).
  Cross-validation, Devil's Advocate, Triager.
    ↓
PHASE 5: FINALIZE             (5% of budget)
  Generate report, persist findings, emit to UI.
```

Time allocations are percentages of total budget, not fixed durations. A 5-minute scan spends 30-45 seconds on orientation; a 4-hour scan spends 24-36 minutes. The key invariant: **understanding phases always run before hunting phases**.

### What Changes from v1

| Aspect | v1 (Current) | v2 (Proposed) |
|--------|-------------|---------------|
| **Foundation phase** | 3 parallel agents (profile, scope, threat model) — shallow pass | Expanded to 2 phases with deep module-level analysis |
| **When hunting starts** | Immediately after foundation (15% of budget spent) | After 40-60% of budget spent on understanding |
| **Security Map** | Implicit in FoundationContext (flat dict) | Explicit structured artifact with invariants, trust boundaries, data flows |
| **Specialist knowledge** | Generic prompts in subagents.py | Skills files with methodology + real CVE examples |
| **Depth scaling** | Fixed wave count per tier | Percentage-based: more time = deeper analysis of same components |
| **What agents know** | Foundation Context (profile + scope + threat model) | Security Map + module summaries + data flow maps |
| **Finding quality** | Pattern-match sinks → verify | Understand invariants → identify violations → verify with real-world examples |

---

## Phase 1: Orientation

**Budget:** 10-15% of total
**Goal:** Answer "What is this system and what does it do?"
**Agents:** RepoProfiler, ScopeMapper (parallel)

This phase is largely unchanged from v1 but produces richer output.

### RepoProfiler (unchanged)
- Languages, frameworks, build system, entry points
- Output: `/memories/foundation/repo_profile.json`

### ScopeMapper (enhanced)
- **New:** For each module, produce a 2-3 sentence purpose summary
- **New:** Classify each module's security relevance: `critical | important | supporting | test | vendor`
- **New:** Identify module dependencies (which modules call which)
- Output: `/memories/foundation/scope_map.json`

### Phase 1 Output
```json
{
  "system_type": "web_application",
  "purpose": "Security auditing platform with AI-powered code analysis",
  "languages": ["python"],
  "frameworks": ["fastapi", "sqlalchemy", "react"],
  "modules": {
    "agents/": { "purpose": "AI agent orchestration for security scanning", "relevance": "critical" },
    "routers/": { "purpose": "HTTP API endpoints", "relevance": "critical" },
    "services/": { "purpose": "Business logic layer", "relevance": "important" },
    ...
  },
  "entry_points": ["main.py", "routers/*.py"],
  "security_critical_paths": ["agents/", "routers/", "services/auth*.py"]
}
```

---

## Phase 2: Deep Understanding

**Budget:** 30-45% of total
**Goal:** Build a rich security map through ultra-granular analysis
**Agents:** ModuleAnalyzer (parallel, one per critical module), TrustBoundaryMapper, DataFlowMapper, InvariantExtractor

This is the **new** phase. It doesn't exist in v1. The entire purpose is to deeply understand the system before hunting.

### ModuleAnalyzer (NEW)

Dispatched once per security-critical module (from Phase 1's scope map). Each instance deeply analyzes one module.

**Methodology:**
1. Read every file in the module
2. For each function/method, document:
   - What it does (1 sentence)
   - What it assumes about its inputs (preconditions)
   - What it guarantees about its outputs (postconditions)
   - What state it modifies (side effects)
   - What security-relevant operations it performs (DB queries, file I/O, auth checks, crypto, network calls)
3. Identify the module's **state invariants** — properties that must always be true
4. Identify the module's **trust assumptions** — what does it assume about data it receives?
5. **Flag early signals**: If you notice something suspicious while documenting (missing auth check, raw SQL, unsafe deserialization), record it as an `early_signal` in the output. These feed directly into Phase 3 hunting as pre-identified targets.

**Output:** `/memories/understanding/{module_name}/analysis.json`
```json
{
  "module": "services/auth_service.py",
  "purpose": "Handles user authentication: login, token generation, session management",
  "functions": {
    "authenticate_user": {
      "does": "Validates credentials against DB, returns JWT on success",
      "preconditions": ["username is string", "password is string"],
      "postconditions": ["returns valid JWT or raises AuthError"],
      "side_effects": ["updates last_login in DB", "logs auth attempt"],
      "security_ops": ["password_hash_compare", "jwt_sign"]
    },
    ...
  },
  "state_invariants": [
    "All JWTs contain user_id and role claims",
    "Sessions expire after 24h (config.session_ttl)",
    "Failed login attempts are rate-limited per IP"
  ],
  "trust_assumptions": [
    "Request body is parsed by FastAPI (Pydantic validation)",
    "User ID in JWT is trusted after middleware validation",
    "Database returns correct user record for given ID"
  ],
  "early_signals": [
    {
      "location": "services/auth_service.py:88",
      "observation": "Token refresh endpoint does not check if token is revoked before issuing new one",
      "category": "auth_bypass",
      "confidence": "medium"
    }
  ],
  "internal_dependencies": ["models/user.py", "utils/crypto.py"],
  "external_dependencies": ["jose (JWT)", "passlib (hashing)"]
}
```

### TrustBoundaryMapper (ENHANCED)

Builds on v1's ThreatModeler but now has module analyses to work with.

**Reads:** All `/memories/understanding/*/analysis.json` + scope_map
**Produces:**
- Trust boundaries with precise locations (not just "there is auth")
- For each boundary: what enforces it, what data crosses it, what assumptions hold
- Boundary gaps: places where data crosses a trust boundary WITHOUT enforcement

**Output:** `/memories/understanding/trust_boundaries.json`
```json
{
  "boundaries": [
    {
      "name": "HTTP → Application",
      "enforced_by": ["FastAPI Pydantic models", "auth_middleware.py:verify_token()"],
      "data_crossing": ["request body", "path params", "headers", "cookies"],
      "assumptions": ["Pydantic rejects malformed input", "JWT signature is verified"],
      "gaps": [
        {
          "location": "routers/webhook.py:handle_github_webhook",
          "issue": "No auth middleware on webhook endpoint — relies on HMAC signature check inside handler, not middleware",
          "risk": "If HMAC check has a bug, entire payload is trusted"
        }
      ]
    },
    ...
  ]
}
```

### DataFlowMapper (NEW)

Traces how user-controlled data flows through the system at a high level. Not sink-hunting — this is understanding data lifecycles.

**Reads:** Module analyses + trust boundaries
**Produces:** Data flow map showing how input enters, transforms, and reaches sensitive operations

**Output:** `/memories/understanding/data_flows.json`
```json
{
  "flows": [
    {
      "name": "User Authentication Flow",
      "entry": "routers/auth.py:login()",
      "path": [
        {"step": "Pydantic validates LoginRequest", "file": "routers/auth.py:15"},
        {"step": "auth_service.authenticate_user() called", "file": "services/auth_service.py:42"},
        {"step": "DB query: SELECT * FROM users WHERE email = ?", "file": "services/auth_service.py:55"},
        {"step": "passlib.verify() compares hash", "file": "services/auth_service.py:60"},
        {"step": "JWT signed with server secret", "file": "services/auth_service.py:72"}
      ],
      "trust_transitions": ["untrusted → validated (Pydantic)", "validated → authenticated (password check)"],
      "sensitive_ops": ["database_query", "crypto_compare", "token_generation"]
    },
    ...
  ]
}
```

### InvariantExtractor (NEW)

Synthesizes all module analyses to produce system-wide invariants.

**Reads:** All module analyses, trust boundaries, data flows
**Produces:** A consolidated list of system invariants that, if violated, would constitute security vulnerabilities

**Output:** `/memories/understanding/invariants.json`
```json
{
  "invariants": [
    {
      "id": "INV-001",
      "statement": "All API endpoints except /auth/login and /health require a valid JWT",
      "enforced_by": "middleware/auth.py:AuthMiddleware",
      "violation_impact": "Unauthenticated access to protected resources",
      "confidence": "high",
      "evidence": ["routers/__init__.py:12 — middleware applied globally", "routers/auth.py:8 — explicit exclude"]
    },
    {
      "id": "INV-002",
      "statement": "All SQL queries use parameterized statements (SQLAlchemy ORM)",
      "enforced_by": "SQLAlchemy ORM pattern used throughout services/",
      "violation_impact": "SQL injection",
      "confidence": "medium",
      "evidence": ["services/*.py — all use session.execute(select(...))"],
      "risk_note": "Any raw SQL string construction would violate this"
    },
    ...
  ]
}
```

### The Security Map

All Phase 2 outputs combine into the **Security Map** — a structured artifact that replaces v1's flat FoundationContext.

```
/memories/understanding/
├── {module_name}/analysis.json   (per-module deep analysis)
├── trust_boundaries.json          (all trust boundaries + gaps)
├── data_flows.json                (major data flow paths)
├── invariants.json                (system-wide security invariants)
└── security_map_summary.md        (human-readable synthesis)
```

The `security_map_summary.md` is a natural-language synthesis that gets injected into all Phase 3+ agent prompts (replacing the old FoundationContext string). It includes:
- System purpose and architecture (2-3 paragraphs)
- Trust boundary summary with enforcement points
- Top 10 invariants
- Known gaps and areas of concern
- Data flow summary for critical paths

---

## Phase 3: Targeted Hunting

**Budget:** 25-35% of total
**Goal:** Find invariant violations and vulnerability patterns, guided by the Security Map
**Agents:** Specialist hunters with skills/training packets

### Shift: From Sink Scanning to Invariant Violation Detection

v1 hunting: "Find all calls to `subprocess.run()` and check if input is sanitized"
v2 hunting: "Given invariant INV-002 (all SQL uses parameterized queries), find any code path that constructs SQL strings directly"

The difference is crucial. v1 generates noise by flagging every dangerous function call. v2 targets specific invariant violations, which are *by definition* security-relevant.

### Skills as Training Packets

Each specialist receives a **skill file** containing:

1. **Methodology**: Step-by-step analysis procedure
2. **Decision tree**: How to classify findings (vulnerable vs. hardened vs. by-design)
3. **Real-world CVE examples**: Actual vulnerable code snippets + fixed versions
4. **False positive patterns**: Common things that LOOK vulnerable but aren't
5. **Severity calibration**: What makes this HIGH vs. MEDIUM vs. LOW

Skills are stored as files in the repository:

```
backend/agents/deep_audit/skills/
├── injection/
│   ├── sql_injection.md
│   ├── command_injection.md
│   ├── template_injection.md
│   └── examples/
│       ├── cve-2024-xxxx-django-sql.md
│       ├── cve-2023-xxxx-node-cmd.md
│       └── ...
├── auth/
│   ├── auth_bypass.md
│   ├── idor.md
│   ├── privilege_escalation.md
│   └── examples/
│       └── ...
├── memory/
│   ├── buffer_overflow.md
│   ├── use_after_free.md
│   └── examples/
│       └── ...
├── crypto/
│   ├── weak_randomness.md
│   ├── crypto_misuse.md
│   └── examples/
│       └── ...
├── web/
│   ├── ssrf.md
│   ├── path_traversal.md
│   └── examples/
│       └── ...
├── deserialization/
│   ├── unsafe_deserialization.md
│   └── examples/
│       └── ...
├── concurrency/
│   ├── race_conditions.md
│   ├── toctou.md
│   └── examples/
│       └── ...
└── logic/
    ├── trust_boundary_violations.md
    ├── state_invariant_breaks.md
    └── examples/
        └── ...
```

### Skill File Format

```markdown
# SQL Injection Detection

## Methodology

### Step 1: Identify Query Construction Points
Search for all locations where SQL queries are constructed. This includes:
- Raw string concatenation with SQL keywords
- f-string or .format() with SQL keywords
- String templates with SQL fragments
- ORM raw query methods (e.g., `text()`, `raw()`, `execute()`)

### Step 2: Trace Input Source
For each query construction point, trace backwards:
- Is ANY part of the query derived from user input?
- How many hops between user input and query construction?
- Are there sanitization/validation steps in between?

### Step 3: Evaluate Defenses
Check for:
- Parameterized queries (safe)
- ORM-level escaping (usually safe, check version)
- Manual escaping (fragile — check for bypass)
- Input validation (defense-in-depth, not sufficient alone)
- WAF rules (not a fix, just a band-aid)

### Step 4: Classify
- **VULNERABLE**: User input reaches query construction without parameterization
- **HARDENED**: Defense exists but is fragile (e.g., manual escaping, allowlist that might be incomplete)
- **SAFE**: Parameterized query or ORM with no raw SQL
- **BY_DESIGN**: Raw SQL used but input is not user-controlled (e.g., admin-only config)

## Decision Tree

```
Is SQL constructed from external input?
├── No → SAFE (not a finding)
├── Yes → Is it parameterized?
    ├── Yes → SAFE
    ├── No → Is input validated/sanitized?
        ├── No → VULNERABLE (Critical if unauth, High if auth)
        ├── Yes → Is validation sufficient?
            ├── Allowlist of known values → SAFE
            ├── Blocklist/regex → HARDENED (Medium — bypass risk)
            ├── Type cast (int/uuid) → SAFE
            └── Custom escaping → HARDENED (High — fragile)
```

## Real-World Examples

### CVE-2024-XXXXX: Django Raw SQL in Admin View
**Vulnerable code:**
```python
def admin_search(request):
    query = request.GET.get('q', '')
    results = User.objects.raw(f"SELECT * FROM users WHERE name LIKE '%{query}%'")
    return render(request, 'results.html', {'results': results})
```

**Why vulnerable:** User-controlled `query` parameter interpolated directly into raw SQL.
**Impact:** Full database read/write via UNION-based or stacked queries.
**Fix:**
```python
def admin_search(request):
    query = request.GET.get('q', '')
    results = User.objects.raw(
        "SELECT * FROM users WHERE name LIKE %s",
        [f'%{query}%']
    )
    return render(request, 'results.html', {'results': results})
```

### False Positive: ORM Query with Dynamic Column
```python
# This LOOKS dangerous but is NOT user-controlled:
ALLOWED_SORT_COLUMNS = {"name", "created_at", "email"}
sort_by = request.GET.get("sort", "name")
if sort_by not in ALLOWED_SORT_COLUMNS:
    sort_by = "name"
users = session.execute(text(f"SELECT * FROM users ORDER BY {sort_by}"))
```
**Why safe:** `sort_by` is validated against a strict allowlist before use.
```

### Hunting Wave Structure

Instead of v1's rotating 8-category focus, v2 dispatches hunters based on the Security Map:

1. **Invariant Violation Hunters**: One per high-confidence invariant — verify that the invariant actually holds everywhere
2. **Trust Boundary Gap Hunters**: One per identified gap — investigate whether the gap is exploitable
3. **Data Flow Hunters**: One per critical data flow — trace for injection, manipulation, or leakage
4. **Pattern Hunters**: Traditional sink-pattern hunting, but filtered to only security-critical modules and guided by the security map

**Time allocation within Phase 3:**
- 50% for invariant + boundary hunters (highest signal)
- 30% for data flow hunters
- 20% for pattern hunters (catch stragglers)

### Forced Depth with Agent Choice

Agents are **forced to go deep** on their assigned area — they cannot dismiss without evidence. But they **choose where to focus** within that area.

Implementation:
- Each hunter gets a scope (module, invariant, or data flow) and a time budget
- The skill file prescribes minimum analysis steps (can't skip)
- The agent decides which files within the scope deserve the most attention
- Quality gate: Overseer rejects outputs that don't meet minimum evidence thresholds

```python
# Enforcement in dispatcher
MINIMUM_EVIDENCE_THRESHOLDS = {
    "InvariantViolationHunter": {
        "files_examined": 5,           # Must look at >= 5 files
        "functions_analyzed": 10,      # Must analyze >= 10 functions
        "evidence_items": 3,           # Must cite >= 3 pieces of evidence
    },
    "TrustBoundaryGapHunter": {
        "files_examined": 3,
        "paths_traced": 2,
        "evidence_items": 2,
    },
}
```

---

## Phase 4: Verification (Mostly Unchanged)

**Budget:** 15-20% of total
**Goal:** Verify hunting results through multi-stage pipeline

The v1 verification pipeline is solid. Keep:
- **Decider** → "Should we investigate?"
- **FamilyCoordinator** → "Which specialist and what context?"
- **Specialist** → "Is this technically a vulnerability?" (now with skill/training packet)
- **Cross-validation** for CRITICAL findings
- **Devil's Advocate** for quick dismissals
- **Triager** → "Does this match our threat model?"

### Enhancement: Specialist Skills Integration

The key change: when a Specialist is dispatched, it receives its **skill file** as additional context. The skill contains the methodology, decision tree, and CVE examples for that vulnerability class.

```python
# In dispatcher.py, when spawning a specialist:
skill_content = load_skill(specialist_family)  # e.g., "injection/sql_injection.md"
system_prompt = f"""
{security_map_summary}

{skill_content}

{specialist_base_prompt}
"""
```

This means specialists now have:
1. System understanding (security map)
2. Domain expertise (skill/training packet with real CVE examples)
3. Technical analysis capability (tools)

### Enhancement: Invariant-Aware Triager

The Triager now receives the invariants list in addition to the threat model. A finding is more severe if it violates a stated invariant, because the invariant represents a deliberate security design decision.

---

## Eager Finding Persistence (Cross-Cutting)

Findings are persisted to the database **the moment they are confirmed** — not at finalize. This is a hard rule carried over from the v1 fixes:

1. **Phase 3 (Hunting)**: When a hunter confirms a signal, it's saved to DB immediately with `status: "unverified"` and emitted to WebSocket. The UI shows it right away.
2. **Phase 4 (Verification)**: When the Triager confirms a finding, the DB record is updated to `status: "verified"` with severity and classification. The UI updates in-place.
3. **Phase 4 (Verification)**: When the Triager dismisses a finding, the DB record is updated to `status: "dismissed"`. The UI can filter these.
4. **Phase 5 (Finalize)**: Only produces the final report and summary. All findings are already in DB.

The UI always reads from DB. If the scan crashes at any point, all findings discovered so far are preserved and visible.

```
Finding lifecycle in DB:
  Phase 3 hunter confirms → INSERT with status="unverified"  → UI shows immediately
  Phase 4 triager confirms → UPDATE status="verified"         → UI updates in-place
  Phase 4 triager dismisses → UPDATE status="dismissed"       → UI can filter
  Phase 5 finalize         → No DB writes (just report gen)   → UI unchanged
```

---

## Phase 5: Finalize

**Budget:** 5% of total

- Generate final report synthesis (`/memories/overseer/final_report.md`)
- All findings already persisted to DB from Phase 3/4
- Emit scan completion event to WebSocket
- Final statistics and coverage summary

---

## Time-Scaled Depth

The budget percentages above define how time is distributed. As the total budget grows, each phase gets proportionally more time, which translates to **deeper analysis** of the same components.

### What More Time Buys

| Component | 5 min | 15 min | 45 min | 90 min | 4 hr |
|-----------|-------|--------|--------|--------|------|
| **Orientation** | 1 agent, top-level scan | 2 agents, module-level | Full scope map with dependencies | + cross-module analysis | + third-party integration mapping |
| **Understanding** | Skip (not enough time) | 2-3 critical modules analyzed | All critical modules, basic invariants | + important modules, full invariants | Ultra-granular: every function documented in critical modules |
| **Hunting** | Pattern-only, top 3 sinks | Invariant + pattern, top module | All invariants + boundary gaps | + data flow tracing | Multiple passes with variant analysis |
| **Verification** | Decider + Triager only | + Specialist for HIGH+ | + Cross-validation for CRITICAL | + Devil's Advocate | Full pipeline for all findings |

### Adaptive Budget Allocation

The Overseer adjusts phase budgets based on what it finds:

```python
# Overseer decision logic (simplified)
if understanding_phase_found_many_invariant_gaps:
    # Spend more time hunting, less on further understanding
    hunting_budget *= 1.3
    understanding_budget *= 0.7
elif understanding_phase_found_few_concerns:
    # System is well-designed — spend more on edge cases
    hunting_budget *= 0.8
    # Reallocate to deeper verification
    verification_budget *= 1.2
```

### Minimum Viable Scan (5 minutes)

Even the shortest scan follows the understand-first principle:
1. **30s**: RepoProfiler (what is this?)
2. **60s**: Quick scope assessment (what's security-critical?)
3. **120s**: Pattern hunting on top 2-3 critical modules
4. **60s**: Decider + Triager on top findings
5. **30s**: Finalize

The understanding phase is compressed but never skipped.

---

## Memory Files Pattern

All agents write their understanding to `/memories/`. This serves three purposes:

1. **Context passing**: Later agents read earlier agents' summaries instead of re-analyzing code
2. **Progressive summarization**: Each layer adds structure and insight
3. **Crash recovery**: If an agent crashes, its partial output is preserved

### Memory Directory Structure (v2)

```
/memories/
├── foundation/
│   ├── repo_profile.json          (RepoProfiler)
│   └── scope_map.json             (ScopeMapper)
│
├── understanding/                  (NEW - Phase 2)
│   ├── {module_name}/
│   │   └── analysis.json          (ModuleAnalyzer — per module)
│   ├── trust_boundaries.json      (TrustBoundaryMapper)
│   ├── data_flows.json            (DataFlowMapper)
│   ├── invariants.json            (InvariantExtractor)
│   └── security_map_summary.md    (Overseer synthesis)
│
├── hunting/                        (Phase 3 — replaces signals/)
│   ├── invariant_violations/
│   │   └── {invariant_id}.json    (InvariantViolationHunter results)
│   ├── boundary_gaps/
│   │   └── {gap_id}.json          (TrustBoundaryGapHunter results)
│   ├── data_flow_issues/
│   │   └── {flow_id}.json         (DataFlowHunter results)
│   └── pattern_matches/
│       └── {wave_id}.json         (PatternHunter results)
│
├── verification/                   (Phase 4 — replaces routing/)
│   ├── {signal_id}/
│   │   ├── decider.json
│   │   ├── coordinator.json
│   │   ├── specialist.json
│   │   ├── challenge.json         (Devil's Advocate, if triggered)
│   │   └── triager.json
│   └── ...
│
├── overseer/
│   ├── phase_1_synthesis.md
│   ├── phase_2_synthesis.md
│   ├── phase_3_synthesis.md
│   ├── campaign_state.json
│   └── final_report.md
│
└── skills_used.json               (which skills were loaded for which agents)
```

---

## New Agent Types

### ModuleAnalyzer (NEW)

**Purpose:** Deep analysis of a single module's security properties
**Tools:** `read_file`, `search_code`, `list_directory`, `find_usages`
**Input:** Module path + scope_map context
**Output:** `/memories/understanding/{module}/analysis.json`
**Time budget:** Scales with module size. Base: 60s for <500 LOC, 120s for <2000 LOC, 240s for <5000 LOC, 360s for >5000 LOC.

**Prompt excerpt:**
```
You are performing ultra-granular security analysis of a single module.
Your job is NOT to find vulnerabilities. Your job is to UNDERSTAND this code
deeply enough that vulnerabilities become obvious.

For every function/method, document:
1. What it does (1 sentence)
2. Preconditions (what must be true for it to work correctly)
3. Postconditions (what it guarantees)
4. Side effects (state mutations, I/O, network calls)
5. Security-relevant operations (auth checks, crypto, DB queries, file I/O, subprocess, network)

Then synthesize:
- State invariants: properties that must always hold
- Trust assumptions: what this module assumes about its inputs
- Attack surface: where external input touches this module
```

### TrustBoundaryMapper (ENHANCED from ThreatModeler)

**Purpose:** Map all trust boundaries with enforcement details
**Tools:** `read_file`, `search_code`, `find_usages`, `list_directory`
**Input:** All module analyses
**Output:** `/memories/understanding/trust_boundaries.json`

### DataFlowMapper (NEW)

**Purpose:** Map critical data flows from entry to sensitive operation
**Tools:** `read_file`, `search_code`, `find_usages`, `trace_data_flow`
**Input:** Module analyses + trust boundaries
**Output:** `/memories/understanding/data_flows.json`

### InvariantExtractor (NEW)

**Purpose:** Synthesize system-wide invariants from module analyses
**Tools:** `read_file` (reads other agents' outputs)
**Input:** All module analyses + trust boundaries + data flows
**Output:** `/memories/understanding/invariants.json`

### InvariantViolationHunter (NEW)

**Purpose:** Verify a specific invariant holds across the codebase
**Tools:** `read_file`, `search_code`, `find_usages`, `grep_semantic`
**Input:** One invariant from invariants.json + security map
**Skill:** Loaded based on invariant category (e.g., auth invariant → auth_bypass.md skill)
**Output:** `/memories/hunting/invariant_violations/{invariant_id}.json`

### TrustBoundaryGapHunter (NEW)

**Purpose:** Investigate an identified boundary gap for exploitability
**Tools:** `read_file`, `search_code`, `find_usages`, `trace_data_flow`
**Input:** One gap from trust_boundaries.json + security map
**Skill:** Loaded based on gap type
**Output:** `/memories/hunting/boundary_gaps/{gap_id}.json`

### Existing Agents (Retained)

- **SinkHunter** → renamed to **PatternHunter**, demoted to supplementary role
- **EntrypointHunter** → merged into ScopeMapper
- **DataflowTracer** → retained for verification phase
- **Decider, FamilyCoordinator, Specialist, Triager, Devil's Advocate, Arbiter** → retained

---

## Skills Integration

### How Skills Are Loaded

```python
# skills_loader.py (NEW)

SKILLS_DIR = Path("backend/agents/deep_audit/skills")

def load_skill(family: str, vuln_type: str) -> str:
    """Load a skill file for a specialist.

    Args:
        family: e.g., "injection", "auth", "memory"
        vuln_type: e.g., "sql_injection", "auth_bypass"

    Returns:
        Skill content as string, or empty string if no skill exists.
    """
    skill_path = SKILLS_DIR / family / f"{vuln_type}.md"
    if skill_path.exists():
        return skill_path.read_text()
    return ""

def load_examples(family: str, vuln_type: str, max_examples: int = 3) -> str:
    """Load real-world CVE examples for a vulnerability type."""
    examples_dir = SKILLS_DIR / family / "examples"
    if not examples_dir.exists():
        return ""

    examples = []
    for f in sorted(examples_dir.glob(f"*{vuln_type}*.md"))[:max_examples]:
        examples.append(f.read_text())

    return "\n\n---\n\n".join(examples)
```

### Skill Injection Points

1. **Phase 3 hunters**: InvariantViolationHunter and TrustBoundaryGapHunter receive the relevant skill based on the category of invariant/gap they're investigating
2. **Phase 4 specialists**: Specialist agents receive the skill for their vulnerability family (this is the biggest quality improvement — specialists go from generic prompts to domain-expert training packets)
3. **Phase 4 Devil's Advocate**: Receives the same skill as the specialist it's challenging, plus the false positive patterns section

### Creating Skills

Skills should be created iteratively:
1. Start with the most common vulnerability families (injection, auth, web)
2. Each skill starts with methodology + decision tree
3. Add real-world CVE examples as they're found or curated
4. Refine based on false positive/negative rates from calibration data

Priority order for initial skill creation:
1. `injection/sql_injection.md` — most common, well-understood
2. `injection/command_injection.md` — high impact
3. `auth/auth_bypass.md` — logic-heavy, benefits most from examples
4. `web/ssrf.md` — common in modern apps
5. `web/path_traversal.md` — common, well-understood
6. `deserialization/unsafe_deserialization.md` — high impact
7. `auth/idor.md` — logic bug, hard to pattern-match
8. `crypto/weak_randomness.md` — subtle, examples help
9. `logic/trust_boundary_violations.md` — NEW category, needs methodology
10. `logic/state_invariant_breaks.md` — NEW category, needs methodology

---

## Implementation Plan

### Phase A: Skills Infrastructure (Foundation)

**Bead: qh-skills-infra**

1. Create `backend/agents/deep_audit/skills/` directory structure
2. Create `backend/agents/deep_audit/skills_loader.py` with `load_skill()` and `load_examples()`
3. Create 3 initial skill files:
   - `injection/sql_injection.md`
   - `auth/auth_bypass.md`
   - `logic/trust_boundary_violations.md`
4. Wire skills loading into dispatcher.py specialist spawning
5. Tests: skill loading, fallback when skill doesn't exist

### Phase B: Understanding Phase Agents (Core Change)

**Bead: qh-understanding-agents**

1. Create ModuleAnalyzer agent prompt + dispatch logic
2. Create TrustBoundaryMapper enhanced prompt (upgrade from ThreatModeler)
3. Create DataFlowMapper agent prompt + dispatch logic
4. Create InvariantExtractor agent prompt + dispatch logic
5. Update `/memories/` directory structure in filesystem.py
6. Tests: mock agent outputs, verify memory file structure

### Phase C: Security Map Synthesis

**Bead: qh-security-map**

1. Add Overseer Phase 2 logic: dispatch understanding agents, collect outputs
2. Implement `security_map_summary.md` generation from Phase 2 outputs
3. Replace FoundationContext prompt injection with SecurityMap injection
4. Update phase transitions: ORIENTATION → UNDERSTANDING → HUNTING
5. Tests: end-to-end Phase 1+2 with mock agents

### Phase D: Targeted Hunting

**Bead: qh-targeted-hunting**

1. Create InvariantViolationHunter agent prompt
2. Create TrustBoundaryGapHunter agent prompt
3. Rename SinkHunter → PatternHunter, demote to supplementary
4. Update wave planning to dispatch invariant/boundary hunters first
5. Wire skill loading into hunting agents
6. Tests: hunting with mock security map

### Phase E: Verification Enhancement

**Bead: qh-verification-enhance**

1. Wire skills into Specialist agent spawning
2. Wire skills into Devil's Advocate spawning
3. Add invariant-aware severity scoring to Triager
4. Tests: verification pipeline with skills

### Phase F: Time Scaling & Budget Logic

**Bead: qh-time-scaling**

1. Implement percentage-based budget allocation (replace fixed tiers)
2. Implement adaptive budget reallocation
3. Implement minimum evidence thresholds for hunting agents
4. Update Overseer loop for phase-based budget tracking
5. Tests: budget allocation at various scan durations

### Phase G: Additional Skills

**Bead: qh-skills-pack-1**

Create remaining priority skills:
- `injection/command_injection.md`
- `web/ssrf.md`
- `web/path_traversal.md`
- `deserialization/unsafe_deserialization.md`
- `auth/idor.md`
- `crypto/weak_randomness.md`
- `logic/state_invariant_breaks.md`

Each with methodology, decision tree, and at least 2 CVE examples.

---

## Migration Strategy

This is NOT a rewrite. It's an expansion of the existing pipeline.

**What stays:**
- WaveDispatcher (subprocess spawning via claude CLI)
- CampaignState (add new fields, don't remove existing)
- /memories/ filesystem (expand directory structure)
- Verification pipeline (Decider → Coordinator → Specialist → Triager)
- Calibration system
- JSON-only output format
- All existing tools

**What changes:**
- Phase pipeline: 5 phases → 5 phases (but different composition)
- Foundation phase: expanded to 2 phases (Orientation + Understanding)
- FoundationContext: replaced by SecurityMap (richer, structured)
- Hunting: guided by invariants/boundaries instead of blind sink scanning
- Specialist prompts: enhanced with skill files

**What's new:**
- ModuleAnalyzer, DataFlowMapper, InvariantExtractor agent types
- InvariantViolationHunter, TrustBoundaryGapHunter agent types
- Skills directory with methodology + CVE example files
- skills_loader.py
- Security Map artifact
- Percentage-based time allocation

**Backwards compatibility:**
- Old scan tiers still work (time budgets map to percentages)
- SinkHunter/EntrypointHunter still exist as fallback agents
- If understanding phase produces no invariants (empty codebase), falls back to v1 pattern hunting

---

## Success Criteria

1. **False positive rate drops by >50%** compared to v1 on the same test repositories
2. **Trust boundary violations detected** — a class of finding v1 cannot produce
3. **State invariant breaks detected** — another class v1 cannot produce
4. **Specialist accuracy improves** as measured by calibration system (skills training packets working)
5. **Longer scans produce proportionally deeper results** — not just more of the same
6. **Security Map artifact is human-readable** and useful as a standalone security document

---

## Resolved Design Decisions

1. **Model selection**: User chooses the model for all subagents. No hardcoded model per agent type. The dispatcher passes through whatever model the user selected in the scan configuration.

2. **Finding emission**: Findings persist to DB the moment they're confirmed (eager persistence). The UI always reads from DB. See "Eager Finding Persistence" section above.

3. **ModuleAnalyzer behavior**: Both document AND hunt. If it notices suspicious patterns while analyzing, it records them as `early_signals` that feed directly into Phase 3 hunting.

4. **Initial skills authorship**: We (Claude) draft the initial skills with methodology, decision trees, and example CVEs. User curates and refines.

5. **Inspiration, not imitation**: The architecture is inspired by professional audit methodology but is our own design. No direct copying of external frameworks.

6. **Skill maintenance**: Skills are versioned in git. Updates are manual (curated), not automated. Focus on methodology over exhaustive CVE lists.

## Open Questions

1. **Module granularity**: Should ModuleAnalyzer operate on directories or files? Directories risk being too coarse; files risk being too many agents. **Proposed:** Directories for large codebases, files for small ones (< 50 files).

2. **Invariant extraction accuracy**: LLMs may hallucinate invariants. **Proposed:** InvariantExtractor cites evidence (file:line) for every invariant. Overseer quality-checks citations.

3. **Cross-module understanding**: Some vulnerabilities span multiple modules (e.g., auth bypass requires understanding both the middleware and the route handler). **Proposed:** TrustBoundaryMapper and DataFlowMapper naturally cross module boundaries since they read all module analyses.

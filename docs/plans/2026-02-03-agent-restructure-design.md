# Agent Architecture Restructure Design

**Date:** 2026-02-03
**Status:** Draft
**Author:** Collaborative design session

## Problem Statement

The current agent system finds issues that are:
- Sometimes invalid (false positives)
- Sometimes valid but low-severity
- Missing deeper, more critical issues because it's not going deep enough
- Flagging things like "funky exec() function" without understanding if input is from trusted source

## Solution Overview

A restructured multi-phase architecture that:
1. Builds complete context BEFORE hunting (Foundation Phase)
2. Uses threat model to filter what's actually suspicious
3. Routes suspicious signals to domain-expert specialists (64 across 14 families)
4. Employs "Devil's Advocate" pushing at every level to force deeper analysis
5. Uses an Arbiter for disagreement resolution with "broader first" approach

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         OVERSEER                                 │
│            (Orchestrator + Devil's Advocate)                     │
│         Adaptive time management, pushes all agents              │
└─────────────────────────────────────────────────────────────────┘
                              │
         ┌────────────────────┼────────────────────┐
         ▼                    ▼                    ▼
   RepoProfiler          ScopeMapper         ThreatModeler
         │                    │                    │
         └────────────────────┼────────────────────┘
                              │
                    [Foundation Context]
                              │
         ┌────────────────────┼────────────────────┐
         ▼                    ▼                    │
   EntrypointHunter      SinkHunter               │
   (with threat model)   (with threat model)      │
         │                    │                   │
         └─────────┬──────────┘                   │
                   ▼                              │
          Suspicious Signals                      │
                   │                              │
                   ▼                              │
              DECIDER ─────────────────────────────
            (Family assignment)                   │
                   │                              │
    ┌──────────────┼──────────────┐              │
    ▼              ▼              ▼              │
 Family        Family         Family            │
 Coord 1       Coord 2        Coord N           │
 (Memory)    (Injection)      (etc.)            │
    │              │              │              │
    ▼              ▼              ▼              │
Specialists   Specialists   Specialists          │
(1-N each)    (1-N each)    (1-N each)          │
    │              │              │              │
    └──────────────┼──────────────┘              │
                   │                              │
            [If disagreement]                     │
                   ▼                              │
               ARBITER ───────────────────────────
         (Broader scan first,                    │
          then detailed analysis)                │
                   │                              │
                   ▼                              │
              TRIAGER                             │
         (Code-based final call)                 │
                   │                              │
                   ▼                              │
           CONFIRMED FINDINGS                     │
                   │                              │
                   ▼                              │
            [FUTURE: Reproducer]                  │
                                                  │
    DataflowTracer ◄──────────────────────────────┘
    (Passive, updates diagram throughout)
```

## Phase 1: Foundation

**Purpose:** Build complete context BEFORE any vulnerability hunting begins.

**Agents:**
- **RepoProfiler** - Analyzes repo structure, languages, build systems, frameworks
- **ScopeMapper** - Maps modules, identifies key files, entry points, security-relevant areas
- **ThreatModeler** - Creates threat model defining trust boundaries, attacker capabilities, what's in-scope

**Execution:** All three run in parallel at audit start.

**Output:** Foundation Context object:
```json
{
  "repo_profile": {
    "languages": ["C++", "Python"],
    "frameworks": ["gRPC", "Protobuf"],
    "build_system": "Bazel",
    "entry_points": ["src/server/main.cc", "api/handlers/"]
  },
  "scope_map": {
    "security_critical": ["crypto/", "auth/", "api/"],
    "test_code": ["test/", "*_test.cc"],
    "vendor": ["third_party/"]
  },
  "threat_model": {
    "trust_boundaries": [...],
    "attacker_capabilities": "network access, no auth initially",
    "out_of_scope": ["admin-only internal tools"]
  }
}
```

**Key principle:** No hunting happens until Foundation is complete.

## Phase 2: Hunting

**Purpose:** Find suspicious signals, NOT verify them. Lower bar for flagging, higher bar for verification.

**Agents:**
- **EntrypointHunter** - Finds HTTP routes, CLI handlers, RPC endpoints, message queue consumers
- **SinkHunter** - Identifies dangerous sinks: SQL queries, command execution, file operations, memory operations

**Key behavior:** Hunters have Foundation Context injected. They use ThreatModel to filter:
- Is input from untrusted source?
- Is this test/vendor code?
- Is this in-scope per threat model?

**Output:** Suspicious Signals (not findings):
```json
{
  "signal_id": "sig-001",
  "type": "dangerous_sink",
  "location": {"file": "api/execute.cc", "line": 45},
  "sink_category": "command_execution",
  "code_snippet": "exec(user_command)",
  "why_suspicious": "User-controlled string flows to exec()",
  "entry_point_trace": ["POST /api/run", "handle_run()", "exec()"]
}
```

**Time scaling:** More review time = looser filtering (report more). Less time = stricter (only high-confidence).

**Multiple passes:** Longer runs = more waves, each looking deeper or at different angles.

## Phase 3: Routing

**Stage 1 - Decider:**
- Receives suspicious signal
- Classifies into one of 14 families
- Passes signal + Foundation Context to Family Coordinator

**Stage 2 - Family Coordinator:**
- Evaluates which specialist(s) within family should analyze
- Errs on side of inclusion - if multiple specialists might be relevant, send to all
- Challenges specialists when they return with "not vulnerable" too quickly

**What gets passed to specialists:**
```json
{
  "signal": { ... },
  "foundation_context": { "repo_profile": {}, "scope_map": {}, "threat_model": {} },
  "related_signals": [],
  "entry_point_trace": [],
  "coordinator_notes": "Consider multiple attack angles"
}
```

## Phase 4: Specialists

**Structure:** 64 specialists across 14 families.

### Specialist Families

| Family | Count | Specialists |
|--------|-------|-------------|
| Memory Safety | 8 | OOB Read/Write, UAF, Double-Free, Uninit Memory, Integer Overflow, Format String, Type Confusion, Unsafe FFI |
| Injection | 10 | SQL, NoSQL, OS Command, Template (SSTI), Expression/Eval, LDAP, XPath, CRLF/Header, Log, Email/SMTP |
| Web Edge Cases | 4 | SSRF, Request Smuggling, Cache Poisoning, Host Header |
| Browser/Client | 4 | XSS, Prototype Pollution, Clickjacking, CSP/Frontend |
| Deserialization/Parsing | 6 | Unsafe Deser, Parser Differential, XXE, Zip Slip, ReDoS, File Parser |
| File System | 4 | Path Traversal, File Upload, Symlink/TOCTOU, Temp File/Permissions |
| AuthN/Session | 5 | AuthN Bypass, Session Management, CSRF, OAuth/OIDC, JWT Validation |
| AuthZ/Business Logic | 5 | IDOR/BOLA, Privilege Escalation, Multi-Tenant Isolation, Workflow Bypass, Rate Limit |
| Crypto/Secrets | 4 | Crypto Misuse, Randomness/Token Gen, Secrets Handling, TLS/Cert Validation |
| Infrastructure | 4 | Insecure Config, Container/Sandbox, Kubernetes Manifest, CI/CD Pipeline |
| Supply Chain | 3 | Dependency Risk, Dependency Confusion, Plugin/Extension System |
| Concurrency | 2 | Race Condition, DoS/Resource Exhaustion |
| Data Exposure | 2 | Sensitive Data Exposure, Token/PII in URL |
| API Design | 3 | Mass Assignment, Parameter Pollution, GraphQL Security |

### Specialist Workflow

```
1. Receive signal + full context

2. Understand the system first:
   - How does this code fit into the larger system?
   - What are the trust boundaries around it?
   - What does the threat model say?

3. Attempt to exploit (conceptually):
   - What would an attacker need to control?
   - Is that actually controllable given entry points?
   - Are there bypasses to apparent protections?

4. Go broader when stuck:
   - Alternative paths to same sink?
   - Different entry points?
   - What if assumptions are wrong?

5. Conclude with evidence:
   - VULNERABLE: Exact path, why protections fail
   - NOT VULNERABLE: Every angle tried, why each fails
```

**Key principle:** Specialists try to BREAK it. Failure to break (after thorough attempts) = confidence it's secure.

## Phase 5: Arbiter

**Triggered when:** Multiple specialists disagree on same signal.

**Workflow:**
```
1. Receive all specialist reports with reasoning

2. EXPAND THE SEARCH FIRST:
   - Find all related sinks
   - Find all entry points to this area
   - Scan for similar patterns
   - Build complete picture of attack surface

3. THEN analyze each avenue:
   - With full context of all possibilities
   - Detailed check of each path

4. Verdict based on complete understanding
```

**Key principle:** Can't judge one path without knowing ALL paths first. Broad discovery → then deep analysis.

## Phase 6: Triager

**Purpose:** Final classification before reporting.

**Works on:** Pure codebase analysis, no execution.

**Classifications:**
- **VALID_SECURITY_ISSUE** - Real, exploitable, in-scope
- **HARDENING** - Good to fix but not exploitable as-is
- **BY_DESIGN** - Intentional, threat model accepts this risk
- **SPECULATIVE** - Requires too many assumptions

## Future: Reproducer

**Status:** Back burner - needs infrastructure work.

**Would need:**
- Safe execution environment (containerized)
- Tooling to create and run PoCs
- Feedback loop when stuck
- Bottleneck/backlog management

## Devil's Advocate System

**Built into Overseer:** Challenges Hunters, Foundation agents.

**Built into Family Coordinators:** Challenges Specialists.

### Challenge Approach

**Wrong (leads to hallucination):**
```
"Check line 42, there's an overflow there"
```

**Right (pushes deeper thinking):**
```
"You concluded this is not vulnerable.
- Is there ANY alternative path that could make this exploitable?
- What would need to be true for this to BE vulnerable?
- Try to prove yourself wrong."
```

**Key phrases:**
- "Is there any merit to making this valid?"
- "What would need to be true for this to be exploitable?"
- "Try to find a way to make this work"
- "Think broader - what did you assume that might not hold?"

**Grounded in reality:** Always referring back to actual code. No inventing.

## Time Management

**Philosophy:**
- Time tiers set total budget (quick, medium, deep, exhaustive)
- Overseer adaptively decides how to spend it
- NO fixed phase time limits
- Phases complete when actually done, not arbitrarily cut short

**Adaptive behaviors:**
- Remaining time vs signals found → adjust strictness
- Patterns emerging → trigger targeted collaboration
- Running behind → prioritize highest-severity

**Continuous deepening:**
- Never accept "I've searched everything" at face value
- Push for more passes, different angles
- Collaboration grows over time - agents share discoveries

## Key Design Decisions

| Decision | Choice |
|----------|--------|
| Foundation first | RepoProfiler + ScopeMapper + ThreatModeler before any hunting |
| Hunters | Report suspicious signals, not verified findings |
| Routing | Two-stage: Decider → Family → Specialist(s) |
| Multiple specialists | If equal likelihood, send to all, merge results |
| Disagreement | Arbiter expands search first, then analyzes |
| Devil's Advocate | Built into Overseer AND Family Coordinators |
| Pushing approach | "Prove yourself wrong" - go broader, deeper, more context |
| No hallucination | Push on methodology/approach, not specific details |
| Time management | Adaptive within total budget, no fixed phase limits |
| Specialists | 64 across 14 families, each with trigger criteria + proficiency |
| Triager | Code-based final classification |
| Reproducer | Future - needs execution environment |
| DataflowTracer | Passive, updates diagram from orchestrator activity |

## Implementation Notes

This is a significant restructure. Recommended approach:
1. Start with Foundation Phase (most independent)
2. Refactor Hunters to output signals (not findings) with threat model context
3. Build Decider + one Family Coordinator as proof of concept
4. Add specialists incrementally by family
5. Add Arbiter once multiple specialists exist
6. Refine Devil's Advocate prompting iteratively

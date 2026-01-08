# CASS: Continuous Architecture Security Scanner

## Overview

CASS is a two-phase security analysis system that builds deep understanding of a codebase before hunting vulnerabilities. Instead of scanning files in isolation, it constructs a knowledge graph of security-relevant components, then uses that context for deep analysis.

**Problem:** Single-pass scans lack context. They can't trace cross-file vulnerabilities, don't understand which inputs are validated, and can't see the full attack surface.

**Solution:** An agentic architecture discovery system that explores incrementally, builds a structured knowledge graph, and feeds rich context to the Ultrathink verification cascade.

## Two-Phase Workflow

```
┌─────────────────────┐         ┌─────────────────────┐
│  PHASE 1            │         │  PHASE 2            │
│  Map Architecture   │───────▶ │  Security Scan      │
│                     │  User   │                     │
│  Agent explores     │ Reviews │  Attack surface     │
│  Builds graph       │  Graph  │  generation         │
│  Emits progress     │         │  Ultrathink cascade │
└─────────────────────┘         └─────────────────────┘
```

### Phase 1: Map Architecture

The agent explores the codebase using tools, building a structured knowledge graph. It works in passes:

1. **Bootstrap** - Detect frameworks, languages, dependencies
2. **Entry Points** - Find all ways into the application
3. **Data Flow** - Trace inputs to dangerous sinks
4. **Security Boundaries** - Map auth, validation, access control

The agent decides what to explore next based on gaps in its knowledge graph and security-risk prioritization.

### Phase 2: Security Scan

User reviews the knowledge graph (visualized in UI), then triggers security analysis. The scan:

- Generates attack surface candidates from graph paths
- Builds rich context for each candidate (full path, validators, auth checks)
- Feeds candidates to Ultrathink cascade for verification
- Reports verified findings

## Knowledge Graph Schema

### Security-Critical Node Types (Priority)

```
┌─────────────────────────────────────────────────────────────────┐
│                      KNOWLEDGE GRAPH                            │
├─────────────────────────────────────────────────────────────────┤
│  ENTRY POINTS          │  INPUT VECTORS                        │
│  ─────────────         │  ─────────────                        │
│  • HTTP routes         │  • Query params                       │
│  • GraphQL resolvers   │  • Request body                       │
│  • WebSocket handlers  │  • Headers/cookies                    │
│  • CLI commands        │  • File uploads                       │
│  • Event listeners     │  • Environment vars                   │
├─────────────────────────────────────────────────────────────────┤
│  DATA CLASSIFICATION   │  AUTH & IDENTITY                      │
│  ─────────────────     │  ───────────────                      │
│  • PII fields          │  • Auth middleware                    │
│  • PCI data            │  • Session handling                   │
│  • PHI data            │  • Role/permission checks             │
│  • Secrets/credentials │  • Token validation                   │
├─────────────────────────────────────────────────────────────────┤
│  DATA FLOW             │  DEPENDENCIES                         │
│  ─────────             │  ────────────                         │
│  • Sources (inputs)    │  • Packages + versions                │
│  • Sinks (dangerous)   │  • Third-party APIs                   │
│  • Validators          │  • Known CVEs                         │
│  • Transformers        │  • Crypto libraries                   │
└─────────────────────────────────────────────────────────────────┘
```

### Key Relationships

| Relationship | Example |
|--------------|---------|
| `RECEIVES_INPUT` | Route → Query Param |
| `FLOWS_TO` | Input → Function → Sink |
| `VALIDATES` | Middleware → Input Vector |
| `AUTHENTICATES` | Auth handler → Route |
| `HANDLES_DATA` | Function → PII Field |
| `DEPENDS_ON` | Module → Package@version |

### Future Node Types (Post-MVP)

- Service/Process
- Message Queue/Topic
- Scheduled Job
- Infrastructure Resource
- CI/CD Pipeline
- Network Boundary/Zone

## Agent Tools

### File & Code Exploration

| Tool | Purpose |
|------|---------|
| `read_file` | Read file contents with optional line range |
| `list_directory` | List folder contents with file types |
| `search_code` | Regex/pattern search across codebase |
| `search_semantic` | Natural language search |
| `get_file_info` | Size, last modified, language, line count |
| `read_gitignore` | Understand what's excluded |

### Static Analysis

| Tool | Purpose |
|------|---------|
| `get_ast` | Parse file into AST structure |
| `get_imports` | Extract imports/requires/includes |
| `get_exports` | What does this module expose |
| `get_function_signature` | Params, return type, decorators |
| `get_class_structure` | Methods, properties, inheritance |
| `get_call_graph` | What calls what (within file or cross-file) |
| `find_references` | All usages of a symbol |
| `find_definitions` | Where is this symbol defined |
| `trace_data_flow` | Follow variable from source to sink |
| `get_control_flow` | Branches, loops, early returns |

### Framework Detection & Parsing

| Tool | Purpose |
|------|---------|
| `detect_frameworks` | Identify backend, frontend, ORM, auth libs |
| `detect_languages` | Languages used + distribution |
| `parse_routes` | HTTP routes (Flask, Express, FastAPI, etc.) |
| `parse_graphql_schema` | Types, queries, mutations, resolvers |
| `parse_websocket_handlers` | WS event handlers |
| `parse_event_listeners` | Pub/sub, message queue consumers |
| `parse_cli_commands` | CLI entry points (Click, argparse, etc.) |
| `parse_scheduled_jobs` | Cron, celery beats, scheduled tasks |
| `parse_orm_models` | Database models, relationships, fields |
| `parse_middleware` | Middleware chain, order of execution |

### Dependency Analysis

| Tool | Purpose |
|------|---------|
| `get_dependencies` | All packages from manifest files |
| `get_dependency_tree` | Transitive dependencies |
| `check_known_cves` | Query CVE database for packages |
| `get_package_info` | Version, license, last update |
| `find_outdated` | Packages with newer versions |
| `detect_vendored` | Vendored/copied dependencies |

### Security-Specific Detection

| Tool | Purpose |
|------|---------|
| `find_entry_points` | All ways into the application |
| `find_input_vectors` | User-controlled inputs |
| `find_sinks` | Dangerous operations (SQL, exec, file, etc.) |
| `find_validators` | Input validation/sanitization functions |
| `find_auth_checks` | Authentication verification points |
| `find_authz_checks` | Authorization/permission checks |
| `find_secrets` | Hardcoded secrets, API keys, passwords |
| `find_crypto_usage` | Encryption, hashing, signing |
| `find_sensitive_data` | PII/PCI/PHI field detection |
| `find_logging` | What gets logged (sensitive data leaks?) |
| `find_error_handlers` | Exception handling, error responses |
| `detect_auth_pattern` | JWT, session, OAuth, API key, etc. |

### Memory & Low-Level Security

| Tool | Purpose |
|------|---------|
| `find_memory_ops` | malloc, free, realloc, buffer copies |
| `find_unsafe_patterns` | Unchecked array access, pointer math |
| `find_integer_ops` | Arithmetic that could overflow/underflow |
| `find_format_strings` | printf-family with dynamic format |
| `find_race_conditions` | Shared state without synchronization |
| `find_resource_leaks` | Unclosed handles, missing cleanup |
| `find_ffi_boundaries` | Native code calls, unsafe blocks |
| `detect_language_safety` | Memory-safe (Rust, Go) vs unsafe (C, C++) |

### Config & Environment

| Tool | Purpose |
|------|---------|
| `parse_env_files` | .env, .env.example, etc. |
| `parse_config_files` | YAML, JSON, TOML configs |
| `find_env_usage` | Where env vars are read |
| `detect_secrets_manager` | Vault, AWS SM, K8s secrets |
| `parse_dockerfile` | Docker build steps, base images |
| `parse_compose` | Docker compose services |
| `parse_k8s_manifests` | Kubernetes deployments, services |
| `parse_terraform` | Infrastructure definitions |
| `parse_ci_config` | GitHub Actions, Jenkins, etc. |

### Knowledge Graph Operations

| Tool | Purpose |
|------|---------|
| `add_node` | Create node with type and properties |
| `update_node` | Update node properties |
| `add_relationship` | Connect two nodes |
| `query_graph` | Query nodes/relationships |
| `get_node` | Get node by ID |
| `find_paths` | Find paths between nodes |
| `get_neighbors` | Get connected nodes |
| `get_subgraph` | Extract portion of graph |
| `graph_stats` | Coverage stats, node counts |
| `find_gaps` | What areas haven't been explored |

### Agent Control

| Tool | Purpose |
|------|---------|
| `emit_progress` | Send progress update to UI |
| `emit_discovery` | Report significant finding |
| `request_guidance` | Ask user for direction (optional) |
| `mark_explored` | Mark file/area as analyzed |
| `set_priority` | Adjust exploration priority |
| `checkpoint` | Save current graph state |

## Exploration Strategy

### Loop Structure

```
┌─────────────────────────────────────────────────────────────────┐
│                    EXPLORATION LOOP                             │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    ┌─────────────────┐
                    │  1. BOOTSTRAP   │
                    │  detect_frameworks()
                    │  detect_languages()
                    │  get_dependencies()
                    └────────┬────────┘
                              │
                              ▼
                    ┌─────────────────┐
                    │ 2. ENTRY POINTS │
                    │  parse_routes()
                    │  parse_cli_commands()
                    │  find_entry_points()
                    └────────┬────────┘
                              │
                              ▼
                    ┌─────────────────┐
                    │ 3. PRIORITIZE   │
                    │  query_graph("gaps")
                    │  rank by security risk
                    │  pick next target
                    └────────┬────────┘
                              │
                              ▼
                    ┌─────────────────┐
                    │ 4. DEEP DIVE    │
                    │  read_file()
                    │  trace_data_flow()
                    │  find_sinks()
                    │  add_node/relationship
                    └────────┬────────┘
                              │
                              ▼
                    ┌─────────────────┐
                    │ 5. COVERAGE?    │──── No ────┐
                    │  graph_stats()  │            │
                    │  find_gaps()    │            │
                    └────────┬────────┘            │
                              │                    │
                             Yes                   │
                              │                    │
                              ▼                    │
                    ┌─────────────────┐            │
                    │  6. COMPLETE    │            │
                    │  emit summary   │◄───────────┘
                    │  ready for scan │
                    └─────────────────┘
```

### Prioritization Heuristics

| Signal | Priority Boost |
|--------|----------------|
| Handles user input | +High |
| Touches database/files | +High |
| Auth/session related | +High |
| Has no validation upstream | +Critical |
| Uses dangerous functions | +Critical |
| Contains secrets/credentials | +Critical |
| External API integration | +Medium |
| Memory operations (malloc, free, memcpy) | +Critical |
| Buffer/array operations without bounds | +Critical |
| Pointer arithmetic | +High |
| Integer operations (overflow potential) | +High |
| Format strings with user input | +Critical |
| Concurrent/shared state access | +High |
| Resource handles lifecycle | +Medium |
| FFI/native code boundaries | +High |

### Completion Criteria

Agent stops when:
- Entry points mapped
- Critical sinks traced to sources
- Auth boundaries identified
- User-defined coverage threshold reached

## Phase 2 Integration

### Attack Surface Generation

```
┌─────────────────────────────────────────────────────────────────┐
│                 KNOWLEDGE GRAPH (from Phase 1)                  │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
                ┌───────────────────────┐
                │   ATTACK SURFACE      │
                │   GENERATOR           │
                │                       │
                │ • Enumerate all paths │
                │   from entry → sink   │
                │ • Rank by risk score  │
                │ • Group by vuln class │
                └───────────┬───────────┘
                            │
            ┌───────────────┼───────────────┐
            ▼               ▼               ▼
    ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
    │ SQL Injection│ │ Memory Safety│ │ Auth Bypass  │
    │ Candidates   │ │ Candidates   │ │ Candidates   │
    └──────┬───────┘ └──────┬───────┘ └──────┬───────┘
           │                │                │
           └────────────────┼────────────────┘
                            │
                            ▼
                ┌───────────────────────┐
                │   ULTRATHINK CASCADE  │
                └───────────────────────┘
```

### Context Injection for Ultrathink

Instead of passing just the vulnerable file, we pass:

```python
context = {
    "target_path": graph.get_path(entry_point, sink),
    "source_code": [read each file in path],
    "validators_in_scope": graph.query("validators connected to path"),
    "auth_checks": graph.query("auth between entry and sink"),
    "data_classification": graph.get_node(sink).handles_data,
    "related_sinks": graph.query("similar sinks in codebase"),
    "framework_context": graph.get("framework_conventions"),
}
```

This gives Ultrathink the full picture to make accurate judgments.

## UI: Knowledge Graph Review

```
┌─────────────────────────────────────────────────────────────────────────┐
│  ARCHITECTURE MAP                                        [Scan Now →]  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Coverage: ████████████░░ 78%          Nodes: 342    Relationships: 891 │
│                                                                         │
├──────────────────────┬──────────────────────────────────────────────────┤
│  SUMMARY             │  GRAPH VIEW                                      │
│  ────────            │  ──────────                                      │
│                      │                                                  │
│  Entry Points: 23    │      ┌─────────┐                                │
│  ├─ HTTP Routes: 18  │      │ /login  │──RECEIVES──→[password]         │
│  ├─ WebSocket: 3     │      └────┬────┘              (PII)             │
│  └─ CLI: 2           │           │                                      │
│                      │       CALLS                                      │
│  Input Vectors: 47   │           │                                      │
│  ├─ Query Params: 21 │           ▼                                      │
│  ├─ Body Fields: 19  │    ┌────────────┐                               │
│  └─ Headers: 7       │    │authenticate│──QUERIES──→[users.db]         │
│                      │    └────────────┘                               │
│  Dangerous Sinks: 31 │                                                  │
│  ├─ SQL Queries: 12  │                                                  │
│  ├─ File Ops: 8      │  [Filter: Entry Points ▼] [Show: All ▼]        │
│  ├─ Exec/Eval: 4     │                                                  │
│  └─ Memory Ops: 7    │                                                  │
│                      │                                                  │
│  High-Risk Paths: 14 │                                                  │
│  ⚠ Unvalidated: 6   │                                                  │
│  ⚠ No Auth: 3       │                                                  │
│                      │                                                  │
├──────────────────────┴──────────────────────────────────────────────────┤
│  RISK AREAS (click to explore)                                          │
│  ──────────                                                             │
│  🔴 POST /admin/exec → shell_exec() — no auth, user input direct       │
│  🔴 GET /export → file_read() — path traversal possible                │
│  🟠 POST /search → sql_query() — parameterized but complex             │
│  🟡 GET /user/:id → db.find() — auth present, check IDOR               │
└─────────────────────────────────────────────────────────────────────────┘
```

User can:
- Explore the graph visually
- Click risk areas to see full path details
- Filter by node type, risk level, or area
- Trigger scan on specific paths or full codebase

## Implementation Structure

```
backend/
├── cass/                          # Continuous Architecture Security Scanner
│   ├── __init__.py
│   ├── config.py                  # CASS configuration
│   │
│   ├── graph/                     # Knowledge Graph
│   │   ├── __init__.py
│   │   ├── schema.py              # Node types, relationship types
│   │   ├── store.py               # In-memory graph storage
│   │   └── queries.py             # Graph query helpers
│   │
│   ├── tools/                     # Agent Tools
│   │   ├── __init__.py
│   │   ├── file_tools.py          # read, list, search
│   │   ├── static_analysis.py     # AST, call graph, data flow
│   │   ├── framework_parsers.py   # Route, ORM, middleware parsing
│   │   ├── dependency_tools.py    # Package analysis, CVE lookup
│   │   ├── security_detectors.py  # Sinks, validators, secrets, memory
│   │   ├── config_tools.py        # Env, docker, k8s parsing
│   │   └── graph_tools.py         # Add/query knowledge graph
│   │
│   ├── explorer/                  # Architecture Mapping Agent
│   │   ├── __init__.py
│   │   ├── agent.py               # Main exploration loop
│   │   ├── strategy.py            # Prioritization logic
│   │   └── prompts.py             # LLM prompts for reasoning
│   │
│   ├── scanner/                   # Security Scan (Phase 2)
│   │   ├── __init__.py
│   │   ├── attack_surface.py      # Generate candidates from graph
│   │   ├── context_builder.py     # Build rich context for Ultrathink
│   │   └── orchestrator.py        # Run scans, coordinate with cascade
│   │
│   └── events.py                  # WebSocket events for CASS
│
├── agents/
│   └── cass_agent.py              # Agent wrapper for CASS
│
frontend/
├── components/
│   └── ArchitecturePanel/         # Knowledge Graph UI
│       ├── ArchitecturePanel.tsx  # Main panel
│       ├── GraphView.tsx          # Interactive graph visualization
│       ├── SummaryStats.tsx       # Coverage, node counts
│       ├── RiskList.tsx           # High-risk paths list
│       └── index.ts
```

## Summary

| Aspect | Design Decision |
|--------|-----------------|
| **Approach** | Agentic exploration with tool use, incremental passes |
| **Knowledge Store** | Structured graph with security-critical nodes |
| **Workflow** | Two-phase: Map Architecture → Review → Security Scan |
| **Tools** | 50+ tools for code, static analysis, frameworks, security |
| **Node Types** | Entry points, inputs, sinks, auth, secrets, data classification, memory ops |
| **Exploration** | Priority-based loop, focuses on high-risk paths first |
| **Scan Integration** | Graph feeds rich context to Ultrathink cascade |
| **UI** | Visual graph + summary stats + risk list |

## Key Value

- **Large codebases become tractable** - Agent builds understanding over time
- **Cross-file vulnerabilities detectable** - Graph traces full paths
- **Ultrathink gets full context** - Not just single file
- **User can review/guide before scan** - Two-phase explicit workflow
- **Memory safety included** - Low-level vulns alongside web security

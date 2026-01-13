# Deep Agents + LangGraph Segmented Audit Refactor

**Date:** 2026-01-12
**Status:** Design Approved
**Branch:** `refactor/deep-agents-langgraph-segmented-audit`

## Executive Summary

This document describes a full refactor of quick_hack's audit agent architecture, replacing the current ReAct-style loop with a segmented, context-isolated multi-agent system using LangChain's Deep Agents package and LangGraph orchestration.

**Key Goals:**
- Replace monolithic ReAct loop with supervisor + worker subagents
- Implement filesystem-based context offloading to prevent context overflow
- Preserve all existing API contracts and security boundaries
- Reuse existing security scanners and tool implementations
- Enable pause/resume via LangGraph checkpointing

## Architecture Overview

### New Dependencies

```python
deepagents>=0.1.0           # Official Deep Agents package
langgraph>=0.2.0            # State graph orchestration
langchain>=0.3.0            # Core LangChain
langchain-anthropic>=0.2.0  # Anthropic provider
```

### System Components

1. **Supervisor Agent** (LangGraph StateGraph)
   - Orchestrates audit workflow
   - Builds file tree and partitions codebase into scopes
   - Dispatches worker subagents
   - Ranks signals and builds case files
   - Dispatches auditor subagents
   - Repeats until time budget exhausted

2. **Worker Subagents** (Deep Agents)
   - `RepoProfiler` - Detect language/framework/layout
   - `ScopeMapper(scope_id)` - Summarize scope purpose
   - `SinkHunter(scope_id)` - Find candidate sinks
   - `EntrypointHunter(scope_id)` - Find routes/handlers

3. **Auditor Subagent** (Deep Agent)
   - Verifies signals using AST/dataflow analysis
   - Promotes verified signals to Findings
   - Only component allowed to create Findings

4. **Virtual Filesystem**
   - `/repo/` - Read-only view of source code
   - `/memories/` - Writable agent memory
   - Enforces security boundaries at filesystem layer

## State Management

### Supervisor State Schema

```python
class SupervisorState(BaseModel):
    project_id: str
    scan_tier: str
    deadline: float

    repo_profile_path: str
    scope_plan: List[Dict[str, str]]
    completed_scopes: List[str]

    coverage_map: Dict[str, bool]

    signal_queue: List[str]
    active_case_ids: List[str]

    max_signals: int = 100
    max_findings: int = 50
    signal_count: int = 0
    finding_count: int = 0
```

### Graph Nodes

1. **init_state** - Initialize deadline, create `/memories` structure
2. **build_scopes** - Partition codebase, dispatch RepoProfiler
3. **dispatch_workers** - Spawn ScopeMapper, SinkHunter, EntrypointHunter
4. **merge_signals** - Collect worker outputs, upsert to sink_signals.json
5. **prioritize_cases** - Rank signals, build case files
6. **dispatch_auditor** - Spawn Auditor for each case
7. **check_budget** - Conditional: continue or finalize
8. **finalize** - Generate report, broadcast completion

### Conditional Edges

- `check_budget` → `dispatch_workers` if time remains AND uncovered scopes
- `check_budget` → `finalize` if deadline passed OR no signals

## Filesystem Layer

### Virtual Filesystem

```python
class ProjectFilesystem:
    def __init__(self, project_id: str):
        self.repo_root = Path(f"data/projects/{project_id}/repo")
        self.memory_root = Path(f"data/projects/{project_id}/memories")

    def resolve_path(self, virtual_path: str) -> tuple[Path, bool]:
        # Maps /repo/* to repo_root (read-only)
        # Maps /memories/* to memory_root (writable)
```

### Memory Layout

```
data/projects/<project_id>/
├── repo/                    # Source code (read-only)
├── memories/                # Agent memory (writable)
│   ├── repo_profile.json
│   ├── coverage.json
│   ├── scopes/
│   │   └── <scope_id>/
│   │       ├── summary.md
│   │       ├── entrypoints.json
│   │       └── signals.json
│   └── cases/
│       └── <signal_id>.md
└── sink_signals.json
```

## Subagent Specifications

### Worker Subagents

**RepoProfiler**
- Tools: `read_file`, `ls`, `write_file`
- Output: `/memories/repo_profile.json`
- Purpose: Detect language, framework, build system

**ScopeMapper(scope_id)**
- Tools: `read_file`, `ls`, `write_file`
- Output: `/memories/scopes/{scope_id}/summary.md`
- Purpose: Summarize scope purpose and risks

**SinkHunter(scope_id)**
- Tools: `read_file`, `grep_semantic`, `write_file`
- Output: `/memories/scopes/{scope_id}/signals.json`
- Purpose: Find sink candidates (NO vulnerability claims)

**EntrypointHunter(scope_id)**
- Tools: `read_file`, `grep_semantic`, `write_file`
- Output: `/memories/scopes/{scope_id}/entrypoints.json`
- Purpose: Find HTTP routes, CLI handlers, consumers

### Auditor Subagent

**Auditor(case_file)**
- Tools: `read_file`, `analyze_ast`, `trace_dataflow`, `promote_finding`
- Input: `/memories/cases/<signal_id>.md`
- Output: Finding OR refined Signal
- Constraint: ONLY component that can call `promote_finding`

### Signal Format

```json
{
  "signal_id": "sql_inj_auth_001",
  "fingerprint": "sha256:...",
  "signal_type": "sql_injection_candidate",
  "file_path": "/repo/auth/db.py",
  "line_range": [45, 52],
  "sink_snippet": "cursor.execute(f\"SELECT * FROM users...\")",
  "suspected_sources": ["request.args.get('id')"],
  "confidence": 0.8,
  "scope_id": "auth",
  "next_steps": ["Trace user_id", "Check sanitization"]
}
```

## API Integration

### Preserved Endpoints

All HTTP endpoints unchanged:

```
POST   /api/agents              # Create agent
POST   /api/agents/{id}/start   # Start agent
POST   /api/agents/{id}/pause   # Pause (LangGraph checkpoint)
POST   /api/agents/{id}/resume  # Resume (restore checkpoint)
POST   /api/agents/{id}/cancel  # Cancel agent
GET    /api/agents              # List agents
```

### Agent Orchestrator Update

```python
AGENT_CLASSES = {
    AgentType.QUICK_AUDIT: QuickAuditAgent,
    AgentType.CUSTOM: ReActSecurityAgent,
    AgentType.DEEP_AUDIT: DeepAuditSupervisor,      # NEW
    AgentType.STRICT_ANALYSIS: DeepAuditSupervisor, # NEW
    AgentType.ULTRA_STRICT: DeepAuditSupervisor,    # NEW
}
```

### WebSocket Events

```json
{
  "type": "agent_progress",
  "data": {
    "current_node": "dispatch_workers",
    "scope": "auth",
    "coverage_percent": 45,
    "signal_count": 12,
    "finding_count": 3
  }
}
```

### Flow Graph Updates

New node types for investigation tree:
- `scope_analysis` - Worker analyzing scope
- `signal_generated` - SinkHunter emitted signal
- `case_verification` - Auditor verifying case
- `finding_promoted` - Signal promoted to Finding

Edge pattern: `Supervisor → Worker → Signal → Auditor → Finding`

## Implementation Plan

### New Files

```
backend/agents/deep_audit/
├── __init__.py
├── supervisor.py           # DeepAuditSupervisor (LangGraph)
├── state.py                # SupervisorState model
├── filesystem.py           # ProjectFilesystem
├── nodes.py                # Graph node implementations
├── subagents.py            # Worker/Auditor prompts
├── tools.py                # Custom tools (upsert, promote)
└── case_builder.py         # Signal → case file
```

### Files to Delete

```
backend/agents/react_agent.py          # Main ReAct agent (2021 lines)
backend/agents/deep_audit_agent.py     # If exists
backend/agents/ultrathink_agent.py     # Legacy experimental
```

### Files to Preserve

```
backend/agents/tools.py                     # ToolExecutor + registry
backend/agents/dual_model_config.py        # Model selection
backend/services/tool_core.py              # Tool implementations
backend/services/security_scanners/*       # All scanners (CRITICAL)
backend/services/sink_signal_service.py    # Signal persistence
backend/services/flow_service.py           # Investigation graph
backend/services/observability_service.py  # Logging
```

### Files to Refactor

```
backend/services/agent_orchestrator.py     # Update AGENT_CLASSES
```

## Testing Strategy

### New Unit Tests

```
backend/tests/agents/deep_audit/
├── test_supervisor_state.py        # State management
├── test_filesystem.py               # Virtual FS
├── test_case_builder.py             # Case generation
├── test_signal_tools.py             # Tools
└── test_graph_nodes.py              # Node logic
```

### Integration Tests

```
backend/tests/agents/
├── test_deep_audit_integration.py   # Full workflow
└── test_agent_orchestrator.py       # Update mapping tests
```

### Existing Tests (No Changes)

```
backend/tests/services/security_scanners/  # 201 tests
backend/tests/services/test_sink_signals.py
```

## Verification Checklist

- [ ] All 201 security scanner tests pass
- [ ] Create agent via POST /api/agents
- [ ] Start agent, verify WebSocket events
- [ ] Verify sink_signals.json updated
- [ ] Verify findings created by Auditor
- [ ] Pause/resume using checkpoints
- [ ] Cancel agent gracefully
- [ ] Time-tier budgets respected
- [ ] /memories directory created
- [ ] No writes to /repo (security boundary)

## Security Boundaries

### Preserved Constraints

- **WorkspacePolicy**: Path validation, excluded dirs, file size limits, symlink rejection
- **ScanLimits**: Time budgets, cancellation, resource caps
- **Offline-first**: No network fetching
- **Secret redaction**: Fingerprinting for deduplication

### New Filesystem Enforcement

- `/repo` namespace strictly read-only
- `/memories` namespace writable
- `ProjectFilesystem.resolve_path()` enforces at layer boundary

## Migration Notes

### Backwards Compatibility

- Frontend sees no API changes
- WebSocket message format unchanged
- Existing schemas (Finding, Agent) preserved
- Time-tier budgets work identically

### Breaking Changes

- None for external consumers
- Internal: ReAct agent code completely removed

## References

- [Deep Agents Overview - LangChain Docs](https://docs.langchain.com/oss/python/deepagents/overview)
- [GitHub - langchain-ai/deepagents](https://github.com/langchain-ai/deepagents)
- [deepagents PyPI Package](https://pypi.org/project/deepagents/)
- [LangGraph Documentation](https://langchain-ai.github.io/langgraph/)

## Success Criteria

1. Deep audit scans complete successfully with new architecture
2. All existing tests pass
3. API contracts preserved (no frontend changes)
4. Security boundaries maintained
5. Memory-based context offloading working
6. Pause/resume functional
7. No legacy ReAct code remains
8. Documentation updated

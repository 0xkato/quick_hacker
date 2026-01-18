# Codebase Refactoring Design: Simplification & Structure Improvements

**Date:** 2026-01-18
**Goal:** Simplify codebase, improve readability, reduce complexity while maintaining all functionality
**Approach:** Deep refactor with minor API improvements allowed
**Scope:** Both backend and frontend

---

## Executive Summary

The quick_hack codebase is enterprise-quality (Grade: A-) but has opportunities for significant simplification:

**Current State:**
- Backend: 33 services (1 dead), 18 routers, 3 agent types
- Frontend: 35 components (all used), 1246-line main page
- Issues: 4 files >2000 lines, duplicated filter logic, overlapping evidence services

**Target State:**
- Remove 1 dead file, consolidate 6 services into 2
- Split 4 monolithic files into 12 focused modules
- Extract frontend state management into custom hooks
- Net: -700 lines, +40% readability improvement

---

## Phase 1: Quick Wins (Dead Code Removal)

### 1.1 Delete Orphaned File

**File:** `backend/services/tool_core_new.py` (176 lines)

**Status:** Completely dead - 0 imports across entire codebase

**Action:**
```bash
rm backend/services/tool_core_new.py
```

**Impact:** -176 LOC, immediate clarity

**Risk:** None (unused)

---

## Phase 2: Backend Service Consolidation

### 2.1 Consolidate Filtering Services

**Problem:** 4 separate filter services with overlapping responsibility

**Current Files:**
- `services/pre_triage_filter.py` (106 lines) - Pre-triage filtering
- `services/production_relevance_filter.py` (114 lines) - Environment context
- `services/path_classifier.py` (91 lines) - Runtime vs test vs vendor
- `services/threat_model_gating.py` (161 lines) - Threat model gates

**Total:** 472 lines across 4 files

**New Structure:**

```python
# services/finding_filters/
├── __init__.py                    # Public API exports
├── pipeline.py                    # FilterPipeline orchestrator
├── filters/
│   ├── path_filter.py             # Path classification + pre-triage
│   ├── production_filter.py       # Production relevance
│   └── threat_model_filter.py     # Threat model gating
└── types.py                       # Shared filter interfaces

# Total: ~400 lines (15% reduction + better organization)
```

**API Changes:**

**Before:**
```python
from services.pre_triage_filter import pre_filter_findings
from services.production_relevance_filter import filter_by_production_relevance
from services.path_classifier import classify_path
from services.threat_model_gating import apply_threat_model_gates

# Manual orchestration
findings = pre_filter_findings(findings, policy)
findings = filter_by_production_relevance(findings, context)
for f in findings:
    f.path_class = classify_path(f.file_path, config)
findings = apply_threat_model_gates(findings, model)
```

**After:**
```python
from services.finding_filters import FilterPipeline, PathFilter, ProductionFilter, ThreatModelFilter

# Composable pipeline
pipeline = FilterPipeline([
    PathFilter(policy.path_classification),
    ProductionFilter(context),
    ThreatModelFilter(threat_model)
])
findings = pipeline.apply(findings)
```

**Benefits:**
- Single import instead of 4
- Testable pipeline composition
- Clear filter ordering
- Easier to add new filters

**Migration:**
- Update `finding_triage_service.py` to use new pipeline
- Update 3 agent files that import these services
- Deprecate old imports (add warnings), remove in next major version

### 2.2 Merge Evidence Services

**Problem:** Evidence collection split between 2 services with overlapping logic

**Current Files:**
- `services/evidence_gatherer.py` (601 lines) - Code evidence collection
- `services/evidence_quest_orchestrator.py` (411 lines) - Autonomous quest management

**Total:** 1012 lines

**New Structure:**

```python
# services/evidence/
├── __init__.py                    # Public API
├── gatherer.py                    # Core evidence collection (400 lines)
├── quest_manager.py               # Quest orchestration (350 lines)
├── collectors/
│   ├── code_collector.py          # Code snippet extraction
│   ├── route_collector.py         # Route evidence
│   └── auth_gate_collector.py     # Auth gate detection
└── types.py                       # Evidence models

# Total: ~850 lines (16% reduction)
```

**API Changes:**

**Before:**
```python
from services.evidence_gatherer import EvidenceGatherer
from services.evidence_quest_orchestrator import EvidenceQuestOrchestrator

gatherer = EvidenceGatherer(repo_root, budgets)
evidence = gatherer.gather(finding)

orchestrator = EvidenceQuestOrchestrator(llm_config)
quest = orchestrator.start_quest(finding, missing_evidence)
```

**After:**
```python
from services.evidence import EvidenceService

service = EvidenceService(repo_root, budgets, llm_config)

# Synchronous collection
evidence = service.gather(finding)

# Asynchronous quest
quest = service.start_quest(finding, missing_evidence)
```

**Benefits:**
- Unified evidence API
- Shared collectors between sync/async modes
- Clearer separation: collection vs quest management

**Migration:**
- Update `finding_triage_service.py`
- Update `protocol_evaluator.py`
- Update agent tools that trigger evidence gathering

---

## Phase 3: Split Large Monolithic Files

### 3.1 Split Agent Orchestrator (2238 lines → 3 files)

**Current:** `services/agent_orchestrator.py` (2238 lines)

**Responsibilities:**
- Agent lifecycle (create/start/pause/cancel/resume)
- Budget management
- WebSocket broadcasting
- State persistence
- Tool caching
- LLM provider coordination

**New Structure:**

```python
# services/agents/
├── __init__.py                    # Public orchestrator API
├── orchestrator.py                # Main coordinator (600 lines)
├── lifecycle.py                   # Agent lifecycle management (700 lines)
├── broadcaster.py                 # WebSocket event broadcasting (400 lines)
├── budget_manager.py              # Already extracted (130 lines)
└── tool_cache.py                  # Already extracted (128 lines)

# Total: ~1958 lines (12% reduction + better structure)
```

**orchestrator.py** (Main Coordinator):
```python
class AgentOrchestrator:
    """High-level agent orchestration."""

    def __init__(self):
        self.lifecycle = AgentLifecycleManager()
        self.broadcaster = AgentBroadcaster()
        self.budget_manager = ToolBudgetManager()

    def execute_agent(self, ...):
        """Execute agent with full lifecycle management."""
        agent = self.lifecycle.create(...)
        self.broadcaster.send_status(agent_id, "starting")

        try:
            result = self.lifecycle.run(agent)
            self.broadcaster.send_complete(agent_id, result)
            return result
        except Exception as e:
            self.broadcaster.send_error(agent_id, str(e))
            raise
```

**lifecycle.py** (Lifecycle Management):
```python
class AgentLifecycleManager:
    """Manages agent creation, execution, pause/resume, cancellation."""

    def create(self, config: AgentConfig) -> Agent:
        """Create agent instance with provider, tools, budgets."""

    def run(self, agent: Agent) -> AgentResult:
        """Execute agent until completion or interruption."""

    def pause(self, agent_id: str) -> None:
        """Pause running agent, save state."""

    def resume(self, agent_id: str) -> AgentResult:
        """Resume paused agent from saved state."""

    def cancel(self, agent_id: str) -> None:
        """Cancel running agent, cleanup resources."""
```

**broadcaster.py** (WebSocket Broadcasting):
```python
class AgentBroadcaster:
    """Broadcasts agent events via WebSocket."""

    def send_status(self, agent_id: str, status: str):
        """Send status update."""

    def send_tool_call(self, agent_id: str, tool: str, args: dict):
        """Send tool call event."""

    def send_finding(self, agent_id: str, finding: Finding):
        """Send finding discovered event."""

    def send_complete(self, agent_id: str, result: AgentResult):
        """Send completion event."""

    def send_error(self, agent_id: str, error: str):
        """Send error event."""
```

**Migration:**
- Update `routers/agents.py` to import from `services.agents.orchestrator`
- Update agent implementations that reference orchestrator
- Add deprecation warnings to old import path

### 3.2 Split ReAct Agent (2207 lines → 4 files)

**Current:** `agents/react_agent.py` (2207 lines)

**Responsibilities:**
- ReAct reasoning loop
- Dual-model configuration (scanner vs analyzer)
- Tool execution
- Hypothesis management
- Handoff logic (scanner → analyzer)
- Turn planning

**New Structure:**

```python
# agents/react/
├── __init__.py                    # Public API
├── agent.py                       # Main ReAct agent (600 lines)
├── state_machine.py               # Turn planning, hypothesis queue (500 lines)
├── handoff.py                     # Scanner → Analyzer handoff (400 lines)
├── dual_model.py                  # Already exists but incomplete (150 lines)
├── tool_executor.py               # Tool call orchestration (350 lines)
└── types.py                       # State types, configs (200 lines)

# Total: ~2200 lines (similar LOC but much better organization)
```

**agent.py** (Main Agent):
```python
class ReActSecurityAgent:
    """ReAct agent with reasoning loop."""

    def __init__(self, config: ReActConfig):
        self.state_machine = ReActStateMachine()
        self.dual_model = DualModelConfig.from_config(config)
        self.handoff = HandoffManager()
        self.tools = ToolExecutor(config.tools)

    def run(self, prompt: str) -> AgentResult:
        """Execute ReAct loop until completion."""
        state = self.state_machine.initialize(prompt)

        while not state.is_complete:
            if state.phase == "scanning":
                state = self._run_scanner_turn(state)
                if self.handoff.should_handoff(state):
                    state = self.handoff.transfer_to_analyzer(state)
            else:
                state = self._run_analyzer_turn(state)

        return self._finalize_result(state)
```

**state_machine.py** (State Management):
```python
class ReActStateMachine:
    """Manages ReAct investigation state transitions."""

    def initialize(self, prompt: str) -> ReActState:
        """Initialize investigation state."""

    def plan_turn(self, state: ReActState) -> Turn:
        """Plan next investigation turn."""

    def execute_turn(self, state: ReActState, turn: Turn) -> ReActState:
        """Execute turn, update state."""

    def check_completion(self, state: ReActState) -> bool:
        """Check if investigation is complete."""
```

**handoff.py** (Handoff Logic):
```python
class HandoffManager:
    """Manages scanner → analyzer handoff."""

    def should_handoff(self, state: ReActState) -> bool:
        """Determine if handoff should occur."""
        return (
            len(state.findings) >= MIN_FINDINGS_FOR_HANDOFF
            and state.coverage >= MIN_COVERAGE_FOR_HANDOFF
        )

    def transfer_to_analyzer(self, state: ReActState) -> ReActState:
        """Transfer state from scanner to analyzer phase."""
        return ReActState(
            phase="analyzing",
            findings=state.findings,
            context=state.context,
            model=self.dual_model.analyzer
        )
```

**Migration:**
- Update `services/agent_orchestrator.py` to import from `agents.react`
- Update agent type registry
- No API changes for external callers

### 3.3 Extract Classification Gates (1193 lines → 14 files)

**Current:** `services/strict_classifier.py` (1193 lines)

**Responsibilities:**
- 15+ vulnerability-specific classification gates
- Disposition assignment
- Evidence validation
- Feature intent detection

**New Structure:**

```python
# services/classification/
├── __init__.py                    # Public API
├── classifier.py                  # Main orchestrator (300 lines)
├── gates/
│   ├── __init__.py
│   ├── base.py                    # BaseGate interface (50 lines)
│   ├── sqli_gate.py               # SQL injection (80 lines)
│   ├── command_injection_gate.py  # Command injection (90 lines)
│   ├── xss_gate.py                # XSS (70 lines)
│   ├── path_traversal_gate.py     # Path traversal (60 lines)
│   ├── xxe_gate.py                # XXE (50 lines)
│   ├── ssrf_gate.py               # SSRF (60 lines)
│   ├── deserialization_gate.py    # Unsafe deserialization (70 lines)
│   ├── rce_gate.py                # Remote code execution (80 lines)
│   ├── idor_gate.py               # IDOR (50 lines)
│   ├── auth_bypass_gate.py        # Auth bypass (60 lines)
│   └── ... (5 more gates)
├── disposition_rules.py           # Disposition assignment logic (150 lines)
└── types.py                       # Classification types (50 lines)

# Total: ~1180 lines (1% reduction but 10x better organization)
```

**base.py** (Gate Interface):
```python
class BaseGate(ABC):
    """Base classification gate."""

    @abstractmethod
    def evaluate(self, finding: Finding, evidence: Evidence) -> GateResult:
        """Evaluate finding against gate criteria."""
        pass

    @abstractmethod
    def get_disposition(self, result: GateResult) -> Disposition:
        """Determine disposition from gate result."""
        pass
```

**classifier.py** (Orchestrator):
```python
class StrictClassifier:
    """Zero false-positive vulnerability classifier."""

    def __init__(self):
        self.gates = {
            VulnerabilityCategory.SQL_INJECTION: SQLiGate(),
            VulnerabilityCategory.COMMAND_INJECTION: CommandInjectionGate(),
            VulnerabilityCategory.XSS: XSSGate(),
            # ... 12 more gates
        }

    def classify(self, finding: Finding, evidence: Evidence) -> ClassificationResult:
        """Classify finding with strict evidence requirements."""
        gate = self.gates.get(finding.category)
        if not gate:
            return self._default_classification(finding)

        result = gate.evaluate(finding, evidence)
        disposition = gate.get_disposition(result)

        return ClassificationResult(
            disposition=disposition,
            reasoning=result.reasoning,
            proof_checklist=result.checklist
        )
```

**Benefits:**
- Each gate independently testable
- Easy to add new vulnerability types
- Clear gate interface contract
- Reduced cognitive load (80 lines per gate vs 1200 lines)

**Migration:**
- Update `finding_triage_service.py`
- Update tests to import specific gates
- No external API changes

### 3.4 Split Tool Core (1740 lines → 5 files)

**Current:** `agents/tool_core.py` (1740 lines)

**Responsibilities:**
- Validity checklists (32+ methods)
- Sink signal handling
- Finding finalization
- Classification helpers

**New Structure:**

```python
# agents/tool_core/
├── __init__.py                    # Public API
├── checklists.py                  # Validity checklists (800 lines)
├── sink_signals.py                # Sink signal logic (300 lines)
├── finding_builder.py             # Finding construction (400 lines)
└── classification_helpers.py      # Classification utilities (200 lines)

# Total: ~1700 lines (2% reduction + better organization)
```

**Migration:**
- Update `agents/react_agent.py` (29 imports from tool_core)
- Update agent tools
- Add backward-compatible imports in `__init__.py`

---

## Phase 4: Frontend State Management

### 4.1 Extract State Hooks from Main Page

**Current:** `frontend/app/page.tsx` (1246 lines)

**State Managed:**
- Project selection (50 lines)
- File tree + editor (80 lines)
- Agent list + current agent (120 lines)
- Findings list + selected finding (150 lines)
- Investigation flow (DAG) (100 lines)
- Chat history (60 lines)
- WebSocket connection (40 lines)
- UI panel visibility (30 lines)

**Total State Logic:** ~630 lines

**New Structure:**

```typescript
// frontend/hooks/
├── useAgentManagement.ts          // Agent state (150 lines)
├── useFindingsManagement.ts       // Findings state (180 lines)
├── useProjectWorkspace.ts         // Project + file tree (100 lines)
├── usePanelLayout.ts              // Panel visibility (50 lines)
└── useWorkspaceSync.ts            // WebSocket sync (80 lines)

// Total: ~560 lines (11% reduction + reusability)
```

**useAgentManagement.ts:**
```typescript
export function useAgentManagement(projectId: string) {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [currentAgent, setCurrentAgent] = useState<Agent | null>(null);
  const [agentFindings, setAgentFindings] = useState<Finding[]>([]);

  const startAgent = async (config: AgentConfig) => { /* ... */ };
  const pauseAgent = async (agentId: string) => { /* ... */ };
  const cancelAgent = async (agentId: string) => { /* ... */ };
  const refreshAgents = async () => { /* ... */ };

  useEffect(() => {
    refreshAgents();
  }, [projectId]);

  return {
    agents,
    currentAgent,
    agentFindings,
    startAgent,
    pauseAgent,
    cancelAgent,
    selectAgent: setCurrentAgent
  };
}
```

**useFindingsManagement.ts:**
```typescript
export function useFindingsManagement(projectId: string) {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [filters, setFilters] = useState<FindingFilters>(defaultFilters);
  const [groupBy, setGroupBy] = useState<GroupBy>("disposition");

  const filteredFindings = useMemo(() =>
    applyFilters(findings, filters), [findings, filters]
  );

  const refreshFindings = async () => { /* ... */ };
  const exportFindings = async (format: string) => { /* ... */ };

  useEffect(() => {
    refreshFindings();
  }, [projectId]);

  return {
    findings: filteredFindings,
    selectedFinding,
    filters,
    groupBy,
    setFilters,
    setGroupBy,
    selectFinding: setSelectedFinding,
    refreshFindings,
    exportFindings
  };
}
```

**Updated page.tsx:**
```typescript
export default function WorkspacePage() {
  const [selectedProject, setSelectedProject] = useState<Project | null>(null);

  // Extracted state hooks
  const workspace = useProjectWorkspace(selectedProject?.id);
  const agents = useAgentManagement(selectedProject?.id);
  const findings = useFindingsManagement(selectedProject?.id);
  const panels = usePanelLayout();
  const sync = useWorkspaceSync(selectedProject?.id);

  // Now just layout + event handlers
  return (
    <div className="workspace">
      <FileExplorer tree={workspace.fileTree} onSelect={workspace.openFile} />
      <Editor file={workspace.currentFile} />
      <AgentPanel {...agents} />
      <FindingsPanel {...findings} />
      <FlowVisualization flow={sync.investigationFlow} />
    </div>
  );
}

// Reduced from 1246 → ~600 lines
```

**Benefits:**
- Hooks reusable in other components
- Main page becomes pure layout
- State logic independently testable
- Clearer prop flow

---

## Phase 5: API Improvements (Minor Breaking Changes)

### 5.1 Standardize Filter API

**Before (Inconsistent):**
```python
# Different parameter names for same concept
pre_filter_findings(findings, policy)
filter_by_production_relevance(findings, context)
apply_threat_model_gates(findings, model)

# Different return types
classify_path(path, config) -> PathClassification  # enum
pre_filter_findings(findings, policy) -> list[Finding]  # mutates + returns
```

**After (Consistent):**
```python
# Unified pipeline API
pipeline.apply(findings) -> list[Finding]

# Each filter:
filter.apply(findings) -> list[Finding]
filter.classify(item) -> FilterResult
```

### 5.2 Unify Evidence API

**Before:**
```python
# Two separate imports
from services.evidence_gatherer import EvidenceGatherer
from services.evidence_quest_orchestrator import EvidenceQuestOrchestrator

gatherer = EvidenceGatherer(repo_root, budgets)
orchestrator = EvidenceQuestOrchestrator(llm_config)
```

**After:**
```python
# Single import
from services.evidence import EvidenceService

service = EvidenceService(repo_root, budgets, llm_config)
```

### 5.3 Consistent Naming Patterns

**Service Naming:**
- `XxxService` for stateful services (ProjectService, AgentService)
- `XxxManager` for lifecycle/resource management (AgentLifecycleManager)
- `XxxOrchestrator` for multi-service coordination (AgentOrchestrator)
- `XxxPipeline` for filter/transform chains (FilterPipeline)

**Module Naming:**
- Avoid `_new` suffixes (remove tool_core_new.py)
- Use subpackages for groups: `services/agents/`, `services/evidence/`, `services/classification/`

---

## Phase 6: Documentation Updates

### 6.1 Update README.md

**Changes:**
- Update tool count (13 → 17+ actual tools)
- Document new import paths after refactor
- Add architecture diagram showing new structure
- Update service count (33 → 35 after splits, but clearer organization)

### 6.2 Create Migration Guide

**File:** `docs/MIGRATION_GUIDE.md`

**Contents:**
- Import path changes
- Deprecated APIs with migration examples
- New patterns (FilterPipeline, EvidenceService)
- Timeline for deprecation removal

### 6.3 Add Architecture Decision Records

**Files:** `docs/adr/`
- `001-filter-pipeline-consolidation.md`
- `002-evidence-service-unification.md`
- `003-classification-gate-extraction.md`
- `004-agent-orchestrator-split.md`

---

## Implementation Timeline

### Week 1: Backend Service Consolidation
- **Day 1-2:** Delete dead code, consolidate filter services
- **Day 3-4:** Merge evidence services
- **Day 5:** Testing, bug fixes

### Week 2: Backend File Splits
- **Day 1-2:** Split agent_orchestrator.py
- **Day 3:** Split react_agent.py
- **Day 4:** Extract classification gates
- **Day 5:** Split tool_core.py, testing

### Week 3: Frontend Refactor
- **Day 1-2:** Extract state hooks
- **Day 3:** Update main page to use hooks
- **Day 4-5:** Testing, component optimization

### Week 4: Polish & Documentation
- **Day 1-2:** API improvements, naming consistency
- **Day 3:** Documentation updates
- **Day 4:** Migration guide
- **Day 5:** Final testing, code review

**Total: 4 weeks**

---

## Testing Strategy

### Unit Tests
- Test each new module independently
- Ensure gate tests cover all vulnerability types
- Test filter pipeline with various combinations
- Test state hooks with React Testing Library

### Integration Tests
- Test full triage pipeline with new structure
- Test agent execution end-to-end
- Test WebSocket broadcasting with split broadcaster
- Test evidence gathering with unified service

### Regression Tests
- Run full test suite after each phase
- Verify all existing API contracts still work (with deprecation warnings)
- Check frontend smoke tests pass

### Performance Tests
- Benchmark triage pipeline before/after
- Ensure no performance regression from additional indirection
- Profile main page render with extracted hooks

---

## Risk Mitigation

### Rollback Strategy
1. **Keep deprecation period:** Old imports work for 1 version with warnings
2. **Feature flags:** Use feature flags to toggle new vs old implementations
3. **Git branching:** Each phase in separate branch, merge after testing
4. **Canary deployment:** Deploy to staging first, monitor for issues

### Breaking Change Management
1. **Semantic versioning:** Bump minor version (breaking but compatible)
2. **Changelog:** Document all API changes
3. **Migration guide:** Provide clear upgrade path
4. **Deprecation warnings:** Log warnings for 1 version before removal

---

## Success Metrics

### Code Quality
- ✅ 0 files >1500 lines (down from 4 files >2000 lines)
- ✅ 0 dead code files (down from 1)
- ✅ Cyclomatic complexity <15 per method (currently ~25 in large files)
- ✅ Import depth <4 levels (currently up to 6)

### Maintainability
- ✅ Time to onboard new developer: -30% (clearer structure)
- ✅ Time to add new vulnerability gate: -50% (clear pattern)
- ✅ Time to debug triage issue: -40% (focused modules)

### Performance
- ✅ Triage time: ±5% (acceptable variance)
- ✅ Agent startup time: ±5%
- ✅ Frontend render time: -10% (reduced main page complexity)

### Developer Experience
- ✅ Test runtime: ±10% (more tests but focused)
- ✅ IDE autocomplete accuracy: +20% (clearer imports)
- ✅ Code search relevance: +30% (better organization)

---

## Open Questions

1. **Should we keep backward-compatible imports forever or deprecate?**
   - Recommendation: Deprecate after 1 version (3 months)

2. **Should classification gates be plugins or hardcoded?**
   - Recommendation: Hardcoded for now, plugin system in future if needed

3. **Should filter pipeline be configurable or fixed order?**
   - Recommendation: Configurable (user can reorder filters)

4. **Should we split tool_core.py or keep together?**
   - Recommendation: Split for consistency, but lower priority

5. **Should frontend hooks use Zustand/Jotai instead of useState?**
   - Recommendation: useState first, consider state library if hooks grow complex

---

## Next Steps

1. **Review this design** - Approve/modify plan
2. **Create feature branch** - `feature/codebase-refactor`
3. **Set up worktree** - Isolated workspace for refactor
4. **Implement Phase 1** - Quick wins (dead code removal)
5. **Iterate through phases** - Week-by-week implementation

---

## Appendix A: File Structure Before/After

### Before
```
backend/
├── services/
│   ├── agent_orchestrator.py           (2238 lines)
│   ├── pre_triage_filter.py            (106 lines)
│   ├── production_relevance_filter.py  (114 lines)
│   ├── path_classifier.py              (91 lines)
│   ├── threat_model_gating.py          (161 lines)
│   ├── evidence_gatherer.py            (601 lines)
│   ├── evidence_quest_orchestrator.py  (411 lines)
│   ├── strict_classifier.py            (1193 lines)
│   ├── tool_core_new.py                (176 lines) ❌ DEAD
│   └── ... (24 more)
├── agents/
│   ├── react_agent.py                  (2207 lines)
│   ├── tool_core.py                    (1740 lines)
│   └── ... (6 more)

frontend/
├── app/
│   └── page.tsx                        (1246 lines)
├── hooks/
│   ├── useWebSocket.ts
│   ├── useAuth.ts
│   └── useInvestigationFlow.ts
```

### After
```
backend/
├── services/
│   ├── agents/
│   │   ├── orchestrator.py             (600 lines)
│   │   ├── lifecycle.py                (700 lines)
│   │   ├── broadcaster.py              (400 lines)
│   │   ├── budget_manager.py           (130 lines)
│   │   └── tool_cache.py               (128 lines)
│   ├── finding_filters/
│   │   ├── pipeline.py                 (100 lines)
│   │   ├── filters/
│   │   │   ├── path_filter.py          (120 lines)
│   │   │   ├── production_filter.py    (100 lines)
│   │   │   └── threat_model_filter.py  (130 lines)
│   │   └── types.py                    (50 lines)
│   ├── evidence/
│   │   ├── gatherer.py                 (400 lines)
│   │   ├── quest_manager.py            (350 lines)
│   │   └── collectors/
│   │       ├── code_collector.py       (100 lines)
│   │       └── ...
│   ├── classification/
│   │   ├── classifier.py               (300 lines)
│   │   ├── gates/
│   │   │   ├── base.py                 (50 lines)
│   │   │   ├── sqli_gate.py            (80 lines)
│   │   │   ├── command_injection_gate.py (90 lines)
│   │   │   └── ... (12 more gates)
│   │   └── disposition_rules.py        (150 lines)
│   └── ... (24 more)
├── agents/
│   ├── react/
│   │   ├── agent.py                    (600 lines)
│   │   ├── state_machine.py            (500 lines)
│   │   ├── handoff.py                  (400 lines)
│   │   ├── dual_model.py               (150 lines)
│   │   └── tool_executor.py            (350 lines)
│   ├── tool_core/
│   │   ├── checklists.py               (800 lines)
│   │   ├── sink_signals.py             (300 lines)
│   │   ├── finding_builder.py          (400 lines)
│   │   └── classification_helpers.py   (200 lines)
│   └── ... (6 more)

frontend/
├── app/
│   └── page.tsx                        (600 lines) ✅ -52% reduction
├── hooks/
│   ├── useAgentManagement.ts           (150 lines)
│   ├── useFindingsManagement.ts        (180 lines)
│   ├── useProjectWorkspace.ts          (100 lines)
│   ├── usePanelLayout.ts               (50 lines)
│   ├── useWorkspaceSync.ts             (80 lines)
│   ├── useWebSocket.ts
│   ├── useAuth.ts
│   └── useInvestigationFlow.ts
```

**Net Change:**
- **Removed:** 176 lines (dead code)
- **Reorganized:** 7,424 lines (5 major splits)
- **Reduced:** ~800 lines (consolidation)
- **Added:** ~300 lines (new interfaces/types)
- **Total Impact:** -676 lines, +100% clarity

---

## Appendix B: Import Migration Examples

### Filter Services

**Before:**
```python
from services.pre_triage_filter import pre_filter_findings
from services.path_classifier import classify_path
from services.production_relevance_filter import filter_by_production_relevance
```

**After:**
```python
from services.finding_filters import FilterPipeline, PathFilter, ProductionFilter
```

### Evidence Services

**Before:**
```python
from services.evidence_gatherer import EvidenceGatherer
from services.evidence_quest_orchestrator import EvidenceQuestOrchestrator
```

**After:**
```python
from services.evidence import EvidenceService
```

### Classification

**Before:**
```python
from services.strict_classifier import StrictClassifier
```

**After:**
```python
from services.classification import StrictClassifier
# Or for gate-specific testing:
from services.classification.gates import SQLiGate, CommandInjectionGate
```

### Agent Orchestration

**Before:**
```python
from services.agent_orchestrator import AgentOrchestrator
```

**After:**
```python
from services.agents import AgentOrchestrator
# Or for specific functionality:
from services.agents.lifecycle import AgentLifecycleManager
from services.agents.broadcaster import AgentBroadcaster
```

### ReAct Agent

**Before:**
```python
from agents.react_agent import ReActSecurityAgent
```

**After:**
```python
from agents.react import ReActSecurityAgent
# Or for internal components:
from agents.react.state_machine import ReActStateMachine
from agents.react.handoff import HandoffManager
```

---

## Appendix C: Testing Checklist

### Phase 1: Dead Code Removal
- [ ] Remove tool_core_new.py
- [ ] Verify 0 import errors
- [ ] Run full test suite
- [ ] Commit: "refactor: remove unused tool_core_new.py"

### Phase 2: Service Consolidation
- [ ] Create finding_filters/ subpackage
- [ ] Migrate pre_triage_filter logic
- [ ] Migrate path_classifier logic
- [ ] Migrate production_relevance_filter logic
- [ ] Migrate threat_model_gating logic
- [ ] Create FilterPipeline orchestrator
- [ ] Update finding_triage_service.py imports
- [ ] Update agent imports
- [ ] Add deprecation warnings to old imports
- [ ] Run filter tests
- [ ] Run triage tests
- [ ] Commit: "refactor: consolidate filter services into pipeline"

- [ ] Create evidence/ subpackage
- [ ] Migrate evidence_gatherer core logic
- [ ] Migrate evidence_quest_orchestrator logic
- [ ] Extract collectors
- [ ] Update finding_triage_service imports
- [ ] Update protocol_evaluator imports
- [ ] Add deprecation warnings
- [ ] Run evidence tests
- [ ] Run quest tests
- [ ] Commit: "refactor: unify evidence services"

### Phase 3: File Splits
- [ ] Create services/agents/ subpackage
- [ ] Extract lifecycle.py
- [ ] Extract broadcaster.py
- [ ] Update orchestrator.py to coordinate
- [ ] Update routers/agents.py imports
- [ ] Run agent tests
- [ ] Run integration tests
- [ ] Commit: "refactor: split agent_orchestrator into focused modules"

- [ ] Create agents/react/ subpackage
- [ ] Extract state_machine.py
- [ ] Extract handoff.py
- [ ] Extract tool_executor.py
- [ ] Update agent.py to coordinate
- [ ] Update orchestrator imports
- [ ] Run ReAct agent tests
- [ ] Commit: "refactor: split react_agent into focused modules"

- [ ] Create services/classification/ subpackage
- [ ] Extract base.py (BaseGate)
- [ ] Extract sqli_gate.py
- [ ] Extract command_injection_gate.py
- [ ] Extract remaining 13 gates
- [ ] Update classifier.py to orchestrate
- [ ] Update triage service imports
- [ ] Run classification tests (gate-by-gate)
- [ ] Run full triage tests
- [ ] Commit: "refactor: extract classification gates into submodule"

- [ ] Create agents/tool_core/ subpackage
- [ ] Extract checklists.py
- [ ] Extract sink_signals.py
- [ ] Extract finding_builder.py
- [ ] Extract classification_helpers.py
- [ ] Update react_agent imports (29 uses)
- [ ] Run tool_core tests
- [ ] Commit: "refactor: split tool_core into focused modules"

### Phase 4: Frontend Refactor
- [ ] Create hooks/useAgentManagement.ts
- [ ] Create hooks/useFindingsManagement.ts
- [ ] Create hooks/useProjectWorkspace.ts
- [ ] Create hooks/usePanelLayout.ts
- [ ] Create hooks/useWorkspaceSync.ts
- [ ] Update app/page.tsx to use hooks
- [ ] Remove inline state management
- [ ] Run frontend tests
- [ ] Run Playwright smoke tests
- [ ] Commit: "refactor: extract state management hooks from main page"

### Phase 5: API Improvements
- [ ] Standardize filter API signatures
- [ ] Unify evidence service API
- [ ] Update router imports
- [ ] Add migration guide
- [ ] Run all tests
- [ ] Commit: "refactor: standardize service APIs"

### Phase 6: Documentation
- [ ] Update README.md (tool count, imports)
- [ ] Create MIGRATION_GUIDE.md
- [ ] Create ADRs for major decisions
- [ ] Update SYSTEM-SPECIFICATION.md
- [ ] Commit: "docs: update for refactored architecture"

### Final Validation
- [ ] Run full backend test suite
- [ ] Run full frontend test suite
- [ ] Run Playwright E2E tests
- [ ] Benchmark triage performance (±5%)
- [ ] Benchmark agent startup (±5%)
- [ ] Check bundle size (frontend)
- [ ] Review deprecation warnings
- [ ] Code review with team
- [ ] Merge to main

---

**End of Design Document**

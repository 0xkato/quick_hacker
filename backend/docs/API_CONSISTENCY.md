# API Consistency Guide

This document defines the naming conventions, import patterns, and organizational structure for the backend codebase after the Phase 1-4 refactoring.

## Table of Contents

- [Import Patterns](#import-patterns)
- [Naming Conventions](#naming-conventions)
- [Module Organization](#module-organization)
- [Deprecation Timeline](#deprecation-timeline)
- [Migration Examples](#migration-examples)

## Import Patterns

### Filter Services

```python
# New (recommended)
from services.finding_filters import FilterPipeline, PathFilter, ProductionRelevanceFilter, ThreatModelFilter

# Old (deprecated - will show DeprecationWarning)
from services.pre_triage_filter import pre_filter_findings
from services.path_classifier import classify_path
from services.production_relevance_filter import ProductionRelevanceFilter
from services.threat_model_gating import derive_allowed_input_channels
```

### Evidence Services

```python
# New (recommended)
from services.evidence import EvidenceService, EvidenceGatherer, EvidenceQuestOrchestrator
from services.evidence import SymbolInfo, EvidenceMatch, SSRFAnalysis, EvidenceResult
from services.evidence.collectors import CodeCollector, RouteCollector, AuthGateCollector

# Old (deprecated - will show DeprecationWarning)
from services.evidence_gatherer import EvidenceGatherer
from services.evidence_quest_orchestrator import EvidenceQuestOrchestrator
```

### Agent Services

```python
# New (recommended)
from services.agents import AgentOrchestrator, orchestrator
from services.agents import AgentLifecycleManager, AgentBroadcaster
from services.agents import AGENT_CLASSES

# Old (deprecated - will show DeprecationWarning)
from services.agent_orchestrator import AgentOrchestrator, orchestrator
```

### Classification Services

```python
# New (recommended)
from services.classification import StrictClassifier, ClassificationResult
from services.classification import BaseGate, GateResult
from services.classification.gates import SQLiGate, XSSGate, CommandInjectionGate

# Old (deprecated - will show DeprecationWarning)
from services.strict_classifier import StrictClassifier, ClassificationResult
```

### ReAct Agent

```python
# New (recommended)
from agents.react import ReActSecurityAgent
from agents.react import AgentLimits, DualModelState, HandoffManager

# Old (deprecated - will show DeprecationWarning in agents/react_agent.py)
from agents.react_agent import ReActSecurityAgent
```

## Naming Conventions

The codebase follows consistent naming patterns to indicate the purpose and responsibility of each class:

### Services: `XxxService`

Stateful services that manage business logic and coordinate operations.

**Examples:**
- `ProjectService` - Manages projects and their configuration
- `FindingTriageService` - Orchestrates the finding triage pipeline
- `EvidenceService` - Coordinates evidence gathering
- `AttackSurfaceService` - Manages attack surface analysis

**Pattern:** Business logic + state management

### Managers: `XxxManager`

Lifecycle and resource management responsibilities.

**Examples:**
- `AgentLifecycleManager` - Creates, pauses, resumes, cancels agents
- `ToolBudgetManager` - Tracks and enforces tool usage budgets
- `TimeBudgetManager` - Manages time budgets for agents

**Pattern:** Resource lifecycle + quota/limit enforcement

### Orchestrators: `XxxOrchestrator`

Multi-service coordination and workflow management.

**Examples:**
- `AgentOrchestrator` - Coordinates agent execution across multiple services
- `EvidenceQuestOrchestrator` - Manages autonomous evidence gathering quests
- `ClaudeSDKOrchestrator` - Orchestrates Claude SDK interactions

**Pattern:** High-level coordination + workflow management

### Pipelines: `XxxPipeline`

Filter and transform chains that process data sequentially.

**Examples:**
- `FilterPipeline` - Chains finding filters together

**Pattern:** Sequential processing + composition

### Gates: `XxxGate`

Classification gates for specific vulnerability types.

**Examples:**
- `SQLiGate` - SQL injection detection
- `XSSGate` - Cross-site scripting detection
- `CommandInjectionGate` - Command injection detection
- `AuthBypassGate` - Authentication bypass detection

**Pattern:** Single responsibility + binary decision (pass/fail)

### Filters: `XxxFilter`

Finding filters that determine whether findings should be kept or filtered out.

**Examples:**
- `PathFilter` - Filters findings based on file path classification
- `ProductionRelevanceFilter` - LLM-based production relevance filtering
- `ThreatModelFilter` - Filters based on threat model configuration

**Pattern:** Single criterion + boolean result

### Collectors: `XxxCollector`

Evidence collectors that gather specific types of evidence.

**Examples:**
- `CodeCollector` - Collects code snippets and context
- `RouteCollector` - Collects route registration evidence
- `AuthGateCollector` - Collects authentication/authorization checks

**Pattern:** Focused data collection + structured output

### Broadcasters: `XxxBroadcaster`

Event broadcasting and notification systems.

**Examples:**
- `AgentBroadcaster` - Broadcasts agent events via WebSocket

**Pattern:** Event distribution + pub/sub

## Module Organization

```
backend/
├── services/               # Backend services
│   ├── agents/             # Agent orchestration
│   │   ├── orchestrator.py         # Main coordinator (legacy location)
│   │   ├── lifecycle.py            # Agent lifecycle management
│   │   └── broadcaster.py          # WebSocket broadcasting
│   ├── classification/     # Vulnerability classification
│   │   ├── classifier.py           # StrictClassifier
│   │   └── gates/                  # Category-specific gates
│   │       ├── base.py
│   │       ├── sqli_gate.py
│   │       ├── xss_gate.py
│   │       └── ...
│   ├── evidence/           # Evidence gathering
│   │   ├── gatherer.py             # EvidenceService
│   │   ├── quest_manager.py        # Quest orchestration
│   │   ├── types.py                # Shared types
│   │   └── collectors/             # Evidence collectors
│   │       ├── code_collector.py
│   │       ├── route_collector.py
│   │       └── auth_gate_collector.py
│   ├── finding_filters/    # Finding filters
│   │   ├── pipeline.py             # FilterPipeline
│   │   ├── types.py                # Shared types
│   │   └── filters/                # Filter implementations
│   │       ├── path_filter.py
│   │       ├── production_filter.py
│   │       └── threat_model_filter.py
│   └── ...                # Other services
├── agents/                # Agent implementations
│   ├── react/             # ReAct agent module
│   │   ├── agent.py               # Main coordinator
│   │   ├── state_machine.py       # State management
│   │   ├── handoff.py             # Scanner → Analyzer handoff
│   │   ├── dual_model.py          # Dual-model config
│   │   ├── tool_executor.py       # Tool execution
│   │   └── types.py               # Common types
│   ├── quick_audit_agent.py       # Quick audit agent
│   ├── deep_audit/                # Deep audit agent
│   └── ...
├── routers/               # API endpoints
├── models/                # Data models and schemas
└── docs/                  # Documentation
```

## Deprecation Timeline

The migration from old to new APIs follows a phased approach:

### Phase 1 (Current) - Deprecation Warnings

- **Status:** All old files have deprecation warnings
- **Behavior:** Old imports work but show `DeprecationWarning`
- **Action Required:** None immediately, but update imports when convenient

**Files with deprecation warnings:**
- `services/pre_triage_filter.py` → `services.finding_filters.PathFilter`
- `services/path_classifier.py` → `services.finding_filters.PathFilter`
- `services/production_relevance_filter.py` → `services.finding_filters.ProductionRelevanceFilter`
- `services/threat_model_gating.py` → `services.finding_filters.ThreatModelFilter`
- `services/evidence_gatherer.py` → `services.evidence.EvidenceService`
- `services/evidence_quest_orchestrator.py` → `services.evidence.EvidenceQuestOrchestrator`
- `services/agent_orchestrator.py` → `services.agents.AgentOrchestrator`
- `services/strict_classifier.py` → `services.classification.StrictClassifier`
- `agents/react_agent.py` → `agents.react.ReActSecurityAgent`

### Phase 2 (3 months) - Remove Backward Compatibility

- **Status:** Planned
- **Behavior:** Old imports raise `ImportError`
- **Action Required:** Update all imports before this phase

**Changes:**
- Remove re-exports from deprecated modules
- Keep deprecation stubs that raise `ImportError` with migration instructions

### Phase 3 (6 months) - Delete Deprecated Files

- **Status:** Planned
- **Behavior:** Old files no longer exist
- **Action Required:** All imports must use new paths

**Changes:**
- Delete all deprecated shim files
- Update documentation to remove old import examples

## Migration Examples

### Example 1: Migrating Filter Imports

**Before:**
```python
from services.pre_triage_filter import pre_filter_findings
from services.path_classifier import classify_path
from services.production_relevance_filter import ProductionRelevanceFilter
from services.threat_model_gating import derive_allowed_input_channels

# Use scattered functions
filtered = pre_filter_findings(findings, policy)
classification = classify_path(file_path, config)
```

**After:**
```python
from services.finding_filters import FilterPipeline, PathFilter, ProductionRelevanceFilter, ThreatModelFilter

# Use pipeline
pipeline = FilterPipeline()
pipeline.add_filter(PathFilter(policy))
pipeline.add_filter(ThreatModelFilter(threat_model))
pipeline.add_filter(ProductionRelevanceFilter(api_key))

filtered = pipeline.filter(findings)
```

### Example 2: Migrating Evidence Imports

**Before:**
```python
from services.evidence_gatherer import EvidenceGatherer, SymbolInfo
from services.evidence_quest_orchestrator import EvidenceQuestOrchestrator

gatherer = EvidenceGatherer(repo_root, budgets)
evidence = gatherer.gather(finding)
```

**After:**
```python
from services.evidence import EvidenceService, SymbolInfo
from services.evidence import EvidenceQuestOrchestrator

service = EvidenceService(repo_root, budgets)
evidence = service.gather(finding)
```

### Example 3: Migrating Classification Imports

**Before:**
```python
from services.strict_classifier import StrictClassifier, ClassificationResult

classifier = StrictClassifier()
result = classifier.classify(finding, evidence, threat_model)
```

**After:**
```python
from services.classification import StrictClassifier, ClassificationResult

classifier = StrictClassifier()
result = classifier.classify(finding, evidence, threat_model)
```

### Example 4: Migrating ReAct Agent Imports

**Before:**
```python
from agents.react_agent import ReActSecurityAgent

agent = ReActSecurityAgent(request, repo_path)
findings = await agent.run()
```

**After:**
```python
from agents.react import ReActSecurityAgent

agent = ReActSecurityAgent(request, repo_path)
findings = await agent.run()
```

## Best Practices

1. **Import from top-level module**: Always import from the module's `__init__.py` rather than internal files
   ```python
   # Good
   from services.finding_filters import PathFilter

   # Bad
   from services.finding_filters.filters.path_filter import PathFilter
   ```

2. **Use specific imports**: Import specific classes rather than using wildcard imports
   ```python
   # Good
   from services.evidence import EvidenceService, SymbolInfo

   # Bad
   from services.evidence import *
   ```

3. **Group imports by category**: Organize imports by type (stdlib, third-party, local)
   ```python
   import asyncio
   from typing import Optional

   from anthropic import Anthropic

   from services.evidence import EvidenceService
   from models.schemas import Finding
   ```

4. **Update deprecation warnings gradually**: Don't rush to update all imports at once; do it incrementally as you touch files

## Summary

The refactoring establishes clear patterns:

- **Naming**: Reflects purpose (Service/Manager/Orchestrator/Pipeline/Gate/Filter)
- **Organization**: Grouped by domain (agents/evidence/classification/filters)
- **Imports**: Top-level module imports with `__all__` exports
- **Deprecation**: Gradual migration with clear warnings and timeline

All new code should follow these patterns. When updating existing code, prefer the new import paths and naming conventions.

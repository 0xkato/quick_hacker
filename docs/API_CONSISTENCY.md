# API Consistency Guide

## Overview

This guide defines naming patterns and architectural conventions used throughout the refactored codebase.

## Naming Patterns

### Service Layer Patterns

#### Service
**Purpose:** Unified facade providing high-level API
**Example:** `EvidenceService`

```python
class EvidenceService:
    """Unified service for evidence gathering and quests."""

    def __init__(self, gatherer, quest_orchestrator):
        self.gatherer = gatherer
        self.quest_orchestrator = quest_orchestrator

    def gather(self, finding):
        """Synchronous evidence gathering."""
        return self.gatherer.gather(finding)

    def start_quest(self, finding, missing_evidence):
        """Asynchronous evidence quest."""
        return self.quest_orchestrator.start_quest(finding, missing_evidence)
```

**When to use:**
- Providing unified API for multiple related components
- Facade pattern over complex subsystems
- Single entry point for a feature area

---

#### Manager
**Purpose:** CRUD operations and persistence
**Example:** `AgentManager`

```python
class AgentManager:
    """Manages agent CRUD operations."""

    async def create_agent(self, project_id, config):
        """Create new agent."""

    async def get_agent(self, agent_id):
        """Get agent by ID."""

    async def update_agent(self, agent_id, updates):
        """Update agent."""

    async def delete_agent(self, agent_id):
        """Delete agent."""
```

**When to use:**
- Database CRUD operations
- Entity lifecycle management
- Data persistence layer

---

#### Orchestrator
**Purpose:** Lifecycle coordination and workflow
**Example:** `AgentOrchestrator`

```python
class AgentOrchestrator:
    """Orchestrates agent execution lifecycle."""

    async def execute_agent(self, config, agent_id):
        """Execute agent with lifecycle management."""
        # 1. Initialize
        # 2. Execute
        # 3. Handle errors
        # 4. Cleanup
        # 5. Broadcast events
```

**When to use:**
- Complex lifecycle management
- Multi-step workflows
- Coordinating multiple services

---

#### Pipeline
**Purpose:** Data transformation chain
**Example:** `FilterPipeline`

```python
class FilterPipeline:
    """Composable filter chain."""

    def __init__(self, filters: list):
        self.filters = filters

    def apply(self, findings):
        """Apply all filters in sequence."""
        for filter in self.filters:
            findings = filter.apply(findings)
        return findings
```

**When to use:**
- Sequential data transformations
- Composable processing steps
- Chain of responsibility pattern

---

#### Gate
**Purpose:** Decision point with specific logic
**Example:** `SQLiGate`

```python
class SQLiGate:
    """SQL Injection classification gate."""

    def classify(self, finding, evidence):
        """Determine if finding is valid SQLi."""
        # Check evidence
        # Validate proofs
        # Return classification
```

**When to use:**
- Boolean or enum decision making
- Specific classification logic
- Guard clauses / validation

---

#### Filter
**Purpose:** Select/exclude items from collection
**Example:** `PathFilter`

```python
class PathFilter:
    """Filters findings by path classification."""

    def apply(self, findings):
        """Filter findings based on path criteria."""
        return [f for f in findings if self._should_include(f)]
```

**When to use:**
- Selecting/excluding items
- Collection filtering
- Predicate-based selection

---

#### Gatherer
**Purpose:** Collect related data
**Example:** `EvidenceGatherer`

```python
class EvidenceGatherer:
    """Gathers evidence for findings."""

    def gather(self, finding):
        """Collect all relevant evidence."""
        return {
            'code_snippet': self._get_code(),
            'route_info': self._get_routes(),
            'auth_gates': self._get_auth()
        }
```

**When to use:**
- Collecting related data
- Aggregating information
- Building composite objects

---

#### Tracker
**Purpose:** Monitor state over time
**Example:** `CoverageTracker`

```python
class CoverageTracker:
    """Tracks investigation coverage."""

    def register_path(self, entry, sink):
        """Register new path to track."""

    def update_status(self, path_id, status):
        """Update path status."""

    def get_stats(self):
        """Get coverage statistics."""
```

**When to use:**
- Tracking state changes
- Monitoring progress
- Statistics collection

---

#### Validator
**Purpose:** Input validation and verification
**Example:** `InputValidator`

```python
class InputValidator:
    """Validates tool inputs."""

    def validate(self, tool_name, arguments):
        """Validate tool arguments."""
        # Check required fields
        # Validate types
        # Check constraints
        return validation_result
```

**When to use:**
- Input validation
- Type checking
- Constraint verification

---

### Frontend Patterns

#### Hook: use[Noun][Action]
**Purpose:** Reusable stateful logic
**Examples:**
- `useAgentManagement` - Agent state and operations
- `useFindingsManagement` - Findings state and filtering
- `useProjectWorkspace` - Workspace lifecycle

```typescript
export function useAgentManagement(projectId: string) {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [currentAgent, setCurrentAgent] = useState<Agent | null>(null);

  // Logic here

  return {
    agents,
    currentAgent,
    startAgent,
    stopAgent,
    loading,
    error
  };
}
```

**When to use:**
- Reusable state logic
- Component-independent logic
- Cross-component state

---

#### Component: [Noun][Qualifier]
**Examples:**
- `FindingsList` - List of findings
- `AgentManager` - Agent management UI
- `FileExplorer` - File tree browser

**When to use:**
- UI components
- Visual elements
- User interactions

---

## File Organization

### Backend Structure

```
services/
├── [feature]/              # Feature-based organization
│   ├── service.py         # Main facade (if needed)
│   ├── manager.py         # CRUD operations
│   ├── orchestrator.py    # Lifecycle management
│   └── [submodules]/      # Specialized modules
```

**Examples:**
```
services/
├── agents/
│   ├── orchestrator.py
│   ├── manager.py
│   └── execution_context.py
├── finding_filters/
│   ├── pipeline.py
│   ├── path_filter.py
│   ├── production_filter.py
│   └── threat_model_filter.py
├── evidence/
│   ├── service.py
│   ├── gatherer.py
│   └── quest_orchestrator.py
└── classification/
    ├── strict_classifier.py
    └── gates/
        ├── sqli_gate.py
        ├── xss_gate.py
        └── ...
```

---

### Frontend Structure

```
hooks/
├── use[Feature][Action].ts  # Custom hooks

components/
├── [Feature]/               # Feature components
│   ├── [Component].tsx
│   ├── [Component].module.css
│   └── index.ts
```

**Examples:**
```
hooks/
├── useAgentManagement.ts
├── useFindingsManagement.ts
└── useProjectWorkspace.ts

components/
├── Agent/
│   ├── AgentManager.tsx
│   ├── AgentStatus.tsx
│   └── index.ts
├── Findings/
│   ├── FindingsList.tsx
│   ├── FindingDrawer.tsx
│   └── index.ts
```

---

## Module Size Guidelines

### Ideal Sizes
- **Single file:** 200-500 lines (sweet spot)
- **Small module:** 50-200 lines
- **Large module:** 500-800 lines (consider splitting)
- **Too large:** >1000 lines (should be split)

### When to Split
Split when:
- File exceeds 800-1000 lines
- Multiple distinct responsibilities
- High cognitive load
- Difficult to navigate

### How to Split
1. Identify logical boundaries
2. Group related functionality
3. Extract to separate files
4. Create clear interfaces
5. Maintain backward compatibility

---

## Import Conventions

### Backend

**Preferred:**
```python
# Import from new modular structure
from services.finding_filters import FilterPipeline, PathFilter
from services.evidence import EvidenceService
from services.classification.gates import SQLiGate
```

**Deprecated (but still works):**
```python
# Old monolithic imports
from services.pre_triage_filter import pre_filter_findings
from services.evidence_gatherer import EvidenceGatherer
from services.strict_classifier import StrictClassifier
```

---

### Frontend

**Preferred:**
```typescript
// Import from hooks
import { useAgentManagement } from '@/hooks/useAgentManagement';
import { useFindingsManagement } from '@/hooks/useFindingsManagement';

// Import from component index
import { FindingsList, FindingDrawer } from '@/components/Findings';
```

**Avoid:**
```typescript
// Direct file imports
import { FindingsList } from '@/components/Findings/FindingsList';
```

---

## Deprecation Strategy

### Adding Deprecation Warning

```python
import warnings

# In old module
def old_function():
    warnings.warn(
        "old_function is deprecated. Use NewClass.new_method instead.",
        DeprecationWarning,
        stacklevel=2
    )
    # Delegate to new implementation
    return NewClass().new_method()
```

### Timeline
1. **Month 0:** Add deprecation warnings
2. **Month 3:** Remove backward compatibility
3. **Month 6:** Delete deprecated files

---

## Testing Patterns

### Service Tests
```python
def test_evidence_service():
    service = EvidenceService(gatherer, orchestrator)
    evidence = service.gather(finding)
    assert evidence.code_snippet is not None
```

### Pipeline Tests
```python
def test_filter_pipeline():
    pipeline = FilterPipeline([PathFilter(), ProductionFilter()])
    results = pipeline.apply(findings)
    assert len(results) < len(findings)  # Some filtered
```

### Gate Tests
```python
def test_sqli_gate():
    gate = SQLiGate()
    result = gate.classify(finding, evidence)
    assert result.disposition == "VALID_SECURITY_ISSUE"
```

### Hook Tests
```typescript
test('useAgentManagement', () => {
  const { result } = renderHook(() => useAgentManagement('project-123'));

  expect(result.current.agents).toEqual([]);
  expect(result.current.loading).toBe(true);
});
```

---

## Quick Reference

| Pattern | Purpose | Example |
|---------|---------|---------|
| Service | Unified facade | EvidenceService |
| Manager | CRUD operations | AgentManager |
| Orchestrator | Lifecycle coordination | AgentOrchestrator |
| Pipeline | Data transformation chain | FilterPipeline |
| Gate | Decision point | SQLiGate |
| Filter | Collection filtering | PathFilter |
| Gatherer | Data collection | EvidenceGatherer |
| Tracker | State monitoring | CoverageTracker |
| Validator | Input validation | InputValidator |
| Hook | Reusable state logic | useAgentManagement |
| Component | UI element | FindingsList |

---

**Last updated:** 2026-01-18
**Version:** 1.0.0

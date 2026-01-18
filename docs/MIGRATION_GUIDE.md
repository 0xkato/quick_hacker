# Migration Guide: Refactored Architecture

## Overview

This guide helps you migrate code to use the refactored architecture introduced on 2026-01-18.

**Good news:** All old imports still work with deprecation warnings. You can migrate gradually.

## Backend Migrations

### Filter Services

**Before:**
```python
from services.pre_triage_filter import pre_filter_findings
from services.path_classifier import classify_path
from services.production_relevance_filter import ProductionRelevanceFilter
from services.threat_model_gating import derive_allowed_input_channels

# Manual orchestration
findings = pre_filter_findings(findings, policy)
for f in findings:
    f.path_classification = classify_path(f.file_path, config)
```

**After:**
```python
from services.finding_filters import FilterPipeline, PathFilter, ProductionFilter, ThreatModelFilter

# Composable pipeline
pipeline = FilterPipeline([
    PathFilter(policy.path_classification, policy),
    ProductionFilter(context),
    ThreatModelFilter(threat_model)
])
findings = pipeline.apply(findings)
```

**Benefits:**
- Composable filter chain
- Single pass through findings
- Easy to add/remove filters
- Better testability

---

### Evidence Services

**Before:**
```python
from services.evidence_gatherer import EvidenceGatherer
from services.evidence_quest_orchestrator import EvidenceQuestOrchestrator

# Two separate services
gatherer = EvidenceGatherer(repo_root, budgets)
evidence = gatherer.gather(finding)

orchestrator = EvidenceQuestOrchestrator(llm_config)
quest = orchestrator.start_quest(finding, missing_evidence)
```

**After:**
```python
from services.evidence import EvidenceService

# Unified service
service = EvidenceService(repo_root, budgets, llm_config)

# Synchronous evidence gathering
evidence = service.gather(finding)

# Asynchronous quest orchestration
quest = service.start_quest(finding, missing_evidence)
```

**Benefits:**
- Single entry point
- Consistent interface
- Easier dependency injection
- Clear service boundary

---

### Classification Gates

**Before:**
```python
from services.strict_classifier import StrictClassifier

# Monolithic classifier
classifier = StrictClassifier()
result = classifier.classify(finding, evidence)
```

**After:**
```python
from services.classification import StrictClassifier

# Same interface, modular implementation
classifier = StrictClassifier()
result = classifier.classify(finding, evidence)

# Or import specific gates for testing
from services.classification.gates import SQLiGate, XSSGate

sqli_gate = SQLiGate()
result = sqli_gate.classify(finding, evidence)
```

**Benefits:**
- Same top-level API
- Gates independently testable
- Easy to add new vulnerability types
- Clear separation per CWE

**Gate Modules:**
- `sqli_gate.py` - SQL Injection (CWE-89)
- `xss_gate.py` - Cross-Site Scripting (CWE-79)
- `code_injection_gate.py` - Code Injection (CWE-94)
- `idor_gate.py` - Insecure Direct Object Reference (CWE-639)
- `ssrf_gate.py` - Server-Side Request Forgery (CWE-918)
- `path_traversal_gate.py` - Path Traversal (CWE-22)
- `xxe_gate.py` - XML External Entity (CWE-611)
- `deserialization_gate.py` - Insecure Deserialization (CWE-502)
- `auth_bypass_gate.py` - Authentication Bypass (CWE-287)
- `crypto_weakness_gate.py` - Cryptographic Weakness (CWE-327)
- `rce_gate.py` - Remote Code Execution (CWE-94)
- `file_upload_gate.py` - Unrestricted File Upload (CWE-434)
- `open_redirect_gate.py` - Open Redirect (CWE-601)
- `csrf_gate.py` - Cross-Site Request Forgery (CWE-352)
- `race_condition_gate.py` - Race Condition (CWE-362)
- `dos_gate.py` - Denial of Service (CWE-400)

---

### Agent Orchestration

**Before:**
```python
from services.agent_orchestrator import AgentOrchestrator

orchestrator = AgentOrchestrator()
result = await orchestrator.execute_agent(config, agent_id)
```

**After:**
```python
from services.agents import AgentOrchestrator

# Same interface, better organized
orchestrator = AgentOrchestrator()
result = await orchestrator.execute_agent(config, agent_id)

# Or use specific components
from services.agents import AgentManager, ExecutionContext

manager = AgentManager()
context = ExecutionContext(project_id, agent_id)
```

**Benefits:**
- Clear separation of concerns
- Smaller, focused modules
- Easier to test components
- Better code organization

---

### ReAct Agent

**Before:**
```python
from agents.react_agent import ReActAgent

agent = ReActAgent(tools, llm_config)
result = await agent.run(prompt)
```

**After:**
```python
from agents.react import ReActAgent

# Same interface, modular implementation
agent = ReActAgent(tools, llm_config)
result = await agent.run(prompt)

# Or use specific components for testing
from agents.react import AgentCore, Reasoning, Memory, ToolAdapter

core = AgentCore(llm_config)
reasoning = Reasoning(core)
memory = Memory()
tools = ToolAdapter(tool_executor)
```

**Benefits:**
- Main API unchanged
- Internal modules testable
- Clear separation of concerns
- Easier to extend

---

### Tool Core

**Before:**
```python
from services.tool_core import ToolCore

tool_core = ToolCore(repo_path, project_id)
result = await tool_core.read_file(path)
```

**After:**
```python
from agents.tool_core import ToolCore

# Same interface, modular implementation
tool_core = ToolCore(repo_path, project_id)
result = await tool_core.read_file(path)

# Or use specific utilities
from agents.tool_core import ToolCache, BudgetManager, Validator

cache = ToolCache()
budget = BudgetManager(time_budget_ms)
validator = Validator()
```

**Benefits:**
- Utilities independently usable
- Better testability
- Clear responsibility per module
- Easier to extend

---

## Frontend Migrations

### State Management

**Before (in page.tsx):**
```typescript
const [agents, setAgents] = useState<Agent[]>([]);
const [currentAgent, setCurrentAgent] = useState<Agent | null>(null);

useEffect(() => {
  // 50+ lines of agent management logic
  const fetchAgents = async () => {
    const response = await api.get(`/agents/${projectId}`);
    setAgents(response.data);
  };
  fetchAgents();
}, [projectId]);

const startAgent = async (type: string) => {
  // 30+ lines of agent start logic
};
```

**After:**
```typescript
import { useAgentManagement } from '@/hooks/useAgentManagement';

const agents = useAgentManagement(projectId);

// Access everything you need
agents.agents         // Agent list
agents.currentAgent   // Current agent
agents.startAgent     // Start agent function
agents.stopAgent      // Stop agent function
agents.loading        // Loading state
agents.error          // Error state
```

**Benefits:**
- Reusable across components
- Centralized logic
- Easier testing
- Reduced page complexity

---

### Other Hooks

**Findings Management:**
```typescript
import { useFindingsManagement } from '@/hooks/useFindingsManagement';

const findings = useFindingsManagement(projectId);

findings.findings              // Finding list
findings.filteredFindings      // Filtered findings
findings.filter                // Current filter
findings.setFilter             // Update filter
findings.selectedFinding       // Selected finding
findings.selectFinding         // Select finding
```

**Project Workspace:**
```typescript
import { useProjectWorkspace } from '@/hooks/useProjectWorkspace';

const workspace = useProjectWorkspace(projectId);

workspace.project              // Project data
workspace.files                // File list
workspace.loading              // Loading state
workspace.reloadProject        // Reload function
```

**Panel Layout:**
```typescript
import { usePanelLayout } from '@/hooks/usePanelLayout';

const panels = usePanelLayout();

panels.leftPanelWidth          // Left panel width
panels.rightPanelWidth         // Right panel width
panels.setLeftPanelWidth       // Resize left
panels.setRightPanelWidth      // Resize right
```

**Code Editor State:**
```typescript
import { useCodeEditorState } from '@/hooks/useCodeEditorState';

const editor = useCodeEditorState();

editor.selectedFile            // Current file
editor.fileContent             // File content
editor.setSelectedFile         // Change file
editor.updateContent           // Update content
```

---

## Deprecation Timeline

### Phase 1: Now (Deprecation Warnings)
- All old imports work
- Deprecation warnings logged to console
- No breaking changes
- Start migrating gradually

### Phase 2: 3 Months (Remove Shims)
- Remove backward compatibility shims
- Old imports will fail
- Warnings have given 3 months notice

### Phase 3: 6 Months (Delete Old Files)
- Delete deprecated files entirely
- Clean up codebase
- Complete migration

---

## Common Issues

### DeprecationWarning in logs

**Problem:**
```
DeprecationWarning: pre_triage_filter is deprecated. Use services.finding_filters.PathFilter instead.
```

**Solution:** Update import to new path:
```python
# Old
from services.pre_triage_filter import pre_filter_findings

# New
from services.finding_filters import PathFilter
```

---

### Import not found

**Problem:**
```
ImportError: cannot import name 'pre_filter_findings' from 'services.finding_filters'
```

**Solution:** The function name changed to class-based API:
```python
# Old
findings = pre_filter_findings(findings, policy)

# New
filter = PathFilter(policy)
findings = filter.apply(findings)
```

---

### Type errors in frontend

**Problem:**
```
Type 'Agent[]' is not assignable to type 'AgentState'
```

**Solution:** Use the hook instead of managing state manually:
```typescript
// Old
const [agents, setAgents] = useState<Agent[]>([]);

// New
const { agents } = useAgentManagement(projectId);
```

---

## Getting Help

- **API patterns:** Check [API_CONSISTENCY.md](API_CONSISTENCY.md)
- **Overview:** Review [REFACTORING_SUMMARY.md](REFACTORING_SUMMARY.md)
- **Deprecation warnings:** Follow the suggested path in the warning message
- **Tests:** Look at test files for usage examples

---

## Checklist

### Backend Migration
- [ ] Update filter service imports
- [ ] Update evidence service imports
- [ ] Update classification imports (if directly used)
- [ ] Update agent orchestration imports (if directly used)
- [ ] Run tests to verify
- [ ] Remove deprecation warnings

### Frontend Migration
- [ ] Replace state management with hooks
- [ ] Update component imports
- [ ] Test UI functionality
- [ ] Check TypeScript types
- [ ] Verify build succeeds

---

**Last updated:** 2026-01-18
**Version:** 1.0.0

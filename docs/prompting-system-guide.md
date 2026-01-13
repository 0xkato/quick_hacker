# Prompting System Guide

## Overview

The prompting system uses modular template composition to assemble context-aware prompts for vulnerability analysis agents. It provides evidence-first reasoning with tri-state proof checklists, category-aware routing, and a critic/refuter loop for evidence gap identification.

## Architecture

**Composition Model:** `BASE_PROMPT + SELECTED_MODULES + TASK`

**Directory Structure:**
```
prompting/
├── base/
│   └── base_prompt.md               # Always included
├── stages/
│   ├── identify_entrypoints.md     # DeepAudit stage 1
│   ├── trace_dataflow.md           # DeepAudit stage 2
│   ├── validate_exploitability.md  # DeepAudit stage 3
│   └── triage.md                   # DeepAudit stage 4
├── contexts/
│   ├── django.md                   # Framework-specific context (confidence > 0.8)
│   ├── fastapi.md
│   ├── flask.md
│   └── express.md
└── validity_checklists/
    ├── sql_injection.md            # Category-specific proof checklist
    ├── ssrf.md
    ├── auth_idor.md
    └── memory_safety.md
```

## Core Components

### 1. Prompt Router (`services/prompt_router.py`)

Routes to appropriate prompt modules based on context and assembles the final prompt.

**Key Features:**
- Category-aware validity checklist selection
- Stage-specific guidance for DeepAudit workflow
- Framework context injection (gated by confidence threshold)
- Template concatenation with `"\n\n"` separator

### 2. Critic Loop (`services/critic_loop.py`)

Implements feedback loop for evidence gap identification and filling.

**Decision Types:**
- `READY_TO_REPORT` - All evidence sufficient, proceed to report
- `CONTINUE` - Blocking gaps remain, continue gathering evidence
- `STOP_FILTERED` - Finding filtered out (e.g., misconfiguration-only)
- `STOP_SPECULATIVE` - Pass limit reached with insufficient evidence

**Pass Number Logic:**
- Pass 1: Always continue if blocking gaps exist
- Pass 2+: Stop speculative by default
- Pass 3 exception: Continue if exactly 1 gap + 3+ tool calls remaining ("one more push")

### 3. Blocking Gaps Service (`services/blocking_gaps.py`)

Determines which checklist items MUST be PROVEN to upgrade from SPECULATIVE to VALID_SECURITY_ISSUE.

**Category-Specific Rules:**
- **Default**: All 6 standard fields required
- **CODE_INJECTION/COMMAND_INJECTION**: Rule 3b exception (security_control_bypassed can replace boundary_crossed)
- **SECRETS**: Only sink_present + not_only_misconfig required
- **XSS**: Standard 6 fields + security_control_bypassed (escaping proof)

## Usage

### Basic Routing

```python
from services.prompt_router import PromptRouter

router = PromptRouter()

# Route for SQL injection
modules = router.route(category="SQL_INJECTION")

# Assemble final prompt
final_prompt = router.assemble_from_paths(modules, task="Find SQL injection in /api/users")
```

### DeepAudit Stage Routing

```python
# Route for specific DeepAudit stage
modules = router.route(
    category="SQL_INJECTION",
    stage="trace_dataflow"
)
```

### Framework Context

```python
# Route with framework context (requires confidence > 0.8)
modules = router.route(
    category="SQL_INJECTION",
    framework="django",
    framework_confidence=0.9  # High confidence required
)
```

### Complete Pipeline Example

```python
from services.prompt_router import PromptRouter
from services.critic_loop import CriticLoop, CriticInput
from services.blocking_gaps import get_blocking_gaps_for_category
from models.schemas import Finding, ProofChecklist, Disposition

# Step 1: Route to appropriate modules
router = PromptRouter()
modules = router.route(
    category="SQL_INJECTION",
    stage="trace_dataflow",
    framework="django",
    framework_confidence=0.9
)

# Step 2: Assemble prompt
final_prompt = router.assemble_from_paths(modules, task="Find SQL injection")

# Step 3: After evidence gathering, evaluate with critic
critic = CriticLoop()
decision = critic.evaluate(
    CriticInput(
        finding=finding,
        evidence=evidence,
        checklist=checklist,
        preliminary_disposition=Disposition.SPECULATIVE,
        pass_number=1,
        remaining_tool_calls=10,
        hypothesis_span_id="span_123"
    )
)

# Step 4: Handle decision
if decision.decision == "CONTINUE":
    # Execute recommended tool calls
    for tool_call in decision.recommended_tool_calls:
        execute_tool(tool_call)
elif decision.decision == "READY_TO_REPORT":
    # All evidence gathered, proceed to report
    report_finding(finding)
elif decision.decision == "STOP_FILTERED":
    # Finding filtered out (e.g., misconfiguration)
    filter_finding(finding, decision.disposition_hint)
elif decision.decision == "STOP_SPECULATIVE":
    # Pass limit reached, mark as speculative
    mark_speculative(finding)
```

## Critic Loop Details

The critic loop identifies evidence gaps and recommends tool calls:

```python
from services.critic_loop import CriticLoop, CriticInput

critic = CriticLoop()

decision = critic.evaluate(
    CriticInput(
        finding=finding,
        evidence=evidence,
        checklist=checklist,
        preliminary_disposition=Disposition.SPECULATIVE,
        pass_number=1,
        remaining_tool_calls=10,
        hypothesis_span_id="span_123"
    )
)

if decision.decision == "CONTINUE":
    # Execute recommended tool calls
    for tool_call in decision.recommended_tool_calls:
        execute_tool(tool_call)
```

**Critic Decision Fields:**
- `decision` - READY_TO_REPORT | CONTINUE | STOP_FILTERED | STOP_SPECULATIVE
- `blocking_gaps` - List of checklist field names that are blocking (UNKNOWN but required)
- `recommended_tool_calls` - List of tool names to execute for each gap
- `reasoning` - Human-readable explanation of the decision
- `disposition_hint` - Suggested disposition for filtered findings (e.g., "MISCONFIGURATION")

## Blocking Gaps

Category-aware blocking gaps determine which checklist items must be PROVEN:

```python
from services.blocking_gaps import get_blocking_gaps_for_category

blocking = get_blocking_gaps_for_category("SQL_INJECTION", checklist)
# Returns: ["dataflow_evidenced", "boundary_crossed"] if those are UNKNOWN
```

**Checklist Fields:**
- `source_controlled_input` - Input comes from user/attacker
- `sink_present` - Dangerous operation identified
- `dataflow_evidenced` - Data flows from source to sink
- `reachable` - Code path is reachable
- `boundary_crossed` - External input reaches internal system
- `not_only_misconfig` - Not just a configuration issue
- `security_control_bypassed` - Security controls are bypassed (optional, used for XSS and Rule 3b)

**Tri-State Values:**
- `PROVEN` - Evidence confirms this is true
- `DISPROVEN` - Evidence confirms this is false
- `UNKNOWN` - Insufficient evidence

## Observability Integration

The agent orchestrator emits observability events for the critic loop:

```python
from services.agent_orchestrator import AgentOrchestrator

orchestrator = AgentOrchestrator()

# Evaluate with observability
decision = await orchestrator.evaluate_with_critic(
    agent_id=agent_id,
    finding=finding,
    evidence=evidence,
    checklist=checklist,
    preliminary_disposition=disposition,
    pass_number=pass_number,
    remaining_tool_calls=remaining_tool_calls,
    hypothesis_span_id=hypothesis_span_id
)
```

**Events Emitted:**
- `critic_started` - Critic evaluation begins (with span_id and parent_span_id)
- `critic_decision` - Decision made (CONTINUE/READY_TO_REPORT/STOP_FILTERED/STOP_SPECULATIVE)
- `critic_output` - Details (blocking gaps, recommended tool calls, disposition hint)
- `critic_completed` - Critic evaluation finished

## Testing

### Unit Tests

```bash
# Prompt router tests
pytest backend/tests/services/test_prompt_router.py -v

# Critic loop tests
pytest backend/tests/services/test_critic_loop.py -v

# Blocking gaps tests
pytest backend/tests/services/test_blocking_gaps.py -v

# Agent orchestrator events tests
pytest backend/tests/services/test_agent_orchestrator_events.py -v
```

### Integration Tests

```bash
# Full pipeline integration test
pytest backend/tests/integration/test_prompting_pipeline.py -v -m integration
```

### Benchmarks

```bash
# Performance benchmarks
pytest backend/tests/benchmarks/test_prompt_performance.py -v -m benchmark -s
```

**Performance Requirements:**
- Prompt assembly: p95 < 10ms
- Routing: p95 < 1ms

### Test Fixtures

**Golden Sessions:** `backend/tests/fixtures/golden_sessions/session_001_sql_injection/`
- `events.jsonl` - Event stream with critic events
- `artifacts.json` - Artifacts captured during session
- `expected_spans.json` - Expected span hierarchy
- `metadata.json` - Session configuration

**Seeded Corpus:** `backend/tests/corpus/sql_injection/`
- `vulnerable/string_concat.py` - Expected: VALID_SECURITY_ISSUE
- `safe/parameterized.py` - Expected: BY_DESIGN
- `speculative/missing_dataflow.py` - Expected: SPECULATIVE

## Adding New Modules

### New Vulnerability Category

1. **Create validity checklist:**
   ```bash
   # Create prompting/validity_checklists/xss.md
   ```

2. **Add mapping in PromptRouter:**
   ```python
   # services/prompt_router.py
   VALIDITY_CHECKLIST_MAP = {
       ...
       "XSS": "validity_checklists/xss.md",
   }
   ```

3. **Add category-specific blocking gaps (if needed):**
   ```python
   # services/blocking_gaps.py
   elif category == "XSS":
       required_fields = [
           "source_controlled_input",
           "sink_present",
           "dataflow_evidenced",
           "reachable",
           "boundary_crossed",
           "not_only_misconfig",
           "security_control_bypassed"  # XSS requires escaping proof
       ]
   ```

4. **Add test corpus:**
   ```bash
   mkdir -p backend/tests/corpus/xss/vulnerable
   mkdir -p backend/tests/corpus/xss/safe
   ```

### New Framework Context

1. **Create context module:**
   ```bash
   # Create prompting/contexts/rails.md
   ```

2. **Add mapping in PromptRouter:**
   ```python
   # services/prompt_router.py
   CONTEXT_MODULE_MAP = {
       ...
       "rails": "contexts/rails.md",
   }
   ```

3. **Test routing:**
   ```python
   modules = router.route(
       framework="rails",
       framework_confidence=0.9
   )
   assert modules.context_module == "contexts/rails.md"
   ```

### New DeepAudit Stage

1. **Create stage module:**
   ```bash
   # Create prompting/stages/verify_patch.md
   ```

2. **Add mapping in PromptRouter:**
   ```python
   # services/prompt_router.py
   STAGE_MODULE_MAP = {
       ...
       "verify_patch": "stages/verify_patch.md",
   }
   ```

3. **Test routing:**
   ```python
   modules = router.route(stage="verify_patch")
   assert modules.stage_module == "stages/verify_patch.md"
   ```

## Module Template Guidelines

### Validity Checklist Template

```markdown
# Validity Checklist: [Category Name]

## Overview
Brief description of vulnerability category.

## Proof Checklist Mapping

### 1. source_controlled_input
- **Goal:** Prove input comes from user/attacker
- **Tools:** search_code, read_file
- **Evidence Required:** [Specific patterns to look for]

### 2. sink_present
- **Goal:** Identify dangerous operation
- **Tools:** search_code, read_file
- **Evidence Required:** [Specific sink patterns]

[Continue for all 7 checklist items...]

## Common Pitfalls
- False positive scenario 1: [Description]
- False positive scenario 2: [Description]

## Tool Call Examples

```json
{
  "tool": "search_code",
  "arguments": {
    "pattern": "request\\.",
    "file_pattern": "*.py"
  },
  "reason": "Find user input sources"
}
```
```

### Framework Context Template

```markdown
# Framework Context: [Framework Name]

## Request Handling
[How framework handles HTTP requests]

## Database Patterns
[Common ORM/query patterns]

## Authentication Patterns
[How framework implements auth]

## Common Vulnerabilities
- Pattern 1: [Description + example]
- Pattern 2: [Description + example]
```

### Stage Module Template

```markdown
# Stage: [Stage Name]

## Goal
[What this stage should accomplish]

## Available Tools
- tool_name(args) - Description

## Output Required
[What the agent should produce]

## Approach
1. Step 1
2. Step 2
3. Step 3

## Checklist Focus
- field_name: What to prove in this stage
```

## Troubleshooting

### Prompt Not Loading

**Symptom:** `FileNotFoundError` when loading prompt modules

**Solution:** Verify file paths are relative to `prompting/` directory:
```python
# Correct
modules = router.route(category="SQL_INJECTION")
# modules.validity_checklist == "validity_checklists/sql_injection.md"

# Incorrect (absolute path)
modules.validity_checklist = "/Users/.../validity_checklists/sql_injection.md"
```

### Framework Context Not Loading

**Symptom:** `context_module` is None even though framework is specified

**Solution:** Check framework confidence threshold:
```python
# Below threshold - context_module will be None
modules = router.route(framework="django", framework_confidence=0.75)

# Above threshold - context_module will be loaded
modules = router.route(framework="django", framework_confidence=0.85)
```

### Critic Loop Not Continuing

**Symptom:** Critic returns `STOP_SPECULATIVE` on Pass 1

**Solution:** Check if finding is misconfiguration-only:
```python
# If not_only_misconfig.status == DISPROVEN, critic stops immediately
checklist.not_only_misconfig = ChecklistItem(
    value=False,
    status=ChecklistStatus.DISPROVEN,
    reason="Only a config issue"
)
```

### Blocking Gaps Mismatch

**Symptom:** Blocking gaps returned by critic don't match category requirements

**Solution:** Ensure category string matches exactly:
```python
# Correct
get_blocking_gaps_for_category("SQL_INJECTION", checklist)

# Incorrect (case mismatch)
get_blocking_gaps_for_category("sql_injection", checklist)
```

## Performance Optimization

### Prompt Caching

The `prompting_loader` uses `@lru_cache(maxsize=256)` to cache loaded prompts:

```python
from prompting_loader import load_prompt

# First call: loads from disk
prompt1 = load_prompt("base/base_prompt.md")  # ~1ms

# Second call: cached
prompt2 = load_prompt("base/base_prompt.md")  # ~0.01ms
```

**Cache Size:** 256 entries (sufficient for 7 categories × 4 stages × 4 frameworks = 112 combinations)

### Routing Performance

Routing uses dictionary lookups (O(1)):

```python
# Fast routing (< 1ms)
modules = router.route(
    category="SQL_INJECTION",
    stage="trace_dataflow",
    framework="django",
    framework_confidence=0.9
)
```

### Assembly Performance

Template concatenation is optimized:

```python
# Strips trailing newlines and joins with "\n\n"
parts = [base_prompt.rstrip("\n")]
if validity_checklist:
    parts.append(validity_checklist.rstrip("\n"))
# ...
return "\n\n".join(parts) + "\n"
```

**Benchmark:** p95 < 10ms for full assembly with all modules

## References

- **Design Document:** `docs/plans/2026-01-13-prompting-system-design.md`
- **Implementation Plan:** `docs/plans/2026-01-13-prompting-system-implementation.md`
- **StrictClassifier Rules:** `backend/services/strict_classifier.py`
- **Tool Implementation:** `backend/agents/tools.py`
- **Observability Service:** `backend/services/observability_service.py`

## Agent Integration

### DeepAudit

DeepAudit automatically loads category-specific validity checklists:

```python
# In case_builder.py
prompt = self._assemble_prompt_for_category(
    category="SQL_INJECTION",
    stage="trace_dataflow",
    task="Trace user input to database query"
)
```

The supervisor passes category information to subagents, which use PromptRouter to assemble the appropriate prompt.

### ReAct Agent

ReAct agent detects category from focus_areas and loads the matching validity checklist:

```python
# Automatically happens in __init__
category = self._detect_category_from_focus_areas()
system_prompt = self._build_system_prompt_with_checklist(category)
```

### UI Display

Findings with `proof_checklist` show a detailed breakdown in the expanded view:

- ✓ Green checkmark = PROVEN
- ✗ Red X = DISPROVEN
- ? Gray question = UNKNOWN

Each checklist item shows:
- Label (e.g., "Source Controlled Input")
- Description (e.g., "User/attacker controls the input")
- Reason from classifier (e.g., "Found request.args.get('id')")

## Next Steps

- **Verification:** Run all tests to ensure system works end-to-end
- **Integration:** Connect critic loop to DeepAudit Supervisor
- **Monitoring:** Set up observability dashboards for critic decisions
- **Expansion:** Add more validity checklists for additional vulnerability categories
- **Tuning:** Adjust framework confidence threshold based on false positive rates

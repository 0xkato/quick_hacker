# Audit Completion Enforcement Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Prevent premature audit completion by enforcing coverage thresholds and investigation queue requirements before allowing the agent to terminate.

**Architecture:** Replace string-based completion detection with a `complete_audit` tool that validates coverage thresholds, integrates the existing CoverageTracker, and requires the investigation queue to be drained before accepting completion.

**Tech Stack:** Python, existing CoverageTracker service, depth_enforcement module

---

## Root Cause Summary

The current `DeepAuditAgent` completes prematurely because:

1. **String-based completion detection** (lines 441-444): If LLM outputs "FINAL OUTCOME" or "Case A/B/C", the audit immediately terminates with no validation
2. **No coverage enforcement**: Prompts require coverage thresholds but nothing validates them
3. **Tool results not queued**: Results from `get_entry_points`, `trace_data_flow` etc. are stored but not required to be investigated
4. **CoverageTracker not integrated**: The coverage tracking we built isn't connected to the agent

---

## Phase 1: Block Premature Completion (Critical)

### Task 1: Add `complete_audit` tool schema to tools.py

**Files:**
- Modify: `backend/agents/tools.py:269` (after existing tools)

**Step 1: Write the test**

```python
# tests/agents/test_complete_audit_tool.py
import pytest
from agents.tools import AGENT_TOOLS, COMPLETE_AUDIT_SCHEMA

def test_complete_audit_schema_exists():
    """complete_audit tool should be in AGENT_TOOLS."""
    tool_names = [t["name"] for t in AGENT_TOOLS]
    assert "complete_audit" in tool_names

def test_complete_audit_schema_structure():
    """complete_audit schema should have required parameters."""
    schema = COMPLETE_AUDIT_SCHEMA
    assert schema["name"] == "complete_audit"
    params = schema["parameters"]["properties"]
    assert "outcome" in params
    assert "summary" in params
    assert "coverage_acknowledgment" in params
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -m pytest tests/agents/test_complete_audit_tool.py -v`
Expected: FAIL - COMPLETE_AUDIT_SCHEMA not found

**Step 3: Implement the schema**

Add to `backend/agents/tools.py` after line 316 (after TRACE_PATH_VERDICT_SCHEMA):

```python
# Tool schema for completing the audit (gated by coverage validation)
COMPLETE_AUDIT_SCHEMA = {
    "name": "complete_audit",
    "description": "Request to complete the security audit. This will be REJECTED if coverage thresholds are not met or investigation queue is not empty. Only call when you have thoroughly investigated all discovered paths.",
    "parameters": {
        "type": "object",
        "properties": {
            "outcome": {
                "type": "string",
                "enum": ["validated_findings", "no_findings", "insufficient_coverage"],
                "description": "Final outcome: 'validated_findings' if vulns found, 'no_findings' if clean, 'insufficient_coverage' if cannot meet thresholds"
            },
            "summary": {
                "type": "string",
                "description": "Brief summary of what was investigated and concluded"
            },
            "coverage_acknowledgment": {
                "type": "boolean",
                "description": "Set to true to acknowledge you have traced all discovered paths or deferred them with reason"
            },
            "findings_count": {
                "type": "integer",
                "description": "Number of validated findings reported"
            }
        },
        "required": ["outcome", "summary", "coverage_acknowledgment"]
    }
}
```

Also add to AGENT_TOOLS list:

```python
# After the existing tools in AGENT_TOOLS list, add:
AGENT_TOOLS.append({
    "name": "complete_audit",
    "description": "Request to complete the security audit. This will be REJECTED if coverage thresholds are not met or investigation queue is not empty.",
    "parameters": COMPLETE_AUDIT_SCHEMA["parameters"]
})
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -m pytest tests/agents/test_complete_audit_tool.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add backend/agents/tools.py tests/agents/test_complete_audit_tool.py
git commit -m "feat: add complete_audit tool schema for gated completion"
```

---

### Task 2: Add `trace_path_verdict` to AGENT_TOOLS

**Files:**
- Modify: `backend/agents/tools.py:269`

**Step 1: Write the test**

```python
# tests/agents/test_trace_path_verdict_tool.py
import pytest
from agents.tools import AGENT_TOOLS

def test_trace_path_verdict_in_agent_tools():
    """trace_path_verdict should be in AGENT_TOOLS list."""
    tool_names = [t["name"] for t in AGENT_TOOLS]
    assert "trace_path_verdict" in tool_names
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -m pytest tests/agents/test_trace_path_verdict_tool.py -v`
Expected: FAIL - trace_path_verdict not in AGENT_TOOLS

**Step 3: Add to AGENT_TOOLS**

Add after the TRACE_PATH_VERDICT_SCHEMA definition in `tools.py`:

```python
# Add trace_path_verdict to AGENT_TOOLS
AGENT_TOOLS.append({
    "name": TRACE_PATH_VERDICT_SCHEMA["name"],
    "description": TRACE_PATH_VERDICT_SCHEMA["description"],
    "parameters": TRACE_PATH_VERDICT_SCHEMA["parameters"]
})
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -m pytest tests/agents/test_trace_path_verdict_tool.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add backend/agents/tools.py tests/agents/test_trace_path_verdict_tool.py
git commit -m "feat: add trace_path_verdict to AGENT_TOOLS for coverage tracking"
```

---

### Task 3: Create completion validation function in depth_enforcement.py

**Files:**
- Modify: `backend/agents/depth_enforcement.py`

**Step 1: Write the test**

```python
# tests/agents/test_completion_validation.py
import pytest
from services.coverage_tracker import CoverageTracker, PathStatus
from agents.depth_enforcement import (
    DepthEnforcementConfig,
    validate_completion_request,
    CompletionValidationResult
)

def test_completion_rejected_when_no_files_examined():
    """Completion should be rejected if no files were examined."""
    tracker = CoverageTracker("test-agent")
    config = DepthEnforcementConfig()

    result = validate_completion_request(
        coverage_tracker=tracker,
        config=config,
        files_examined=set(),  # Empty
        iteration_count=5,
        pending_investigations=0
    )

    assert not result.can_complete
    assert "files" in result.rejection_reason.lower()

def test_completion_rejected_when_insufficient_iterations():
    """Completion should be rejected if not enough iterations."""
    tracker = CoverageTracker("test-agent")
    config = DepthEnforcementConfig(min_iterations=10)

    result = validate_completion_request(
        coverage_tracker=tracker,
        config=config,
        files_examined={"a.py", "b.py", "c.py", "d.py", "e.py"},
        iteration_count=3,  # Less than 10
        pending_investigations=0
    )

    assert not result.can_complete
    assert "iteration" in result.rejection_reason.lower()

def test_completion_rejected_when_pending_investigations():
    """Completion should be rejected if investigation queue not empty."""
    tracker = CoverageTracker("test-agent")
    config = DepthEnforcementConfig()

    result = validate_completion_request(
        coverage_tracker=tracker,
        config=config,
        files_examined={"a.py", "b.py", "c.py", "d.py", "e.py"},
        iteration_count=15,
        pending_investigations=5  # Still pending
    )

    assert not result.can_complete
    assert "pending" in result.rejection_reason.lower() or "queue" in result.rejection_reason.lower()

def test_completion_rejected_when_low_coverage():
    """Completion should be rejected if coverage below threshold."""
    tracker = CoverageTracker("test-agent")
    # Register paths but don't trace them
    tracker.register_path("a.py", 10, "handler", "b.py", 20, "sql", "execute")
    tracker.register_path("a.py", 30, "handler2", "c.py", 40, "cmd", "system")

    config = DepthEnforcementConfig(min_coverage_percent=80.0)

    result = validate_completion_request(
        coverage_tracker=tracker,
        config=config,
        files_examined={"a.py", "b.py", "c.py", "d.py", "e.py"},
        iteration_count=15,
        pending_investigations=0
    )

    assert not result.can_complete
    assert "coverage" in result.rejection_reason.lower()

def test_completion_allowed_when_all_requirements_met():
    """Completion should be allowed when all requirements are met."""
    tracker = CoverageTracker("test-agent")
    # Register and trace paths
    path_id = tracker.register_path("a.py", 10, "handler", "b.py", 20, "sql", "execute")
    tracker.update_status(path_id, PathStatus.TRACED_SAFE, "No injection possible")

    config = DepthEnforcementConfig(min_coverage_percent=80.0)

    result = validate_completion_request(
        coverage_tracker=tracker,
        config=config,
        files_examined={"a.py", "b.py", "c.py", "d.py", "e.py"},
        iteration_count=15,
        pending_investigations=0
    )

    assert result.can_complete
    assert result.rejection_reason is None
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -m pytest tests/agents/test_completion_validation.py -v`
Expected: FAIL - validate_completion_request not found

**Step 3: Implement the validation function**

Add to `backend/agents/depth_enforcement.py`:

```python
@dataclass
class CompletionValidationResult:
    """Result of completion validation."""
    can_complete: bool
    rejection_reason: Optional[str] = None
    coverage_stats: Optional[dict] = None
    guidance: Optional[str] = None


@dataclass
class DepthEnforcementConfig:
    """Configuration for depth enforcement."""
    min_coverage_percent: float = 80.0
    max_inconclusive: int = 3
    require_explicit_skip_reason: bool = True
    min_files_examined: int = 5
    min_iterations: int = 10


def validate_completion_request(
    coverage_tracker: CoverageTracker,
    config: DepthEnforcementConfig,
    files_examined: set[str],
    iteration_count: int,
    pending_investigations: int
) -> CompletionValidationResult:
    """Validate if audit completion can be accepted.

    Checks:
    1. Minimum files examined
    2. Minimum iterations
    3. Investigation queue empty
    4. Coverage threshold met

    Returns CompletionValidationResult with can_complete and reason if rejected.
    """
    # Check 1: Minimum files examined
    if len(files_examined) < config.min_files_examined:
        return CompletionValidationResult(
            can_complete=False,
            rejection_reason=f"Must examine at least {config.min_files_examined} files. Currently: {len(files_examined)}",
            guidance="Use read_file and search_code to examine more of the codebase before completing."
        )

    # Check 2: Minimum iterations
    if iteration_count < config.min_iterations:
        return CompletionValidationResult(
            can_complete=False,
            rejection_reason=f"Must run at least {config.min_iterations} iterations. Currently: {iteration_count}",
            guidance="Continue investigating. The audit needs more depth before completion."
        )

    # Check 3: Investigation queue empty
    if pending_investigations > 0:
        return CompletionValidationResult(
            can_complete=False,
            rejection_reason=f"{pending_investigations} items in investigation queue must be processed or explicitly deferred",
            guidance="Process pending investigation items or defer them with explicit reasoning."
        )

    # Check 4: Coverage threshold
    stats = coverage_tracker.get_coverage_stats()

    # Special case: if no paths registered, that's suspicious
    if stats.total_paths == 0:
        return CompletionValidationResult(
            can_complete=False,
            rejection_reason="No entry point to sink paths have been registered. Cannot verify coverage.",
            guidance="Use get_entry_points to discover entry points, then trace_data_flow to find paths to dangerous sinks, then trace_path_verdict to record verdicts."
        )

    if stats.coverage_percent < config.min_coverage_percent:
        unexplored = coverage_tracker.get_unexplored_paths()
        paths_summary = ", ".join([
            f"{r.entry_point_file}:{r.entry_point_line}"
            for r in unexplored[:5]
        ])
        if len(unexplored) > 5:
            paths_summary += f" ... and {len(unexplored) - 5} more"

        return CompletionValidationResult(
            can_complete=False,
            rejection_reason=f"Coverage is {stats.coverage_percent:.1f}%, minimum required is {config.min_coverage_percent}%",
            coverage_stats={
                "total_paths": stats.total_paths,
                "traced_count": stats.traced_count,
                "coverage_percent": stats.coverage_percent
            },
            guidance=f"Trace remaining paths and call trace_path_verdict for each. Unexplored: {paths_summary}"
        )

    # Check 5: Too many inconclusive
    if stats.inconclusive_count > config.max_inconclusive:
        return CompletionValidationResult(
            can_complete=False,
            rejection_reason=f"{stats.inconclusive_count} paths marked inconclusive, maximum allowed is {config.max_inconclusive}",
            guidance="Review inconclusive paths and either gather more context or make a determination."
        )

    # All checks passed
    return CompletionValidationResult(
        can_complete=True,
        coverage_stats={
            "total_paths": stats.total_paths,
            "traced_count": stats.traced_count,
            "coverage_percent": stats.coverage_percent,
            "vuln_count": stats.traced_vuln_count
        }
    )
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -m pytest tests/agents/test_completion_validation.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add backend/agents/depth_enforcement.py tests/agents/test_completion_validation.py
git commit -m "feat: add validate_completion_request with multi-check validation"
```

---

## Phase 2: Integrate CoverageTracker into DeepAuditAgent

### Task 4: Initialize CoverageTracker in DeepAuditAgent

**Files:**
- Modify: `backend/agents/deep_audit_agent.py`

**Step 1: Write the test**

```python
# tests/agents/test_deep_audit_coverage_integration.py
import pytest
from unittest.mock import Mock, AsyncMock
from agents.deep_audit_agent import DeepAuditAgent
from models.schemas import AgentCreateRequest
from services.coverage_tracker import CoverageTracker

def test_agent_has_coverage_tracker():
    """DeepAuditAgent should initialize a CoverageTracker."""
    request = AgentCreateRequest(
        repo_id="test-repo",
        name="test-audit"
    )
    agent = DeepAuditAgent(request, "/tmp/test-repo")

    assert hasattr(agent, 'coverage_tracker')
    assert isinstance(agent.coverage_tracker, CoverageTracker)
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -m pytest tests/agents/test_deep_audit_coverage_integration.py::test_agent_has_coverage_tracker -v`
Expected: FAIL - no coverage_tracker attribute

**Step 3: Add CoverageTracker initialization**

In `backend/agents/deep_audit_agent.py`:

Add import at top:
```python
from services.coverage_tracker import CoverageTracker, PathStatus
from agents.depth_enforcement import (
    DepthEnforcementConfig,
    validate_completion_request,
)
```

Add in `__init__` method (after line 159, after `self.tool_executor = ToolExecutor(self.repo_path)`):
```python
# Coverage tracking
self.coverage_tracker = CoverageTracker(self.id)
self.depth_config = DepthEnforcementConfig()
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -m pytest tests/agents/test_deep_audit_coverage_integration.py::test_agent_has_coverage_tracker -v`
Expected: PASS

**Step 5: Commit**

```bash
git add backend/agents/deep_audit_agent.py tests/agents/test_deep_audit_coverage_integration.py
git commit -m "feat: initialize CoverageTracker in DeepAuditAgent"
```

---

### Task 5: Handle trace_path_verdict tool calls in DeepAuditAgent

**Files:**
- Modify: `backend/agents/deep_audit_agent.py` (`_process_tool_calls` method)

**Step 1: Write the test**

```python
# Add to tests/agents/test_deep_audit_coverage_integration.py

@pytest.mark.asyncio
async def test_agent_handles_trace_path_verdict():
    """DeepAuditAgent should update coverage when trace_path_verdict is called."""
    request = AgentCreateRequest(repo_id="test-repo", name="test-audit")
    agent = DeepAuditAgent(request, "/tmp/test-repo")
    agent.state = AuditState(run_id="test-run")
    agent.state.budgets = {"tc_rem": 100}

    # Simulate trace_path_verdict tool call
    tool_calls = [{
        "name": "trace_path_verdict",
        "arguments": json.dumps({
            "entry_point_file": "routes/api.py",
            "entry_point_line": 25,
            "sink_file": "db/queries.py",
            "sink_line": 100,
            "verdict": "safe",
            "reasoning": "Input is properly parameterized",
            "files_examined": ["routes/api.py", "db/queries.py"]
        })
    }]

    await agent._process_tool_calls(tool_calls)

    # Check coverage was updated
    stats = agent.coverage_tracker.get_coverage_stats()
    assert stats.total_paths == 1
    assert stats.traced_safe_count == 1
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -m pytest tests/agents/test_deep_audit_coverage_integration.py::test_agent_handles_trace_path_verdict -v`
Expected: FAIL - trace_path_verdict not handled

**Step 3: Add trace_path_verdict handling**

In `_process_tool_calls` method, add handling for trace_path_verdict before the tool execution (around line 828):

```python
# Handle trace_path_verdict specially (coverage tracking)
if tool_name == "trace_path_verdict":
    from agents.tools import handle_trace_path_verdict

    def broadcast_coverage(event_type: str, data: dict):
        self._broadcast(WSMessageType.PROGRESS, {"type": event_type, **data})

    result_msg = handle_trace_path_verdict(
        arguments,
        self.coverage_tracker,
        broadcast_coverage
    )

    # Log the verdict
    self._log_audit_event("path_verdict", {
        "entry": f"{arguments['entry_point_file']}:{arguments['entry_point_line']}",
        "sink": f"{arguments['sink_file']}:{arguments['sink_line']}",
        "verdict": arguments["verdict"],
        "reasoning": arguments["reasoning"]
    })

    # Update budgets
    self.state.budgets["tc_rem"] = max(0, int(self.state.budgets.get("tc_rem", 0)) - 1)
    continue  # Skip normal tool execution
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -m pytest tests/agents/test_deep_audit_coverage_integration.py::test_agent_handles_trace_path_verdict -v`
Expected: PASS

**Step 5: Commit**

```bash
git add backend/agents/deep_audit_agent.py tests/agents/test_deep_audit_coverage_integration.py
git commit -m "feat: handle trace_path_verdict in DeepAuditAgent for coverage tracking"
```

---

### Task 6: Handle complete_audit tool calls with validation

**Files:**
- Modify: `backend/agents/deep_audit_agent.py`

**Step 1: Write the test**

```python
# Add to tests/agents/test_deep_audit_coverage_integration.py

@pytest.mark.asyncio
async def test_complete_audit_rejected_when_no_coverage():
    """complete_audit should be rejected when coverage requirements not met."""
    request = AgentCreateRequest(repo_id="test-repo", name="test-audit")
    agent = DeepAuditAgent(request, "/tmp/test-repo")
    agent.state = AuditState(run_id="test-run")
    agent.state.budgets = {"tc_rem": 100}
    agent.state.iteration = 5  # Too few iterations

    # Simulate complete_audit tool call
    tool_calls = [{
        "name": "complete_audit",
        "arguments": json.dumps({
            "outcome": "no_findings",
            "summary": "No vulnerabilities found",
            "coverage_acknowledgment": True
        })
    }]

    await agent._process_tool_calls(tool_calls)

    # Agent should NOT have completion flag set
    assert not getattr(agent, '_completion_approved', False)

@pytest.mark.asyncio
async def test_complete_audit_accepted_when_requirements_met():
    """complete_audit should be accepted when all requirements are met."""
    request = AgentCreateRequest(repo_id="test-repo", name="test-audit")
    agent = DeepAuditAgent(request, "/tmp/test-repo")
    agent.state = AuditState(run_id="test-run")
    agent.state.budgets = {"tc_rem": 100}
    agent.state.iteration = 15  # Enough iterations

    # Add some coverage
    path_id = agent.coverage_tracker.register_path(
        "a.py", 10, "handler", "b.py", 20, "sql", "execute"
    )
    agent.coverage_tracker.update_status(path_id, PathStatus.TRACED_SAFE)

    # Add examined files
    agent.files_examined = {"a.py", "b.py", "c.py", "d.py", "e.py"}

    # Simulate complete_audit tool call
    tool_calls = [{
        "name": "complete_audit",
        "arguments": json.dumps({
            "outcome": "no_findings",
            "summary": "Thoroughly reviewed, no vulnerabilities",
            "coverage_acknowledgment": True
        })
    }]

    await agent._process_tool_calls(tool_calls)

    # Agent should have completion flag set
    assert getattr(agent, '_completion_approved', False)
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -m pytest tests/agents/test_deep_audit_coverage_integration.py::test_complete_audit_rejected_when_no_coverage -v`
Expected: FAIL - complete_audit not handled

**Step 3: Add complete_audit handling**

Add `_completion_approved` flag in `__init__`:
```python
self._completion_approved = False
```

In `_process_tool_calls` method, add handling for complete_audit:

```python
# Handle complete_audit with validation
if tool_name == "complete_audit":
    # Count pending investigations (paths discovered but not traced)
    unexplored = self.coverage_tracker.get_unexplored_paths()
    pending_count = len(unexplored)

    # Validate completion request
    validation_result = validate_completion_request(
        coverage_tracker=self.coverage_tracker,
        config=self.depth_config,
        files_examined=self.files_examined,
        iteration_count=self.state.iteration,
        pending_investigations=pending_count
    )

    if validation_result.can_complete:
        self._completion_approved = True
        self._log_audit_event("completion_approved", {
            "outcome": arguments.get("outcome"),
            "summary": arguments.get("summary"),
            "coverage_stats": validation_result.coverage_stats
        })
        self._log(f"Audit completion approved: {arguments.get('summary')}")
    else:
        # Rejection - tell LLM what's missing
        self._log_audit_event("completion_rejected", {
            "reason": validation_result.rejection_reason,
            "guidance": validation_result.guidance,
            "coverage_stats": validation_result.coverage_stats
        })
        self._log(f"Completion rejected: {validation_result.rejection_reason}", "warning")

        # Add rejection to evidence so LLM sees it
        rejection_event = {
            "id": f"REJECT-{self.state.seq}",
            "k": "rejection",
            "reason": validation_result.rejection_reason,
            "guidance": validation_result.guidance,
        }
        self._store_evidence(self.state.seq, rejection_event)

    self.state.budgets["tc_rem"] = max(0, int(self.state.budgets.get("tc_rem", 0)) - 1)
    continue  # Skip normal tool execution
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -m pytest tests/agents/test_deep_audit_coverage_integration.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add backend/agents/deep_audit_agent.py tests/agents/test_deep_audit_coverage_integration.py
git commit -m "feat: handle complete_audit with coverage validation"
```

---

### Task 7: Replace string-based completion with tool-based completion

**Files:**
- Modify: `backend/agents/deep_audit_agent.py` (`_audit_loop` method)

**Step 1: Write the test**

```python
# Add to tests/agents/test_deep_audit_coverage_integration.py

def test_string_completion_detection_removed():
    """The old string-based completion detection should be removed."""
    import inspect
    from agents.deep_audit_agent import DeepAuditAgent

    # Get the source code of _audit_loop
    source = inspect.getsource(DeepAuditAgent._audit_loop)

    # These patterns should NOT be in the code anymore
    assert '"FINAL OUTCOME"' not in source or 'in content' not in source
    assert '"Case A:"' not in source or 'in content' not in source
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -m pytest tests/agents/test_deep_audit_coverage_integration.py::test_string_completion_detection_removed -v`
Expected: FAIL - string detection still present

**Step 3: Remove string detection and add tool-based completion check**

In `_audit_loop` method, replace lines 437-447:

```python
# OLD CODE (REMOVE):
# if response.get("tool_calls"):
#     await self._process_tool_calls(response["tool_calls"])
# else:
#     content = response.get("content", "")
#     # Check for completion signals
#     if "FINAL OUTCOME" in content or "Case A:" in content or "Case B:" in content or "Case C:" in content:
#         self._log("Audit complete - final outcome reached")
#         self._log_audit_event("note", {"message": "Final outcome reached"})
#         break
#     # Parse AUDIT_JSONL from response
#     self._parse_audit_jsonl(content)

# NEW CODE:
if response.get("tool_calls"):
    await self._process_tool_calls(response["tool_calls"])

    # Check if completion was approved via complete_audit tool
    if self._completion_approved:
        self._log("Audit complete - completion approved via validation")
        self._log_audit_event("note", {"message": "Completion approved after validation"})
        break
else:
    content = response.get("content", "")
    # Parse AUDIT_JSONL from response (for logging/state updates)
    self._parse_audit_jsonl(content)

    # NOTE: String-based completion removed. LLM must use complete_audit tool.
    # If LLM tries to declare completion in text, it will be ignored.
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -m pytest tests/agents/test_deep_audit_coverage_integration.py::test_string_completion_detection_removed -v`
Expected: PASS

**Step 5: Commit**

```bash
git add backend/agents/deep_audit_agent.py tests/agents/test_deep_audit_coverage_integration.py
git commit -m "feat: replace string-based completion with tool-based validation"
```

---

## Phase 3: Update Prompts

### Task 8: Update hard_rules.py to document new completion mechanism

**Files:**
- Modify: `backend/prompts/hard_rules.py`

**Step 1: Write the test**

```python
# tests/prompts/test_completion_prompt.py
from prompts.hard_rules import get_hard_rules_prompt

def test_prompt_mentions_complete_audit_tool():
    """Prompt should document the complete_audit tool requirement."""
    prompt = get_hard_rules_prompt()
    assert "complete_audit" in prompt.lower()

def test_prompt_removes_old_final_outcome_format():
    """Prompt should not have the old FINAL OUTCOME text format."""
    prompt = get_hard_rules_prompt()
    # Should not instruct to output "FINAL OUTCOME" as text
    assert "your final user-facing report must be exactly one of:" not in prompt.lower()
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -m pytest tests/prompts/test_completion_prompt.py -v`
Expected: FAIL - complete_audit not in prompt

**Step 3: Update the prompt**

In `backend/prompts/hard_rules.py`, replace section E (FINAL OUTCOME RULE):

```python
# REPLACE section E with:
---------------------------
E) COMPLETION PROTOCOL (Tool-Based, Validated)
---------------------------

To complete the audit, you MUST call the complete_audit tool. Text-based completion signals are ignored.

The complete_audit tool will VALIDATE:
1. Minimum files examined (at least 5 files read)
2. Minimum iterations (at least 10 audit turns)
3. Investigation queue empty (all discovered paths processed or deferred)
4. Coverage threshold met (at least 80% of registered paths traced)

If validation fails, the tool returns rejection with specific guidance on what's missing.

WORKFLOW:
1. Discover entry points → get_entry_points tool
2. For each entry point, find dangerous sinks → trace_data_flow tool
3. For each potential path, investigate and call → trace_path_verdict tool
4. When all paths have verdicts → call complete_audit tool

The complete_audit tool accepts three outcomes:
- "validated_findings": Exploitable vulnerabilities were found and reported
- "no_findings": No exploitable vulnerabilities found (requires thorough coverage)
- "insufficient_coverage": Cannot achieve coverage threshold, escalate to human

DO NOT attempt to complete by outputting text like "FINAL OUTCOME" or "Case A/B/C".
These text patterns are ignored. You MUST use the complete_audit tool.
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -m pytest tests/prompts/test_completion_prompt.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add backend/prompts/hard_rules.py tests/prompts/test_completion_prompt.py
git commit -m "docs: update hard_rules prompt to document tool-based completion"
```

---

### Task 9: Update workflow_engine.py to document trace_path_verdict

**Files:**
- Modify: `backend/prompts/workflow_engine.py`

**Step 1: Write the test**

```python
# tests/prompts/test_workflow_prompt.py
from prompts.workflow_engine import get_developer_prompt

def test_prompt_documents_trace_path_verdict():
    """Prompt should document the trace_path_verdict tool."""
    prompt = get_developer_prompt()
    assert "trace_path_verdict" in prompt.lower()

def test_prompt_documents_coverage_workflow():
    """Prompt should explain the coverage tracking workflow."""
    prompt = get_developer_prompt()
    assert "coverage" in prompt.lower()
    # Should mention the workflow of discovering → tracing → verdicting
    assert "entry point" in prompt.lower() or "entry_point" in prompt.lower()
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -m pytest tests/prompts/test_workflow_prompt.py -v`
Expected: FAIL - trace_path_verdict not documented

**Step 3: Update the prompt**

In `backend/prompts/workflow_engine.py`, add to section 2 (TOOLING MODEL):

```python
# Add after the existing REPORTING TOOLS section:

COVERAGE TRACKING TOOLS:
- trace_path_verdict(entry_point_file, entry_point_line, sink_file, sink_line, verdict, reasoning, files_examined)
  Call this AFTER investigating each entry point → sink path. Records your verdict for coverage tracking.
  Verdicts: "safe" (no vuln), "vulnerable" (finding reported), "blocked" (defenses prevent), "inconclusive" (need more context)

- complete_audit(outcome, summary, coverage_acknowledgment)
  Call this when you believe the audit is complete. Will be REJECTED if coverage requirements not met.
  You MUST have called trace_path_verdict for all discovered paths before this will succeed.

COVERAGE WORKFLOW:
1. Use get_entry_points to discover API routes, form handlers, CLI inputs
2. For each entry point, use trace_data_flow to find paths to dangerous sinks
3. Investigate each path: read files, check validators, trace data transformations
4. Call trace_path_verdict with your conclusion for each path
5. When all paths have verdicts, call complete_audit

The audit CANNOT complete until:
- You have examined at least 5 files
- You have run at least 10 iterations
- All discovered paths have verdicts (via trace_path_verdict)
- Coverage is at least 80%
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -m pytest tests/prompts/test_workflow_prompt.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add backend/prompts/workflow_engine.py tests/prompts/test_workflow_prompt.py
git commit -m "docs: update workflow prompt to document coverage tracking tools"
```

---

## Phase 4: Integration Testing

### Task 10: Create integration test for full audit flow

**Files:**
- Create: `backend/tests/agents/test_audit_completion_flow.py`

**Step 1: Write the integration test**

```python
# tests/agents/test_audit_completion_flow.py
"""Integration tests for audit completion enforcement."""
import pytest
import json
from unittest.mock import Mock, AsyncMock, patch
from agents.deep_audit_agent import DeepAuditAgent, AuditState
from models.schemas import AgentCreateRequest
from services.coverage_tracker import PathStatus

@pytest.mark.asyncio
async def test_audit_cannot_complete_without_coverage():
    """Full flow: audit should not complete if coverage requirements not met."""
    request = AgentCreateRequest(repo_id="test-repo", name="test-audit")
    agent = DeepAuditAgent(request, "/tmp/test-repo")

    # Mock provider to return complete_audit tool call immediately
    mock_response = {
        "tool_calls": [{
            "name": "complete_audit",
            "arguments": json.dumps({
                "outcome": "no_findings",
                "summary": "Quick scan complete",
                "coverage_acknowledgment": True
            })
        }]
    }

    with patch.object(agent.provider, 'chat_with_tools', new_callable=AsyncMock) as mock_chat:
        mock_chat.return_value = mock_response

        # Run a few iterations
        agent.state = AuditState(run_id="test")
        agent.state.budgets = {"tc_rem": 100, "lr_max": 180, "sr_max": 40, "ev_max": 3, "tok_max": 3500}
        agent._completion_approved = False

        # Simulate one iteration
        for _ in range(3):
            agent.state.iteration += 1
            response = await agent.provider.chat_with_tools([], [])
            if response.get("tool_calls"):
                await agent._process_tool_calls(response["tool_calls"])

        # Completion should NOT be approved (no coverage)
        assert not agent._completion_approved

@pytest.mark.asyncio
async def test_audit_completes_after_coverage_met():
    """Full flow: audit should complete after coverage requirements met."""
    request = AgentCreateRequest(repo_id="test-repo", name="test-audit")
    agent = DeepAuditAgent(request, "/tmp/test-repo")
    agent.state = AuditState(run_id="test")
    agent.state.budgets = {"tc_rem": 100, "lr_max": 180, "sr_max": 40, "ev_max": 3, "tok_max": 3500}
    agent.state.iteration = 15  # Enough iterations

    # Add coverage
    path_id = agent.coverage_tracker.register_path(
        "routes/api.py", 10, "get_user",
        "db/queries.py", 50, "sql", "execute"
    )
    agent.coverage_tracker.update_status(path_id, PathStatus.TRACED_SAFE, "Parameterized query used")

    # Add examined files
    agent.files_examined = {"routes/api.py", "db/queries.py", "models/user.py", "utils/auth.py", "config.py"}

    # Simulate complete_audit tool call
    tool_calls = [{
        "name": "complete_audit",
        "arguments": json.dumps({
            "outcome": "no_findings",
            "summary": "Thoroughly reviewed all SQL paths, parameterized queries used throughout",
            "coverage_acknowledgment": True
        })
    }]

    await agent._process_tool_calls(tool_calls)

    # Completion should be approved
    assert agent._completion_approved
```

**Step 2: Run test to verify it passes**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -m pytest tests/agents/test_audit_completion_flow.py -v`
Expected: PASS

**Step 3: Commit**

```bash
git add tests/agents/test_audit_completion_flow.py
git commit -m "test: add integration tests for audit completion enforcement"
```

---

### Task 11: Run full test suite and verify no regressions

**Step 1: Run all tests**

```bash
cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -m pytest -v
```

Expected: All tests pass

**Step 2: If any failures, fix them**

Address any test failures before completing.

**Step 3: Final commit**

```bash
git add -A
git commit -m "feat: complete audit completion enforcement implementation"
```

---

## Summary of Changes

| File | Change |
|------|--------|
| `agents/tools.py` | Add `complete_audit` schema, add `trace_path_verdict` to AGENT_TOOLS |
| `agents/depth_enforcement.py` | Add `validate_completion_request()` function |
| `agents/deep_audit_agent.py` | Initialize CoverageTracker, handle trace_path_verdict, handle complete_audit with validation, remove string-based completion |
| `prompts/hard_rules.py` | Document tool-based completion protocol |
| `prompts/workflow_engine.py` | Document coverage tracking tools and workflow |

## Expected Behavior After Implementation

1. **Agent CANNOT complete** by outputting "FINAL OUTCOME" or "Case A/B/C" - these are ignored
2. **Agent MUST call `complete_audit` tool** to request completion
3. **`complete_audit` validates**:
   - At least 5 files examined
   - At least 10 iterations run
   - All discovered paths have verdicts (via `trace_path_verdict`)
   - Coverage >= 80%
4. **If validation fails**: Agent receives rejection with specific guidance on what's missing
5. **If validation passes**: Audit completes normally

This ensures the audit cannot terminate prematurely - it must actually do the work before being allowed to finish.

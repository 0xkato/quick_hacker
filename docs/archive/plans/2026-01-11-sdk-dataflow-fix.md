# Claude SDK Data Flow Fix - Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix data flow between user, LLM, and tools in the Claude SDK path to properly populate LLM interactions, investigation flow diagrams, findings, and reports.

**Architecture:** Integrate the Claude SDK orchestrator with the existing FlowService, ObservabilityService, and ReportService that the ReAct agent uses successfully.

**Tech Stack:** Python (asyncio), FlowService, ObservabilityService, ReportService, WebSocket events

---

## Problem Analysis

The Claude SDK integration works correctly (events stream, tools execute, findings are reported), but it's **not integrated** with three critical services that the ReAct agent uses:

1. **FlowService** (`flow_service.py`) - Creates the investigation flow diagram (nodes + edges)
2. **ObservabilityService** (`observability_service.py`) - Persists LLM interactions for the UI panel
3. **ReportService** (`report_service.py`) - Generates reports at audit completion

### How ReAct Agent Does It (Working Code)

From `react_agent.py`:

```python
# 1. Initialize flow at start (line 946-951)
flow_service.initialize_flow(self.id)
start_node = flow_service.add_node(
    self.id, "user_input", "Start Investigation",
    {"agent_type": self.agent_type.value}
)
flow_service.update_node_status(self.id, start_node.id, "completed")

# 2. Add nodes for tool calls (line 1483-1488)
tool_node = flow_service.add_node(
    self.id, node_type, node_label,
    {"tool": tool_name, "args": arguments}
)
flow_service.update_node_status(self.id, tool_node.id, "running")
self._broadcast_flow_update()

# 3. Log LLM interactions (line 1380-1406)
request_id = observability_service.log_llm_request(...)
observability_service.log_llm_response(...)

# 4. Log tool executions (line 1576-1586)
observability_service.log_tool_execution(...)

# 5. Broadcast flow updates (line 984-991)
def _broadcast_flow_update(self):
    flow = flow_service.get_flow(self.id)
    if flow:
        self._broadcast(WSMessageType.PROGRESS, {
            "type": "flow_update",
            "flow": flow.to_dict()
        })
```

### Current SDK Path (Missing Integration)

The SDK path in `agent_orchestrator.py` `_run_sdk_agent()` only transforms events for WebSocket - it doesn't call FlowService or ObservabilityService.

---

## Implementation Tasks

### Task 1: Add FlowService Integration to SDK Agent Runner

**Files:**
- Modify: `backend/services/agent_orchestrator.py`

**Step 1: Add imports**

At the top of `agent_orchestrator.py`, add:
```python
from services.flow_service import flow_service
from services.observability_service import observability_service
```

**Step 2: Initialize flow before SDK audit**

In `_run_sdk_agent()`, before calling `sdk_orchestrator.run_audit()`, add:
```python
# Initialize flow tracking for visualization
flow_service.initialize_flow(agent.id)
start_node = flow_service.add_node(
    agent.id, "user_input", "Start Investigation",
    {"agent_type": agent.request.agent_type.value if hasattr(agent.request, 'agent_type') else "sdk_audit"}
)
flow_service.update_node_status(agent.id, start_node.id, "completed")
```

**Step 3: Add flow nodes in on_sdk_event callback**

Inside the `on_sdk_event` function, add flow tracking for tool events:
```python
# Track current tool node for status updates
current_tool_node_id = None

if event_type_str == "tool_call":
    tool_name = event.get("name", "")
    tool_args = event.get("args", {})

    # Determine node type based on tool
    node_type = "tool_call"
    if tool_name in ("read_file", "list_directory"):
        node_type = "code_read"
    elif tool_name in ("search_code", "grep_semantic"):
        node_type = "search"
    elif tool_name in ("scan_repo_for_secrets", "dependency_audit"):
        node_type = "scan"
    elif tool_name == "report_finding":
        node_type = "finding"
    elif tool_name == "upsert_sink_signal":
        kind = tool_args.get("kind", "")
        node_type = "entry_point" if kind == "entry_point" else "dangerous_sink"

    # Create node label
    label = f"{tool_name}: {str(tool_args)[:50]}..."

    # Add flow node
    tool_node = flow_service.add_node(
        agent_id, node_type, label,
        {"tool": tool_name, "args": tool_args}
    )
    flow_service.update_node_status(agent_id, tool_node.id, "running")
    current_tool_node_id = tool_node.id

    # Broadcast flow update
    flow = flow_service.get_flow(agent_id)
    if flow:
        self._broadcast_message(WSMessage(
            type=WSMessageType.PROGRESS,
            agent_id=agent_id,
            data={"type": "flow_update", "flow": flow.to_dict()}
        ))

elif event_type_str == "tool_result":
    # Update tool node status
    if current_tool_node_id:
        is_error = event.get("is_error", False)
        status = "failed" if is_error else "completed"
        flow_service.update_node_status(agent_id, current_tool_node_id, status)
        current_tool_node_id = None

        # Broadcast flow update
        flow = flow_service.get_flow(agent_id)
        if flow:
            self._broadcast_message(WSMessage(
                type=WSMessageType.PROGRESS,
                agent_id=agent_id,
                data={"type": "flow_update", "flow": flow.to_dict()}
            ))
```

**Step 4: Run and verify**

Run: `./run-local.sh`
Expected: Investigation Flow diagram should show nodes for tool calls

**Step 5: Commit**

```bash
git add backend/services/agent_orchestrator.py
git commit -m "feat(sdk): integrate FlowService with Claude SDK agent

- Initialize flow at SDK audit start
- Add flow nodes for tool_call events
- Update node status on tool_result events
- Broadcast flow updates to frontend"
```

---

### Task 2: Add ObservabilityService Integration

**Files:**
- Modify: `backend/services/agent_orchestrator.py`

**Step 1: Track request IDs for correlation**

Add state tracking at the start of `_run_sdk_agent()`:
```python
# Track LLM request ID for correlating responses
current_request_id = None
current_tool_calls = []
```

**Step 2: Log LLM requests**

In `on_sdk_event`, when we emit `llm_request`:
```python
if event_type_str == "llm_request":
    prompt = event.get("prompt", "")
    turn = event.get("turn", 0)

    # Log to observability service
    current_request_id = observability_service.log_llm_request(
        agent_id=agent_id,
        messages=[{"role": "user", "content": prompt}],
        tools_available=None,  # SDK manages tools internally
        model="claude-sdk",
        provider="claude_sdk",
    )
```

**Step 3: Log LLM responses**

When we receive `agent_text`:
```python
elif event_type_str == "agent_text":
    text = event.get("text", "")

    # Log to observability service
    if current_request_id and text:
        observability_service.log_llm_response(
            agent_id=agent_id,
            request_id=current_request_id,
            content=text,
            tool_calls=current_tool_calls if current_tool_calls else None,
            model="claude-sdk",
            provider="claude_sdk",
        )
        current_tool_calls = []  # Reset for next response
```

**Step 4: Log tool executions**

When we receive `tool_result`:
```python
elif event_type_str == "tool_result":
    tool_use_id = event.get("tool_use_id", "")
    result = event.get("result", "")
    is_error = event.get("is_error", False)

    # Find the corresponding tool_call
    tool_name = "unknown"
    tool_args = {}
    for tc in current_tool_calls:
        if tc.get("id") == tool_use_id:
            tool_name = tc.get("name", "unknown")
            tool_args = tc.get("args", {})
            break

    # Log to observability service
    observability_service.log_tool_execution(
        agent_id=agent_id,
        tool_name=tool_name,
        tool_call_id=tool_use_id,
        arguments=tool_args,
        result=result,
        success=not is_error,
        duration_ms=0,  # SDK doesn't provide timing
        error_message=str(result) if is_error else None,
    )
```

**Step 5: Track tool calls**

When we receive `tool_call`, track it:
```python
elif event_type_str == "tool_call":
    # Track for correlation with results
    current_tool_calls.append({
        "id": event.get("id", ""),
        "name": event.get("name", ""),
        "args": event.get("args", {}),
    })
```

**Step 6: Run and verify**

Run: `./run-local.sh`
Expected: LLM Interactions panel should show requests (blue) and responses (green)

**Step 7: Commit**

```bash
git add backend/services/agent_orchestrator.py
git commit -m "feat(sdk): integrate ObservabilityService with Claude SDK agent

- Log LLM requests via observability_service.log_llm_request
- Log LLM responses via observability_service.log_llm_response
- Log tool executions via observability_service.log_tool_execution
- Track request IDs for request/response correlation"
```

---

### Task 3: Add Report Generation on SDK Completion

**Files:**
- Modify: `backend/services/agent_orchestrator.py`
- Possibly modify: `backend/services/report_service.py`

**Step 1: Check how report_service.generate_report works**

Read `report_service.py` to understand the interface.

**Step 2: Call report generation after SDK audit**

In `_run_sdk_agent()`, after successful completion:
```python
# After SDK audit completes successfully
if result.get("success", True) and findings:
    try:
        # Generate report
        report_service.generate_sdk_report(
            agent_id=agent.id,
            repo_id=agent.repo_id,
            repo_path=agent.repo_path,
            findings=findings,
            agent_type=agent.request.agent_type.value if hasattr(agent.request, 'agent_type') else "sdk_audit",
        )
        print(f"[Orchestrator] Generated report for SDK agent {agent.id}")
    except Exception as e:
        print(f"[Orchestrator] Failed to generate report: {e}")
```

**Step 3: Add generate_sdk_report method if needed**

If `report_service` expects a full agent object, add an adapter method:
```python
# In report_service.py
def generate_sdk_report(
    agent_id: str,
    repo_id: str,
    repo_path: str,
    findings: list,
    agent_type: str = "sdk_audit",
):
    """Generate report for SDK-based audit."""
    # Create minimal agent-like data for report generation
    agent_data = {
        "id": agent_id,
        "repo_id": repo_id,
        "repo_path": repo_path,
        "findings": findings,
        "agent_type": agent_type,
    }
    # Call existing report generation logic
    # ...
```

**Step 4: Run and verify**

Run an audit and check that a report is generated in the data directory.

**Step 5: Commit**

```bash
git add backend/services/agent_orchestrator.py backend/services/report_service.py
git commit -m "feat(sdk): add report generation for Claude SDK audits

- Call report_service after successful SDK audit completion
- Add generate_sdk_report adapter for SDK agent data"
```

---

### Task 4: Add Finding Nodes to Flow

**Files:**
- Modify: `backend/services/agent_orchestrator.py`

**Step 1: Add finding nodes when findings are detected**

In `on_sdk_event`, when a finding is detected (from `tool_result` with `report_finding`):
```python
# In the tool_result handler, after detecting a finding
if tool_name == "report_finding" and not is_error:
    # Parse finding data from result
    try:
        finding_data = json.loads(result) if isinstance(result, str) else result
        if isinstance(finding_data, dict) and "finding" in finding_data:
            finding = finding_data["finding"]
            severity = finding.get("severity", "medium")
            title = finding.get("title", "Finding")

            # Add finding node to flow
            finding_node = flow_service.add_node(
                agent_id, "finding", f"{severity.upper()}: {title}",
                {"severity": severity, "finding": finding}
            )
            flow_service.update_node_status(agent_id, finding_node.id, "completed")
    except Exception as e:
        print(f"[Orchestrator] Failed to add finding node: {e}")
```

**Step 2: Add sink signal nodes**

Similarly for `upsert_sink_signal`:
```python
if tool_name == "upsert_sink_signal" and not is_error:
    try:
        signal_data = json.loads(result) if isinstance(result, str) else result
        if isinstance(signal_data, dict) and "signal" in signal_data:
            signal = signal_data["signal"]
            kind = signal.get("kind", "sink")
            label = signal.get("label", "Signal")

            node_type = "entry_point" if kind == "entry_point" else "dangerous_sink"
            signal_node = flow_service.add_node(
                agent_id, node_type, label,
                {"signal": signal}
            )
            flow_service.update_node_status(agent_id, signal_node.id, "completed")
    except Exception as e:
        print(f"[Orchestrator] Failed to add signal node: {e}")
```

**Step 3: Run and verify**

Run: `./run-local.sh`
Expected: Investigation Flow should show finding and sink signal nodes

**Step 4: Commit**

```bash
git add backend/services/agent_orchestrator.py
git commit -m "feat(sdk): add finding and sink signal nodes to flow

- Create finding nodes when report_finding succeeds
- Create sink signal nodes when upsert_sink_signal succeeds
- Show severity and type information in node labels"
```

---

### Task 5: Add Completion Node to Flow

**Files:**
- Modify: `backend/services/agent_orchestrator.py`

**Step 1: Add completion node after audit**

After SDK audit completes (success or failure):
```python
# After sdk_orchestrator.run_audit() returns
completion_status = "completed" if result.get("success", True) else "failed"
flow_service.add_node(
    agent.id, "analysis", f"Audit {completion_status.title()}",
    {"findings_count": len(findings), "elapsed_s": result.get("elapsed_s", 0)}
)

# Broadcast final flow update
flow = flow_service.get_flow(agent.id)
if flow:
    self._broadcast_message(WSMessage(
        type=WSMessageType.PROGRESS,
        agent_id=agent.id,
        data={"type": "flow_update", "flow": flow.to_dict()}
    ))
```

**Step 2: Run and verify**

Run: `./run-local.sh`
Expected: Investigation Flow should show "Audit Complete" or "Audit Failed" node at the end

**Step 3: Commit**

```bash
git add backend/services/agent_orchestrator.py
git commit -m "feat(sdk): add completion node to investigation flow

- Add 'Audit Complete' or 'Audit Failed' node at end
- Include findings count and elapsed time in node data
- Broadcast final flow update to frontend"
```

---

## Summary

This plan addresses the data flow issues by integrating the Claude SDK path with:

1. **FlowService** - Creates the investigation flow diagram with nodes for:
   - Start Investigation (user_input)
   - Tool calls (code_read, search, scan, etc.)
   - Findings
   - Sink signals (entry_point, dangerous_sink)
   - Audit completion

2. **ObservabilityService** - Persists interactions for the LLM Interactions panel:
   - LLM requests (blue)
   - LLM responses (green)
   - Tool executions

3. **ReportService** - Generates reports at audit completion

The changes are isolated to `agent_orchestrator.py` (and possibly `report_service.py`), ensuring we don't touch the working Claude SDK integration code.

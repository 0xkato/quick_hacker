"""Triage Agent Service - Iterative one-at-a-time finding triage.

This service processes findings ONE AT A TIME to avoid context overflow:
1. get_next_finding - returns the next finding to triage
2. read_file - examines the actual code
3. submit_decision - records decision and moves to next finding

This keeps context small - only one finding in scope at any time.
"""
from __future__ import annotations

import asyncio
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from models.schemas import (
    Agent,
    AgentStatus,
    AgentType,
    Finding,
    Disposition,
    WSMessage,
    WSMessageType,
)
from services.observability_service import observability_service


@dataclass
class TriageDecision:
    """Result of triaging a single finding."""
    finding_id: str
    decision: str
    confidence: int
    reasoning: list[str]


@dataclass
class TriageAgentResult:
    """Result from triage agent."""
    decisions: list[TriageDecision]
    triaged_findings: list[Finding]


# System prompt for iterative triage - ONE finding at a time
TRIAGE_SYSTEM_PROMPT = """You are an extremely strict security auditor. You will triage findings ONE AT A TIME.

## YOUR WORKFLOW (repeat for each finding):

1. Call `get_next_finding` to get the next finding to review
2. Call `read_file` to examine the actual source code at the file path
3. Analyze: Is this a REAL vulnerability in PRODUCTION code?
4. Call `submit_decision` with your verdict
5. Repeat until get_next_finding returns "No more findings"

## REJECTION CRITERIA (mark as by_design, hardening, or speculative):

- Test/dev/example code (test files, seeders, fixtures, mocks, examples)
- Intentional dev flags (disableAuth, debugMode, testMode)
- Config templates (.env.example, settings.sample)
- Vendor code (node_modules, vendor, third_party)
- Placeholder secrets ("changeme", "password123")
- No clear exploitation path

## ACCEPTANCE CRITERIA (valid_security_issue):

- SQL/Command injection with user input -> dangerous sink
- Auth bypass in PRODUCTION code
- RCE with clear exploitation
- SSRF to internal networks
- Path traversal with file access
- Real hardcoded credentials

## Decision values:
- valid_security_issue: Real exploitable vulnerability
- bug: Code defect but not security
- misconfiguration: Config issue
- hardening: Security improvement suggestion
- by_design: Intentional behavior
- speculative: Theoretical/unlikely attack

BE STRICT. When in doubt, REJECT. We prefer zero valid issues over any false positives.

START NOW: Call get_next_finding to begin."""


@dataclass
class TriageState:
    """Mutable state for iterative triage."""
    findings: list[Finding]
    current_index: int = 0
    decisions: list[TriageDecision] = field(default_factory=list)

    def get_next(self) -> Finding | None:
        if self.current_index < len(self.findings):
            finding = self.findings[self.current_index]
            return finding
        return None

    def submit(self, decision: TriageDecision) -> None:
        self.decisions.append(decision)
        self.current_index += 1


class TriageAgent:
    """A lightweight agent for triage with observability tracking."""

    def __init__(
        self,
        agent_id: str,
        repo_id: str,
        repo_path: str,
        name: str,
        on_message: Callable[[WSMessage], None] | None = None,
    ):
        self.id = agent_id
        self.repo_id = repo_id
        self.repo_path = repo_path
        self.name = name
        self.on_message = on_message

        self.agent_type = AgentType.TRIAGE
        self.status = AgentStatus.PENDING
        self.created_at = datetime.utcnow()
        self.started_at: datetime | None = None
        self.completed_at: datetime | None = None
        self.files_analyzed = 0
        self.findings: list[Finding] = []
        self.findings_count = 0
        self.error_message: str | None = None

    def to_schema(self) -> Agent:
        """Convert to API schema."""
        from models.schemas import ProviderConfig, ProviderType
        return Agent(
            id=self.id,
            repo_id=self.repo_id,
            name=self.name,
            agent_type=self.agent_type,
            status=self.status,
            provider_config=ProviderConfig(provider=ProviderType.ANTHROPIC, model="claude-sonnet-4-20250514"),
            created_at=self.created_at,
            started_at=self.started_at,
            completed_at=self.completed_at,
            files_analyzed=self.files_analyzed,
            findings_count=self.findings_count,
            error_message=self.error_message,
        )

    def broadcast(self, msg_type: WSMessageType, data: dict[str, Any] | None = None):
        """Broadcast a message via callback."""
        if self.on_message:
            self.on_message(WSMessage(type=msg_type, agent_id=self.id, data=data or {}))


def _create_triage_tools(state: TriageState, repo_path: str):
    """Create MCP-style tools for iterative triage."""

    async def get_next_finding(args: dict) -> dict:
        """Get the next finding to triage."""
        finding = state.get_next()
        if finding is None:
            return {
                "status": "complete",
                "message": "No more findings to triage",
                "triaged_count": len(state.decisions),
            }

        return {
            "status": "pending",
            "finding_number": state.current_index + 1,
            "total_findings": len(state.findings),
            "finding": {
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity,
                "vulnerability_type": finding.vulnerability_type,
                "file_path": finding.file_path,
                "line_start": finding.line_start,
                "line_end": finding.line_end,
                "description": finding.description,
                "code_snippet": finding.code_snippet[:500] if finding.code_snippet else None,
            }
        }

    async def read_file(args: dict) -> dict:
        """Read file content for verification."""
        file_path = args.get("file_path", "")

        # Resolve relative to repo
        if not file_path.startswith("/"):
            full_path = Path(repo_path) / file_path
        else:
            full_path = Path(file_path)

        try:
            if not full_path.exists():
                return {"error": f"File not found: {file_path}"}

            content = full_path.read_text(errors="replace")

            # Limit content size
            if len(content) > 10000:
                content = content[:10000] + "\n... [truncated]"

            return {
                "file_path": str(file_path),
                "content": content,
                "line_count": content.count("\n") + 1,
            }
        except Exception as e:
            return {"error": f"Failed to read file: {e}"}

    async def submit_decision(args: dict) -> dict:
        """Submit triage decision for current finding."""
        finding_id = args.get("finding_id", "")
        decision = args.get("decision", "speculative")
        confidence = args.get("confidence", 50)
        reasoning = args.get("reasoning", [])

        if isinstance(reasoning, str):
            reasoning = [reasoning]

        # Validate decision
        valid_decisions = ["valid_security_issue", "bug", "misconfiguration", "hardening", "by_design", "speculative"]
        if decision not in valid_decisions:
            return {"error": f"Invalid decision: {decision}. Must be one of: {valid_decisions}"}

        # Record decision
        state.submit(TriageDecision(
            finding_id=finding_id,
            decision=decision,
            confidence=confidence,
            reasoning=reasoning,
        ))

        remaining = len(state.findings) - state.current_index
        return {
            "status": "recorded",
            "finding_id": finding_id,
            "decision": decision,
            "remaining_findings": remaining,
            "message": f"Decision recorded. {remaining} findings remaining." if remaining > 0 else "All findings triaged!",
        }

    # Return tools in MCP format
    return {
        "get_next_finding": {
            "fn": get_next_finding,
            "schema": {
                "name": "get_next_finding",
                "description": "Get the next finding to triage. Returns finding details or 'complete' status when done.",
                "input_schema": {"type": "object", "properties": {}, "required": []},
            }
        },
        "read_file": {
            "fn": read_file,
            "schema": {
                "name": "read_file",
                "description": "Read file content to verify the finding. Use the file_path from the finding.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "file_path": {"type": "string", "description": "Path to the file to read"}
                    },
                    "required": ["file_path"],
                },
            }
        },
        "submit_decision": {
            "fn": submit_decision,
            "schema": {
                "name": "submit_decision",
                "description": "Submit your triage decision for the current finding.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "finding_id": {"type": "string", "description": "The ID of the finding being triaged"},
                        "decision": {
                            "type": "string",
                            "enum": ["valid_security_issue", "bug", "misconfiguration", "hardening", "by_design", "speculative"],
                            "description": "Your triage decision"
                        },
                        "confidence": {"type": "integer", "minimum": 0, "maximum": 100, "description": "Confidence in decision (0-100)"},
                        "reasoning": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of reasons for your decision"
                        },
                    },
                    "required": ["finding_id", "decision", "reasoning"],
                },
            }
        },
    }


async def run_triage_agent(
    findings: list[Finding],
    repo_id: str,
    repo_path: str,
    api_key: str | None = None,
    model: str = "claude-sonnet-4-20250514",
    use_claude_code_auth: bool = False,
    on_message: Callable[[WSMessage], None] | None = None,
) -> tuple[TriageAgent, TriageAgentResult]:
    """Run iterative triage agent that processes findings one at a time.

    Returns:
        Tuple of (agent, result) - agent can be used for tracking in UI
    """
    import os
    import time

    # Check SDK availability
    try:
        from claude_agent_sdk import ClaudeSDKClient, ClaudeAgentOptions
    except ImportError:
        raise RuntimeError("Claude SDK not installed")

    # Create triage agent
    agent_id = f"triage-{str(uuid.uuid4())[:8]}"
    agent = TriageAgent(
        agent_id=agent_id,
        repo_id=repo_id,
        repo_path=repo_path,
        name=f"Triage ({len(findings)} findings)",
        on_message=on_message,
    )

    agent.status = AgentStatus.RUNNING
    agent.started_at = datetime.utcnow()
    agent.broadcast(WSMessageType.AGENT_STATUS, {"agent": agent.to_schema().model_dump()})

    print(f"[TriageAgent] Created agent {agent_id} for {len(findings)} findings (iterative mode)")

    # Set up observability
    observability_service.set_broadcast_callback(on_message)

    # Create triage state and tools
    state = TriageState(findings=findings)
    tools = _create_triage_tools(state, repo_path)

    # Build auth
    env: dict[str, str] = {}
    setting_sources: list[str] | None = None

    if use_claude_code_auth:
        setting_sources = ["user"]
        print("[TriageAgent] Using Claude Code auth")
    else:
        resolved_key = (api_key or "").strip()
        if not resolved_key:
            resolved_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
        if not resolved_key:
            resolved_key = os.environ.get("ANTHROPIC_AUTH_TOKEN", "").strip()

        if not resolved_key:
            agent.status = AgentStatus.FAILED
            agent.error_message = "No API key configured"
            raise RuntimeError("No API key configured")

        if resolved_key.lower().startswith("sk-ant-oat"):
            env["ANTHROPIC_AUTH_TOKEN"] = resolved_key
        else:
            env["ANTHROPIC_API_KEY"] = resolved_key
        print(f"[TriageAgent] Using API key")

    # Create MCP server config for our tools
    from claude_agent_sdk import McpSdkServerConfig

    # Build tool handlers
    tool_handlers = {name: info["fn"] for name, info in tools.items()}
    tool_schemas = [info["schema"] for info in tools.values()]

    # Create SDK MCP server
    from mcp.server import Server
    from mcp import types as mcp_types

    mcp_server = Server("triage-tools")

    @mcp_server.list_tools()
    async def list_tools() -> list[mcp_types.Tool]:
        return [
            mcp_types.Tool(
                name=schema["name"],
                description=schema["description"],
                inputSchema=schema["input_schema"],
            )
            for schema in tool_schemas
        ]

    @mcp_server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[mcp_types.TextContent]:
        handler = tool_handlers.get(name)
        if not handler:
            return [mcp_types.TextContent(type="text", text=json.dumps({"error": f"Unknown tool: {name}"}))]

        try:
            result = await handler(arguments)
            return [mcp_types.TextContent(type="text", text=json.dumps(result, indent=2))]
        except Exception as e:
            return [mcp_types.TextContent(type="text", text=json.dumps({"error": str(e)}))]

    # Create SDK options
    allowed_tools = [f"mcp__triage__{name}" for name in tools.keys()]

    options = ClaudeAgentOptions(
        model=model,
        system_prompt=TRIAGE_SYSTEM_PROMPT,
        cwd=repo_path,
        max_turns=len(findings) * 4 + 10,  # ~4 turns per finding (get, read, decide, next)
        permission_mode="bypassPermissions",
        allowed_tools=allowed_tools,
        mcp_servers={"triage": mcp_server},
        env=env,
        setting_sources=setting_sources,
        hooks={},  # Disable inherited hooks to prevent tool concurrency errors
    )

    client = ClaudeSDKClient(options)

    try:
        await client.connect()
        print(f"[TriageAgent] SDK connected, starting iterative triage")

        # Log initial request
        request_id = observability_service.log_llm_request(
            agent_id=agent_id,
            messages=[{"role": "system", "content": TRIAGE_SYSTEM_PROMPT[:500] + "..."}],
            tools_available=list(tools.keys()),
            model=model,
            provider="anthropic",
        )

        # Start the triage loop
        await client.query("Begin triaging findings. Call get_next_finding to start.")

        tool_calls: list[dict] = []
        pending_tools: dict[str, tuple[str, dict, float]] = {}

        async for message in client.receive_response():
            msg_type = message.__class__.__name__

            if msg_type == "AssistantMessage":
                content_blocks = getattr(message, "content", [])
                for block in content_blocks:
                    block_type = block.__class__.__name__
                    if block_type == "ToolUseBlock":
                        tool_name = getattr(block, "name", "unknown")
                        tool_input = getattr(block, "input", {})
                        tool_id = getattr(block, "id", "")

                        pending_tools[tool_id] = (tool_name, tool_input, time.time())

                        # Broadcast progress
                        if "get_next_finding" in tool_name:
                            agent.broadcast(WSMessageType.PROGRESS, {
                                "current": state.current_index,
                                "total": len(findings),
                                "message": f"Triaging finding {state.current_index + 1}/{len(findings)}",
                            })

            elif msg_type == "ToolResultMessage":
                content = getattr(message, "content", [])
                for block in content:
                    block_type = block.__class__.__name__
                    if block_type == "ToolResultBlock":
                        tool_use_id = getattr(block, "tool_use_id", "")
                        is_error = getattr(block, "is_error", False)
                        result_content = getattr(block, "content", "")

                        if tool_use_id in pending_tools:
                            tool_name, tool_input, start_time = pending_tools.pop(tool_use_id)
                            duration_ms = int((time.time() - start_time) * 1000)

                            observability_service.log_tool_execution(
                                agent_id=agent_id,
                                tool_name=tool_name,
                                tool_call_id=tool_use_id,
                                arguments=tool_input,
                                result=str(result_content)[:500],
                                success=not is_error,
                                duration_ms=duration_ms,
                            )

        # Log completion
        if request_id:
            observability_service.log_llm_response(
                agent_id=agent_id,
                request_id=request_id,
                content=f"Triaged {len(state.decisions)} findings",
                model=model,
                provider="anthropic",
            )

        print(f"[TriageAgent] Triage complete: {len(state.decisions)} decisions")

    except Exception as e:
        print(f"[TriageAgent] Error: {e}")
        import traceback
        traceback.print_exc()
        agent.status = AgentStatus.FAILED
        agent.error_message = str(e)
        raise

    finally:
        await client.disconnect()

    # Apply decisions to findings
    decision_map = {d.finding_id: d for d in state.decisions}
    triaged_findings: list[Finding] = []

    disposition_map = {
        "valid_security_issue": Disposition.VALID_SECURITY_ISSUE,
        "bug": Disposition.BUG,
        "misconfiguration": Disposition.MISCONFIGURATION,
        "hardening": Disposition.HARDENING,
        "by_design": Disposition.BY_DESIGN,
        "speculative": Disposition.SPECULATIVE,
    }

    for finding in findings:
        decision = decision_map.get(finding.id)
        if decision:
            finding.disposition = disposition_map.get(decision.decision, Disposition.SPECULATIVE)
            finding.classification_confidence = decision.confidence
            finding.reasoning = decision.reasoning
        else:
            finding.disposition = Disposition.SPECULATIVE
            finding.classification_confidence = 30
            finding.reasoning = ["No triage decision received"]
        triaged_findings.append(finding)

    # Complete agent
    agent.status = AgentStatus.COMPLETED
    agent.completed_at = datetime.utcnow()
    agent.findings_count = len([f for f in triaged_findings if f.disposition == Disposition.VALID_SECURITY_ISSUE])
    agent.broadcast(WSMessageType.AGENT_STATUS, {"agent": agent.to_schema().model_dump()})

    print(f"[TriageAgent] Completed: {agent.findings_count} valid issues found")

    return agent, TriageAgentResult(decisions=state.decisions, triaged_findings=triaged_findings)

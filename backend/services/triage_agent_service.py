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
# DISPROVE-FIRST methodology - try to REJECT before accepting
TRIAGE_SYSTEM_PROMPT = """You are an EXTREMELY STRICT security auditor using DISPROVE-FIRST methodology.

## CRITICAL MINDSET: PROVE IT'S NOT VULNERABLE FIRST

Your job is NOT to confirm findings. Your job is to try to DISPROVE them.
For each finding, you must actively look for reasons it is NOT exploitable.
Only if you CANNOT find any disproof should you mark it as valid.

## YOUR WORKFLOW (repeat for each finding):

1. Call `get_next_finding` to get the next finding
2. Call `read_file` to examine the actual source code at the file path
3. **DISPROVE PHASE**: Look for ANY of these reasons to REJECT:
   - Is there input validation/sanitization?
   - Is there a bounds check or length limit?
   - Is there authentication/authorization gating access?
   - Is the code in test/dev/example files?
   - Does the framework provide automatic protection?
   - Is the input from a trusted internal source only?
4. Call `submit_decision` with your verdict
5. Repeat until get_next_finding returns "No more findings"

## ABSOLUTE REJECTION RULES (if ANY is true → REJECT)

### Rule 1: EXISTING CONTROLS = SPECULATIVE
If the code has ANY security control in place (validation, sanitization, bounds check, length limit, allowlist, etc.) and the attack scenario requires "bypassing" or "evading" that control, it is SPECULATIVE.

EXAMPLE OF WHAT TO REJECT:
```c
char buffer[256];
strncpy(buffer, user_input, sizeof(buffer) - 1);  // LENGTH CHECK EXISTS
```
If finding says "buffer overflow if attacker bypasses length check" → REJECT AS SPECULATIVE
The length check EXISTS. You cannot assume it can be bypassed.

### Rule 2: SPECULATIVE LANGUAGE = REJECT
If the attack scenario uses ANY of these phrases, it is SPECULATIVE:
- "if the attacker can bypass..."
- "if validation is disabled..."
- "assuming no sanitization..."
- "if the length check is circumvented..."
- "if authentication is bypassed..."
- "could potentially be exploited if..."
These assume bypassing real protections. REJECT them.

### Rule 3: TEST/DEV/EXAMPLE CODE = REJECT (by_design or hardening)
- Files in: test/, tests/, __tests__/, spec/, examples/, fixtures/, mocks/, seeders/
- Files named: *_test.*, *_spec.*, test_*.*, *.test.*, *.spec.*
- Code with: @pytest, describe(), it(), unittest, mock, faker

### Rule 4: VENDOR/THIRD-PARTY CODE = REJECT (by_design)
- Paths containing: node_modules/, vendor/, third_party/, packages/, .bundle/

### Rule 5: PLACEHOLDER/EXAMPLE SECRETS = REJECT (by_design)
- Values like: "changeme", "password123", "CHANGE_ME", "your-api-key-here", "xxx", "***"
- Files like: .env.example, config.sample.*, settings.template.*

### Rule 6: FRAMEWORK PROTECTION = REJECT
- Django ORM = parameterized queries (no SQL injection)
- React/Angular/Vue with default settings = auto-escaping (no XSS)
- Rust borrower checker = memory safety
- subprocess with shell=False and list args = no command injection
MUST prove the framework protection is disabled or bypassed.

## WHAT YOU MUST PROVE FOR valid_security_issue:

ALL of these must be PROVEN TRUE (not assumed):
1. ✅ SINK EXISTS: Dangerous operation actually exists in production code
2. ✅ SOURCE CONTROLLED: Attacker can control the input (not internal-only)
3. ✅ DATAFLOW UNPROTECTED: No validation/sanitization in the path
4. ✅ CONTROLS ABSENT OR BYPASSED: No security controls, OR you can prove how to bypass them
5. ✅ REACHABLE: Code path is reachable in production (not dead code)
6. ✅ NOT CONFIG-DEPENDENT: Works under default/common configuration

If ANY of these cannot be proven, mark as `speculative` or appropriate disposition.

## DECISION VALUES:
- valid_security_issue: Proven exploitable with no controls or proven bypass
- bug: Code defect without security impact
- misconfiguration: Only exploitable with non-default config
- hardening: Improvement suggestion, not exploitable
- by_design: Intentional behavior (test code, placeholders)
- speculative: Theoretical attack OR requires bypassing existing controls

## VERIFICATION QUESTIONS (ask yourself for each finding):

1. "Is there ANY validation/sanitization on this input?"
   → If YES and you can't prove bypass, REJECT as speculative

2. "Is this in production code or test/dev/example?"
   → If test/dev/example, REJECT as by_design

3. "Does the framework provide automatic protection?"
   → If YES and not disabled, REJECT

4. "Does the attack scenario assume bypassing a control?"
   → If YES, REJECT as speculative

5. "Can I demonstrate a concrete exploit path?"
   → If NO, REJECT

## CONFIDENCE SCORING:
- 90-100: Proven exploitable, no controls, clear path
- 70-89: Very likely exploitable, controls verified absent
- 50-69: Probably exploitable but some uncertainty
- 30-49: Uncertain, some controls may exist
- 0-29: Unlikely exploitable, controls probably in place

## FINAL RULE: WHEN IN DOUBT, REJECT

Better to miss a real vulnerability than report a false positive.
If you cannot PROVE exploitation, it is not valid_security_issue.

START NOW: Call get_next_finding to begin."""


@dataclass
class TriageState:
    """Mutable state for iterative triage, persisted to file for subprocess access."""
    findings: list[Finding]
    current_index: int = 0
    decisions: list[TriageDecision] = field(default_factory=list)
    state_file: str = ""  # Path to state file for subprocess communication

    def get_next(self) -> Finding | None:
        if self.current_index < len(self.findings):
            finding = self.findings[self.current_index]
            return finding
        return None

    def submit(self, decision: TriageDecision) -> None:
        self.decisions.append(decision)
        self.current_index += 1

    def save_to_file(self) -> None:
        """Save state to file for subprocess access."""
        if not self.state_file:
            return
        state_data = {
            "current_index": self.current_index,
            "total_findings": len(self.findings),
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                    "vulnerability_type": f.vulnerability_type,
                    "file_path": f.file_path,
                    "line_start": f.line_start,
                    "line_end": f.line_end,
                    "description": f.description,
                    "code_snippet": (f.code_snippet[:500] if f.code_snippet else None),
                }
                for f in self.findings
            ],
            "decisions": [
                {
                    "finding_id": d.finding_id,
                    "decision": d.decision,
                    "confidence": d.confidence,
                    "reasoning": d.reasoning,
                }
                for d in self.decisions
            ],
        }
        Path(self.state_file).write_text(json.dumps(state_data, indent=2))

    def load_decisions_from_file(self) -> None:
        """Load decisions back from file after subprocess completes."""
        if not self.state_file or not Path(self.state_file).exists():
            return
        state_data = json.loads(Path(self.state_file).read_text())
        self.current_index = state_data.get("current_index", 0)
        self.decisions = [
            TriageDecision(
                finding_id=d["finding_id"],
                decision=d["decision"],
                confidence=d["confidence"],
                reasoning=d["reasoning"],
            )
            for d in state_data.get("decisions", [])
        ]


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

    Uses Claude SDK with file-based state for subprocess communication.

    Returns:
        Tuple of (agent, result) - agent can be used for tracking in UI
    """
    import os
    import time
    import tempfile

    # Check SDK availability
    try:
        from claude_agent_sdk import ClaudeSDKClient, ClaudeAgentOptions, tool, create_sdk_mcp_server
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

    print(f"[TriageAgent] Created agent {agent_id} for {len(findings)} findings (SDK mode)")

    # Set up observability
    observability_service.set_broadcast_callback(on_message)

    # Create state file for subprocess communication
    state_file = tempfile.mktemp(suffix=".json", prefix="triage_state_")
    print(f"[TriageAgent] State file: {state_file}")

    # Create initial state and write to file
    state = TriageState(findings=findings, state_file=state_file)
    state.save_to_file()
    print(f"[TriageAgent] Saved {len(findings)} findings to state file")

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

    # Create SDK tools that read/write state from file
    # These need to be module-level or use file I/O (not closures to in-memory state)
    # because they run in the SDK's MCP server process

    @tool("get_next_finding", "Get the next finding to triage. Returns finding details or 'complete' status when done.", {})
    async def sdk_get_next_finding(args: dict) -> dict:
        """Get the next finding from state file."""
        try:
            state_data = json.loads(Path(state_file).read_text())
            current_index = state_data.get("current_index", 0)
            findings_list = state_data.get("findings", [])

            if current_index >= len(findings_list):
                return {
                    "status": "complete",
                    "message": "No more findings to triage",
                    "triaged_count": len(state_data.get("decisions", [])),
                }

            finding = findings_list[current_index]
            return {
                "status": "pending",
                "finding_number": current_index + 1,
                "total_findings": len(findings_list),
                "finding": finding,
            }
        except Exception as e:
            return {"error": f"Failed to read state: {e}"}

    @tool("read_file", "Read file content to verify the finding.", {"file_path": str})
    async def sdk_read_file(args: dict) -> dict:
        """Read file content."""
        file_path = args.get("file_path", "")
        try:
            if not file_path.startswith("/"):
                full_path = Path(repo_path) / file_path
            else:
                full_path = Path(file_path)

            if not full_path.exists():
                return {"error": f"File not found: {file_path}"}

            content = full_path.read_text(errors="replace")
            if len(content) > 10000:
                content = content[:10000] + "\n... [truncated]"

            return {"file_path": str(file_path), "content": content, "line_count": content.count("\n") + 1}
        except Exception as e:
            return {"error": f"Failed to read file: {e}"}

    @tool("submit_decision", "Submit your triage decision.", {
        "finding_id": str, "decision": str, "confidence": int, "reasoning": list
    })
    async def sdk_submit_decision(args: dict) -> dict:
        """Submit decision and advance to next finding."""
        try:
            finding_id = args.get("finding_id", "")
            decision = args.get("decision", "speculative")
            confidence = args.get("confidence", 50)
            reasoning = args.get("reasoning", [])

            if isinstance(reasoning, str):
                reasoning = [reasoning]

            valid_decisions = ["valid_security_issue", "bug", "misconfiguration", "hardening", "by_design", "speculative"]
            if decision not in valid_decisions:
                return {"error": f"Invalid decision: {decision}"}

            # Read current state
            state_data = json.loads(Path(state_file).read_text())

            # Add decision
            decisions = state_data.get("decisions", [])
            decisions.append({
                "finding_id": finding_id,
                "decision": decision,
                "confidence": confidence,
                "reasoning": reasoning,
            })
            state_data["decisions"] = decisions
            state_data["current_index"] = state_data.get("current_index", 0) + 1

            # Write back
            Path(state_file).write_text(json.dumps(state_data, indent=2))

            remaining = len(state_data.get("findings", [])) - state_data["current_index"]
            return {
                "status": "recorded",
                "finding_id": finding_id,
                "decision": decision,
                "remaining_findings": remaining,
                "message": f"Decision recorded. {remaining} remaining." if remaining > 0 else "All triaged!",
            }
        except Exception as e:
            return {"error": f"Failed to save decision: {e}"}

    # Create SDK MCP server
    sdk_tools = [sdk_get_next_finding, sdk_read_file, sdk_submit_decision]
    mcp_server = create_sdk_mcp_server(name="triage", version="1.0.0", tools=sdk_tools)
    allowed_tools = [f"mcp__triage__{t.name}" for t in sdk_tools]

    print(f"[TriageAgent] Allowed tools: {allowed_tools}")

    options = ClaudeAgentOptions(
        model=model,
        system_prompt=TRIAGE_SYSTEM_PROMPT,
        cwd=repo_path,
        max_turns=len(findings) * 4 + 10,
        permission_mode="bypassPermissions",
        allowed_tools=allowed_tools,
        mcp_servers={"triage": mcp_server},
        env=env,
        setting_sources=setting_sources,
        hooks={},
    )

    client = ClaudeSDKClient(options)

    try:
        await client.connect()
        print(f"[TriageAgent] SDK connected, starting triage")

        await client.query("Begin triaging findings. Call get_next_finding to start.")
        print(f"[TriageAgent] Query sent, receiving response stream...")

        message_count = 0
        async for message in client.receive_response():
            message_count += 1
            msg_type = message.__class__.__name__
            print(f"[TriageAgent] Message #{message_count}: {msg_type}")

            if msg_type == "AssistantMessage":
                for block in getattr(message, "content", []):
                    block_type = block.__class__.__name__
                    if block_type == "ToolUseBlock":
                        tool_name = getattr(block, "name", "unknown")
                        print(f"[TriageAgent]   Tool call: {tool_name}")
                        if "get_next_finding" in tool_name:
                            # Reload state to get current progress
                            state.load_decisions_from_file()
                            agent.broadcast(WSMessageType.PROGRESS, {
                                "current": state.current_index,
                                "total": len(findings),
                                "message": f"Triaging finding {state.current_index + 1}/{len(findings)}",
                            })
                    elif block_type == "TextBlock":
                        text = getattr(block, "text", "")[:200]
                        print(f"[TriageAgent]   Text: {text}...")

            elif msg_type == "ResultMessage":
                print(f"[TriageAgent] Conversation complete")

        print(f"[TriageAgent] Response stream ended after {message_count} messages")

        # Load final decisions from state file
        state.load_decisions_from_file()
        print(f"[TriageAgent] Loaded {len(state.decisions)} decisions from state file")

    except Exception as e:
        print(f"[TriageAgent] Error: {e}")
        import traceback
        traceback.print_exc()
        agent.status = AgentStatus.FAILED
        agent.error_message = str(e)
        raise

    finally:
        await client.disconnect()
        try:
            if Path(state_file).exists():
                Path(state_file).unlink()
        except Exception:
            pass

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

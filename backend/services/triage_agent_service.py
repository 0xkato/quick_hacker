"""Triage Agent Service - Creates a triage agent with tool access and observability.

This service creates a proper agent for triage that:
1. Appears in the agent dropdown
2. Has access to file reading tools to verify findings
3. Logs all LLM interactions to the observability service
4. Uses the same auth flow as scan agents
"""
from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass
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


# Strict triage system prompt
TRIAGE_SYSTEM_PROMPT = """You are an extremely strict security auditor with access to file reading tools.

## CRITICAL RULE: We prefer ZERO valid issues over ANY false positives.

You MUST use the read_file tool to verify each finding before making a decision.

## ALWAYS REJECT (mark as by_design, hardening, or speculative):

1. **Intentional Features**: Auth bypass flags like `disableAuthentication`, `skipAuth`, `devMode`, `debugMode`, `testMode`
2. **Dev/Test Code**: ANYTHING in test files, seeders, fixtures, factories, examples, demos, mocks, stubs
3. **Development Vulnerabilities**: Issues that only exist in dev/debug builds or require debug flags
4. **No Direct Security Impact**: Information disclosure without sensitive data, missing headers, etc.
5. **Speculative Attacks**: Issues requiring unlikely conditions, specific timing, or attacker-controlled servers
6. **Hardening Suggestions**: "Should use X instead of Y" without actual vulnerability
7. **Configuration Templates**: .env.example, config.sample, settings.template files
8. **Vendor/Third-Party Code**: Issues in node_modules, vendor, third_party directories
9. **Obvious Placeholders**: "changeme", "password123", "secret" in example configs
10. **Feature Flags**: Intentional toggles that disable security for testing/development

## ONLY ACCEPT as valid_security_issue:

- SQL injection with clear user input → query path
- Command injection with clear user input → shell execution
- Authentication bypass in PRODUCTION code (not dev flags)
- Remote code execution with clear exploitation path
- SSRF with internal network access potential
- Path traversal with file read/write capability
- Hardcoded PRODUCTION credentials (not test/example)
- Privilege escalation between real user roles

## Workflow

For EACH finding:
1. Use read_file to examine the actual code
2. Look for context clues (dev flags, test patterns, etc.)
3. Determine if it's exploitable in production
4. Make your decision

## Response Format

After examining all findings, output ONLY a JSON array:
```json
[{"finding_id": "id", "decision": "disposition", "confidence": 0-100, "reasoning": ["reason1", "reason2"]}]
```

BE AGGRESSIVE. When in doubt, REJECT."""


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
        return Agent(
            id=self.id,
            repo_id=self.repo_id,
            name=self.name,
            agent_type=self.agent_type,
            status=self.status,
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
            self.on_message(WSMessage(type=msg_type, agent_id=self.id, data=data))


async def run_triage_agent(
    findings: list[Finding],
    repo_id: str,
    repo_path: str,
    api_key: str | None = None,
    model: str = "claude-sonnet-4-20250514",
    use_claude_code_auth: bool = False,
    on_message: Callable[[WSMessage], None] | None = None,
) -> tuple[TriageAgent, TriageAgentResult]:
    """Run a triage agent that verifies findings with file access.

    Returns:
        Tuple of (agent, result) - agent can be used for tracking in UI
    """
    import json
    import os

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
    agent.broadcast(WSMessageType.AGENT_STARTED, {"agent": agent.to_schema().model_dump()})

    print(f"[TriageAgent] Created agent {agent_id} for {len(findings)} findings")

    # Set up observability
    observability_service.set_broadcast_callback(on_message)

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

    # Build findings prompt
    findings_text = []
    for i, finding in enumerate(findings, 1):
        findings_text.append(f"""
## Finding {i}: {finding.title}
- **ID**: {finding.id}
- **File**: {finding.file_path}
- **Line**: {finding.line_start or "unknown"}
- **Type**: {finding.vulnerability_type}
- **Severity**: {finding.severity}

**Description**: {finding.description}
""")

    user_prompt = f"""Please triage these {len(findings)} security findings.

For EACH finding, use the read_file tool to examine the actual source code before deciding.

{chr(10).join(findings_text)}

After examining all findings, output your decisions as a JSON array."""

    # Create SDK options with file reading tool
    options = ClaudeAgentOptions(
        model=model,
        system_prompt=TRIAGE_SYSTEM_PROMPT,
        cwd=repo_path,
        max_turns=len(findings) * 2 + 5,  # Allow multiple reads per finding
        permission_mode="bypassPermissions",
        allowed_tools=["Read"],  # Only allow file reading
        env=env,
        setting_sources=setting_sources,
    )

    client = ClaudeSDKClient(options)
    decisions: list[TriageDecision] = []

    try:
        await client.connect()
        print(f"[TriageAgent] SDK connected, starting triage")

        # Log initial request
        request_id = observability_service.log_llm_request(
            agent_id=agent_id,
            messages=[
                {"role": "system", "content": TRIAGE_SYSTEM_PROMPT[:500] + "..."},
                {"role": "user", "content": user_prompt[:1000] + "..."},
            ],
            tools_available=["read_file"],
            model=model,
            provider="anthropic",
        )

        await client.query(user_prompt)

        response_parts: list[str] = []
        tool_calls: list[dict] = []

        async for message in client.receive_response():
            msg_type = message.__class__.__name__

            if msg_type == "AssistantMessage":
                content_blocks = getattr(message, "content", [])
                for block in content_blocks:
                    block_type = block.__class__.__name__
                    if block_type == "TextBlock":
                        text = getattr(block, "text", "")
                        if text:
                            response_parts.append(text)
                    elif block_type == "ToolUseBlock":
                        tool_name = getattr(block, "name", "unknown")
                        tool_input = getattr(block, "input", {})
                        tool_id = getattr(block, "id", "")

                        # Log tool use
                        observability_service.log_tool_execution(
                            agent_id=agent_id,
                            tool_name=tool_name,
                            tool_call_id=tool_id,
                            input_data=tool_input,
                            output_data=None,
                            duration_ms=0,
                            is_error=False,
                        )
                        tool_calls.append({
                            "name": tool_name,
                            "input": tool_input,
                        })
                        print(f"[TriageAgent] Tool call: {tool_name}({tool_input.get('file_path', '')})")

            elif msg_type == "ToolResultMessage":
                # Tool result received
                pass

        # Log final response
        full_response = "".join(response_parts)
        if request_id:
            observability_service.log_llm_response(
                agent_id=agent_id,
                request_id=request_id,
                content=full_response[:2000] + ("..." if len(full_response) > 2000 else ""),
                tool_calls=tool_calls if tool_calls else None,
                model=model,
                provider="anthropic",
            )

        print(f"[TriageAgent] Response received ({len(full_response)} chars)")

        # Parse decisions from response
        decisions = _parse_triage_response(full_response, [f.id for f in findings])

    except Exception as e:
        print(f"[TriageAgent] Error: {e}")
        agent.status = AgentStatus.FAILED
        agent.error_message = str(e)
        raise

    finally:
        await client.disconnect()

    # Apply decisions to findings
    decision_map = {d.finding_id: d for d in decisions}
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
    agent.broadcast(WSMessageType.AGENT_COMPLETED, {"agent": agent.to_schema().model_dump()})

    print(f"[TriageAgent] Completed: {agent.findings_count} valid issues found")

    return agent, TriageAgentResult(decisions=decisions, triaged_findings=triaged_findings)


def _parse_triage_response(response_text: str, finding_ids: list[str]) -> list[TriageDecision]:
    """Parse triage decisions from response."""
    import json

    decisions = []

    try:
        text = response_text.strip()

        # Extract JSON
        if "```json" in text:
            start = text.find("```json") + 7
            end = text.find("```", start)
            text = text[start:end]
        elif "```" in text:
            start = text.find("```") + 3
            end = text.find("```", start)
            text = text[start:end]

        # Find array
        start_idx = text.find("[")
        end_idx = text.rfind("]")

        if start_idx != -1 and end_idx != -1:
            json_text = text[start_idx:end_idx + 1]
            parsed = json.loads(json_text)

            if isinstance(parsed, list):
                for item in parsed:
                    if isinstance(item, dict):
                        decisions.append(TriageDecision(
                            finding_id=item.get("finding_id", "unknown"),
                            decision=item.get("decision", "speculative"),
                            confidence=item.get("confidence", 50),
                            reasoning=item.get("reasoning", []),
                        ))

    except Exception as e:
        print(f"[TriageAgent] Parse error: {e}")

    # Fill in missing decisions
    seen_ids = {d.finding_id for d in decisions}
    for fid in finding_ids:
        if fid not in seen_ids:
            decisions.append(TriageDecision(
                finding_id=fid,
                decision="speculative",
                confidence=30,
                reasoning=["Could not parse triage decision"],
            ))

    return decisions

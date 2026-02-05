"""Triage Agent Service - Iterative finding triage using prompt-based approach.

This service processes findings by including them in prompts and parsing Claude's
output for decisions. Works with Claude Code subscription auth.
"""
from __future__ import annotations

import asyncio
import json
import re
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


# System prompt for batch triage
TRIAGE_SYSTEM_PROMPT = """You are an EXTREMELY STRICT security auditor using DISPROVE-FIRST methodology.

## YOUR TASK

You will be given security findings to triage. For EACH finding, you must:
1. Try to DISPROVE it (look for reasons it's NOT exploitable)
2. Only mark as valid if you CANNOT disprove it

## ABSOLUTE REJECTION RULES (if ANY is true → REJECT)

### Rule 1: EXISTING CONTROLS = SPECULATIVE
If the code has ANY security control (validation, sanitization, bounds check, length limit, allowlist) and the attack requires "bypassing" that control → REJECT AS SPECULATIVE

### Rule 2: SPECULATIVE LANGUAGE = REJECT
If attack scenario uses: "if attacker bypasses...", "if validation disabled...", "assuming no sanitization..." → REJECT

### Rule 3: TEST/DEV/EXAMPLE CODE = REJECT
Files in: test/, tests/, examples/, fixtures/, mocks/, seeders/
Files named: *_test.*, test_*.*, *.spec.*

### Rule 4: VENDOR/THIRD-PARTY = REJECT
Files in: vendor/, third_party/, node_modules/

## OUTPUT FORMAT (REQUIRED)

For EACH finding, output a decision block in this EXACT format:

```decision
FINDING_ID: <the finding id>
DECISION: <valid_security_issue|speculative|hardening|by_design|bug|misconfiguration>
CONFIDENCE: <0-100>
REASONING: <brief explanation>
```

Valid decisions:
- valid_security_issue: Real exploitable vulnerability
- speculative: Requires assuming controls can be bypassed
- hardening: Improvement opportunity, not a vulnerability
- by_design: Intentional behavior, not a bug
- bug: Functional bug, not security issue
- misconfiguration: Config issue, not code vulnerability

IMPORTANT: Output one decision block for EACH finding. Do not skip any."""


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


def _format_finding_for_triage(finding: Finding, index: int) -> str:
    """Format a single finding for inclusion in the triage prompt."""
    lines = [
        f"## Finding {index + 1}: {finding.title}",
        f"**FINDING_ID:** `{finding.id}` (USE THIS EXACT ID IN YOUR RESPONSE)",
        f"**Severity:** {finding.severity.value}",
        f"**File:** {finding.file_path}:{finding.line_start}",
        f"**Type:** {finding.vulnerability_type}",
        "",
        f"**Description:** {finding.description[:500] if finding.description else 'N/A'}",
    ]

    if finding.vulnerable_code:
        lines.extend([
            "",
            "**Code:**",
            "```",
            finding.vulnerable_code[:500],
            "```",
        ])

    if finding.attack_scenario:
        lines.extend([
            "",
            f"**Attack Scenario:** {finding.attack_scenario[:300]}",
        ])

    return "\n".join(lines)


def _parse_decisions_from_text(text: str) -> list[TriageDecision]:
    """Parse triage decisions from Claude's text output."""
    decisions = []

    # Look for decision blocks
    pattern = r"```decision\s*\n(.*?)\n```"
    blocks = re.findall(pattern, text, re.DOTALL | re.IGNORECASE)

    # Also try without code blocks
    if not blocks:
        pattern = r"FINDING_ID:\s*([^\n]+)\s*\nDECISION:\s*([^\n]+)\s*\nCONFIDENCE:\s*(\d+)\s*\nREASONING:\s*([^\n]+)"
        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            finding_id, decision, confidence, reasoning = match
            decisions.append(TriageDecision(
                finding_id=finding_id.strip(),
                decision=decision.strip().lower(),
                confidence=min(100, max(0, int(confidence))),
                reasoning=[reasoning.strip()],
            ))
        return decisions

    for block in blocks:
        try:
            finding_id = ""
            decision = "speculative"
            confidence = 50
            reasoning = []

            for line in block.strip().split("\n"):
                line = line.strip()
                if line.upper().startswith("FINDING_ID:"):
                    finding_id = line.split(":", 1)[1].strip()
                elif line.upper().startswith("DECISION:"):
                    decision = line.split(":", 1)[1].strip().lower()
                elif line.upper().startswith("CONFIDENCE:"):
                    try:
                        confidence = min(100, max(0, int(line.split(":", 1)[1].strip())))
                    except ValueError:
                        pass
                elif line.upper().startswith("REASONING:"):
                    reasoning = [line.split(":", 1)[1].strip()]

            if finding_id:
                decisions.append(TriageDecision(
                    finding_id=finding_id,
                    decision=decision,
                    confidence=confidence,
                    reasoning=reasoning,
                ))
        except Exception as e:
            print(f"[TriageAgent] Failed to parse decision block: {e}")
            continue

    return decisions


async def run_triage_agent(
    findings: list[Finding],
    repo_id: str,
    repo_path: str,
    api_key: str | None = None,
    model: str = "claude-sonnet-4-20250514",
    use_claude_code_auth: bool = False,
    on_message: Callable[[WSMessage], None] | None = None,
) -> tuple[TriageAgent, TriageAgentResult]:
    """Run triage agent that processes findings via prompt-based approach.

    Embeds findings in the prompt and parses Claude's text output for decisions.
    Works with Claude Code subscription auth.

    Returns:
        Tuple of (agent, result) - agent can be used for tracking in UI
    """
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
    agent.broadcast(WSMessageType.AGENT_STATUS, {"agent": agent.to_schema().model_dump()})

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

    # Format findings for prompt - batch if needed
    BATCH_SIZE = 5  # Process 5 findings at a time to avoid context overflow
    all_decisions: list[TriageDecision] = []

    # Process in batches
    for batch_start in range(0, len(findings), BATCH_SIZE):
        batch_end = min(batch_start + BATCH_SIZE, len(findings))
        batch_findings = findings[batch_start:batch_end]

        print(f"[TriageAgent] Processing batch {batch_start + 1}-{batch_end} of {len(findings)} findings")

        agent.broadcast(WSMessageType.PROGRESS, {
            "current": batch_start,
            "total": len(findings),
            "message": f"Triaging findings {batch_start + 1}-{batch_end} of {len(findings)}",
        })

        # Build prompt with findings
        findings_text = "\n\n---\n\n".join(
            _format_finding_for_triage(f, batch_start + i)
            for i, f in enumerate(batch_findings)
        )

        user_prompt = f"""Triage the following {len(batch_findings)} security findings using DISPROVE-FIRST methodology.

For EACH finding below, output a decision block. Do not skip any finding.

CRITICAL: Use the EXACT FINDING_ID shown for each finding (the value in backticks after "FINDING_ID:"). Do NOT use "Finding 1" or other labels.

{findings_text}

Remember: Output one ```decision``` block for EACH finding above. Use the EXACT FINDING_ID from the finding (e.g., `finding-abc123`), not "Finding 1"."""

        # Configure SDK client - no tools, just prompt/response
        options = ClaudeAgentOptions(
            model=model,
            system_prompt=TRIAGE_SYSTEM_PROMPT,
            cwd=repo_path,
            max_turns=3,  # Simple prompt/response
            permission_mode="bypassPermissions",
            allowed_tools=[],  # No tools needed
            env=env,
            setting_sources=setting_sources,
            hooks={},
        )

        client = ClaudeSDKClient(options)
        collected_text = []

        try:
            await client.connect()
            print(f"[TriageAgent] SDK connected for batch {batch_start + 1}-{batch_end}")

            await client.query(user_prompt)

            async for message in client.receive_response():
                msg_type = message.__class__.__name__

                if msg_type == "AssistantMessage":
                    for block in getattr(message, "content", []):
                        block_type = block.__class__.__name__
                        if block_type == "TextBlock":
                            text = getattr(block, "text", "")
                            collected_text.append(text)

                elif msg_type == "ResultMessage":
                    break

        except Exception as e:
            print(f"[TriageAgent] Error in batch {batch_start + 1}-{batch_end}: {e}")
            import traceback
            traceback.print_exc()
            # Continue with next batch

        finally:
            try:
                await client.disconnect()
            except Exception:
                pass

        # Parse decisions from collected text
        full_response = "".join(collected_text)
        batch_decisions = _parse_decisions_from_text(full_response)
        print(f"[TriageAgent] Parsed {len(batch_decisions)} decisions from batch")

        all_decisions.extend(batch_decisions)

    print(f"[TriageAgent] Total decisions collected: {len(all_decisions)}")
    for d in all_decisions:
        print(f"[TriageAgent]   Decision: {d.finding_id} -> {d.decision} ({d.confidence}%)")

    # Apply decisions to findings with flexible matching
    # Build multiple lookup maps for robust matching
    decision_by_exact = {d.finding_id: d for d in all_decisions}
    decision_by_lower = {d.finding_id.lower().strip(): d for d in all_decisions}
    # Also build index-based map (Finding 1 -> index 0, etc.)
    decision_by_index: dict[int, TriageDecision] = {}
    for d in all_decisions:
        # Try to extract index from "Finding 1", "finding-1", etc.
        import re
        match = re.search(r'(\d+)', d.finding_id)
        if match:
            idx = int(match.group(1)) - 1  # Convert 1-based to 0-based
            if idx >= 0:
                decision_by_index[idx] = d

    triaged_findings: list[Finding] = []

    disposition_map = {
        "valid_security_issue": Disposition.VALID_SECURITY_ISSUE,
        "bug": Disposition.BUG,
        "misconfiguration": Disposition.MISCONFIGURATION,
        "hardening": Disposition.HARDENING,
        "by_design": Disposition.BY_DESIGN,
        "speculative": Disposition.SPECULATIVE,
    }

    valid_count = 0
    matched_count = 0
    for idx, finding in enumerate(findings):
        # Try multiple matching strategies
        decision = None

        # 1. Exact match
        decision = decision_by_exact.get(finding.id)

        # 2. Case-insensitive match
        if not decision:
            decision = decision_by_lower.get(finding.id.lower().strip())

        # 3. Partial match (finding ID contains or is contained in decision ID)
        if not decision:
            for d in all_decisions:
                if finding.id in d.finding_id or d.finding_id in finding.id:
                    decision = d
                    break

        # 4. Index-based fallback (if LLM output "Finding 1" instead of actual ID)
        if not decision:
            decision = decision_by_index.get(idx)

        if decision:
            matched_count += 1
            finding.disposition = disposition_map.get(decision.decision, Disposition.SPECULATIVE)
            finding.classification_confidence = decision.confidence
            finding.reasoning = decision.reasoning
            finding.triaged_at = datetime.utcnow()
            print(f"[TriageAgent] Matched {finding.id} -> {decision.decision}")
            if decision.decision == "valid_security_issue":
                valid_count += 1
        else:
            # No decision received - mark as needing review
            finding.disposition = Disposition.SPECULATIVE
            finding.classification_confidence = 30
            finding.reasoning = ["No triage decision received - needs manual review"]
            print(f"[TriageAgent] No match for finding {finding.id}")
        triaged_findings.append(finding)

    print(f"[TriageAgent] Matched {matched_count}/{len(findings)} findings to decisions")

    # Complete agent
    agent.status = AgentStatus.COMPLETED
    agent.completed_at = datetime.utcnow()
    agent.findings_count = valid_count
    agent.broadcast(WSMessageType.AGENT_STATUS, {"agent": agent.to_schema().model_dump()})

    print(f"[TriageAgent] Completed: {valid_count} valid issues found out of {len(findings)}")

    return agent, TriageAgentResult(decisions=all_decisions, triaged_findings=triaged_findings)

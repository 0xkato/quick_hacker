"""LLM Triage Service - Uses Claude SDK for intelligent finding triage.

This service uses the same Claude SDK approach as the scan, but with a triage-focused
prompt to analyze findings and determine their validity and disposition.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

# Try to import Claude SDK
SDK_AVAILABLE = False
ClaudeSDKClient = None
ClaudeAgentOptions = None

try:
    from claude_agent_sdk import (
        ClaudeSDKClient as _ClaudeSDKClient,
        ClaudeAgentOptions as _ClaudeAgentOptions,
    )
    ClaudeSDKClient = _ClaudeSDKClient
    ClaudeAgentOptions = _ClaudeAgentOptions
    SDK_AVAILABLE = True
    logger.info("LLM Triage Service: Claude SDK available")
except ImportError as e:
    logger.warning(f"LLM Triage Service: Claude SDK not installed: {e}")


@dataclass
class TriageDecision:
    """Result of triaging a single finding."""
    finding_id: str
    decision: str  # valid_security_issue, bug, misconfiguration, hardening, by_design, speculative
    confidence: int  # 0-100
    reasoning: list[str]


@dataclass
class TriageResult:
    """Result of triaging multiple findings."""
    decisions: list[TriageDecision]
    raw_response: str


TRIAGE_SYSTEM_PROMPT = """You are an expert security auditor reviewing vulnerability findings from an automated security scan.

Your task is to triage each finding and determine:
1. Is it a real security vulnerability, or a false positive?
2. What is the correct disposition?

## Dispositions

- **valid_security_issue**: A genuine exploitable security vulnerability that could be used by an attacker
- **bug**: A code defect that could cause issues but is not directly exploitable as a security issue
- **misconfiguration**: Insecure configuration that should be fixed but may not be directly exploitable
- **hardening**: A defensive improvement suggestion, not an actual vulnerability
- **by_design**: The behavior is intentional and acceptable given the context
- **speculative**: Theoretical issue that would require specific conditions to exploit; needs more investigation

## Key Considerations

1. **Test/Demo Code**: Findings in test files, seeders, fixtures, examples, or demo code are usually NOT real vulnerabilities
2. **Context Matters**: A hardcoded password in a seeder file is NOT the same as one in production code
3. **Exploitability**: Can an attacker actually exploit this? What would they need?
4. **Impact**: If exploited, what's the actual impact?
5. **False Positives**: Be skeptical of generic findings without specific exploitation paths

## Response Format

Respond with a JSON array where each element has:
```json
{
  "finding_id": "the finding ID",
  "decision": "one of: valid_security_issue, bug, misconfiguration, hardening, by_design, speculative",
  "confidence": 0-100,
  "reasoning": ["reason 1", "reason 2", ...]
}
```

Only output the JSON array, nothing else."""


def _build_triage_prompt(findings: list[dict[str, Any]]) -> str:
    """Build the triage prompt with finding details."""
    findings_text = []

    for i, finding in enumerate(findings, 1):
        finding_id = finding.get("id", f"unknown-{i}")
        title = finding.get("title", "Unknown")
        severity = finding.get("severity", "unknown")
        file_path = finding.get("file_path", "unknown")
        vuln_type = finding.get("vulnerability_type", "unknown")
        description = finding.get("description", "No description")
        code_snippet = finding.get("code_snippet", "")
        attack_scenario = finding.get("attack_scenario", "")

        finding_text = f"""
## Finding {i}: {title}
- **ID**: {finding_id}
- **Severity**: {severity}
- **File**: {file_path}
- **Type**: {vuln_type}

**Description**: {description}
"""
        if code_snippet:
            finding_text += f"\n**Code Snippet**:\n```\n{code_snippet}\n```\n"
        if attack_scenario:
            finding_text += f"\n**Attack Scenario**: {attack_scenario}\n"

        findings_text.append(finding_text)

    prompt = f"""Please triage the following {len(findings)} security findings:

{''.join(findings_text)}

Analyze each finding and provide your triage decisions as a JSON array."""

    return prompt


def _parse_triage_response(response_text: str, finding_ids: list[str]) -> list[TriageDecision]:
    """Parse the triage response from Claude."""
    decisions = []

    # Try to extract JSON from response
    try:
        # Find JSON array in response
        text = response_text.strip()

        # Handle common response formats
        if text.startswith("```json"):
            text = text[7:]
        if text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]

        # Find the JSON array
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

    except json.JSONDecodeError as e:
        logger.warning(f"Failed to parse triage response as JSON: {e}")

    # If we couldn't parse, create default decisions
    if not decisions:
        logger.warning("No decisions parsed from response, using defaults")
        for fid in finding_ids:
            decisions.append(TriageDecision(
                finding_id=fid,
                decision="speculative",
                confidence=30,
                reasoning=["Could not parse LLM response, needs manual review"],
            ))

    return decisions


async def run_llm_triage(
    findings: list[dict[str, Any]],
    api_key: str | None = None,
) -> TriageResult:
    """Run LLM-based triage on findings using Claude SDK.

    Args:
        findings: List of finding dicts to triage
        api_key: Optional API key (falls back to environment variable)

    Returns:
        TriageResult with decisions for each finding

    Raises:
        RuntimeError: If Claude SDK is not available
    """
    if not SDK_AVAILABLE:
        raise RuntimeError(
            "Claude SDK not installed. Install with: pip install claude-agent-sdk"
        )

    if not findings:
        return TriageResult(decisions=[], raw_response="")

    # Get API key
    resolved_key = (api_key or "").strip()
    if not resolved_key:
        resolved_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not resolved_key:
        resolved_key = os.environ.get("ANTHROPIC_AUTH_TOKEN", "").strip()

    # Build environment for SDK
    env: dict[str, str] = {}
    setting_sources: list[str] | None = None

    if resolved_key:
        if resolved_key.lower().startswith("sk-ant-oat"):
            env["ANTHROPIC_AUTH_TOKEN"] = resolved_key
        else:
            env["ANTHROPIC_API_KEY"] = resolved_key
        logger.info(f"LLM Triage: Using API key (prefix: {resolved_key[:10]}...)")
    else:
        # Fall back to Claude Code auth
        setting_sources = ["user"]
        logger.info("LLM Triage: Using Claude Code auth")

    # Create SDK options (no tools needed for triage)
    options = ClaudeAgentOptions(
        model="claude-sonnet-4-20250514",
        system_prompt=TRIAGE_SYSTEM_PROMPT,
        mcp_servers={},  # No MCP tools needed
        allowed_tools=[],  # No tools needed
        cwd=os.getcwd(),  # Required by SDK
        max_turns=1,  # Single turn for triage
        permission_mode="bypassPermissions",  # No permissions needed for triage
        env=env,
        setting_sources=setting_sources,
    )
    print(f"[LLM Triage] SDK options: model={options.model}, cwd={options.cwd}")

    # Create and connect client
    client = ClaudeSDKClient(options)

    try:
        await client.connect()
        print("[LLM Triage] SDK client connected")

        # Build triage prompt
        prompt = _build_triage_prompt(findings)
        print(f"[LLM Triage] Sending {len(findings)} findings for triage")
        print(f"[LLM Triage] Prompt preview: {prompt[:500]}...")

        # Send query and collect response
        await client.query(prompt)

        response_parts: list[str] = []
        message_count = 0
        async for message in client.receive_response():
            message_count += 1
            msg_type = message.__class__.__name__
            print(f"[LLM Triage] Message {message_count}: {msg_type}")

            if msg_type == "AssistantMessage":
                content_blocks = getattr(message, "content", [])
                print(f"[LLM Triage] AssistantMessage has {len(content_blocks)} blocks")
                for block in content_blocks:
                    block_type = block.__class__.__name__
                    print(f"[LLM Triage] Block type: {block_type}")
                    if block_type == "TextBlock":
                        text = getattr(block, "text", "")
                        if text:
                            print(f"[LLM Triage] TextBlock content: {text[:200]}...")
                            response_parts.append(text)
            elif msg_type == "ResultMessage":
                is_error = getattr(message, "is_error", False)
                result = getattr(message, "result", None)
                print(f"[LLM Triage] ResultMessage: is_error={is_error}, result={result}")

        raw_response = "".join(response_parts)
        print(f"[LLM Triage] Total response: {len(raw_response)} chars")
        if raw_response:
            print(f"[LLM Triage] Response preview: {raw_response[:500]}...")

        # Parse response
        finding_ids = [f.get("id", f"unknown-{i}") for i, f in enumerate(findings)]
        decisions = _parse_triage_response(raw_response, finding_ids)

        return TriageResult(decisions=decisions, raw_response=raw_response)

    finally:
        await client.disconnect()
        logger.info("LLM Triage: SDK client disconnected")

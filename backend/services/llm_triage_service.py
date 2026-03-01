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


TRIAGE_SYSTEM_PROMPT = """You are an extremely strict security auditor. Your job is to AGGRESSIVELY FILTER OUT false positives.

## CRITICAL RULE: We prefer ZERO valid issues over ANY false positives.

Only mark something as "valid_security_issue" if you are 95%+ confident it is a REAL, EXPLOITABLE vulnerability that an attacker could actually use in production.

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

## Dispositions

- **valid_security_issue**: ONLY for clearly exploitable production vulnerabilities (use sparingly!)
- **by_design**: Intentional features, dev flags, test configurations
- **hardening**: Suggestions without actual vulnerability
- **speculative**: Theoretical issues, unlikely conditions required
- **bug**: Code defects without security impact
- **misconfiguration**: Config issues without direct exploit path

## Response Format

JSON array only:
```json
[{"finding_id": "id", "decision": "disposition", "confidence": 0-100, "reasoning": ["reason1", "reason2"]}]
```

BE AGGRESSIVE. When in doubt, REJECT. False positives waste security team time."""


def _read_file_context(repo_path: str, file_path: str, line_start: int | None = None, context_lines: int = 50) -> str:
    """Read file content with context around the vulnerable line."""
    from pathlib import Path

    try:
        full_path = Path(repo_path) / file_path
        if not full_path.exists():
            return f"[File not found: {file_path}]"

        if full_path.stat().st_size > 500000:  # 500KB limit
            return f"[File too large: {file_path}]"

        content = full_path.read_text(errors="replace")
        lines = content.split("\n")

        if line_start and line_start > 0:
            # Get context around the vulnerable line
            start = max(0, line_start - context_lines)
            end = min(len(lines), line_start + context_lines)
            context = lines[start:end]

            # Add line numbers
            numbered_lines = []
            for i, line in enumerate(context, start=start + 1):
                marker = ">>>" if i == line_start else "   "
                numbered_lines.append(f"{marker} {i:4d} | {line}")

            return "\n".join(numbered_lines)
        else:
            # Return first 100 lines with line numbers
            return "\n".join(f"   {i:4d} | {line}" for i, line in enumerate(lines[:100], 1))

    except Exception as e:
        return f"[Error reading file: {e}]"


def _build_triage_prompt(findings: list[dict[str, Any]], repo_path: str | None = None) -> str:
    """Build the triage prompt with finding details and actual code."""
    findings_text = []

    for i, finding in enumerate(findings, 1):
        finding_id = finding.get("id", f"unknown-{i}")
        title = finding.get("title", "Unknown")
        severity = finding.get("severity", "unknown")
        file_path = finding.get("file_path", "unknown")
        line_start = finding.get("line_start")
        vuln_type = finding.get("vulnerability_type", "unknown")
        description = finding.get("description", "No description")
        code_snippet = finding.get("code_snippet", "")
        attack_scenario = finding.get("attack_scenario", "")

        finding_text = f"""
## Finding {i}: {title}
- **ID**: {finding_id}
- **Severity**: {severity}
- **File**: {file_path}
- **Line**: {line_start or "unknown"}
- **Type**: {vuln_type}

**Description**: {description}
"""
        # Include original code snippet if available
        if code_snippet:
            finding_text += f"\n**Reported Code Snippet**:\n```\n{code_snippet}\n```\n"

        # Read actual file content for verification
        if repo_path and file_path:
            actual_code = _read_file_context(repo_path, file_path, line_start)
            finding_text += f"\n**Actual File Content (with context)**:\n```\n{actual_code}\n```\n"

        if attack_scenario:
            finding_text += f"\n**Attack Scenario**: {attack_scenario}\n"

        findings_text.append(finding_text)

    prompt = f"""Please triage the following {len(findings)} security findings.

IMPORTANT: You have access to the ACTUAL FILE CONTENT. Use it to verify:
1. Is this code actually vulnerable as described?
2. Is there additional context (dev flags, test code, etc.) that invalidates this finding?
3. Look for patterns like: disableAuth, debugMode, testMode, DEV_ONLY, etc.

{''.join(findings_text)}

Analyze each finding using the actual code and provide your triage decisions as a JSON array."""

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
    model: str = "claude-sonnet-4-5-20250929",
    use_claude_code_auth: bool = False,
    repo_path: str | None = None,
) -> TriageResult:
    """Run LLM-based triage on findings using Claude SDK.

    Args:
        findings: List of finding dicts to triage
        api_key: Optional API key (falls back to environment variable)
        model: Model to use for triage
        use_claude_code_auth: If True, use Claude Code subscription auth

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

    # Build environment and auth settings based on mode
    env: dict[str, str] = {}
    setting_sources: list[str] | None = None

    if use_claude_code_auth:
        # Use Claude Code subscription auth (loads user settings)
        setting_sources = ["user"]
        print("[LLM Triage] Using Claude Code auth mode")
    else:
        # Use API key auth
        resolved_key = (api_key or "").strip()
        if not resolved_key:
            resolved_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
        if not resolved_key:
            resolved_key = os.environ.get("ANTHROPIC_AUTH_TOKEN", "").strip()

        if not resolved_key:
            raise RuntimeError(
                "No API key provided. Configure in Settings or use Claude Code auth."
            )

        if resolved_key.lower().startswith("sk-ant-oat"):
            env["ANTHROPIC_AUTH_TOKEN"] = resolved_key
        else:
            env["ANTHROPIC_API_KEY"] = resolved_key
        print(f"[LLM Triage] Using API key (prefix: {resolved_key[:15]}...)")

    # Create SDK options (no tools needed for triage)
    options = ClaudeAgentOptions(
        model=model,
        system_prompt=TRIAGE_SYSTEM_PROMPT,
        mcp_servers={},  # No MCP tools needed
        allowed_tools=[],  # No tools needed
        cwd=os.getcwd(),  # Required by SDK
        max_turns=1,  # Single turn for triage
        permission_mode="bypassPermissions",  # No permissions needed for triage
        env=env,
        setting_sources=setting_sources,
    )
    print(f"[LLM Triage] SDK options: model={model}, auth_mode={'claude_code' if use_claude_code_auth else 'api_key'}")

    # Create and connect client
    client = ClaudeSDKClient(options)

    try:
        await client.connect()
        print("[LLM Triage] SDK client connected")

        # Build triage prompt with actual file content
        prompt = _build_triage_prompt(findings, repo_path)
        print(f"[LLM Triage] Sending {len(findings)} findings for triage (with file context)")
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

"""LM-driven root cause analysis for artifacts.

Reads evidence (artifact details, replay traces, code context) and
asks the LM to determine root cause, impact, severity, and fix.
"""
from __future__ import annotations

import os
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


async def analyze_artifact(
    artifact_id: str,
    evidence_refs: list[str] | None = None,
    target_source: str | None = None,
    artifact_details: dict | None = None,
) -> dict:
    """Analyze an artifact for root cause using LM.

    Returns:
        {
            "artifact_id": str,
            "root_cause": str | None,
            "impact": str | None,
            "severity_recommendation": str | None,  # critical/high/medium/low
            "recommended_fix": str | None,
            "analyzed": bool,
        }
    """
    result = {
        "artifact_id": artifact_id,
        "root_cause": None,
        "impact": None,
        "severity_recommendation": None,
        "recommended_fix": None,
        "analyzed": False,
    }

    # Build context for LM
    context_parts = [f"Artifact ID: {artifact_id}"]

    if artifact_details:
        context_parts.append(f"Type: {artifact_details.get('type', 'unknown')}")
        context_parts.append(f"Method: {artifact_details.get('method', 'unknown')}")
        context_parts.append(f"Path: {artifact_details.get('path', 'unknown')}")
        context_parts.append(f"Status: {artifact_details.get('status_code', 'unknown')}")
        if artifact_details.get("details"):
            context_parts.append(f"Details:\n{artifact_details['details'][:2000]}")

    if evidence_refs:
        context_parts.append(f"Evidence files: {', '.join(evidence_refs[:10])}")

    if target_source:
        context_parts.append(f"Target source:\n{target_source[:5000]}")

    context = "\n".join(context_parts)

    prompt = f"""You are a security researcher analyzing a fuzzing artifact. Determine the root cause, impact, severity, and recommended fix.

## Artifact Context
{context}

## Analysis Required
1. **Root Cause**: What is the underlying code defect? Be specific about the vulnerable code path.
2. **Impact**: What can an attacker do by exploiting this? (e.g., RCE, data leak, DoS, auth bypass)
3. **Severity**: Rate as critical/high/medium/low based on exploitability and impact.
4. **Recommended Fix**: What specific code change would fix this?

## Output Format (JSON)
{{
    "root_cause": "description of the root cause",
    "impact": "description of the security impact",
    "severity_recommendation": "critical|high|medium|low",
    "recommended_fix": "specific fix recommendation"
}}
"""

    # Try LM call
    lm_response = _call_lm(prompt)
    if lm_response:
        parsed = _parse_json_response(lm_response)
        if parsed:
            result.update(parsed)
            result["analyzed"] = True

    return result


def _call_lm(prompt: str) -> str | None:
    """Call the LM via Claude CLI or Anthropic SDK."""
    # Try Claude CLI
    try:
        import subprocess
        proc = subprocess.run(
            ["claude", "-p", "--output-format", "text"],
            input=prompt, capture_output=True, text=True, timeout=60,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Try Anthropic SDK
    try:
        import anthropic
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if api_key:
            client = anthropic.Anthropic(api_key=api_key)
            response = client.messages.create(
                model="claude-sonnet-4-5-20250514",
                max_tokens=2000,
                messages=[{"role": "user", "content": prompt}],
            )
            return response.content[0].text
    except (ImportError, Exception) as e:
        logger.debug("LM analysis failed: %s", e)

    return None


def _parse_json_response(response: str) -> dict | None:
    """Extract JSON from LM response."""
    import json

    # Try direct JSON parse
    try:
        return json.loads(response)
    except json.JSONDecodeError:
        pass

    # Try extracting JSON from markdown code block
    import re
    json_match = re.search(r'```(?:json)?\s*\n(.*?)\n```', response, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group(1))
        except json.JSONDecodeError:
            pass

    # Try finding JSON object in response
    brace_start = response.find("{")
    brace_end = response.rfind("}")
    if brace_start >= 0 and brace_end > brace_start:
        try:
            return json.loads(response[brace_start:brace_end + 1])
        except json.JSONDecodeError:
            pass

    return None

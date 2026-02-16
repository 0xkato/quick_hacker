"""JSON extraction utilities for parsing Claude CLI output.

Claude CLI outputs can contain JSON embedded in text, code blocks, or as raw JSON.
This module provides robust extraction with precompiled patterns for performance.
"""

import json
import re
from typing import Optional, Union

# Precompiled patterns for better performance
_JSON_CODE_BLOCK_PATTERN = re.compile(r'```json\s*([\s\S]*?)\s*```')
_JSON_GENERIC_BLOCK_PATTERN = re.compile(r'```\s*([\s\S]*?)\s*```')


def extract_json_from_output(content: str) -> Optional[dict]:
    """Extract JSON from Claude CLI output which may include preamble text.

    Tries multiple strategies in order:
    1. Direct JSON parse (if content is pure JSON)
    2. Extract from ```json code blocks
    3. Extract from generic ``` code blocks
    4. Find first { to last } and parse
    5. Find first [ to last ] and wrap as {"items": [...]}

    Args:
        content: Raw output from Claude CLI subprocess

    Returns:
        Parsed dict, or None if no valid JSON found
    """
    if not content:
        return None

    content = content.strip()

    # Strategy 1: Try direct parse (fastest path for pure JSON)
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass

    # Strategy 2: Find ALL ```json code blocks and prefer ones with pipeline-expected keys
    # Using findall instead of search ensures we don't miss the result block
    # when the first block is commentary/examples
    EXPECTED_KEYS = {"verdict", "classification", "signal_id", "signals", "findings", "sinks", "data_flows"}
    json_blocks = _JSON_CODE_BLOCK_PATTERN.findall(content)
    if json_blocks:
        best = None
        for block in json_blocks:
            try:
                parsed = json.loads(block.strip())
                if isinstance(parsed, dict):
                    if any(k in parsed for k in EXPECTED_KEYS):
                        return parsed  # Immediately return if it has expected keys
                    if best is None:
                        best = parsed
                elif isinstance(parsed, list) and best is None:
                    best = {"items": parsed}
            except json.JSONDecodeError:
                continue
        if best:
            return best

    # Strategy 3: Find ALL generic code blocks and prefer pipeline-relevant ones
    generic_blocks = _JSON_GENERIC_BLOCK_PATTERN.findall(content)
    if generic_blocks:
        best = None
        for block in generic_blocks:
            block_content = block.strip()
            if block_content.startswith('{') or block_content.startswith('['):
                try:
                    parsed = json.loads(block_content)
                    if isinstance(parsed, dict):
                        if any(k in parsed for k in EXPECTED_KEYS):
                            return parsed
                        if best is None:
                            best = parsed
                    elif isinstance(parsed, list) and best is None:
                        best = {"items": parsed}
                except json.JSONDecodeError:
                    continue
        if best:
            return best

    # Strategy 4: Find JSON object boundaries
    # Use a more robust approach - find matching braces
    json_obj = _extract_json_object(content)
    if json_obj is not None:
        return json_obj

    # Strategy 5: Find JSON array boundaries
    json_arr = _extract_json_array(content)
    if json_arr is not None:
        return {"items": json_arr}

    return None


def _extract_json_object(content: str) -> Optional[dict]:
    """Extract a JSON object from content by finding balanced braces.

    Args:
        content: Text potentially containing a JSON object

    Returns:
        Parsed dict or None
    """
    start = content.find('{')
    if start == -1:
        return None

    # Find the matching closing brace
    depth = 0
    in_string = False
    escape_next = False

    for i, char in enumerate(content[start:], start):
        if escape_next:
            escape_next = False
            continue

        if char == '\\' and in_string:
            escape_next = True
            continue

        if char == '"' and not escape_next:
            in_string = not in_string
            continue

        if in_string:
            continue

        if char == '{':
            depth += 1
        elif char == '}':
            depth -= 1
            if depth == 0:
                # Found matching brace
                try:
                    return json.loads(content[start:i + 1])
                except json.JSONDecodeError:
                    # Try to find another object
                    next_start = content.find('{', start + 1)
                    if next_start != -1:
                        return _extract_json_object(content[next_start:])
                    return None

    return None


def _extract_json_array(content: str) -> Optional[list]:
    """Extract a JSON array from content by finding balanced brackets.

    Args:
        content: Text potentially containing a JSON array

    Returns:
        Parsed list or None
    """
    start = content.find('[')
    if start == -1:
        return None

    # Find the matching closing bracket
    depth = 0
    in_string = False
    escape_next = False

    for i, char in enumerate(content[start:], start):
        if escape_next:
            escape_next = False
            continue

        if char == '\\' and in_string:
            escape_next = True
            continue

        if char == '"' and not escape_next:
            in_string = not in_string
            continue

        if in_string:
            continue

        if char == '[':
            depth += 1
        elif char == ']':
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(content[start:i + 1])
                except json.JSONDecodeError:
                    return None

    return None


def extract_all_json_objects(content: str) -> list[dict]:
    """Extract all JSON objects from content.

    Useful when output contains multiple JSON objects.

    Args:
        content: Text containing one or more JSON objects

    Returns:
        List of parsed dicts (may be empty)
    """
    results = []
    remaining = content

    while remaining:
        obj = _extract_json_object(remaining)
        if obj is None:
            break

        results.append(obj)

        # Find where this object ended and continue from there
        # This is approximate - we re-serialize and find the length
        obj_str = json.dumps(obj)
        # Find the actual end in the original content
        start = remaining.find('{')
        if start == -1:
            break

        # Skip past this object by finding its end
        depth = 0
        in_string = False
        escape_next = False
        end_pos = start

        for i, char in enumerate(remaining[start:], start):
            if escape_next:
                escape_next = False
                continue
            if char == '\\' and in_string:
                escape_next = True
                continue
            if char == '"' and not escape_next:
                in_string = not in_string
                continue
            if in_string:
                continue
            if char == '{':
                depth += 1
            elif char == '}':
                depth -= 1
                if depth == 0:
                    end_pos = i + 1
                    break

        remaining = remaining[end_pos:]

    return results

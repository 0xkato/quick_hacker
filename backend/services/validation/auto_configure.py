"""Auto-configure validation profile by analyzing codebase structure with LLM."""

import asyncio
import json
import os
import subprocess
from pathlib import Path
from typing import Optional

from models.validation_profile import ValidationProfile


def generate_directory_tree(
    repo_path: str,
    max_depth: int = 4,
    max_entries: int = 500,
    *,
    max_scandir_entries_per_dir: int = 500,
) -> str:
    """Generate a directory tree representation of the codebase.

    Args:
        repo_path: Path to the repository root
        max_depth: Maximum depth to traverse
        max_entries: Maximum number of entries to include
        max_scandir_entries_per_dir: Maximum number of directory entries to scan per directory

    Returns:
        String representation of the directory tree
    """
    lines = []
    entry_count = 0

    # Directories to always skip (noise)
    skip_dirs = {
        '.git', '.svn', '.hg', 'node_modules', '__pycache__', '.pytest_cache',
        '.mypy_cache', '.tox', '.eggs', '*.egg-info', 'dist', 'build',
        '.next', '.nuxt', '.venv', 'venv', 'env', '.env',
        'coverage', '.coverage', 'htmlcov', '.nyc_output',
        'target', 'out', 'bin', 'obj', '.idea', '.vscode',
    }

    def should_skip(name: str) -> bool:
        return name in skip_dirs or name.startswith('.')

    def walk_dir(path: Path, prefix: str = "", depth: int = 0) -> None:
        nonlocal entry_count

        if depth > max_depth or entry_count >= max_entries:
            return

        try:
            dir_names: list[str] = []
            file_names: list[str] = []
            truncated_dir_scan = False

            scanned = 0
            with os.scandir(path) as it:
                for entry in it:
                    scanned += 1
                    if scanned > max_scandir_entries_per_dir:
                        truncated_dir_scan = True
                        break

                    name = entry.name
                    if name.startswith("."):
                        continue

                    try:
                        if entry.is_symlink():
                            continue
                        is_dir = entry.is_dir(follow_symlinks=False)
                    except OSError:
                        continue

                    if is_dir:
                        if should_skip(name):
                            continue
                        dir_names.append(name)
                    else:
                        # Only include non-hidden files (already filtered by leading dot above)
                        if entry.is_file(follow_symlinks=False):
                            file_names.append(name)
        except (PermissionError, FileNotFoundError, NotADirectoryError):
            return

        dir_names.sort(key=str.lower)
        file_names.sort(key=str.lower)

        # Limit files shown per directory
        if len(file_names) > 10:
            file_names = file_names[:8]
            files_truncated = True
        else:
            files_truncated = False

        all_entries: list[tuple[str, bool]] = [(name, True) for name in dir_names] + [(name, False) for name in file_names]
        if truncated_dir_scan:
            all_entries.append(("... (truncated)", False))

        for i, (name, is_dir) in enumerate(all_entries):
            if entry_count >= max_entries:
                lines.append(f"{prefix}... (truncated)")
                return

            is_last = (i == len(all_entries) - 1) and not files_truncated
            connector = "└── " if is_last else "├── "

            if is_dir:
                lines.append(f"{prefix}{connector}{name}/")
                entry_count += 1
                extension = "    " if is_last else "│   "
                walk_dir(path / name, prefix + extension, depth + 1)
            else:
                lines.append(f"{prefix}{connector}{name}")
                entry_count += 1

        if files_truncated:
            lines.append(f"{prefix}└── ... (more files)")
            entry_count += 1

    root = Path(repo_path)
    lines.append(f"{root.name}/")
    walk_dir(root)

    return "\n".join(lines)


AUTO_CONFIGURE_PROMPT = """You are a security engineer configuring a vulnerability scanner for a codebase.

Analyze this directory tree and suggest a validation profile that will reduce false positives by:
1. Excluding paths that don't matter for security (tests, docs, tools, third-party code, examples, benchmarks)
2. Identifying what kind of project this is (C/C++, web app, library, etc.)
3. Suggesting appropriate attacker models based on what the code does

Directory tree:
```
{tree}
```

Based on this codebase structure, provide a JSON validation profile with these fields:

1. `excluded_paths`: List of directory prefixes to skip. Be generous - exclude anything that:
   - Contains test code (test/, tests/, testing/, *_test/, spec/, __tests__)
   - Is third-party/vendored code (third_party/, vendor/, external/, deps/)
   - Is documentation (docs/, doc/, documentation/)
   - Is build/tooling (tools/, scripts/, build/, cmake/, make/, infra/)
   - Is examples/samples (examples/, samples/, demo/, benchmarks/)
   - Is generated code (gen/, generated/, out/, dist/)

2. `enabled_verifiers`: List of verification tools. Include "gdb" if this is C/C++ code.

3. `require_shipped_reachability`: true (always require proof code actually ships/runs)

4. `default_verdict`: "not_actionable" (be conservative)

Return ONLY valid JSON, no explanation. Example format:
```json
{{
  "excluded_paths": ["test/", "third_party/", "docs/"],
  "enabled_verifiers": ["gdb"],
  "require_shipped_reachability": true,
  "default_verdict": "not_actionable"
}}
```"""


def _call_claude_code(prompt: str, model: str = "claude-sonnet-4-20250514") -> str:
    """Call Claude Code CLI for a one-shot prompt.

    Uses the user's Claude Code authentication (no API key needed).

    Args:
        prompt: The prompt to send
        model: Model to use

    Returns:
        The response text

    Raises:
        RuntimeError: If Claude Code is not available or fails
    """
    import shutil

    # Check if claude is available
    claude_path = shutil.which("claude")
    if not claude_path:
        raise RuntimeError("Claude Code CLI not found. Please install it or configure an API key.")

    # Run claude with the prompt (non-interactive, print mode)
    # Use -p for print mode (non-interactive, just outputs response)
    try:
        result = subprocess.run(
            [
                claude_path,
                "-p",  # Print mode: non-interactive, just print response
                "--model", model,
                "--output-format", "text",  # Plain text output
                prompt
            ],
            capture_output=True,
            text=True,
            timeout=120,  # 2 minute timeout
        )

        if result.returncode != 0:
            error_msg = result.stderr.strip() if result.stderr else "Unknown error"
            raise RuntimeError(f"Claude Code failed (exit {result.returncode}): {error_msg}")

        return result.stdout

    except subprocess.TimeoutExpired:
        raise RuntimeError("Claude Code timed out")
    except FileNotFoundError:
        raise RuntimeError("Claude Code CLI not found")


def _call_anthropic_api(prompt: str, api_key: str, model: str = "claude-sonnet-4-20250514") -> str:
    """Call Anthropic API directly with an API key.

    Args:
        prompt: The prompt to send
        api_key: Anthropic API key
        model: Model to use

    Returns:
        The response text
    """
    import anthropic

    client = anthropic.Anthropic(api_key=api_key)
    message = client.messages.create(
        model=model,
        max_tokens=2000,
        messages=[{"role": "user", "content": prompt}]
    )
    return message.content[0].text


def _call_openai_api(prompt: str, api_key: str, model: str = "gpt-4o") -> str:
    """Call OpenAI API directly with an API key.

    Args:
        prompt: The prompt to send
        api_key: OpenAI API key
        model: Model to use

    Returns:
        The response text
    """
    import openai

    client = openai.OpenAI(api_key=api_key)
    response = client.chat.completions.create(
        model=model,
        max_tokens=2000,
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content


def _parse_llm_response(response_text: str) -> dict:
    """Parse JSON from LLM response, handling markdown code blocks.

    Args:
        response_text: Raw LLM response

    Returns:
        Parsed JSON dict

    Raises:
        ValueError: If response is not valid JSON
    """
    # Extract JSON from response (handle markdown code blocks)
    if "```json" in response_text:
        json_start = response_text.find("```json") + 7
        json_end = response_text.find("```", json_start)
        response_text = response_text[json_start:json_end].strip()
    elif "```" in response_text:
        json_start = response_text.find("```") + 3
        json_end = response_text.find("```", json_start)
        response_text = response_text[json_start:json_end].strip()

    try:
        return json.loads(response_text)
    except json.JSONDecodeError as e:
        raise ValueError(f"LLM returned invalid JSON: {e}\nResponse: {response_text[:500]}")


async def auto_configure_profile(
    repo_path: str,
    api_key: Optional[str] = None,
    provider: str = "anthropic",
    model: str = "claude-sonnet-4-20250514",
) -> ValidationProfile:
    """Auto-configure a validation profile by analyzing codebase with LLM.

    Uses Claude Code CLI if available (no API key needed), otherwise falls back
    to direct API calls with the provided credentials.

    Args:
        repo_path: Path to the repository root
        api_key: Optional API key (not needed if using Claude Code)
        provider: Provider name ("anthropic" or "openai")
        model: Model to use for analysis

    Returns:
        ValidationProfile with suggested settings
    """
    # Generate directory tree
    tree = await asyncio.to_thread(generate_directory_tree, repo_path)
    prompt_content = AUTO_CONFIGURE_PROMPT.format(tree=tree)

    # Try Claude Code CLI first (no API key needed)
    response_text = None
    try:
        print("[AutoConfigure] Trying Claude Code CLI...")
        response_text = await asyncio.to_thread(_call_claude_code, prompt_content, model)
        print("[AutoConfigure] Claude Code CLI succeeded")
    except RuntimeError as e:
        print(f"[AutoConfigure] Claude Code CLI not available: {e}")

        # Fall back to API calls
        if not api_key:
            raise ValueError(
                "Claude Code CLI not available and no API key configured. "
                "Please install Claude Code or configure an API key in Settings."
            )

        print(f"[AutoConfigure] Falling back to {provider} API...")
        if provider == "anthropic":
            response_text = await asyncio.to_thread(_call_anthropic_api, prompt_content, api_key, model)
        elif provider == "openai":
            response_text = await asyncio.to_thread(_call_openai_api, prompt_content, api_key, model)
        else:
            raise ValueError(f"Unsupported provider: {provider}")

    # Parse response
    config = _parse_llm_response(response_text)

    # Build ValidationProfile from LLM suggestions
    profile = ValidationProfile(
        excluded_paths=config.get("excluded_paths", []),
        enabled_verifiers=config.get("enabled_verifiers", []),
        require_shipped_reachability=config.get("require_shipped_reachability", True),
        default_verdict=config.get("default_verdict", "not_actionable"),
        # Keep advanced settings empty - user can customize via JSON editor
        attacker_roles={},
        trust_boundaries={},
        evidence_gates={},
    )

    return profile

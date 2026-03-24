"""LM-driven harness generation — uses Claude/Codex to generate harnesses
that call actual target code based on source analysis.

When the LM is available, it reads the target source, understands the API,
and generates a harness that exercises real functions. When unavailable,
falls back to template harnesses.
"""
from __future__ import annotations

import os
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def generate_harness_with_lm(
    engine: str,
    target: dict,
    repo_path: str,
    template_code: str,
    compiler_prompt: str | None = None,
) -> str | None:
    """Ask the LM to generate a harness for the given engine + target.

    Args:
        engine: Engine name (aflpp, atheris, jazzer, etc.)
        target: Target descriptor with entrypoint, language, etc.
        repo_path: Path to the target repository
        template_code: The template harness (with TODOs) as fallback context
        compiler_prompt: Optional override for the compiler prompt

    Returns:
        Generated harness code, or None if LM is unavailable.
    """
    # Read the target source code
    source_context = _read_target_source(target, repo_path)
    if not source_context:
        logger.warning("Could not read target source for %s", target.get("entrypoint"))
        return None

    # Load the engine-specific compiler prompt
    prompt = compiler_prompt or _load_compiler_prompt(engine)

    # Build the full prompt
    full_prompt = _build_prompt(engine, target, source_context, template_code, prompt)

    # Call the LM
    try:
        response = _call_lm(full_prompt)
        if response:
            # Extract code from response (handle markdown code blocks)
            code = _extract_code(response)
            return code
    except Exception as e:
        logger.warning("LM harness generation failed for %s: %s", engine, e)

    return None


def _read_target_source(target: dict, repo_path: str, max_bytes: int = 50000) -> str | None:
    """Read the target's source code for context."""
    entrypoint = target.get("entrypoint", "")

    # Parse entrypoint to find the source file
    # Formats: "module/file.py:function", "pkg:Class", "GET /api/users", "file.sol:Contract"
    source_file = None

    if ":" in entrypoint and not entrypoint.startswith(("GET ", "POST ", "PUT ", "DELETE ", "PATCH ")):
        # file:function format
        file_part = entrypoint.split(":")[0]
        candidates = [
            Path(repo_path) / file_part,
            Path(repo_path) / f"{file_part}.py",
            Path(repo_path) / f"src/{file_part}",
            Path(repo_path) / f"lib/{file_part}",
        ]
        for c in candidates:
            if c.exists() and c.is_file():
                source_file = c
                break

    if not source_file:
        # Try to find relevant files by extension
        language = target.get("language", "")
        ext_map = {
            "python": "*.py", "c": "*.c", "cpp": "*.cpp", "java": "*.java",
            "go": "*.go", "rust": "*.rs", "solidity": "*.sol",
            "javascript": "*.js", "typescript": "*.ts",
        }
        pattern = ext_map.get(language, "*.*")

        # Find the most relevant source files (filter on relative path to avoid
        # false positives from parent directories like /tmp/pytest-…)
        p = Path(repo_path)
        skip_dirs = {"node_modules", "vendor", ".git", "__pycache__", "test", "spec"}
        source_files = sorted(
            [f for f in p.rglob(pattern)
             if not (skip_dirs & set(f.relative_to(p).parts))],
            key=lambda f: f.stat().st_size,
            reverse=True,
        )[:5]  # Top 5 largest non-test files

        if source_files:
            combined = []
            total = 0
            for sf in source_files:
                content = sf.read_text(errors="ignore")
                if total + len(content) > max_bytes:
                    break
                combined.append(f"// === {sf.relative_to(repo_path)} ===\n{content}")
                total += len(content)
            return "\n\n".join(combined)

    if source_file:
        content = source_file.read_text(errors="ignore")
        return content[:max_bytes]

    return None


def _load_compiler_prompt(engine: str) -> str:
    """Load the engine-specific compiler prompt from prompting/compilers/."""
    prompt_dir = Path(__file__).parent.parent.parent / "prompting" / "compilers"

    # Map engine to prompt file
    prompt_map = {
        "aflpp": "harness_codegen.md",
        "atheris": "harness_codegen.md",
        "hypothesis": "harness_codegen.md",
        "jazzer": "harness_codegen.md",
        "go_fuzz": "harness_codegen.md",
        "cargo_fuzz": "harness_codegen.md",
        "echidna": "invariant_codegen.md",
        "foundry": "invariant_codegen.md",
        "boofuzz": "harness_codegen.md",
        "restler": "harness_codegen.md",
        "schemathesis": "schemathesis_hooks.md",
        "grammarinator": "dictionary_codegen.md",
        "sqlsmith": "harness_codegen.md",
        "radamsa": "mutator_codegen.md",
    }

    prompt_file = prompt_dir / prompt_map.get(engine, "harness_codegen.md")
    if prompt_file.exists():
        return prompt_file.read_text()

    return ""


def _build_prompt(engine: str, target: dict, source: str, template: str, compiler_prompt: str) -> str:
    """Build the full prompt for LM harness generation."""
    return f"""You are a security fuzzing expert. Generate a complete, working fuzz harness.

## Engine: {engine}
## Target: {target.get('entrypoint', 'unknown')}
## Language: {target.get('language', 'unknown')}

## Compiler Instructions
{compiler_prompt}

## Target Source Code
```
{source[:30000]}
```

## Template (fill in the TODOs with real code)
```
{template}
```

## Requirements
1. The harness MUST import and call REAL functions from the target source code
2. The harness MUST compile and run without errors
3. The harness MUST NOT use mocks or stubs
4. The harness MUST handle the target's actual data types and APIs
5. Replace ALL TODO comments with working code

## Output
Return ONLY the complete harness source code. No explanations, no markdown, just code.
"""


def _call_lm(prompt: str) -> str | None:
    """Call the LM to generate harness code.

    Uses Claude CLI if available, falls back to Anthropic SDK.
    """
    # Try Claude CLI first (uses subscription auth)
    try:
        import subprocess
        result = subprocess.run(
            ["claude", "-p", "--output-format", "text"],
            input=prompt,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
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
                max_tokens=8000,
                messages=[{"role": "user", "content": prompt}],
            )
            return response.content[0].text
    except ImportError:
        pass
    except Exception as e:
        logger.warning("Anthropic SDK call failed: %s", e)

    return None


def _extract_code(response: str) -> str:
    """Extract code from LM response, handling markdown code blocks."""
    # Remove markdown code fences if present
    lines = response.strip().splitlines()

    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]

    return "\n".join(lines)

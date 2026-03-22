"""Schemathesis harness compiler.

Generates a Schemathesis test module (Python source code string)
for a given lane spec and target.
"""

from __future__ import annotations

import re
import textwrap


def _safe_identifier(name: str) -> str:
    """Turn an arbitrary string into a valid Python identifier fragment.

    Replaces spaces, slashes, braces, and other non-alphanumeric chars with
    underscores, then collapses runs of underscores and strips leading/trailing
    underscores.
    """
    safe = re.sub(r"[^A-Za-z0-9]", "_", name)
    safe = re.sub(r"_+", "_", safe)
    return safe.strip("_")


def compile_schemathesis_config(
    lane_spec: dict,
    target: dict,
    openapi_url: str,
    base_url: str = "http://target:8080",
) -> str:
    """Generate a Schemathesis test module as Python source code.

    Args:
        lane_spec: Lane spec dict with oracle_packs, feedback_models, etc.
        target: Target dict with entrypoint, stateful, etc.
        openapi_url: URL or path to OpenAPI spec (relative to base_url or
            absolute file path).
        base_url: Base URL of the target service.

    Returns:
        Python source code string ready to be written to a .py file and
        executed by ``schemathesis run`` or ``pytest``.
    """
    entrypoint: str = target.get("entrypoint", "unknown")
    stateful: bool = target.get("stateful", False)
    oracle_packs: list[str] = lane_spec.get("oracle_packs", [])

    func_suffix = _safe_identifier(entrypoint)
    schema_url = f"{base_url.rstrip('/')}/{openapi_url.lstrip('/')}"

    # --- Build schema loader line -------------------------------------------
    if stateful:
        schema_line = (
            f'schema = schemathesis.from_url("{schema_url}", '
            f"stateful=schemathesis.Stateful.links)"
        )
    else:
        schema_line = f'schema = schemathesis.from_url("{schema_url}")'

    # --- Collect oracle assertion blocks ------------------------------------
    oracle_blocks: list[str] = []

    if "schema_conformance" in oracle_packs:
        oracle_blocks.append(
            "    # Oracle: schema_conformance\n"
            "    case.validate_response(response)"
        )

    if "status_code" in oracle_packs:
        oracle_blocks.append(
            "    # Oracle: status_code\n"
            '    assert response.status_code < 500, '
            'f"Server error: {response.status_code}"'
        )

    # --- Auth hook for authz_diff -------------------------------------------
    auth_hook_lines: list[str] = []
    if "authz_diff" in oracle_packs:
        auth_hook_lines = [
            "",
            '@schema.hook("before_call")',
            "def add_auth(context, case, **kwargs):",
            "    case.headers = case.headers or {}",
            '    case.headers["Authorization"] = "Bearer test-token"',
            "",
        ]
        oracle_blocks.append(
            "    # Oracle: authz_diff\n"
            "    # Authorization header injected via before_call hook"
        )

    # --- Assemble oracle body -----------------------------------------------
    if oracle_blocks:
        oracle_body = "\n".join(oracle_blocks)
    else:
        oracle_body = "    pass"

    # --- Final module -------------------------------------------------------
    lines: list[str] = [
        f'"""Auto-generated Schemathesis harness for {entrypoint}"""',
        "import schemathesis",
        "",
        schema_line,
    ]
    lines.extend(auth_hook_lines)
    lines.append("")
    lines.append("@schema.parametrize()")
    lines.append(f"def test_{func_suffix}(case):")
    lines.append("    response = case.call()")
    lines.append(oracle_body)
    lines.append("")

    return "\n".join(lines)

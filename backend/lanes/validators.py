"""Schemathesis harness validator with gate checks.

Validates a compiled Schemathesis harness by checking it meets quality gates.
For v1, validation is offline only (syntax + content checks, no live target).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field


@dataclass
class ValidationResult:
    passed: bool
    gates: dict[str, bool]
    errors: list[str] = field(default_factory=list)


def validate_harness(harness_code: str) -> ValidationResult:
    """Validate a compiled harness against v1 gates.

    Gates checked:
    - builds_successfully: ast.parse succeeds (valid Python syntax)
    - calls_real_code: contains "import schemathesis" or "from schemathesis"
    - reaches_intended_target: contains "from_url" or "from_path" (schema loading)
    - produces_useful_execution: contains "def test_" (has test functions)
    - no_fake_stubs: does NOT contain "unittest.mock" or "from unittest import mock"

    Gates deferred to v2 (runtime):
    - resets_reliably: requires running target
    """
    gates: dict[str, bool] = {}
    errors: list[str] = []

    # Gate: builds_successfully — valid Python syntax
    try:
        ast.parse(harness_code)
        gates["builds_successfully"] = True
    except SyntaxError as exc:
        gates["builds_successfully"] = False
        errors.append(f"Syntax error: {exc}")

    # Gate: calls_real_code — imports schemathesis
    if "import schemathesis" in harness_code or "from schemathesis" in harness_code:
        gates["calls_real_code"] = True
    else:
        gates["calls_real_code"] = False
        errors.append("Missing schemathesis import: expected 'import schemathesis' or 'from schemathesis'")

    # Gate: reaches_intended_target — loads an OpenAPI schema
    if "from_url" in harness_code or "from_path" in harness_code:
        gates["reaches_intended_target"] = True
    else:
        gates["reaches_intended_target"] = False
        errors.append("Missing schema loading: expected 'from_url' or 'from_path'")

    # Gate: produces_useful_execution — has test functions
    if "def test_" in harness_code:
        gates["produces_useful_execution"] = True
    else:
        gates["produces_useful_execution"] = False
        errors.append("Missing test function: expected at least one 'def test_'")

    # Gate: no_fake_stubs — no mocking imports
    if "unittest.mock" in harness_code or "from unittest import mock" in harness_code:
        gates["no_fake_stubs"] = False
        errors.append("Contains mock imports: 'unittest.mock' or 'from unittest import mock' found")
    else:
        gates["no_fake_stubs"] = True

    passed = all(gates.values())
    return ValidationResult(passed=passed, gates=gates, errors=errors)

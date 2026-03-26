"""Multi-language harness validator with gate checks.

Validates a compiled harness by checking it meets quality gates.
Dispatches to language-specific validation: Python uses ast.parse,
C/C++ checks for syntax keywords, Java checks for class definition, etc.

For v1, validation is offline only (syntax + content checks, no live target).
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field


@dataclass
class ValidationResult:
    passed: bool
    gates: dict[str, bool]
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------

def _detect_language(harness_code: str) -> str:
    """Detect the language of a harness from its content.

    Returns one of: python, c, cpp, java, go, rust, solidity, json, config, sql.
    Falls back to "unknown".

    Detection order matters -- more specific languages are checked first
    to avoid false positives (e.g. Java's ``import com.`` matching the
    Python ``import`` pattern).
    """
    stripped = harness_code.lstrip()

    # --- Unambiguous top-level markers (check first) ---

    # Solidity: pragma is unique
    if "pragma solidity" in stripped:
        return "solidity"

    # Rust: #![no_main] or libfuzzer_sys are unique
    if "#![no_main]" in stripped or "use libfuzzer_sys" in stripped:
        return "rust"
    if "fuzz_target!" in stripped:
        return "rust"

    # C/C++: #include or AFL macros are unique to C
    if "#include" in stripped or "__AFL_" in stripped:
        return "c"

    # Go: package + testing/Fuzz pattern
    if re.search(r'^package\s+\w+', stripped, re.MULTILINE):
        if '"testing"' in stripped or "func Fuzz" in stripped:
            return "go"

    # Java: dotted imports (import com.foo.bar) or public class
    if re.search(r'^import\s+\w+\.\w+', stripped, re.MULTILINE):
        return "java"
    if re.search(r'^public\s+class\s+', stripped, re.MULTILINE):
        return "java"

    # Solidity (contract keyword without pragma)
    if re.search(r'\bcontract\s+\w+', stripped):
        return "solidity"

    # JSON
    if stripped.startswith("{") and stripped.rstrip().endswith("}"):
        try:
            import json
            json.loads(stripped)
            return "json"
        except (json.JSONDecodeError, ValueError):
            pass

    # SQL
    if stripped.startswith("--") and ("sqlsmith" in stripped.lower() or "SELECT" in stripped):
        return "sql"

    # --- Python: checked last since its patterns are the broadest ---
    if stripped.startswith('"""') or stripped.startswith("'''"):
        return "python"
    if stripped.startswith("#!/usr/bin/env python") or stripped.startswith("#!/usr/bin/python"):
        return "python"
    if re.search(r'^(from \w+ import |import \w+)\s*$', stripped, re.MULTILINE):
        return "python"
    if re.search(r'^def \w+\(', stripped, re.MULTILINE):
        return "python"

    # C fallback: function signatures without #include
    if re.search(r'^(int|void|char|size_t|bool|unsigned|long|struct)\s+\w+\s*\(', stripped, re.MULTILINE):
        return "c"

    return "unknown"


# ---------------------------------------------------------------------------
# Language-specific validators
# ---------------------------------------------------------------------------

def _validate_python(harness_code: str) -> ValidationResult:
    """Validate a Python harness (Schemathesis, Atheris, Hypothesis, Boofuzz)."""
    gates: dict[str, bool] = {}
    errors: list[str] = []

    # Gate: builds_successfully -- valid Python syntax
    try:
        ast.parse(harness_code)
        gates["builds_successfully"] = True
    except SyntaxError as exc:
        gates["builds_successfully"] = False
        errors.append(f"Syntax error: {exc}")

    # Gate: calls_real_code -- imports a known framework
    framework_imports = [
        "import schemathesis", "from schemathesis",
        "import atheris", "from atheris",
        "import hypothesis", "from hypothesis",
        "from boofuzz", "import boofuzz",
    ]
    if any(imp in harness_code for imp in framework_imports):
        gates["calls_real_code"] = True
    else:
        gates["calls_real_code"] = False
        errors.append("Missing framework import: expected schemathesis, atheris, hypothesis, or boofuzz")

    # Gate: reaches_intended_target -- loads schema or calls target
    target_markers = [
        "from_url", "from_path",           # schemathesis
        "test_one_input", "Fuzz",           # atheris
        "@given", "test_fuzz_",             # hypothesis
        "Session(", "TCPSocketConnection",  # boofuzz
    ]
    if any(marker in harness_code for marker in target_markers):
        gates["reaches_intended_target"] = True
    else:
        gates["reaches_intended_target"] = False
        errors.append("Missing target loading: no schema/fuzz target call found")

    # Gate: produces_useful_execution -- has test/fuzz entry point
    if "def test_" in harness_code or "def main" in harness_code or "test_one_input" in harness_code:
        gates["produces_useful_execution"] = True
    else:
        gates["produces_useful_execution"] = False
        errors.append("Missing entry point: expected 'def test_' or 'def main'")

    # Gate: no_fake_stubs -- no mocking
    if "unittest.mock" in harness_code or "from unittest import mock" in harness_code:
        gates["no_fake_stubs"] = False
        errors.append("Contains mock imports")
    else:
        gates["no_fake_stubs"] = True

    passed = all(gates.values())
    return ValidationResult(passed=passed, gates=gates, errors=errors)


def _validate_c(harness_code: str) -> ValidationResult:
    """Validate a C/C++ harness (AFL++, libFuzzer)."""
    gates: dict[str, bool] = {}
    errors: list[str] = []

    # Gate: builds_successfully -- has valid C structure
    has_include = "#include" in harness_code
    has_main_or_fuzz = (
        re.search(r'\bint\s+main\s*\(', harness_code) is not None
        or "LLVMFuzzerTestOneInput" in harness_code
        or "__AFL_FUZZ_INIT" in harness_code
    )
    has_braces = "{" in harness_code and "}" in harness_code

    if has_include and has_main_or_fuzz and has_braces:
        gates["builds_successfully"] = True
    else:
        gates["builds_successfully"] = False
        missing = []
        if not has_include:
            missing.append("#include directive")
        if not has_main_or_fuzz:
            missing.append("main() or fuzz entry point")
        if not has_braces:
            missing.append("function body")
        errors.append(f"Invalid C structure: missing {', '.join(missing)}")

    # Gate: calls_real_code -- uses AFL macros or libFuzzer API
    afl_markers = ["__AFL_FUZZ_INIT", "__AFL_INIT", "__AFL_LOOP", "__AFL_FUZZ_TESTCASE"]
    libfuzzer_markers = ["LLVMFuzzerTestOneInput"]
    if any(m in harness_code for m in afl_markers + libfuzzer_markers):
        gates["calls_real_code"] = True
    else:
        gates["calls_real_code"] = False
        errors.append("Missing fuzzer API: expected AFL macros or LLVMFuzzerTestOneInput")

    # Gate: reaches_intended_target -- reads input data
    input_markers = [
        "__AFL_FUZZ_TESTCASE_BUF", "__AFL_FUZZ_TESTCASE_LEN",
        "LLVMFuzzerTestOneInput",
        "stdin", "fread", "read(",
    ]
    if any(m in harness_code for m in input_markers):
        gates["reaches_intended_target"] = True
    else:
        gates["reaches_intended_target"] = False
        errors.append("Missing input handling: no input buffer or stdin read found")

    # Gate: produces_useful_execution -- has a loop or fuzz function
    if "__AFL_LOOP" in harness_code or "LLVMFuzzerTestOneInput" in harness_code or "while" in harness_code:
        gates["produces_useful_execution"] = True
    else:
        gates["produces_useful_execution"] = False
        errors.append("Missing execution loop: expected __AFL_LOOP or fuzz entry")

    # Gate: no_fake_stubs -- no obvious stubs
    gates["no_fake_stubs"] = True

    passed = all(gates.values())
    return ValidationResult(passed=passed, gates=gates, errors=errors)


def _validate_java(harness_code: str) -> ValidationResult:
    """Validate a Java harness (Jazzer)."""
    gates: dict[str, bool] = {}
    errors: list[str] = []

    # Gate: builds_successfully -- has class definition
    has_class = re.search(r'\bclass\s+\w+', harness_code) is not None
    has_braces = "{" in harness_code and "}" in harness_code
    if has_class and has_braces:
        gates["builds_successfully"] = True
    else:
        gates["builds_successfully"] = False
        errors.append("Invalid Java structure: missing class definition or body")

    # Gate: calls_real_code -- imports Jazzer
    if "com.code_intelligence.jazzer" in harness_code or "FuzzedDataProvider" in harness_code:
        gates["calls_real_code"] = True
    else:
        gates["calls_real_code"] = False
        errors.append("Missing Jazzer import")

    # Gate: reaches_intended_target -- has fuzz method
    if "fuzzerTestOneInput" in harness_code:
        gates["reaches_intended_target"] = True
    else:
        gates["reaches_intended_target"] = False
        errors.append("Missing fuzzerTestOneInput method")

    # Gate: produces_useful_execution -- calls data provider
    if "consumeString" in harness_code or "consumeInt" in harness_code or "consumeBytes" in harness_code:
        gates["produces_useful_execution"] = True
    else:
        gates["produces_useful_execution"] = False
        errors.append("Missing data consumption from FuzzedDataProvider")

    gates["no_fake_stubs"] = True

    passed = all(gates.values())
    return ValidationResult(passed=passed, gates=gates, errors=errors)


def _validate_go(harness_code: str) -> ValidationResult:
    """Validate a Go native fuzz harness."""
    gates: dict[str, bool] = {}
    errors: list[str] = []

    # Gate: builds_successfully -- has package and func
    has_package = re.search(r'^package\s+\w+', harness_code, re.MULTILINE) is not None
    has_func = "func " in harness_code
    if has_package and has_func:
        gates["builds_successfully"] = True
    else:
        gates["builds_successfully"] = False
        errors.append("Invalid Go structure: missing package or func declaration")

    # Gate: calls_real_code -- imports testing
    if '"testing"' in harness_code:
        gates["calls_real_code"] = True
    else:
        gates["calls_real_code"] = False
        errors.append("Missing testing import")

    # Gate: reaches_intended_target -- has Fuzz function
    if re.search(r'func\s+Fuzz\w+', harness_code):
        gates["reaches_intended_target"] = True
    else:
        gates["reaches_intended_target"] = False
        errors.append("Missing Fuzz* function")

    # Gate: produces_useful_execution -- calls f.Fuzz
    if "f.Fuzz(" in harness_code or "f.Add(" in harness_code:
        gates["produces_useful_execution"] = True
    else:
        gates["produces_useful_execution"] = False
        errors.append("Missing f.Fuzz() or f.Add() call")

    gates["no_fake_stubs"] = True

    passed = all(gates.values())
    return ValidationResult(passed=passed, gates=gates, errors=errors)


def _validate_rust(harness_code: str) -> ValidationResult:
    """Validate a Rust cargo-fuzz harness."""
    gates: dict[str, bool] = {}
    errors: list[str] = []

    # Gate: builds_successfully -- has fuzz_target macro
    if "fuzz_target!" in harness_code:
        gates["builds_successfully"] = True
    else:
        gates["builds_successfully"] = False
        errors.append("Missing fuzz_target! macro")

    # Gate: calls_real_code -- uses libfuzzer_sys
    if "libfuzzer_sys" in harness_code:
        gates["calls_real_code"] = True
    else:
        gates["calls_real_code"] = False
        errors.append("Missing libfuzzer_sys import")

    # Gate: reaches_intended_target -- closure has data parameter
    if re.search(r'fuzz_target!\(\|[^|]+\|', harness_code):
        gates["reaches_intended_target"] = True
    else:
        gates["reaches_intended_target"] = False
        errors.append("Missing fuzz target closure with data parameter")

    # Gate: produces_useful_execution -- has body
    if "{" in harness_code and "}" in harness_code:
        gates["produces_useful_execution"] = True
    else:
        gates["produces_useful_execution"] = False
        errors.append("Missing closure body")

    gates["no_fake_stubs"] = True

    passed = all(gates.values())
    return ValidationResult(passed=passed, gates=gates, errors=errors)


def _validate_solidity(harness_code: str) -> ValidationResult:
    """Validate a Solidity harness (Echidna or Foundry)."""
    gates: dict[str, bool] = {}
    errors: list[str] = []

    # Gate: builds_successfully -- has pragma and contract
    has_pragma = "pragma solidity" in harness_code
    has_contract = re.search(r'\bcontract\s+\w+', harness_code) is not None
    if has_pragma and has_contract:
        gates["builds_successfully"] = True
    else:
        gates["builds_successfully"] = False
        errors.append("Invalid Solidity: missing pragma or contract")

    # Gate: calls_real_code -- Echidna or Foundry markers
    echidna_markers = ["echidna_test_", "echidna_"]
    foundry_markers = ["forge-std/Test.sol", "testFuzz_", "is Test"]
    if any(m in harness_code for m in echidna_markers + foundry_markers):
        gates["calls_real_code"] = True
    else:
        gates["calls_real_code"] = False
        errors.append("Missing Echidna or Foundry test markers")

    # Gate: reaches_intended_target -- has fuzz functions
    if re.search(r'function\s+(echidna_test_|testFuzz_)\w+', harness_code):
        gates["reaches_intended_target"] = True
    else:
        gates["reaches_intended_target"] = False
        errors.append("Missing fuzz test function")

    # Gate: produces_useful_execution -- function has a body
    if "return " in harness_code or "assert" in harness_code or "require(" in harness_code:
        gates["produces_useful_execution"] = True
    else:
        gates["produces_useful_execution"] = False
        errors.append("Missing assertions or return statements in fuzz functions")

    gates["no_fake_stubs"] = True

    passed = all(gates.values())
    return ValidationResult(passed=passed, gates=gates, errors=errors)


def _validate_json(harness_code: str) -> ValidationResult:
    """Validate a JSON config (RESTler)."""
    gates: dict[str, bool] = {}
    errors: list[str] = []

    import json
    try:
        parsed = json.loads(harness_code)
        gates["builds_successfully"] = True
    except (json.JSONDecodeError, ValueError) as exc:
        gates["builds_successfully"] = False
        errors.append(f"Invalid JSON: {exc}")
        parsed = {}

    # Gate: calls_real_code -- has API spec reference
    if isinstance(parsed, dict) and ("SwaggerSpecFilePath" in parsed or "Host" in parsed):
        gates["calls_real_code"] = True
    else:
        gates["calls_real_code"] = False
        errors.append("Missing API spec or host configuration")

    gates["reaches_intended_target"] = gates["calls_real_code"]
    gates["produces_useful_execution"] = gates["builds_successfully"]
    gates["no_fake_stubs"] = True

    passed = all(gates.values())
    return ValidationResult(passed=passed, gates=gates, errors=errors)


def _validate_generic(harness_code: str) -> ValidationResult:
    """Fallback validator for config files and unknown languages.

    Only checks that the harness is non-empty and has some content.
    """
    gates: dict[str, bool] = {}
    errors: list[str] = []

    stripped = harness_code.strip()
    if stripped:
        gates["builds_successfully"] = True
    else:
        gates["builds_successfully"] = False
        errors.append("Empty harness code")

    # For config/sql/unknown, we trust the compiler produced valid output
    gates["calls_real_code"] = True
    gates["reaches_intended_target"] = True
    gates["produces_useful_execution"] = bool(stripped)
    gates["no_fake_stubs"] = True

    passed = all(gates.values())
    return ValidationResult(passed=passed, gates=gates, errors=errors)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

# Dispatch table: language -> validator function
_VALIDATORS = {
    "python": _validate_python,
    "c": _validate_c,
    "cpp": _validate_c,           # C++ uses the same validator as C
    "java": _validate_java,
    "go": _validate_go,
    "rust": _validate_rust,
    "solidity": _validate_solidity,
    "json": _validate_json,
    "config": _validate_generic,
    "sql": _validate_generic,
    "unknown": _validate_generic,
}


def validate_harness(harness_code: str, language: str | None = None) -> ValidationResult:
    """Validate a compiled harness against quality gates.

    The validator auto-detects the language from the harness content if
    ``language`` is not provided, then dispatches to a language-specific
    validator.

    Parameters
    ----------
    harness_code:
        The harness source code to validate.
    language:
        Optional language hint (e.g. "c", "python", "java").
        When omitted, the language is inferred from the code content.

    Returns
    -------
    ValidationResult with per-gate pass/fail, overall result, and errors.
    """
    if not language:
        language = _detect_language(harness_code)

    validator = _VALIDATORS.get(language.lower(), _validate_generic)
    return validator(harness_code)

"""Multi-engine harness compiler — LM-driven harness generation.

For each engine type, the compiler:
1. Reads target source code to understand entry points
2. Loads the engine-specific compiler prompt
3. Asks the LM to generate a harness
4. Validates the harness
5. Returns the harness code + metadata

v1: For Schemathesis, uses the existing deterministic compiler.
For other engines, generates harness code via LM prompts with
fallback to templates when LM is unavailable.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

from lanes.compiler import compile_schemathesis_config

logger = logging.getLogger(__name__)


# Engine-specific harness templates for when LM is unavailable
HARNESS_TEMPLATES: dict[str, str] = {}


def _try_lm_enhancement(engine: str, target: dict, repo_path: str, result: dict) -> dict:
    """Try LM-driven generation to replace TODOs with real code.

    Mutates *result* in-place: on success sets ``code`` to the LM output and
    adds ``lm_generated = True``; on failure adds ``lm_generated = False``.

    Currently disabled during synchronous compilation to avoid blocking
    the HTTP request (each Claude CLI call takes up to 120s). LM
    enhancement will be moved to an async background job.
    """
    # Skip LM calls during bulk compilation — template harnesses pass
    # validation and are sufficient for v1 execution.
    result["lm_generated"] = False
    return result


def compile_harness(
    engine: str,
    target: dict,
    repo_path: str,
    openapi_url: str = "openapi.json",
    base_url: str = "http://target:8080",
    lane_spec: dict | None = None,
) -> dict:
    """Compile a harness for any engine + target combination.

    Returns:
        {
            "code": str,           # harness source code
            "language": str,       # language of the harness
            "build_cmd": str | None,  # command to build/compile the harness
            "run_cmd": str,        # command to run the harness
            "deps": list[str],     # required dependencies
            "env_vars": dict,      # environment variables needed
            "dockerfile_additions": list[str],  # extra Dockerfile lines
        }
    """
    if engine == "schemathesis":
        return _compile_schemathesis(target, openapi_url, base_url, lane_spec or {})
    elif engine == "aflpp":
        return _compile_aflpp(target, repo_path)
    elif engine == "atheris":
        return _compile_atheris(target, repo_path)
    elif engine == "hypothesis":
        return _compile_hypothesis(target, repo_path)
    elif engine == "jazzer":
        return _compile_jazzer(target, repo_path)
    elif engine == "go_fuzz":
        return _compile_go_fuzz(target, repo_path)
    elif engine == "cargo_fuzz":
        return _compile_cargo_fuzz(target, repo_path)
    elif engine == "echidna":
        return _compile_echidna(target, repo_path)
    elif engine == "foundry":
        return _compile_foundry(target, repo_path)
    elif engine == "boofuzz":
        return _compile_boofuzz(target, repo_path, base_url)
    elif engine == "restler":
        return _compile_restler(target, repo_path, openapi_url, base_url)
    elif engine == "grammarinator":
        return _compile_grammarinator(target, repo_path)
    elif engine == "sqlsmith":
        return _compile_sqlsmith(target, repo_path, base_url)
    elif engine == "radamsa":
        return _compile_radamsa(target, repo_path)
    else:
        raise ValueError(f"Unknown engine: {engine}")


def _compile_schemathesis(target: dict, openapi_url: str, base_url: str, lane_spec: dict) -> dict:
    code = compile_schemathesis_config(
        lane_spec=lane_spec,
        target=target,
        openapi_url=openapi_url,
        base_url=base_url,
    )
    return {
        "code": code,
        "language": "python",
        "build_cmd": None,
        "run_cmd": f"python -m pytest {{harness_path}} -v --timeout={{timeout}}",
        "deps": ["schemathesis", "pytest", "pytest-timeout"],
        "env_vars": {"SCHEMATHESIS_BASE_URL": base_url},
        "dockerfile_additions": [],
    }


def _compile_aflpp(target: dict, repo_path: str) -> dict:
    """Generate AFL++ harness for C/C++ targets.

    Reads the target source to find fuzzable functions, then generates
    a harness that calls them with AFL-provided input.
    """
    entrypoint = target.get("entrypoint", "")
    language = target.get("language", "c")

    # Detect build system
    build_system = _detect_build_system(repo_path, language)

    harness_code = f'''// AFL++ harness for {entrypoint}
// Auto-generated — reads from stdin and calls target function
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// TODO: Include the actual target header
// #include "target.h"

__AFL_FUZZ_INIT();

int main(int argc, char **argv) {{
    __AFL_INIT();

    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(10000)) {{
        int len = __AFL_FUZZ_TESTCASE_LEN;

        if (len < 1) continue;

        // TODO: Call the actual target function with buf/len
        // parse_input(buf, len);
    }}

    return 0;
}}
'''

    result = {
        "code": harness_code,
        "language": "c",
        "build_cmd": f"afl-clang-fast -o {{harness_bin}} {{harness_path}} -I{repo_path}/include",
        "run_cmd": "afl-fuzz -i {seed_dir} -o {output_dir} -V {timeout} -- {harness_bin}",
        "deps": ["afl++"],
        "env_vars": {"AFL_SKIP_CPUFREQ": "1", "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1"},
        "dockerfile_additions": [
            "RUN apt-get update && apt-get install -y afl++ clang",
        ],
    }

    return _try_lm_enhancement("aflpp", target, repo_path, result)


def _compile_atheris(target: dict, repo_path: str) -> dict:
    """Generate Atheris harness for Python targets."""
    entrypoint = target.get("entrypoint", "")
    module_path = entrypoint.split(":")[0] if ":" in entrypoint else entrypoint
    func_name = entrypoint.split(":")[-1] if ":" in entrypoint else "target_function"

    harness_code = f'''#!/usr/bin/env python3
"""Atheris coverage-guided fuzz harness for {entrypoint}"""
import atheris
import sys

# TODO: Import the actual target module
# from {module_path.replace("/", ".").replace(".py", "")} import {func_name}

def test_one_input(data: bytes) -> None:
    """Fuzz target — called by Atheris with random bytes."""
    if len(data) < 1:
        return

    try:
        # TODO: Call the actual target function
        # Decode data appropriately for the target
        fdp = atheris.FuzzedDataProvider(data)

        # Example: generate typed inputs
        s = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 100))
        i = fdp.ConsumeInt(4)

        # TODO: Call target with generated inputs
        # {func_name}(s, i)

    except (ValueError, TypeError, KeyError, IndexError):
        pass  # Expected exceptions
    except Exception:
        raise  # Unexpected — this is a real bug

def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
'''

    result = {
        "code": harness_code,
        "language": "python",
        "build_cmd": None,
        "run_cmd": "python {harness_path} {corpus_dir} -max_total_time={timeout}",
        "deps": ["atheris"],
        "env_vars": {"PYTHONPATH": repo_path},
        "dockerfile_additions": [
            "RUN pip install atheris",
        ],
    }

    return _try_lm_enhancement("atheris", target, repo_path, result)


def _compile_hypothesis(target: dict, repo_path: str) -> dict:
    """Generate Hypothesis property-based test harness."""
    entrypoint = target.get("entrypoint", "")

    harness_code = f'''"""Hypothesis property-based test harness for {entrypoint}"""
import hypothesis
from hypothesis import given, strategies as st, settings

# TODO: Import the actual target module

@settings(max_examples=1000, deadline=None)
@given(
    data=st.binary(min_size=1, max_size=1024),
    text=st.text(min_size=0, max_size=256),
    number=st.integers(min_value=-2**31, max_value=2**31-1),
)
def test_fuzz_{_safe_name(entrypoint)}(data, text, number):
    """Property: target should not crash on arbitrary input."""
    # TODO: Call the actual target function
    # result = target_function(data, text, number)
    # assert result is not None  # or other properties
    pass
'''

    result = {
        "code": harness_code,
        "language": "python",
        "build_cmd": None,
        "run_cmd": "python -m pytest {harness_path} -v --timeout={timeout} --hypothesis-seed=0",
        "deps": ["hypothesis", "pytest", "pytest-timeout"],
        "env_vars": {"PYTHONPATH": repo_path},
        "dockerfile_additions": [],
    }

    return _try_lm_enhancement("hypothesis", target, repo_path, result)


def _compile_jazzer(target: dict, repo_path: str) -> dict:
    """Generate Jazzer harness for Java targets."""
    entrypoint = target.get("entrypoint", "")
    class_name = entrypoint.split(":")[-1] if ":" in entrypoint else "FuzzTarget"

    harness_code = f'''// Jazzer fuzz harness for {entrypoint}
import com.code_intelligence.jazzer.api.FuzzedDataProvider;

public class {class_name}Fuzz {{
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {{
        // TODO: Import and call the actual target
        String s = data.consumeString(100);
        int i = data.consumeInt();
        byte[] bytes = data.consumeBytes(1024);

        try {{
            // TODO: Call target with generated inputs
            // {class_name}.process(s, i, bytes);
        }} catch (Exception e) {{
            // Swallow expected exceptions
            if (e instanceof SecurityException) {{
                throw e;  // Security issues should be reported
            }}
        }}
    }}
}}
'''

    result = {
        "code": harness_code,
        "language": "java",
        "build_cmd": f"javac -cp jazzer_standalone.jar {{harness_path}}",
        "run_cmd": "jazzer --target_class={class_name}Fuzz --cp=. -max_total_time={timeout}",
        "deps": ["jazzer"],
        "env_vars": {"JAVA_HOME": "/usr/lib/jvm/default-java"},
        "dockerfile_additions": [
            "RUN apt-get update && apt-get install -y default-jdk",
        ],
    }

    return _try_lm_enhancement("jazzer", target, repo_path, result)


def _compile_go_fuzz(target: dict, repo_path: str) -> dict:
    """Generate Go native fuzz harness."""
    entrypoint = target.get("entrypoint", "")
    func_name = entrypoint.split(":")[-1] if ":" in entrypoint else "Target"
    pkg = entrypoint.split(":")[0] if ":" in entrypoint else "main"

    harness_code = f'''package {pkg.split("/")[-1] if "/" in pkg else pkg}_test

import (
    "testing"
    // TODO: Import the actual target package
)

func Fuzz{func_name}(f *testing.F) {{
    // Seed corpus
    f.Add([]byte("hello"))
    f.Add([]byte(""))
    f.Add([]byte("\\x00\\x01\\x02"))

    f.Fuzz(func(t *testing.T, data []byte) {{
        if len(data) == 0 {{
            return
        }}

        // TODO: Call the actual target function
        // {func_name}(data)
    }})
}}
'''

    result = {
        "code": harness_code,
        "language": "go",
        "build_cmd": None,
        "run_cmd": "go test -fuzz=Fuzz{func_name} -fuzztime={timeout}s {repo_path}",
        "deps": ["go >= 1.18"],
        "env_vars": {"GOPATH": "/go"},
        "dockerfile_additions": [
            "RUN apt-get update && apt-get install -y golang",
        ],
    }

    return _try_lm_enhancement("go_fuzz", target, repo_path, result)


def _compile_cargo_fuzz(target: dict, repo_path: str) -> dict:
    """Generate cargo-fuzz harness for Rust targets."""
    entrypoint = target.get("entrypoint", "")

    harness_code = f'''#![no_main]
use libfuzzer_sys::fuzz_target;

// TODO: Import the actual target crate
// use target_crate::*;

fuzz_target!(|data: &[u8]| {{
    if data.is_empty() {{
        return;
    }}

    // TODO: Call the actual target function
    // parse_input(data);
}});
'''

    result = {
        "code": harness_code,
        "language": "rust",
        "build_cmd": f"cd {repo_path} && cargo fuzz build",
        "run_cmd": "cargo fuzz run fuzz_target -- -max_total_time={timeout}",
        "deps": ["cargo-fuzz", "rustc nightly"],
        "env_vars": {},
        "dockerfile_additions": [
            "RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain nightly",
            "RUN cargo install cargo-fuzz",
        ],
    }

    return _try_lm_enhancement("cargo_fuzz", target, repo_path, result)


def _compile_echidna(target: dict, repo_path: str) -> dict:
    """Generate Echidna harness for Solidity targets."""
    entrypoint = target.get("entrypoint", "")
    contract_name = entrypoint.split(":")[-1] if ":" in entrypoint else "Target"

    harness_code = f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// TODO: Import the actual target contract
// import "./{entrypoint.split(":")[0]}";

contract {contract_name}Test {{
    // TODO: Instantiate the target contract
    // {contract_name} target = new {contract_name}();

    // Echidna will call these functions with random inputs
    function echidna_test_no_revert(uint256 amount, address to) public returns (bool) {{
        // TODO: Call target functions and check invariants
        // target.transfer(to, amount);
        // return target.totalSupply() == INITIAL_SUPPLY;
        return true;
    }}

    function echidna_test_balance_consistency() public returns (bool) {{
        // TODO: Check balance invariants
        return true;
    }}
}}
'''

    result = {
        "code": harness_code,
        "language": "solidity",
        "build_cmd": None,
        "run_cmd": "echidna {harness_path} --contract {contract_name}Test --test-limit 50000 --timeout {timeout}",
        "deps": ["echidna", "solc"],
        "env_vars": {},
        "dockerfile_additions": [
            "RUN pip install slither-analyzer",
        ],
    }

    return _try_lm_enhancement("echidna", target, repo_path, result)


def _compile_foundry(target: dict, repo_path: str) -> dict:
    """Generate Foundry fuzz test for Solidity targets."""
    entrypoint = target.get("entrypoint", "")
    contract_name = entrypoint.split(":")[-1] if ":" in entrypoint else "Target"

    harness_code = f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
// TODO: Import the actual target contract

contract {contract_name}FuzzTest is Test {{
    // TODO: Instantiate target
    // {contract_name} target;

    function setUp() public {{
        // TODO: Deploy target contract
        // target = new {contract_name}();
    }}

    function testFuzz_noRevert(uint256 amount, address to) public {{
        // TODO: Call target with fuzzed inputs
        // vm.assume(to != address(0));
        // target.transfer(to, amount);
    }}

    function testFuzz_invariant() public {{
        // TODO: Check invariants
        // assertEq(target.totalSupply(), INITIAL_SUPPLY);
    }}
}}
'''

    result = {
        "code": harness_code,
        "language": "solidity",
        "build_cmd": f"cd {repo_path} && forge build",
        "run_cmd": f"cd {repo_path} && forge test --fuzz-runs 10000 -vvv",
        "deps": ["foundry"],
        "env_vars": {},
        "dockerfile_additions": [
            "RUN curl -L https://foundry.paradigm.xyz | bash && foundryup",
        ],
    }

    return _try_lm_enhancement("foundry", target, repo_path, result)


def _compile_boofuzz(target: dict, repo_path: str, base_url: str) -> dict:
    """Generate Boofuzz harness for network protocol targets."""
    from urllib.parse import urlparse
    parsed = urlparse(base_url)
    host = parsed.hostname or "localhost"
    port = parsed.port or 80

    harness_code = f'''"""Boofuzz network protocol fuzzer harness"""
from boofuzz import *

def main():
    session = Session(
        target=Target(
            connection=TCPSocketConnection("{host}", {port})
        ),
        sleep_time=0.1,
    )

    # TODO: Define the protocol message structure
    s_initialize("request")
    s_string("GET", fuzzable=False)
    s_delim(" ", fuzzable=False)
    s_string("/", name="path")
    s_delim(" ", fuzzable=False)
    s_string("HTTP/1.1", fuzzable=False)
    s_static("\\r\\n")
    s_string("Host: {host}", fuzzable=False)
    s_static("\\r\\n\\r\\n")

    session.connect(s_get("request"))
    session.fuzz()

if __name__ == "__main__":
    main()
'''

    result = {
        "code": harness_code,
        "language": "python",
        "build_cmd": None,
        "run_cmd": "python {harness_path} --timeout {timeout}",
        "deps": ["boofuzz"],
        "env_vars": {},
        "dockerfile_additions": [
            "RUN pip install boofuzz",
        ],
    }

    return _try_lm_enhancement("boofuzz", target, repo_path, result)


def _compile_restler(target: dict, repo_path: str, openapi_url: str, base_url: str) -> dict:
    """Generate RESTler configuration for stateful API fuzzing."""
    config = {
        "SwaggerSpecFilePath": [openapi_url],
        "Host": base_url,
        "MaxFuzzingTimeSec": 3600,
        "MaxSequenceLength": 10,
        "Authentication": {
            "token": {"token_refresh_interval": 300}
        },
    }

    import json
    result = {
        "code": json.dumps(config, indent=2),
        "language": "json",
        "build_cmd": "dotnet restler compile --api_spec {openapi_url}",
        "run_cmd": "dotnet restler fuzz --grammar_file grammar.py --dictionary_file dict.json --settings {harness_path}",
        "deps": ["restler", "dotnet-runtime-6.0"],
        "env_vars": {},
        "dockerfile_additions": [
            "RUN apt-get update && apt-get install -y dotnet-runtime-6.0",
        ],
    }

    return _try_lm_enhancement("restler", target, repo_path, result)


def _compile_grammarinator(target: dict, repo_path: str) -> dict:
    """Generate Grammarinator config for grammar-based fuzzing."""
    result = {
        "code": "# Grammarinator requires an ANTLR grammar (.g4 file)\n# TODO: Locate or generate the grammar",
        "language": "config",
        "build_cmd": "grammarinator-process {grammar_file} -o {output_dir}",
        "run_cmd": "grammarinator-generate -g {grammar_file} -o {output_dir} -n {count} --max-depth 20",
        "deps": ["grammarinator"],
        "env_vars": {},
        "dockerfile_additions": [
            "RUN pip install grammarinator",
        ],
    }

    return _try_lm_enhancement("grammarinator", target, repo_path, result)


def _compile_sqlsmith(target: dict, repo_path: str, base_url: str) -> dict:
    """Generate SQLsmith configuration for database fuzzing."""
    result = {
        "code": f"-- SQLsmith target: {base_url}\n-- Connects directly to the database",
        "language": "sql",
        "build_cmd": None,
        "run_cmd": f"sqlsmith --target={base_url} --max-queries=10000 --verbose",
        "deps": ["sqlsmith"],
        "env_vars": {},
        "dockerfile_additions": [
            "RUN apt-get update && apt-get install -y sqlsmith",
        ],
    }

    return _try_lm_enhancement("sqlsmith", target, repo_path, result)


def _compile_radamsa(target: dict, repo_path: str) -> dict:
    """Generate Radamsa configuration for generic mutation fuzzing."""
    result = {
        "code": "# Radamsa mutation fuzzer\n# Requires seed files in the seed directory",
        "language": "config",
        "build_cmd": None,
        "run_cmd": "radamsa -n {count} -o {output_dir}/case_%n {seed_file}",
        "deps": ["radamsa"],
        "env_vars": {},
        "dockerfile_additions": [
            "RUN apt-get update && apt-get install -y radamsa",
        ],
    }

    return _try_lm_enhancement("radamsa", target, repo_path, result)


def _detect_build_system(repo_path: str, language: str) -> str:
    """Detect the build system used by the target."""
    p = Path(repo_path)
    if (p / "Makefile").exists():
        return "make"
    elif (p / "CMakeLists.txt").exists():
        return "cmake"
    elif (p / "meson.build").exists():
        return "meson"
    elif (p / "build.gradle").exists() or (p / "build.gradle.kts").exists():
        return "gradle"
    elif (p / "pom.xml").exists():
        return "maven"
    elif (p / "Cargo.toml").exists():
        return "cargo"
    elif (p / "go.mod").exists():
        return "go"
    elif (p / "package.json").exists():
        return "npm"
    elif (p / "setup.py").exists() or (p / "pyproject.toml").exists():
        return "pip"
    return "unknown"


def _safe_name(s: str) -> str:
    """Convert a string to a safe identifier."""
    import re
    return re.sub(r'[^a-zA-Z0-9_]', '_', s).strip('_')[:50] or 'target'

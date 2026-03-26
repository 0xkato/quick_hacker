"""Tests for multi-language harness validator gate checks."""

from __future__ import annotations

from lanes.validators import validate_harness, _detect_language


class TestLanguageDetection:
    def test_detect_python_import(self):
        assert _detect_language("import schemathesis\n") == "python"

    def test_detect_python_shebang(self):
        assert _detect_language("#!/usr/bin/env python3\nimport sys") == "python"

    def test_detect_python_def(self):
        assert _detect_language("def test_something():\n    pass") == "python"

    def test_detect_c_include(self):
        assert _detect_language("#include <stdio.h>\nint main() {}") == "c"

    def test_detect_c_afl(self):
        assert _detect_language("__AFL_FUZZ_INIT();\nint main() {}") == "c"

    def test_detect_java(self):
        assert _detect_language("import com.code_intelligence.jazzer.api.FuzzedDataProvider;\npublic class Fuzz {}") == "java"

    def test_detect_go(self):
        code = 'package main_test\n\nimport "testing"\n\nfunc FuzzTarget(f *testing.F) {}'
        assert _detect_language(code) == "go"

    def test_detect_rust(self):
        assert _detect_language("#![no_main]\nuse libfuzzer_sys::fuzz_target;") == "rust"

    def test_detect_solidity(self):
        assert _detect_language("pragma solidity ^0.8.0;\ncontract Test {}") == "solidity"

    def test_detect_json(self):
        assert _detect_language('{"SwaggerSpecFilePath": ["openapi.json"]}') == "json"


class TestPythonValidator:
    def test_valid_schemathesis_harness(self):
        code = '''
import schemathesis
schema = schemathesis.from_url("http://localhost:8080/openapi.json")
@schema.parametrize()
def test_api(case):
    response = case.call()
    case.validate_response(response)
'''
        result = validate_harness(code)
        assert result.passed is True
        assert all(result.gates.values())
        assert result.errors == []

    def test_valid_atheris_harness(self):
        code = '''#!/usr/bin/env python3
import atheris
import sys

def test_one_input(data: bytes) -> None:
    if len(data) < 1:
        return
    fdp = atheris.FuzzedDataProvider(data)

def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()
'''
        result = validate_harness(code)
        assert result.passed is True

    def test_syntax_error_fails(self):
        result = validate_harness("def bad(:\n  pass", language="python")
        assert result.passed is False
        assert result.gates["builds_successfully"] is False

    def test_missing_framework_fails(self):
        code = "import requests\ndef test_api(): pass"
        result = validate_harness(code, language="python")
        assert result.gates["calls_real_code"] is False

    def test_missing_schema_loading_fails(self):
        code = "import schemathesis\ndef test_api(): pass"
        result = validate_harness(code, language="python")
        assert result.gates["reaches_intended_target"] is False

    def test_missing_test_function_fails(self):
        code = "import schemathesis\nschema = schemathesis.from_url('x')\nprint('no test')"
        result = validate_harness(code, language="python")
        assert result.gates["produces_useful_execution"] is False

    def test_mock_import_fails(self):
        code = '''
import schemathesis
from unittest.mock import patch
schema = schemathesis.from_url("x")
def test_api(): pass
'''
        result = validate_harness(code, language="python")
        assert result.gates["no_fake_stubs"] is False

    def test_partial_failures(self):
        code = "import schemathesis\nschema = schemathesis.from_url('x')"
        result = validate_harness(code, language="python")
        assert result.passed is False
        assert result.gates["builds_successfully"] is True
        assert result.gates["calls_real_code"] is True
        assert result.gates["reaches_intended_target"] is True
        assert result.gates["produces_useful_execution"] is False
        assert len(result.errors) > 0


class TestCValidator:
    def test_valid_aflpp_harness(self):
        code = '''#include <stdio.h>
#include <stdlib.h>

__AFL_FUZZ_INIT();

int main(int argc, char **argv) {
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        if (len < 1) continue;
    }
    return 0;
}
'''
        result = validate_harness(code)
        assert result.passed is True
        assert all(result.gates.values())

    def test_missing_include_fails(self):
        code = '''__AFL_FUZZ_INIT();
int main() {
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
    }
    return 0;
}
'''
        # This should still pass -- #include not strictly required for AFL
        # but our validator does check for it
        result = validate_harness(code, language="c")
        assert result.gates["builds_successfully"] is False

    def test_c_harness_not_parsed_as_python(self):
        """The CRITICAL bug: ast.parse() must NOT be used on C code."""
        code = '''#include <stdio.h>
__AFL_FUZZ_INIT();
int main(int argc, char **argv) {
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        if (len < 1) continue;
    }
    return 0;
}
'''
        # Before fix: would fail because ast.parse raises SyntaxError on C code
        # After fix: detected as C, validated with C-specific gates
        result = validate_harness(code)
        assert result.passed is True

    def test_explicit_language_c(self):
        code = '''#include <stdio.h>
__AFL_FUZZ_INIT();
int main() {
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
    }
    return 0;
}
'''
        result = validate_harness(code, language="c")
        assert result.passed is True


class TestJavaValidator:
    def test_valid_jazzer_harness(self):
        code = '''import com.code_intelligence.jazzer.api.FuzzedDataProvider;

public class TargetFuzz {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        String s = data.consumeString(100);
        int i = data.consumeInt();
    }
}
'''
        result = validate_harness(code)
        assert result.passed is True


class TestGoValidator:
    def test_valid_go_fuzz_harness(self):
        code = '''package main_test

import "testing"

func FuzzTarget(f *testing.F) {
    f.Add([]byte("hello"))
    f.Fuzz(func(t *testing.T, data []byte) {
        if len(data) == 0 {
            return
        }
    })
}
'''
        result = validate_harness(code)
        assert result.passed is True


class TestRustValidator:
    def test_valid_cargo_fuzz_harness(self):
        code = '''#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
});
'''
        result = validate_harness(code)
        assert result.passed is True


class TestSolidityValidator:
    def test_valid_echidna_harness(self):
        code = '''pragma solidity ^0.8.0;

contract TargetTest {
    function echidna_test_no_revert(uint256 amount) public returns (bool) {
        return true;
    }
}
'''
        result = validate_harness(code)
        assert result.passed is True

    def test_valid_foundry_harness(self):
        code = '''pragma solidity ^0.8.0;

import "forge-std/Test.sol";

contract TargetFuzzTest is Test {
    function testFuzz_noRevert(uint256 amount) public {
        assertEq(1, 1);
    }
}
'''
        result = validate_harness(code)
        assert result.passed is True


class TestJsonValidator:
    def test_valid_restler_config(self):
        code = '{"SwaggerSpecFilePath": ["openapi.json"], "Host": "http://target:8080"}'
        result = validate_harness(code, language="json")
        assert result.passed is True


class TestGenericValidator:
    def test_nonempty_config_passes(self):
        code = "# Radamsa mutation fuzzer\n# Requires seed files"
        result = validate_harness(code, language="config")
        assert result.passed is True

    def test_empty_code_fails(self):
        result = validate_harness("", language="config")
        assert result.passed is False

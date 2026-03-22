"""Tests for harness validator gate checks."""

from __future__ import annotations

from lanes.validators import validate_harness


class TestHarnessValidator:
    def test_valid_harness_passes(self):
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

    def test_syntax_error_fails(self):
        result = validate_harness("def bad(:\n  pass")
        assert result.passed is False
        assert result.gates["builds_successfully"] is False

    def test_missing_schemathesis_fails(self):
        code = "import requests\ndef test_api(): pass"
        result = validate_harness(code)
        assert result.gates["calls_real_code"] is False

    def test_missing_schema_loading_fails(self):
        code = "import schemathesis\ndef test_api(): pass"
        result = validate_harness(code)
        assert result.gates["reaches_intended_target"] is False

    def test_missing_test_function_fails(self):
        code = "import schemathesis\nschema = schemathesis.from_url('x')\nprint('no test')"
        result = validate_harness(code)
        assert result.gates["produces_useful_execution"] is False

    def test_mock_import_fails(self):
        code = '''
import schemathesis
from unittest.mock import patch
schema = schemathesis.from_url("x")
def test_api(): pass
'''
        result = validate_harness(code)
        assert result.gates["no_fake_stubs"] is False

    def test_partial_failures(self):
        code = "import schemathesis\nschema = schemathesis.from_url('x')"
        result = validate_harness(code)
        assert result.passed is False
        assert result.gates["builds_successfully"] is True
        assert result.gates["calls_real_code"] is True
        assert result.gates["reaches_intended_target"] is True
        assert result.gates["produces_useful_execution"] is False
        assert len(result.errors) > 0

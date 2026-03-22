"""Tests for the Schemathesis harness compiler."""

from __future__ import annotations

import ast
import re

from lanes.compiler import compile_schemathesis_config


class TestSchemathesisCompiler:
    def test_generates_valid_python(self):
        code = compile_schemathesis_config(
            lane_spec={"oracle_packs": ["status_code", "schema_conformance"]},
            target={"entrypoint": "GET /api/users", "stateful": False},
            openapi_url="openapi.json",
        )
        # Should be valid Python
        ast.parse(code)

    def test_contains_schemathesis_import(self):
        code = compile_schemathesis_config(
            lane_spec={"oracle_packs": ["status_code"]},
            target={"entrypoint": "GET /api/users", "stateful": False},
            openapi_url="openapi.json",
        )
        assert "import schemathesis" in code

    def test_contains_schema_loading(self):
        code = compile_schemathesis_config(
            lane_spec={"oracle_packs": ["status_code"]},
            target={"entrypoint": "GET /api/users", "stateful": False},
            base_url="http://app:9000",
            openapi_url="docs/openapi.json",
        )
        assert "from_url" in code
        assert "http://app:9000" in code

    def test_stateful_uses_links(self):
        code = compile_schemathesis_config(
            lane_spec={"oracle_packs": ["status_code"]},
            target={"entrypoint": "GET /admin", "stateful": True},
            openapi_url="openapi.json",
        )
        assert "Stateful.links" in code or "stateful=" in code

    def test_status_code_oracle(self):
        code = compile_schemathesis_config(
            lane_spec={"oracle_packs": ["status_code"]},
            target={"entrypoint": "GET /x", "stateful": False},
            openapi_url="openapi.json",
        )
        assert "status_code < 500" in code or "status_code" in code

    def test_schema_conformance_oracle(self):
        code = compile_schemathesis_config(
            lane_spec={"oracle_packs": ["schema_conformance"]},
            target={"entrypoint": "GET /x", "stateful": False},
            openapi_url="openapi.json",
        )
        assert "validate_response" in code

    def test_authz_diff_oracle_adds_auth(self):
        code = compile_schemathesis_config(
            lane_spec={"oracle_packs": ["authz_diff"]},
            target={"entrypoint": "GET /x", "stateful": True},
            openapi_url="openapi.json",
        )
        assert "Authorization" in code or "auth" in code.lower()

    def test_safe_function_name(self):
        code = compile_schemathesis_config(
            lane_spec={"oracle_packs": []},
            target={
                "entrypoint": "POST /api/orders/{id}/approve",
                "stateful": False,
            },
            openapi_url="openapi.json",
        )
        # Should not have invalid Python identifier chars
        assert "def test_" in code
        # No curly braces in function name
        func_names = re.findall(r"def (test_\w+)", code)
        assert len(func_names) >= 1
        for name in func_names:
            assert "{" not in name and "}" not in name

    def test_safe_function_name_is_valid_python(self):
        """The generated function name must itself be a valid identifier."""
        code = compile_schemathesis_config(
            lane_spec={"oracle_packs": []},
            target={
                "entrypoint": "POST /api/orders/{id}/approve",
                "stateful": False,
            },
            openapi_url="openapi.json",
        )
        ast.parse(code)

    def test_default_base_url(self):
        code = compile_schemathesis_config(
            lane_spec={"oracle_packs": []},
            target={"entrypoint": "GET /", "stateful": False},
            openapi_url="openapi.json",
        )
        assert "http://target:8080" in code

    def test_multiple_oracles(self):
        code = compile_schemathesis_config(
            lane_spec={
                "oracle_packs": [
                    "status_code",
                    "schema_conformance",
                    "authz_diff",
                ]
            },
            target={"entrypoint": "GET /x", "stateful": False},
            openapi_url="openapi.json",
        )
        assert "validate_response" in code
        assert "status_code < 500" in code
        assert "Authorization" in code
        ast.parse(code)

"""Tests for campaigns.intake — contract validation and capability detection."""

import json
import os
import textwrap

import pytest

from campaigns.intake import (
    CapabilityProfile,
    ContractValidation,
    detect_capability_profile,
    validate_support_contract,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write(path: str, content: str = "") -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


# ===========================================================================
# validate_support_contract
# ===========================================================================


class TestValidateSupportContract:
    """Tests for validate_support_contract."""

    def test_valid_repo_with_compose_and_openapi(self, tmp_path):
        _write(str(tmp_path / "docker-compose.yml"), "version: '3'")
        _write(
            str(tmp_path / "openapi.json"),
            json.dumps({"openapi": "3.0.0", "info": {"title": "API"}}),
        )

        result = validate_support_contract(str(tmp_path))

        assert isinstance(result, ContractValidation)
        assert result.valid is True
        assert result.reasons == []
        assert result.compose_path is not None
        assert result.openapi_path is not None

    def test_missing_compose_still_valid(self, tmp_path):
        """Repo without docker-compose is still valid -- just warns."""
        _write(
            str(tmp_path / "openapi.yaml"),
            "openapi: '3.0.0'\ninfo:\n  title: API",
        )

        result = validate_support_contract(str(tmp_path))

        assert result.valid is True
        assert any("docker-compose" in r.lower() for r in result.reasons)
        assert result.compose_path is None

    def test_missing_openapi_still_valid(self, tmp_path):
        """Repo without OpenAPI is still valid -- just warns."""
        _write(str(tmp_path / "docker-compose.yml"), "version: '3'")

        result = validate_support_contract(str(tmp_path))

        assert result.valid is True
        assert any("openapi" in r.lower() for r in result.reasons)
        assert result.openapi_path is None

    def test_compose_yaml_variant_accepted(self, tmp_path):
        _write(str(tmp_path / "compose.yaml"), "version: '3'")
        _write(
            str(tmp_path / "openapi.json"),
            json.dumps({"openapi": "3.0.0", "info": {"title": "API"}}),
        )

        result = validate_support_contract(str(tmp_path))

        assert result.valid is True
        assert "compose.yaml" in result.compose_path

    def test_openapi_in_subdirectory(self, tmp_path):
        _write(str(tmp_path / "docker-compose.yml"), "version: '3'")
        _write(
            str(tmp_path / "docs" / "api.yaml"),
            "openapi: '3.0.0'\ninfo:\n  title: API",
        )

        result = validate_support_contract(str(tmp_path))

        assert result.valid is True
        assert result.openapi_path is not None
        assert "docs" in result.openapi_path

    def test_swagger_2_detected(self, tmp_path):
        _write(str(tmp_path / "docker-compose.yml"), "version: '3'")
        _write(
            str(tmp_path / "swagger.json"),
            json.dumps({"swagger": "2.0", "info": {"title": "API"}}),
        )

        result = validate_support_contract(str(tmp_path))

        assert result.valid is True
        assert result.openapi_path is not None

    def test_empty_repo_still_valid(self, tmp_path):
        """Even an empty repo is valid -- we can still scan source."""
        result = validate_support_contract(str(tmp_path))

        assert result.valid is True
        assert len(result.reasons) >= 2
        assert result.compose_path is None
        assert result.openapi_path is None

    def test_repo_with_only_c_code_still_valid(self, tmp_path):
        """Pure C repo without docker-compose is still valid."""
        _write(str(tmp_path / "main.c"), "int main() { return 0; }")
        result = validate_support_contract(str(tmp_path))
        assert result.valid is True
        assert any("docker-compose" in r.lower() for r in result.reasons)


# ===========================================================================
# detect_capability_profile
# ===========================================================================


class TestDetectCapabilityProfile:
    """Tests for detect_capability_profile."""

    def test_detects_python_fastapi(self, tmp_path):
        _write(str(tmp_path / "main.py"), "from fastapi import FastAPI")
        _write(
            str(tmp_path / "requirements.txt"),
            "fastapi==0.100.0\nuvicorn\n",
        )

        result = detect_capability_profile(str(tmp_path))

        assert isinstance(result, CapabilityProfile)
        assert "python" in result.languages
        assert result.framework == "fastapi"

    def test_detects_tests_directory(self, tmp_path):
        os.makedirs(str(tmp_path / "tests"))
        _write(str(tmp_path / "tests" / "__init__.py"))

        result = detect_capability_profile(str(tmp_path))

        assert result.has_tests is True

    def test_detects_node_express(self, tmp_path):
        _write(str(tmp_path / "index.js"), "const express = require('express')")
        _write(
            str(tmp_path / "package.json"),
            json.dumps({"dependencies": {"express": "^4.18.0"}}),
        )

        result = detect_capability_profile(str(tmp_path))

        assert "javascript" in result.languages
        assert result.framework == "express"

    def test_no_framework_returns_none(self, tmp_path):
        _write(str(tmp_path / "main.py"), "print('hello')")

        result = detect_capability_profile(str(tmp_path))

        assert result.framework is None

    def test_detects_languages_from_extensions(self, tmp_path):
        _write(str(tmp_path / "main.go"), "package main")
        _write(str(tmp_path / "lib.rs"), "fn main() {}")
        _write(str(tmp_path / "App.ts"), "console.log('hi')")

        result = detect_capability_profile(str(tmp_path))

        assert "go" in result.languages
        assert "rust" in result.languages
        assert "typescript" in result.languages

    def test_has_docker_when_compose_exists(self, tmp_path):
        _write(str(tmp_path / "docker-compose.yml"), "version: '3'")

        result = detect_capability_profile(str(tmp_path))

        assert result.has_docker is True
        assert result.compose_path is not None

    def test_detects_graphql(self, tmp_path):
        _write(str(tmp_path / "schema.graphql"), "type Query { hello: String }")

        result = detect_capability_profile(str(tmp_path))

        assert result.has_graphql_schema is True

    def test_detects_health_check_in_compose(self, tmp_path):
        compose_content = textwrap.dedent("""\
            version: '3'
            services:
              web:
                image: myapp
                healthcheck:
                  test: curl -f http://localhost/health
        """)
        _write(str(tmp_path / "docker-compose.yml"), compose_content)

        result = detect_capability_profile(str(tmp_path))

        assert result.has_health_check is True

    def test_detects_health_check_in_openapi(self, tmp_path):
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "API"},
            "paths": {"/health": {"get": {"summary": "Health"}}},
        }
        _write(str(tmp_path / "openapi.json"), json.dumps(spec))

        result = detect_capability_profile(str(tmp_path))

        assert result.has_health_check is True

    def test_detects_cmake_build_system(self, tmp_path):
        _write(str(tmp_path / "CMakeLists.txt"), "cmake_minimum_required(VERSION 3.10)")
        _write(str(tmp_path / "main.c"), "int main() { return 0; }")

        result = detect_capability_profile(str(tmp_path))

        assert "cmake" in result.build_systems

    def test_detects_cargo_build_system(self, tmp_path):
        _write(str(tmp_path / "Cargo.toml"), '[package]\nname = "mylib"')
        _write(str(tmp_path / "src" / "lib.rs"), "pub fn add(a: i32, b: i32) -> i32 { a + b }")

        result = detect_capability_profile(str(tmp_path))

        assert "cargo" in result.build_systems
        assert "rust" in result.languages

    def test_detects_go_mod_build_system(self, tmp_path):
        _write(str(tmp_path / "go.mod"), "module example.com/mymod\ngo 1.21")
        _write(str(tmp_path / "main.go"), "package main")

        result = detect_capability_profile(str(tmp_path))

        assert "go_mod" in result.build_systems
        assert "go" in result.languages

    def test_detects_foundry_build_system(self, tmp_path):
        _write(str(tmp_path / "foundry.toml"), "[profile.default]\nsrc = 'src'")

        result = detect_capability_profile(str(tmp_path))

        assert "foundry" in result.build_systems

    def test_detects_multiple_build_systems(self, tmp_path):
        _write(str(tmp_path / "Makefile"), "all:\n\tgcc main.c")
        _write(str(tmp_path / "CMakeLists.txt"), "cmake_minimum_required(VERSION 3.10)")

        result = detect_capability_profile(str(tmp_path))

        assert "make" in result.build_systems
        assert "cmake" in result.build_systems

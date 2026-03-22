"""Tests for the OpenAPI surface extractor."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from targets.extractors.openapi_extractor import (
    extract_targets_from_file,
    extract_targets_from_openapi,
)


def _sample_spec(*, with_security: bool = False) -> dict:
    """Return a minimal OpenAPI 3.0 spec with 2 paths / 5 operations."""
    spec: dict = {
        "openapi": "3.0.3",
        "info": {"title": "Test API", "version": "1.0.0"},
        "paths": {
            "/users": {
                "get": {"summary": "List users", "operationId": "listUsers"},
                "post": {"summary": "Create user", "operationId": "createUser"},
            },
            "/orders/{id}": {
                "get": {"summary": "Get order", "operationId": "getOrder"},
                "put": {"summary": "Update order", "operationId": "updateOrder"},
                "delete": {"summary": "Delete order", "operationId": "deleteOrder"},
            },
        },
    }
    if with_security:
        # Add operation-level security to POST /users
        spec["paths"]["/users"]["post"]["security"] = [{"bearerAuth": []}]
        # Add path-level security to /orders/{id} (applies to all its ops)
        spec["paths"]["/orders/{id}"]["security"] = [{"bearerAuth": []}]
    return spec


# ---- Core extraction tests -------------------------------------------------


def test_extracts_five_routes():
    """A spec with 2 paths (2 + 3 operations) should yield 5 targets."""
    targets = extract_targets_from_openapi(_sample_spec())
    assert len(targets) == 5


def test_all_targets_have_kind_api_route():
    targets = extract_targets_from_openapi(_sample_spec())
    assert all(t["kind"] == "api_route" for t in targets)


def test_entrypoint_format():
    targets = extract_targets_from_openapi(_sample_spec())
    entrypoints = {t["entrypoint"] for t in targets}
    assert "GET /users" in entrypoints
    assert "POST /users" in entrypoints
    assert "GET /orders/{id}" in entrypoints
    assert "PUT /orders/{id}" in entrypoints
    assert "DELETE /orders/{id}" in entrypoints


def test_language_propagated():
    targets = extract_targets_from_openapi(_sample_spec(), language="python")
    assert all(t["language"] == "python" for t in targets)


def test_language_defaults_to_none():
    targets = extract_targets_from_openapi(_sample_spec())
    assert all(t["language"] is None for t in targets)


# ---- Stateful / security detection -----------------------------------------


def test_detects_operation_security_as_stateful():
    spec = _sample_spec(with_security=True)
    targets = extract_targets_from_openapi(spec)
    post_users = next(t for t in targets if t["entrypoint"] == "POST /users")
    assert post_users["stateful"] is True


def test_detects_path_level_security_as_stateful():
    spec = _sample_spec(with_security=True)
    targets = extract_targets_from_openapi(spec)
    order_targets = [t for t in targets if "/orders" in t["entrypoint"]]
    assert all(t["stateful"] is True for t in order_targets)


def test_no_security_means_not_stateful():
    targets = extract_targets_from_openapi(_sample_spec(with_security=False))
    assert all(t["stateful"] is False for t in targets)


# ---- File loading -----------------------------------------------------------


def test_loads_json_spec_from_file(tmp_path: Path):
    spec_file = tmp_path / "api.json"
    spec_file.write_text(json.dumps(_sample_spec()), encoding="utf-8")
    targets = extract_targets_from_file(str(spec_file))
    assert len(targets) == 5


def test_loads_yaml_spec_from_file(tmp_path: Path):
    yaml_content = textwrap.dedent("""\
        openapi: "3.0.3"
        info:
          title: Test API
          version: "1.0.0"
        paths:
          /users:
            get:
              summary: List users
            post:
              summary: Create user
          /orders/{id}:
            get:
              summary: Get order
            put:
              summary: Update order
            delete:
              summary: Delete order
    """)
    spec_file = tmp_path / "api.yaml"
    spec_file.write_text(yaml_content, encoding="utf-8")
    targets = extract_targets_from_file(str(spec_file))
    assert len(targets) == 5


# ---- Edge cases -------------------------------------------------------------


def test_empty_paths_returns_empty_list():
    spec = {"openapi": "3.0.3", "info": {}, "paths": {}}
    assert extract_targets_from_openapi(spec) == []


def test_missing_paths_key_returns_empty_list():
    spec = {"openapi": "3.0.3", "info": {}}
    assert extract_targets_from_openapi(spec) == []


def test_swagger_20_spec_works():
    """Swagger 2.0 uses the same paths structure; extraction should work."""
    spec = {
        "swagger": "2.0",
        "info": {"title": "Legacy API", "version": "1.0"},
        "paths": {
            "/health": {
                "get": {"summary": "Health check"},
            },
            "/login": {
                "post": {
                    "summary": "Login",
                    "security": [{"basic": []}],
                },
            },
        },
    }
    targets = extract_targets_from_openapi(spec)
    assert len(targets) == 2
    login = next(t for t in targets if t["entrypoint"] == "POST /login")
    assert login["stateful"] is True
    health = next(t for t in targets if t["entrypoint"] == "GET /health")
    assert health["stateful"] is False


def test_skips_non_operation_keys():
    """Keys like 'parameters', 'summary', etc. on a path item should be ignored."""
    spec = {
        "openapi": "3.0.3",
        "paths": {
            "/items": {
                "parameters": [{"name": "x", "in": "query"}],
                "summary": "Items endpoint",
                "description": "Manages items",
                "get": {"summary": "List items"},
            },
        },
    }
    targets = extract_targets_from_openapi(spec)
    assert len(targets) == 1
    assert targets[0]["entrypoint"] == "GET /items"


def test_schemas_contain_openapi_path():
    targets = extract_targets_from_openapi(_sample_spec())
    for t in targets:
        assert len(t["schemas"]) == 1
        assert t["schemas"][0].startswith("openapi:")


def test_default_reset_strategy():
    targets = extract_targets_from_openapi(_sample_spec())
    assert all(t["reset_strategy"] == "container_restart" for t in targets)


def test_actors_default_empty():
    targets = extract_targets_from_openapi(_sample_spec())
    assert all(t["actors"] == [] for t in targets)

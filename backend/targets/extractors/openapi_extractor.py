"""Extract attack-surface targets from OpenAPI / Swagger specifications."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

# HTTP methods that represent operations in an OpenAPI path item.
_HTTP_METHODS = frozenset({"get", "post", "put", "delete", "patch", "options", "head"})

# Keys on a path item that are *not* operations and should be skipped.
_NON_OPERATION_KEYS = frozenset(
    {"parameters", "summary", "description", "servers", "$ref"}
)


def extract_targets_from_openapi(
    spec: dict[str, Any],
    language: str | None = None,
) -> list[dict[str, Any]]:
    """Return a list of target descriptors from an OpenAPI/Swagger spec dict.

    Each target represents a single HTTP operation (e.g. ``GET /users``).
    """
    paths: dict[str, Any] = spec.get("paths") or {}
    targets: list[dict[str, Any]] = []

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        path_has_security = "security" in path_item

        for key, operation in path_item.items():
            if key.lower() not in _HTTP_METHODS or key.lower() in _NON_OPERATION_KEYS:
                continue
            if not isinstance(operation, dict):
                continue

            method = key.upper()
            stateful = "security" in operation or path_has_security

            targets.append(
                {
                    "kind": "api_route",
                    "entrypoint": f"{method} {path}",
                    "language": language,
                    "schemas": [f"openapi:{path}"],
                    "stateful": stateful,
                    "actors": [],
                    "reset_strategy": "container_restart",
                }
            )

    return targets


def extract_targets_from_file(
    file_path: str,
    language: str | None = None,
) -> list[dict[str, Any]]:
    """Load an OpenAPI/Swagger spec from *file_path* (JSON or YAML) and extract targets."""
    p = Path(file_path)
    raw = p.read_text(encoding="utf-8")

    if p.suffix in (".json",):
        spec = json.loads(raw)
    else:
        # Treat everything else (.yaml, .yml, etc.) as YAML.
        spec = yaml.safe_load(raw)

    return extract_targets_from_openapi(spec, language=language)

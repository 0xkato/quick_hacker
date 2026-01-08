"""Tests for building a FastAPI call-tree graph."""

import tempfile
from pathlib import Path


def _find_node_ids(graph: dict, symbol_id: str) -> list[str]:
    return [
        n["id"]
        for n in graph.get("nodes", [])
        if (n.get("data") or {}).get("symbol_id") == symbol_id
    ]


def test_builds_call_tree_for_fastapi_route():
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = Path(tmpdir)

        (repo / "requirements.txt").write_text("fastapi==0.100.0\nuvicorn\n")
        (repo / "main.py").write_text(
            """
from fastapi import FastAPI
from helpers import first

app = FastAPI()

@app.get("/root")
def root():
    return first()
"""
        )
        (repo / "helpers.py").write_text(
            """
from inner import second

def first():
    return second()
"""
        )
        (repo / "inner.py").write_text(
            """
import json

def second():
    json.dumps({"x": 1})
    return leaf()

def leaf():
    return "ok"
"""
        )

        from cass.tools.call_tree import CallTreeBuilder

        builder = CallTreeBuilder(str(repo))
        routes = builder.list_fastapi_routes()
        assert len(routes) == 1
        route = routes[0]
        assert route["method"] == "GET"
        assert route["path"] == "/root"
        assert route["handler"] == "root"

        graph = builder.build_call_tree(route, max_depth=5, include_external=True)

        # Function nodes
        root_ids = _find_node_ids(graph, "main:root")
        first_ids = _find_node_ids(graph, "helpers:first")
        second_ids = _find_node_ids(graph, "inner:second")
        leaf_ids = _find_node_ids(graph, "inner:leaf")
        ext_json_ids = _find_node_ids(graph, "external:json.dumps")

        assert len(root_ids) == 1
        assert len(first_ids) == 1
        assert len(second_ids) == 1
        assert len(leaf_ids) == 1
        assert len(ext_json_ids) == 1

        # Key edges exist (by instance IDs)
        edges = {(e["source"], e["target"]) for e in graph.get("edges", [])}
        assert (root_ids[0], first_ids[0]) in edges
        assert (first_ids[0], second_ids[0]) in edges
        assert (second_ids[0], leaf_ids[0]) in edges
        assert (second_ids[0], ext_json_ids[0]) in edges

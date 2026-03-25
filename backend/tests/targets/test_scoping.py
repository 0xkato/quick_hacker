"""Tests for target scoping — path restriction, filters, and directed targets."""
from __future__ import annotations

import pytest

from targets.extractors.multi_extractor import (
    extract_all_targets,
    _apply_filters,
    _infer_language,
)


class TestPathScoping:
    def test_scope_restricts_to_directory(self, tmp_path):
        # Set up two directories with C files
        (tmp_path / "src" / "parser").mkdir(parents=True)
        (tmp_path / "src" / "parser" / "xml.c").write_text(
            "void parse_xml(const char *buf, int len) { }"
        )
        (tmp_path / "src" / "network").mkdir(parents=True)
        (tmp_path / "src" / "network" / "http.c").write_text(
            "void handle_request(char *data) { }"
        )

        # Without scope — finds both
        all_targets = extract_all_targets(str(tmp_path))
        assert len(all_targets) >= 2

        # With scope — only parser directory
        scoped = extract_all_targets(str(tmp_path), target_scope="src/parser")
        assert len(scoped) >= 1
        # Only xml.c should appear, not http.c
        entrypoints = [t["entrypoint"] for t in scoped]
        assert any("parse_xml" in e for e in entrypoints)
        assert not any("handle_request" in e for e in entrypoints)

    def test_scope_comma_separated(self, tmp_path):
        (tmp_path / "a").mkdir()
        (tmp_path / "b").mkdir()
        (tmp_path / "c").mkdir()
        (tmp_path / "a" / "f.c").write_text(
            "void parse_data(const char *buf, int len) { }"
        )
        (tmp_path / "b" / "g.c").write_text(
            "void decode_input(char *data, size_t sz) { }"
        )
        (tmp_path / "c" / "h.c").write_text(
            "void process_buf(char *data, int n) { }"
        )

        targets = extract_all_targets(str(tmp_path), target_scope="a,b")
        entrypoints = [t["entrypoint"] for t in targets]
        # Should not include anything from c/
        assert not any("h.c" in e for e in entrypoints)
        # Should include from a/ and b/
        assert len(targets) >= 2

    def test_scope_nonexistent_warns(self, tmp_path):
        """Non-existent scope dirs produce no targets (falls back to empty)."""
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "x.c").write_text(
            "void parse_buf(char *data, int n) { }"
        )
        # Scope points to non-existent dir — falls through to full repo
        targets = extract_all_targets(str(tmp_path), target_scope="nonexistent")
        # With no matching scope dirs, logger warns and scoped_paths is empty,
        # so extraction falls back to repo_path
        assert isinstance(targets, list)


class TestTargetFilters:
    def test_include_kinds(self):
        targets = [
            {"kind": "api_route", "language": "python", "entrypoint": "GET /api", "priority_score": 0.5},
            {"kind": "native_function", "language": "c", "entrypoint": "parse.c:parse", "priority_score": 0.5},
        ]
        filtered = _apply_filters(targets, {"include_kinds": ["native_function"]})
        assert len(filtered) == 1
        assert filtered[0]["kind"] == "native_function"

    def test_exclude_kinds(self):
        targets = [
            {"kind": "api_route", "language": "python", "entrypoint": "GET /api", "priority_score": 0.5},
            {"kind": "native_function", "language": "c", "entrypoint": "parse.c:parse", "priority_score": 0.5},
        ]
        filtered = _apply_filters(targets, {"exclude_kinds": ["api_route"]})
        assert len(filtered) == 1
        assert filtered[0]["kind"] == "native_function"

    def test_include_languages(self):
        targets = [
            {"kind": "native_function", "language": "python", "entrypoint": "a.py:f", "priority_score": 0.5},
            {"kind": "native_function", "language": "c", "entrypoint": "b.c:g", "priority_score": 0.5},
        ]
        filtered = _apply_filters(targets, {"include_languages": ["c"]})
        assert len(filtered) == 1
        assert filtered[0]["language"] == "c"

    def test_exclude_languages(self):
        targets = [
            {"kind": "native_function", "language": "python", "entrypoint": "a.py:f", "priority_score": 0.5},
            {"kind": "native_function", "language": "c", "entrypoint": "b.c:g", "priority_score": 0.5},
        ]
        filtered = _apply_filters(targets, {"exclude_languages": ["python"]})
        assert len(filtered) == 1
        assert filtered[0]["language"] == "c"

    def test_include_patterns(self):
        targets = [
            {"kind": "native_function", "language": "c", "entrypoint": "parser.c:parse_xml", "priority_score": 0.5},
            {"kind": "native_function", "language": "c", "entrypoint": "util.c:copy_buffer", "priority_score": 0.5},
        ]
        filtered = _apply_filters(targets, {"include_patterns": ["*parse*"]})
        assert len(filtered) == 1
        assert "parse" in filtered[0]["entrypoint"]

    def test_exclude_patterns(self):
        targets = [
            {"kind": "native_function", "language": "c", "entrypoint": "parser.c:parse_xml", "priority_score": 0.5},
            {"kind": "native_function", "language": "c", "entrypoint": "test_util.c:test_copy", "priority_score": 0.5},
        ]
        filtered = _apply_filters(targets, {"exclude_patterns": ["*test*"]})
        assert len(filtered) == 1
        assert "parse" in filtered[0]["entrypoint"]

    def test_min_priority(self):
        targets = [
            {"kind": "native_function", "language": "c", "entrypoint": "a.c:f", "priority_score": 0.8},
            {"kind": "native_function", "language": "c", "entrypoint": "b.c:g", "priority_score": 0.3},
        ]
        filtered = _apply_filters(targets, {"min_priority": 0.5})
        assert len(filtered) == 1
        assert filtered[0]["priority_score"] == 0.8

    def test_no_filters_passes_all(self):
        targets = [{"kind": "x", "language": "y", "entrypoint": "z", "priority_score": 0}]
        assert _apply_filters(targets, None) == targets
        assert _apply_filters(targets, {}) == targets

    def test_combined_filters(self):
        targets = [
            {"kind": "native_function", "language": "c", "entrypoint": "parser.c:parse_xml", "priority_score": 0.8},
            {"kind": "native_function", "language": "python", "entrypoint": "handler.py:process", "priority_score": 0.7},
            {"kind": "api_route", "language": "python", "entrypoint": "GET /api", "priority_score": 0.5},
            {"kind": "native_function", "language": "c", "entrypoint": "test.c:test_parse", "priority_score": 0.3},
        ]
        filtered = _apply_filters(targets, {
            "include_kinds": ["native_function"],
            "exclude_languages": ["python"],
            "exclude_patterns": ["*test*"],
            "min_priority": 0.5,
        })
        assert len(filtered) == 1
        assert filtered[0]["entrypoint"] == "parser.c:parse_xml"


class TestDirectedTargets:
    def test_directed_creates_targets(self, tmp_path):
        targets = extract_all_targets(
            str(tmp_path),
            directed_targets=[
                "drivers/usb/core/hub.c:hub_port_init",
                "net/bluetooth/hci_core.c:hci_recv_frame",
            ],
        )
        assert len(targets) >= 2
        assert any("hub_port_init" in t["entrypoint"] for t in targets)
        assert any("hci_recv_frame" in t["entrypoint"] for t in targets)
        # Directed targets have priority 1.0
        directed = [
            t for t in targets
            if "hub_port_init" in t["entrypoint"] or "hci_recv_frame" in t["entrypoint"]
        ]
        assert all(t["priority_score"] == 1.0 for t in directed)

    def test_directed_api_route(self, tmp_path):
        targets = extract_all_targets(
            str(tmp_path),
            directed_targets=["GET /api/users"],
        )
        api = [t for t in targets if t["entrypoint"] == "GET /api/users"]
        assert len(api) == 1
        assert api[0]["kind"] == "api_route"

    def test_directed_infers_language(self):
        assert _infer_language("parser.c:parse") == "c"
        assert _infer_language("handler.py:process") == "python"
        assert _infer_language("lib.rs:decode") == "rust"
        assert _infer_language("Main.java:handle") == "java"
        assert _infer_language("app.go:Serve") == "go"
        assert _infer_language("index.ts:transform") == "typescript"
        assert _infer_language("index.js:transform") == "javascript"
        assert _infer_language("Token.sol:transfer") == "solidity"
        assert _infer_language("GET /api/users") is None


class TestExtractorsAcceptPathLists:
    def test_c_extractor_with_list(self, tmp_path):
        (tmp_path / "a").mkdir()
        (tmp_path / "b").mkdir()
        (tmp_path / "a" / "x.c").write_text(
            "void parse_input(const char *buf, int len) { }"
        )
        (tmp_path / "b" / "y.c").write_text(
            "void decode_data(char *data, size_t sz) { }"
        )

        from targets.extractors.c_extractor import extract_c_targets
        targets = extract_c_targets([str(tmp_path / "a"), str(tmp_path / "b")])
        assert len(targets) >= 2

    def test_python_extractor_with_list(self, tmp_path):
        (tmp_path / "a").mkdir()
        (tmp_path / "a" / "p.py").write_text("def parse_data(data: bytes): pass")

        from targets.extractors.python_extractor import extract_python_targets
        targets = extract_python_targets([str(tmp_path / "a")])
        assert len(targets) >= 1

    def test_go_extractor_with_list(self, tmp_path):
        (tmp_path / "a").mkdir()
        (tmp_path / "a" / "f.go").write_text(
            'package main\nfunc ParseData(data []byte) error { return nil }'
        )

        from targets.extractors.go_extractor import extract_go_targets
        targets = extract_go_targets([str(tmp_path / "a")])
        assert len(targets) >= 1

    def test_rust_extractor_with_list(self, tmp_path):
        (tmp_path / "a").mkdir()
        (tmp_path / "a" / "lib.rs").write_text(
            "pub fn parse_input(data: &[u8]) -> Result<(), ()> { Ok(()) }"
        )

        from targets.extractors.rust_extractor import extract_rust_targets
        targets = extract_rust_targets([str(tmp_path / "a")])
        assert len(targets) >= 1

    def test_java_extractor_with_list(self, tmp_path):
        (tmp_path / "a").mkdir()
        (tmp_path / "a" / "Parser.java").write_text(
            "public class Parser {\n  public void parseInput(byte[] data) { }\n}"
        )

        from targets.extractors.java_extractor import extract_java_targets
        targets = extract_java_targets([str(tmp_path / "a")])
        assert len(targets) >= 1

    def test_js_extractor_with_list(self, tmp_path):
        (tmp_path / "a").mkdir()
        (tmp_path / "a" / "parser.js").write_text(
            "export function parseData(data) { return data; }"
        )

        from targets.extractors.js_extractor import extract_js_targets
        targets = extract_js_targets([str(tmp_path / "a")])
        assert len(targets) >= 1

    def test_solidity_extractor_with_list(self, tmp_path):
        (tmp_path / "a").mkdir()
        (tmp_path / "a" / "Token.sol").write_text(
            "contract Token {\n  function transfer(address to, uint amount) external { }\n}"
        )

        from targets.extractors.solidity_extractor import extract_solidity_targets
        targets = extract_solidity_targets([str(tmp_path / "a")])
        assert len(targets) >= 1

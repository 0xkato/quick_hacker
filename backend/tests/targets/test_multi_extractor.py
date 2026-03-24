import pytest
from targets.extractors.multi_extractor import extract_all_targets, _detect_languages
from targets.extractors.c_extractor import extract_c_targets
from targets.extractors.python_extractor import extract_python_targets
from targets.extractors.go_extractor import extract_go_targets


class TestCExtractor:
    def test_finds_parser_functions(self, tmp_path):
        (tmp_path / "parser.c").write_text('void parse_input(const char *data, size_t len) { }')
        targets = extract_c_targets(str(tmp_path))
        assert len(targets) >= 1
        assert targets[0]["language"] in ("c", "cpp")
        assert targets[0]["kind"] == "native_function"

    def test_skips_main(self, tmp_path):
        (tmp_path / "main.c").write_text('int main(int argc, char **argv) { }')
        targets = extract_c_targets(str(tmp_path))
        assert len(targets) == 0


class TestPythonExtractor:
    def test_finds_parser_functions(self, tmp_path):
        (tmp_path / "parser.py").write_text('def parse_data(data: bytes) -> dict:\n    return {}')
        targets = extract_python_targets(str(tmp_path))
        assert len(targets) >= 1
        assert targets[0]["language"] == "python"

    def test_skips_private_functions(self, tmp_path):
        (tmp_path / "mod.py").write_text('def _internal(data): pass')
        targets = extract_python_targets(str(tmp_path))
        assert len(targets) == 0


class TestGoExtractor:
    def test_finds_exported_functions(self, tmp_path):
        (tmp_path / "parser.go").write_text('package parser\nfunc ParseInput(data []byte) error { return nil }')
        targets = extract_go_targets(str(tmp_path))
        assert len(targets) >= 1
        assert targets[0]["language"] == "go"


class TestMultiExtractor:
    def test_extracts_from_mixed_repo(self, tmp_path):
        (tmp_path / "parser.c").write_text('void parse_input(const char *buf, int len) { }')
        (tmp_path / "handler.py").write_text('def process_data(data: bytes):\n    pass')
        targets = extract_all_targets(str(tmp_path))
        assert len(targets) >= 2
        langs = {t["language"] for t in targets}
        assert "c" in langs
        assert "python" in langs

    def test_deduplicates(self, tmp_path):
        (tmp_path / "a.py").write_text('def parse(data: bytes): pass')
        targets = extract_all_targets(str(tmp_path))
        entrypoints = [t["entrypoint"] for t in targets]
        assert len(entrypoints) == len(set(entrypoints))

    def test_detects_languages(self, tmp_path):
        (tmp_path / "main.go").write_text("package main")
        (tmp_path / "lib.rs").write_text("pub fn main() {}")
        langs = _detect_languages(str(tmp_path))
        assert "go" in langs
        assert "rust" in langs

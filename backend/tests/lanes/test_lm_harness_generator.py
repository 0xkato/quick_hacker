import pytest
from unittest.mock import patch, MagicMock
from lanes.lm_harness_generator import (
    generate_harness_with_lm,
    _read_target_source,
    _extract_code,
    _build_prompt,
)


class TestReadTargetSource:
    def test_reads_file_from_entrypoint(self, tmp_path):
        (tmp_path / "parser.py").write_text("def parse(data): return data.split()")
        result = _read_target_source({"entrypoint": "parser.py:parse", "language": "python"}, str(tmp_path))
        assert "def parse" in result

    def test_finds_files_by_language(self, tmp_path):
        (tmp_path / "main.py").write_text("def main(): pass")
        result = _read_target_source({"entrypoint": "unknown", "language": "python"}, str(tmp_path))
        assert "def main" in result

    def test_returns_none_for_empty_repo(self, tmp_path):
        result = _read_target_source({"entrypoint": "missing", "language": "python"}, str(tmp_path))
        assert result is None


class TestExtractCode:
    def test_strips_markdown_fences(self):
        response = "```python\ndef foo(): pass\n```"
        assert _extract_code(response) == "def foo(): pass"

    def test_plain_code_unchanged(self):
        response = "def foo(): pass"
        assert _extract_code(response) == "def foo(): pass"


class TestBuildPrompt:
    def test_includes_all_sections(self):
        prompt = _build_prompt("aflpp", {"entrypoint": "test", "language": "c"}, "source code", "template", "instructions")
        assert "aflpp" in prompt
        assert "source code" in prompt
        assert "template" in prompt
        assert "instructions" in prompt


class TestGenerateHarness:
    @patch("lanes.lm_harness_generator._call_lm")
    def test_returns_lm_code_when_available(self, mock_lm, tmp_path):
        (tmp_path / "target.py").write_text("def process(data): pass")
        mock_lm.return_value = "import target\ndef fuzz(data): target.process(data)"

        result = generate_harness_with_lm("atheris", {"entrypoint": "target.py:process", "language": "python"}, str(tmp_path), "template")
        assert "import target" in result

    @patch("lanes.lm_harness_generator._call_lm")
    def test_returns_none_when_lm_unavailable(self, mock_lm, tmp_path):
        (tmp_path / "target.py").write_text("def process(data): pass")
        mock_lm.return_value = None

        result = generate_harness_with_lm("atheris", {"entrypoint": "target.py:process", "language": "python"}, str(tmp_path), "template")
        assert result is None

    def test_returns_none_for_missing_source(self, tmp_path):
        result = generate_harness_with_lm("atheris", {"entrypoint": "missing", "language": "python"}, str(tmp_path), "template")
        assert result is None

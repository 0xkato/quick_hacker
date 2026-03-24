import pytest
from unittest.mock import patch
from issues.analysis import analyze_artifact, _parse_json_response


class TestParseJsonResponse:
    def test_direct_json(self):
        r = _parse_json_response('{"root_cause": "buffer overflow"}')
        assert r["root_cause"] == "buffer overflow"

    def test_json_in_markdown(self):
        r = _parse_json_response('```json\n{"root_cause": "test"}\n```')
        assert r["root_cause"] == "test"

    def test_json_in_text(self):
        r = _parse_json_response('Here is the analysis: {"root_cause": "test"} done.')
        assert r["root_cause"] == "test"

    def test_invalid_returns_none(self):
        assert _parse_json_response("no json here") is None


class TestAnalyzeArtifact:
    @pytest.mark.asyncio
    @patch("issues.analysis._call_lm")
    async def test_returns_analysis_when_lm_available(self, mock_lm):
        mock_lm.return_value = '{"root_cause": "SQL injection", "impact": "data leak", "severity_recommendation": "high", "recommended_fix": "use parameterized queries"}'
        result = await analyze_artifact("art_1", artifact_details={"type": "oracle_hit", "method": "GET", "path": "/api/users"})
        assert result["analyzed"] is True
        assert result["root_cause"] == "SQL injection"

    @pytest.mark.asyncio
    @patch("issues.analysis._call_lm")
    async def test_returns_unanalyzed_when_lm_unavailable(self, mock_lm):
        mock_lm.return_value = None
        result = await analyze_artifact("art_1")
        assert result["analyzed"] is False

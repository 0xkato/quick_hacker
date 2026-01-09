"""Tests for relevance scoring."""

import pytest
from services.relevance_scorer import (
    calculate_relevance,
    score_content,
    score_position,
)


class TestScoreContent:
    def test_auth_patterns_score_high(self):
        # Use "authentication" to avoid "log" substring in "login"
        score, matched = score_content("authentication_user session")
        assert score >= 40
        assert "auth" in matched or "session" in matched

    def test_sql_patterns_score_high(self):
        # "query" and "exec" are the actual patterns that match
        score, matched = score_content("execute_query database")
        assert score >= 40
        assert "query" in matched or "exec" in matched

    def test_test_files_score_negative(self):
        score, matched = score_content("test_something mock_data")
        assert score < 0
        assert "test" in matched or "mock" in matched

    def test_neutral_code_scores_zero(self):
        # Avoid patterns like "form" in format, use simple neutral names
        score, matched = score_content("calculate_total simple_util")
        assert score == 0
        assert matched == []


class TestScorePosition:
    def test_entry_point_scores_highest(self):
        assert score_position(0) == 60

    def test_depth_1_scores_high(self):
        assert score_position(1) == 40

    def test_deep_nodes_score_low(self):
        assert score_position(5) == 5
        assert score_position(10) == 5


class TestCalculateRelevance:
    def test_auth_at_depth_1_is_high(self):
        result = calculate_relevance("authenticate", "auth/handler.py", 1)
        assert result.level == "high"
        assert result.total >= 80

    def test_test_file_is_skip(self):
        # Use neutral function name to avoid auth patterns boosting score
        result = calculate_relevance("test_something", "tests/test_utils.py", 3)
        assert result.level == "skip"
        assert result.total < 20

    def test_utility_at_depth_2_is_low(self):
        # At depth 2 (position_score=25), neutral code gets "low" level (20-49)
        result = calculate_relevance("compute_value", "utils/helpers.py", 2)
        assert result.level == "low"

    def test_entry_point_with_route_is_high(self):
        result = calculate_relevance("get_users", "api/routes.py", 0)
        assert result.level == "high"
        assert result.position_score == 60

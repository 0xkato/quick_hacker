"""Unit tests for the artifact replayer.

Tests cover full reproduction, partial reproduction, and zero reproduction
scenarios using mocked httpx responses.
"""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from evidence.replayer import replay_artifact, ReplayResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_response(status_code: int = 500):
    """Build a minimal httpx-Response-like object."""
    resp = MagicMock()
    resp.status_code = status_code
    return resp


def _make_client_mock(responses: list):
    """Return a mock httpx.Client whose .request() yields *responses* in order.

    Each entry is either a Response mock (returned) or an Exception (raised).
    """
    client = MagicMock()
    side_effects = []
    for r in responses:
        if isinstance(r, Exception):
            side_effects.append(r)
        else:
            side_effects.append(r)
    client.request = MagicMock(side_effect=side_effects)
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    return client


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestReplayArtifactFullReproduction:
    """All attempts reproduce the same failure."""

    def test_all_attempts_reproduce(self):
        """stability_score should be 1.0 when every attempt reproduces."""
        artifact = {
            "method": "POST",
            "path": "/api/users",
            "status_code": 500,
            "headers": {"Content-Type": "application/json"},
            "body": '{"name": "test"}',
        }

        responses = [_make_response(500), _make_response(500), _make_response(500)]
        client = _make_client_mock(responses)

        with patch("evidence.replayer.httpx.Client", return_value=client):
            result = replay_artifact(artifact, "http://localhost:8080", attempts=3)

        assert isinstance(result, ReplayResult)
        assert result.reproduced is True
        assert result.stability_score == 1.0
        assert result.attempts == 3
        assert result.errors == []

    def test_single_attempt_reproduces(self):
        """A single attempt that reproduces should yield 1.0."""
        artifact = {
            "method": "GET",
            "path": "/health",
            "status_code": 503,
        }

        responses = [_make_response(503)]
        client = _make_client_mock(responses)

        with patch("evidence.replayer.httpx.Client", return_value=client):
            result = replay_artifact(artifact, "http://localhost:8080", attempts=1)

        assert result.reproduced is True
        assert result.stability_score == 1.0
        assert result.attempts == 1


class TestReplayArtifactPartialReproduction:
    """Some attempts reproduce, others return a different status."""

    def test_two_of_three_reproduce(self):
        """stability_score should be ~0.667 when 2 of 3 attempts reproduce."""
        artifact = {
            "method": "GET",
            "path": "/api/data",
            "status_code": 500,
        }

        responses = [_make_response(500), _make_response(200), _make_response(500)]
        client = _make_client_mock(responses)

        with patch("evidence.replayer.httpx.Client", return_value=client):
            result = replay_artifact(artifact, "http://localhost:8080", attempts=3)

        assert result.reproduced is True
        assert abs(result.stability_score - 2.0 / 3.0) < 0.01
        assert result.attempts == 3

    def test_one_of_three_reproduce(self):
        """stability_score should be ~0.333 when 1 of 3 attempts reproduce."""
        artifact = {
            "method": "GET",
            "path": "/api/data",
            "status_code": 500,
        }

        responses = [_make_response(200), _make_response(200), _make_response(500)]
        client = _make_client_mock(responses)

        with patch("evidence.replayer.httpx.Client", return_value=client):
            result = replay_artifact(artifact, "http://localhost:8080", attempts=3)

        assert result.reproduced is True
        assert abs(result.stability_score - 1.0 / 3.0) < 0.01


class TestReplayArtifactNoReproduction:
    """No attempts reproduce the failure."""

    def test_no_reproduction(self):
        """stability_score should be 0.0 when no attempts reproduce."""
        artifact = {
            "method": "GET",
            "path": "/api/data",
            "status_code": 500,
        }

        responses = [_make_response(200), _make_response(200), _make_response(200)]
        client = _make_client_mock(responses)

        with patch("evidence.replayer.httpx.Client", return_value=client):
            result = replay_artifact(artifact, "http://localhost:8080", attempts=3)

        assert result.reproduced is False
        assert result.stability_score == 0.0
        assert result.attempts == 3
        assert result.errors == []


class TestReplayArtifactErrors:
    """Request errors during replay."""

    def test_connection_errors_with_no_expected_status(self):
        """Connection errors when no expected status -> count as reproduction."""
        artifact = {
            "method": "GET",
            "path": "/api/data",
            # No status_code -> original was also an error
        }

        error = ConnectionError("Connection refused")
        responses = [error, error, error]
        client = _make_client_mock(responses)

        with patch("evidence.replayer.httpx.Client", return_value=client):
            result = replay_artifact(artifact, "http://localhost:8080", attempts=3)

        assert result.reproduced is True
        assert result.stability_score == 1.0
        assert len(result.errors) == 3

    def test_connection_errors_with_expected_status(self):
        """Connection errors when expected status is set -> not a reproduction."""
        artifact = {
            "method": "GET",
            "path": "/api/data",
            "status_code": 500,
        }

        error = ConnectionError("Connection refused")
        responses = [error, error, error]
        client = _make_client_mock(responses)

        with patch("evidence.replayer.httpx.Client", return_value=client):
            result = replay_artifact(artifact, "http://localhost:8080", attempts=3)

        assert result.reproduced is False
        assert result.stability_score == 0.0
        assert len(result.errors) == 3

    def test_mixed_errors_and_successes(self):
        """Mix of errors and matching responses."""
        artifact = {
            "method": "POST",
            "path": "/api/submit",
            "status_code": 500,
        }

        responses = [
            _make_response(500),
            ConnectionError("timeout"),
            _make_response(500),
        ]
        client = _make_client_mock(responses)

        with patch("evidence.replayer.httpx.Client", return_value=client):
            result = replay_artifact(artifact, "http://localhost:8080", attempts=3)

        assert result.reproduced is True
        assert abs(result.stability_score - 2.0 / 3.0) < 0.01
        assert len(result.errors) == 1


class TestReplayArtifactDefaults:
    """Default parameter handling."""

    def test_defaults_to_get_method(self):
        """Missing method should default to GET."""
        artifact = {"path": "/test", "status_code": 500}

        responses = [_make_response(500), _make_response(500), _make_response(500)]
        client = _make_client_mock(responses)

        with patch("evidence.replayer.httpx.Client", return_value=client):
            result = replay_artifact(artifact, "http://localhost:8080")

        assert result.reproduced is True
        # Verify GET was used
        call_kwargs = client.request.call_args_list[0]
        assert call_kwargs[1]["method"] == "GET" or call_kwargs[0][0] == "GET"

    def test_url_construction(self):
        """URL should be correctly constructed from base_url + path."""
        artifact = {"method": "GET", "path": "/api/test", "status_code": 200}

        responses = [_make_response(200)]
        client = _make_client_mock(responses)

        with patch("evidence.replayer.httpx.Client", return_value=client):
            replay_artifact(artifact, "http://localhost:8080/", attempts=1)

        call_kwargs = client.request.call_args[1]
        assert call_kwargs["url"] == "http://localhost:8080/api/test"

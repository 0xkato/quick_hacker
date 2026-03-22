"""Tests for runs, artifacts, and issues router registration."""


def _get_paths():
    from main import app
    return [r.path for r in app.routes]


def test_runs_routes():
    paths = _get_paths()
    assert any("/runs/" in p for p in paths)


def test_runs_metrics_route():
    paths = _get_paths()
    assert any("/runs/" in p and "metrics" in p for p in paths)


def test_runs_cancel_route():
    paths = _get_paths()
    assert any("/runs/" in p and "cancel" in p for p in paths)


def test_artifacts_routes():
    paths = _get_paths()
    assert any("/artifacts/" in p for p in paths)


def test_artifacts_replay_route():
    paths = _get_paths()
    assert any("/artifacts/" in p and "replay" in p for p in paths)


def test_artifacts_minimize_route():
    paths = _get_paths()
    assert any("/artifacts/" in p and "minimize" in p for p in paths)


def test_artifacts_classify_route():
    paths = _get_paths()
    assert any("/artifacts/" in p and "classify" in p for p in paths)


def test_issues_routes():
    paths = _get_paths()
    assert any("/issues/" in p for p in paths)


def test_issues_revalidate_route():
    paths = _get_paths()
    assert any("/issues/" in p and "revalidate" in p for p in paths)


def test_campaign_artifacts_route():
    paths = _get_paths()
    assert any("/campaigns/" in p and "artifacts" in p for p in paths)


def test_campaign_artifact_buckets_route():
    paths = _get_paths()
    assert any("/campaigns/" in p and "artifact-buckets" in p for p in paths)


def test_campaign_coverage_route():
    paths = _get_paths()
    assert any("/campaigns/" in p and "coverage" in p for p in paths)


def test_campaign_steering_route():
    paths = _get_paths()
    assert any("/campaigns/" in p and "steering" in p for p in paths)


def test_campaign_issues_route():
    paths = _get_paths()
    assert any("/campaigns/" in p and "issues" in p for p in paths)
